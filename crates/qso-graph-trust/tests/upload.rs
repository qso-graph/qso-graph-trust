// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Offline protocol and source-policy tests. Every response is synthetic; no transport is used.

#![forbid(unsafe_code)]

use std::path::Path;

use qso_graph_trust::upload::{
    MAX_MESSAGE_BYTES, MAX_RESPONSE_BYTES, UPLOAD_URL, UploadOutcome, UploadRequest, parse_response,
};

fn header<'a>(request: &'a UploadRequest, name: &str) -> &'a str {
    &request
        .headers()
        .iter()
        .find(|(n, _)| *n == name)
        .expect("header")
        .1
}

// A small multipart reader independent of request construction: delimiters separate parts,
// the blank line separates each part's headers and binary content. Require exactly one file.
fn multipart_file(request: &UploadRequest) -> (Vec<(&str, &str)>, &[u8]) {
    let content_type = header(request, "Content-Type");
    let (media, parameters) = content_type.split_once(';').expect("MIME parameters");
    assert_eq!(media, "multipart/form-data");
    let (key, boundary) = parameters
        .trim()
        .split_once('=')
        .expect("boundary parameter");
    assert_eq!(key, "boundary");
    assert!((1..=70).contains(&boundary.len()));
    assert!(
        boundary
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    );
    let delimiter = format!("--{boundary}");
    let mut rest = request
        .body()
        .strip_prefix(delimiter.as_bytes())
        .expect("opening delimiter");
    rest = rest.strip_prefix(b"\r\n").expect("CRLF");
    let split = rest
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("part headers");
    let headers = std::str::from_utf8(&rest[..split])
        .expect("ASCII MIME headers")
        .split("\r\n")
        .map(|line| line.split_once(": ").expect("header pair"))
        .collect();
    rest = &rest[split + 4..];
    let closing = format!("\r\n{delimiter}--\r\n");
    let payload = rest
        .strip_suffix(closing.as_bytes())
        .expect("closing delimiter");
    assert!(
        !payload
            .windows(boundary.len())
            .any(|w| w == boundary.as_bytes())
    );
    (headers, payload)
}

#[test]
fn multipart_round_trips_binary_and_empty_logs_with_truthful_headers() {
    for tq8 in [
        b"".as_slice(),
        b"\x1f\x8b\0\xff\r\n--pretend-boundary\r\n\0signed test bytes",
    ] {
        let request = UploadRequest::new(tq8);
        assert_eq!(request.method(), "POST");
        assert_eq!(request.url(), UPLOAD_URL);
        assert_eq!(
            header(&request, "User-Agent"),
            format!("QSO Graph Trust/{}", qso_graph_trust::VERSION)
        );
        assert_eq!(request.headers().len(), 2);
        let (headers, payload) = multipart_file(&request);
        assert_eq!(payload, tq8);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1], ("Content-Type", "application/octet-stream"));
        assert_eq!(headers[0].0, "Content-Disposition");
        let disposition = headers[0].1;
        let filename = disposition
            .strip_prefix("form-data; name=\"upfile\"; filename=\"<TQSLUpl ")
            .and_then(|s| s.strip_suffix("> log.tq8\""))
            .expect("TQSL upload filename");
        assert_eq!(filename.len(), 13);
        assert_eq!(&filename[8..9], "-");
        assert!(
            filename[..8]
                .bytes()
                .chain(filename[9..].bytes())
                .all(|b| b.is_ascii_digit())
        );
    }
}

#[test]
fn each_request_uses_fresh_randomness() {
    let first = UploadRequest::try_new(b"test log").unwrap();
    let second = UploadRequest::try_new(b"test log").unwrap();
    assert_ne!(
        header(&first, "Content-Type"),
        header(&second, "Content-Type")
    );
}

fn response(status: &str, message: Option<&str>) -> Vec<u8> {
    let mut body = format!("<html><!-- [UPL] {status} -->");
    if let Some(message) = message {
        body.push_str(&format!("<!-- [UPLMESSAGE] {message} -->"));
    }
    body.push_str("</html>");
    body.into_bytes()
}

#[test]
fn tqsl_status_and_message_markers_and_exit_codes() {
    for status in ["accepted", " ACCEPTED\r\n\t", "AcCePtEd"] {
        for message in [None, Some("File queued for processing")] {
            let outcome = parse_response(200, &response(status, message));
            assert_eq!(
                outcome,
                UploadOutcome::Accepted {
                    message: message.map(str::to_owned)
                }
            );
            assert_eq!(outcome.tqsl_exit_code(), 0);
        }
    }
    for status in ["rejected", "error", "unknown", "", "not accepted"] {
        for message in [None, Some("Synthetic rejection")] {
            let outcome = parse_response(200, &response(status, message));
            assert_eq!(
                outcome,
                UploadOutcome::Rejected {
                    message: message.map(str::to_owned)
                }
            );
            assert_eq!(outcome.tqsl_exit_code(), 2);
        }
    }
    for body in [
        "",
        "<html>OK</html>",
        "<!-- [upl] accepted -->",
        "<!--[UPL] accepted -->",
        "<!-- [UPL] not-accepted -->",
        "<!-- [UPL] accepted",
        "<!-- [UPL]-->",
    ] {
        let outcome = parse_response(200, body.as_bytes());
        assert_eq!(outcome, UploadOutcome::Unknown, "{body}");
        assert_eq!(outcome.tqsl_exit_code(), 3);
    }
}

#[test]
fn fixed_tqsl_expressions_preserve_wildcards_greediness_and_first_match() {
    // TQSL's unescaped wildcard after UPL consumes the M in UPLMESSAGE.
    assert_eq!(
        parse_response(200, b"<!-- [UPLMESSAGE] Message alone -->"),
        UploadOutcome::Rejected {
            message: Some("Message alone".into())
        }
    );
    assert_eq!(
        parse_response(200, b"<!-- (UPL) accepted -->"),
        UploadOutcome::Accepted { message: None }
    );
    assert_eq!(
        parse_response(200, b"<!-- [UPL] bad-value --><!-- [UPL] accepted -->"),
        UploadOutcome::Accepted { message: None }
    );
    assert_eq!(
        parse_response(200, b"<!-- [UPL] rejected --><!-- [UPL] accepted -->"),
        UploadOutcome::Rejected { message: None }
    );
    assert_eq!(
        parse_response(
            200,
            b"<!-- [UPL] accepted --><!-- [UPLMESSAGE] one -->two -->"
        ),
        UploadOutcome::Accepted {
            message: Some("one -->two".into())
        }
    );
    assert_eq!(
        parse_response(
            200,
            &response(
                "accepted",
                Some("Started processing\nYour certificate request contains error")
            )
        ),
        UploadOutcome::Accepted {
            message: Some("Started processingYour certificate request contains error".into())
        }
    );
    assert_eq!(
        parse_response(200, b"<!-- [UPL] accepted --><!-- [UPLMESSAGE]-->"),
        UploadOutcome::Accepted { message: None }
    );
}

#[test]
fn http_status_alone_is_not_the_upload_decision() {
    for http in [200, 202, 302, 400, 403, 500, 503] {
        assert_eq!(
            parse_response(http, b"server error"),
            UploadOutcome::Unknown
        );
        assert_eq!(
            parse_response(http, &response("accepted", None)),
            UploadOutcome::Accepted { message: None }
        );
        assert_eq!(
            parse_response(http, &response("rejected", None)),
            UploadOutcome::Rejected { message: None }
        );
    }
}

#[test]
fn response_limit_and_binary_bodies_are_refused_even_with_success_marker() {
    let mut body = response("accepted", None);
    body.resize(MAX_RESPONSE_BYTES, b' ');
    assert_eq!(
        parse_response(200, &body),
        UploadOutcome::Accepted { message: None }
    );
    body.push(b' ');
    assert_eq!(parse_response(200, &body), UploadOutcome::Unknown);
    for binary in [b'\0', 0xff, 0x80] {
        let mut body = response("accepted", None);
        body.push(binary);
        assert_eq!(parse_response(200, &body), UploadOutcome::Unknown);
    }
    assert_eq!(
        parse_response(200, b"\x1f\x8b\0\xff"),
        UploadOutcome::Unknown
    );
}

#[test]
fn messages_are_trimmed_control_free_and_bounded_on_utf8_boundaries() {
    let outcome = parse_response(
        200,
        &response("rejected", Some(" \r\nA\tB\x1bC\u{85}D\x7f \n")),
    );
    assert_eq!(
        outcome,
        UploadOutcome::Rejected {
            message: Some("ABCD".into())
        }
    );
    for status in ["accepted", "rejected"] {
        let message = format!("a{}", "界".repeat(MAX_MESSAGE_BYTES));
        let outcome = parse_response(200, &response(status, Some(&message)));
        let (UploadOutcome::Accepted {
            message: Some(text),
        }
        | UploadOutcome::Rejected {
            message: Some(text),
        }) = outcome
        else {
            panic!("expected message")
        };
        assert_eq!(
            text,
            format!("a{}", "界".repeat((MAX_MESSAGE_BYTES - 1) / 3))
        );
        assert!(text.len() <= MAX_MESSAGE_BYTES);
    }
}

// Scan all library Rust sources, including currently cfg-disabled modules. Keep these checks
// outside src so that their own planted strings do not exempt anything from the scan.
fn library_sources(dir: &Path, output: &mut String) {
    for entry in std::fs::read_dir(dir).expect("source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            library_sources(&path, output);
        } else if path.extension().is_some_and(|e| e == "rs") {
            output.push_str(&std::fs::read_to_string(path).expect("Rust source"));
            output.push('\n');
        }
    }
}

fn network_free(source: &str) -> bool {
    !["std::net", "TcpStream", "UdpSocket"]
        .iter()
        .any(|token| source.contains(token))
}

fn only_fixed_upload_url(source: &str) -> bool {
    // Grep URL-shaped text as well as literals, catching endpoints added in another module.
    let urls: Vec<_> = source
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>'))
        .filter(|s| {
            (s.starts_with("https://") || s.starts_with("http://")) && s.contains("/upload")
        })
        .collect();
    urls == [UPLOAD_URL]
}

#[test]
fn library_has_no_network_primitives_and_only_one_https_upload_url() {
    assert!(UPLOAD_URL.starts_with("https://"));
    let mut source = String::new();
    library_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut source,
    );
    assert!(network_free(&source));
    assert!(only_fixed_upload_url(&source));

    // Planted cases prove each check fails with a violation, then passes without it.
    for forbidden in ["std::net", "TcpStream", "UdpSocket"] {
        assert!(
            !network_free(&format!("{source}\n{forbidden}")),
            "missed {forbidden}"
        );
        assert!(network_free(&source));
    }
    for url in [
        "http://lotw.arrl.org/lotw/upload",
        "https://example.invalid/upload",
        UPLOAD_URL,
    ] {
        assert!(!only_fixed_upload_url(&format!("{source}\n\"{url}\"")));
        assert!(only_fixed_upload_url(&source));
    }
    assert!(!only_fixed_upload_url(
        &source.replace(UPLOAD_URL, "http://example.invalid/upload")
    ));
}
