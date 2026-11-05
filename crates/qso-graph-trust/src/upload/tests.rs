// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;
use std::time::Duration;

#[test]
fn boundary_collision_is_retried_and_random_failure_is_returned() {
    let payload = format!("binary\0qgt-{}\r\n", "00".repeat(16));
    let mut attempts = 0;
    let boundary = boundary_with(payload.as_bytes(), |out| {
        out.fill(attempts);
        attempts += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(boundary, format!("qgt-{}", "01".repeat(16)));
    assert_eq!(
        boundary_with(b"", |_| Err(Error::Random)),
        Err(Error::Random)
    );
}

#[test]
fn filename_uses_tqsls_utc_format() {
    for (seconds, expected) in [
        (0, "19700101-0000"),
        (951_827_696, "20000229-1234"),
        (4_107_542_400, "21000301-0000"),
    ] {
        assert_eq!(
            filename(UNIX_EPOCH + Duration::from_secs(seconds)),
            format!("<TQSLUpl {expected}> log.tq8")
        );
    }
    assert_eq!(
        filename(UNIX_EPOCH - Duration::from_secs(1)),
        filename(UNIX_EPOCH)
    );
}

#[test]
fn only_a_signed_log_is_one_to_upload() {
    use super::{NotASignedLog, check_signed_log};
    let corpus = |f: &str| {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus/standard")
                .join(f),
        )
        .expect(f)
    };
    let tq7 = corpus("signed/W4W-EVENT.tq7");
    let tq8 = crate::signed_log::tq8(&tq7);
    assert_eq!(check_signed_log(&tq8), Ok(tq8.clone()));
    // Found in review: a key in gzip's comment field, which decompressing skips. What is returned
    // to upload is the checked log alone, gzipped afresh.
    let mut commented = tq8[..10].to_vec();
    commented[3] |= 0x10; // FCOMMENT
    commented.extend_from_slice(b"-----BEGIN PRIVATE KEY-----MIIC-----END PRIVATE KEY-----\0");
    commented.extend_from_slice(&tq8[10..]);
    let sent = check_signed_log(&commented).expect("the log itself is a signed log");
    assert_eq!(sent, tq8);
    assert!(!sent.windows(11).any(|w| w == b"PRIVATE KEY"));
    // And data after the gzip stream.
    let mut trailing = tq8.clone();
    trailing.extend_from_slice(b"-----BEGIN PRIVATE KEY-----");
    if let Ok(sent) = check_signed_log(&trailing) {
        assert_eq!(sent, tq8);
    }
    // A TQSL backup is gzip too, and holds private keys.
    assert_eq!(
        check_signed_log(&corpus("standard.tbk")),
        Err(NotASignedLog)
    );
    // Not gzip, gzip of something else, and a signed log with no QSO.
    assert_eq!(check_signed_log(&tq7), Err(NotASignedLog));
    assert_eq!(
        check_signed_log(&crate::signed_log::tq8(&corpus("adif/W4W-EVENT.adi"))),
        Err(NotASignedLog)
    );
    let text = String::from_utf8(tq7.clone()).expect("text");
    let header: String = text
        .split("<Rec_Type:8>tCONTACT")
        .next()
        .expect("head")
        .into();
    assert_eq!(
        check_signed_log(&crate::signed_log::tq8(header.as_bytes())),
        Err(NotASignedLog)
    );
    // Found in review: a field that no signed log has, and text after the last record.
    let planted = |text: String| check_signed_log(&crate::signed_log::tq8(text.as_bytes()));
    assert_eq!(
        planted(text.replacen(
            "<Rec_Type:8>tCONTACT",
            "<Rec_Type:8>tCONTACT\n<PRIVATE_KEY:4>TEST",
            1
        )),
        Err(NotASignedLog)
    );
    assert_eq!(
        planted(format!(
            "{text}\n-----BEGIN PRIVATE KEY-----\nMIIC\n-----END PRIVATE KEY-----\n"
        )),
        Err(NotASignedLog)
    );
    // A key's base64 where a certificate goes is not a certificate.
    let start = text.find("<CERTIFICATE:").expect("certificate");
    let end = start + text[start..].find("<eor>").expect("end");
    assert_eq!(
        planted(format!(
            "{}<CERTIFICATE:8>TUlJQ2Rn{}",
            &text[..start],
            &text[end..]
        )),
        Err(NotASignedLog)
    );
    // Found in review: a key where the signed data goes. What was signed must be the QSO's own
    // fields, so a PEM there is refused.
    let pem = String::from_utf8(
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus/pki/user-1024.key.pem"),
        )
        .expect("test key"),
    )
    .expect("text");
    let sd = text.find("<SIGNDATA:").expect("signdata");
    let sd_end = sd + text[sd..].find('\n').expect("line");
    assert_eq!(
        planted(format!(
            "{}<SIGNDATA:{}>{pem}{}",
            &text[..sd],
            pem.len(),
            &text[sd_end..]
        )),
        Err(NotASignedLog)
    );
    assert_eq!(
        planted(format!(
            "<TQSL_IDENT:4>TEST\n<Rec_Type:8>tCONTACT\n<SIGNDATA:{}>{pem}<eor>\n",
            pem.len()
        )),
        Err(NotASignedLog)
    );
    // Not bounded by a record count: more records than the ADIF reader takes still pass.
    let head = &text[..text.find("<Rec_Type:8>tCONTACT").expect("contact")];
    let contact = &text[text.find("<Rec_Type:8>tCONTACT").expect("contact")..];
    let contact = &contact[..contact.find("<eor>").expect("end") + 5];
    let mut big = String::from(head);
    for _ in 0..(crate::records::MAX_RECORDS + 1) {
        big.push_str(contact);
        big.push('\n');
    }
    assert!(planted(big).is_ok());
}
