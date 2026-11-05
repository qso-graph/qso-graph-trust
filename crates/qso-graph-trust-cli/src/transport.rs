// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The one connection `qg-trust` makes: a signed log to LoTW's fixed upload address
//! (`upload::UPLOAD_URL`), as the library's upload module asks of its caller. HTTPS only; the
//! certificate and host name are always verified, against Mozilla's roots built into the program;
//! no redirect is followed; the whole exchange has a time limit; and the answer is read only up to
//! the size the library parses. A proxy is taken from the usual environment variables
//! (`HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`), never from a file.

use std::sync::Arc;
use std::time::Duration;

use qso_graph_trust::upload::{MAX_RESPONSE_BYTES, UploadRequest};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

/// Long enough for a large log on a slow line.
const TIMEOUT: Duration = Duration::from_secs(300);

/// Sends `request` and returns LoTW's HTTP status and answer. An answer larger than the library
/// reads, or one cut off, comes back empty, which the library reports as not understood: the log
/// may have arrived, so it is never treated as a failed connection that is safe to retry.
pub(crate) fn upload(request: &UploadRequest) -> Result<(u16, Vec<u8>), String> {
    let mut call = agent().post(request.url());
    for (name, value) in request.headers() {
        call = call.header(*name, value);
    }
    let mut response = call.send(request.body()).map_err(describe)?;
    let status = response.status().as_u16();
    let limit = u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX);
    match response.body_mut().with_config().limit(limit).read_to_vec() {
        Ok(body) => Ok((status, body)),
        Err(_) => Ok((status, Vec::new())),
    }
}

fn agent() -> ureq::Agent {
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::WebPki)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(TIMEOUT))
        .build()
        .new_agent()
}

/// What went wrong, in words, without the request: no header or body is quoted.
fn describe(error: ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(_) => "the connection timed out".into(),
        ureq::Error::HostNotFound => "lotw.arrl.org could not be found (is the network up?)".into(),
        // rustls reports a certificate it refuses as an I/O error carrying its own.
        ureq::Error::Io(e) => match e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
            Some(tls) => format!("LoTW's certificate could not be verified: {tls}"),
            None => format!("the connection failed: {}", e.kind()),
        },
        ureq::Error::Rustls(e) => format!("LoTW's certificate could not be verified: {e}"),
        _ => "the connection failed".into(),
    }
}

#[cfg(test)]
mod tests {
    //! The transport's settings, proved against hosts that are not ARRL's (nothing here calls
    //! LoTW). These need the network, so they run on request:
    //! `cargo test -p qso-graph-trust-cli transport -- --ignored`.

    use super::{agent, describe};

    #[test]
    #[ignore = "needs the network"]
    fn a_verified_https_server_answers() {
        let response = agent().get("https://crates.io/").call().map_err(describe);
        assert!(response.is_ok(), "{:?}", response.err());
    }

    #[test]
    #[ignore = "needs the network"]
    fn certificates_that_do_not_verify_are_refused() {
        for url in [
            "https://self-signed.badssl.com/",
            "https://wrong.host.badssl.com/",
            "https://expired.badssl.com/",
            "https://untrusted-root.badssl.com/",
        ] {
            let error = agent().get(url).call().err().map(describe);
            assert!(
                error
                    .as_deref()
                    .is_some_and(|e| e.contains("could not be verified")),
                "{url}: {error:?}"
            );
        }
    }

    #[test]
    fn plain_http_is_refused_before_connecting() {
        // https_only refuses the URL itself, so nothing is sent.
        let error = agent().get("http://127.0.0.1:9/").call();
        assert!(
            matches!(error, Err(ureq::Error::RequireHttpsOnly(_))),
            "{error:?}"
        );
    }

    #[test]
    fn redirects_are_not_followed() {
        assert_eq!(agent().config().max_redirects(), 0);
        assert!(agent().config().https_only());
    }
}
