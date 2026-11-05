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
    assert_eq!(check_signed_log(&crate::signed_log::tq8(&tq7)), Ok(()));
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
}
