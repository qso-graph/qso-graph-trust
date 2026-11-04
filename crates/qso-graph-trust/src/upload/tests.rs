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
