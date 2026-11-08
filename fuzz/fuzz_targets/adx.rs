// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! An ADX log, signed as `qg-trust` signs one: no panic, no hang, and no signature for a record
//! the library refuses (docs/decisions/0012-fuzzing.md).

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= qso_graph_trust_fuzz::MAX_INPUT {
        qso_graph_trust_fuzz::sign_like_the_cli(data);
    }
});
