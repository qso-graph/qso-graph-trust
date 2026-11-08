// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A TQSL `.tbk` backup, read as the library reads one, trusting only the caller's roots and then
//! its own: no panic, and what is accepted hangs together (docs/decisions/0012-fuzzing.md).

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= qso_graph_trust_fuzz::MAX_INPUT {
        qso_graph_trust_fuzz::read_tbk(data);
    }
});
