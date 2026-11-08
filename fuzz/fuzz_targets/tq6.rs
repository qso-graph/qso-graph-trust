// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A `.tq6`, imported as `qg-trust import` imports one: no panic, and every certificate imported
//! verifies under the store's trust, with no key (docs/decisions/0012-fuzzing.md).

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= qso_graph_trust_fuzz::MAX_INPUT {
        qso_graph_trust_fuzz::import_like_the_cli(
            "tq6",
            |store, trust, root| {
                store
                    .import_tq6(data, trust, root)
                    .map(|imported| imported.into_iter().map(|c| (c.id, c.has_key)).collect())
            },
            false,
        );
    }
});
