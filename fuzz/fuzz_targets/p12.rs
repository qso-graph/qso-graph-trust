// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A `.p12`, imported as `qg-trust import` imports one, with the corpus's test password: no panic,
//! and a certificate imported verifies under the store's trust, with a key that is its own and signs
//! (docs/decisions/0012-fuzzing.md).

#![no_main]
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn password() -> &'static [u8] {
    static PASSWORD: OnceLock<Vec<u8>> = OnceLock::new();
    PASSWORD.get_or_init(|| qso_graph_trust_fuzz::corpus("pki/p12-password"))
}

fuzz_target!(|data: &[u8]| {
    if data.len() <= qso_graph_trust_fuzz::MAX_INPUT {
        qso_graph_trust_fuzz::import_like_the_cli(
            "p12",
            |store, trust, root| {
                store
                    .import_pkcs12(data, password(), trust, root)
                    .map(|c| vec![(c.id, c.has_key)])
            },
            true,
        );
    }
});
