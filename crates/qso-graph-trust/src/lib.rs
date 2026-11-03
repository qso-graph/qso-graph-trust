// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! QSO Graph Trust (QGT): sign and upload logs for ARRL's Logbook of The World,
//! with the operator's key held by the OS credential store.
//!
//! This crate is the library that QSO Graph Desktop, the QGT app, the `qg-trust`
//! command line and other people's tools share. It holds the key, the signing
//! and every file parser, so it contains no `unsafe` code and nothing in its
//! dependency tree is C or C++ (docs/decisions/0002-no-c-in-the-library.md).
//!
//! Phase 1 (qso-graph-desktop#170) sets up the repository; signing arrives in
//! phase 2 (qso-graph-desktop#171).

#![forbid(unsafe_code)]

/// This library's version, as Cargo has it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_semantic() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "{VERSION}");
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()), "{VERSION}");
    }
}
