// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod certificate;
pub mod export;
// gzip is public for this repository's own tests, which edit TQSL backups; it is not part of the
// API and may change in any release.
#[doc(hidden)]
pub mod gzip;
mod lotw;
pub mod qso;
pub mod records;
pub mod signed_log;
pub mod signing;
pub mod station;
pub mod store;
pub mod tbk;
mod xml;

/// This library's version, as Cargo has it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_semantic() {
        // MAJOR.MINOR.PATCH, or a beta of one: MAJOR.MINOR.PATCH-beta.N.
        let (release, beta) = match VERSION.split_once('-') {
            Some((release, pre)) => (release, Some(pre)),
            None => (VERSION, None),
        };
        let parts: Vec<&str> = release.split('.').collect();
        assert_eq!(parts.len(), 3, "{VERSION}");
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()), "{VERSION}");
        if let Some(pre) = beta {
            let n = pre.strip_prefix("beta.").expect(VERSION);
            assert!(n.parse::<u32>().is_ok_and(|n| n > 0), "{VERSION}");
        }
    }
}
