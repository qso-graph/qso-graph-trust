// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Each policy check against a workspace planted with exactly what it must
//! catch (tests/fixtures), then against this repository, which must pass.

#![forbid(unsafe_code)]

use std::path::PathBuf;

fn here(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn the_planted_native_library_is_caught() {
    let meta = xtask::metadata(&here("tests/fixtures/Cargo.toml")).expect("fixture metadata");
    let problems = xtask::no_c(&meta, xtask::PROTECTED);
    assert_eq!(
        problems,
        vec!["planted-native links the native library planted_native"]
    );
}

#[test]
fn the_planted_unsafe_gaps_are_caught() {
    let meta = xtask::metadata(&here("tests/fixtures/Cargo.toml")).expect("fixture metadata");
    let problems = xtask::no_unsafe(&meta);
    assert_eq!(problems.len(), 2, "{problems:#?}");
    assert!(problems.iter().any(|p| p.contains("no-forbid") && p.ends_with("does not say #![forbid(unsafe_code)]")), "{problems:#?}");
    assert!(
        problems
            .iter()
            .any(|p| p == "planted-no-lints does not take the workspace's lints"),
        "{problems:#?}"
    );
}

#[test]
fn this_repository_passes() {
    let meta = xtask::metadata(&here("../Cargo.toml")).expect("workspace metadata");
    assert_eq!(xtask::no_c(&meta, xtask::PROTECTED), Vec::<String>::new());
    assert_eq!(xtask::no_unsafe(&meta), Vec::<String>::new());
}
