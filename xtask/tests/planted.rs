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
fn every_planted_way_to_bring_native_code_is_caught() {
    let meta = xtask::metadata(&here("tests/fixtures/Cargo.toml")).expect("fixture metadata");
    assert_eq!(
        xtask::no_c(&meta, xtask::PROTECTED),
        vec![
            // A build script with no `links`: it could run a compiler itself.
            "planted-build-script 0.0.0 has a build script that has not been reviewed",
            "planted-native 0.0.0 has a build script that has not been reviewed",
            "planted-native links the native library planted_native",
            // Reached only through an optional feature: every feature is checked.
            "planted-optional-native 0.0.0 has a build script that has not been reviewed",
            "planted-optional-native links the native library planted_optional_native",
        ]
    );
}

#[test]
fn every_planted_way_to_allow_unsafe_code_is_caught() {
    let meta = xtask::metadata(&here("tests/fixtures/Cargo.toml")).expect("fixture metadata");
    let root = |dir: &str| {
        here(&format!("tests/fixtures/{dir}/src/lib.rs"))
            .display()
            .to_string()
    };
    assert_eq!(
        xtask::no_unsafe(&meta),
        vec![
            // The attribute is there, but inside a block comment.
            format!("{} does not say #![forbid(unsafe_code)]", root("commented")),
            format!("{} does not say #![forbid(unsafe_code)]", root("no-forbid")),
            // The words "[lints] workspace = true" are there, but inside a string.
            "planted-in-a-string does not take the workspace's lints".to_string(),
            "planted-no-lints does not take the workspace's lints".to_string(),
        ]
    );
}

#[test]
fn this_repository_passes() {
    let meta = xtask::metadata(&here("../Cargo.toml")).expect("workspace metadata");
    assert_eq!(xtask::no_c(&meta, xtask::PROTECTED), Vec::<String>::new());
    assert_eq!(xtask::no_unsafe(&meta), Vec::<String>::new());
}
