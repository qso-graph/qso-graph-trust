// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Each policy check against a workspace planted with exactly what it must
//! catch (tests/fixtures), then against this repository, which must pass.

#![forbid(unsafe_code)]

use serde_json::Value;
use std::path::PathBuf;

fn here(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn fixtures() -> Value {
    xtask::metadata(&here("tests/fixtures/Cargo.toml")).expect("fixture metadata")
}

/// A fixture crate's library root as Cargo reports it, separators and all, so
/// the expected text is right on Windows too (found by Codex review).
fn lib_root(meta: &Value, package: &str) -> String {
    meta["packages"]
        .as_array()
        .and_then(|ps| ps.iter().find(|p| p["name"] == package))
        .and_then(|p| p["targets"].as_array())
        .and_then(|ts| ts.iter().find(|t| t["kind"][0] == "lib"))
        .and_then(|t| t["src_path"].as_str())
        .unwrap_or_else(|| panic!("{package} has no library target"))
        .to_string()
}

#[test]
fn every_planted_way_to_bring_native_code_is_caught() {
    assert_eq!(
        xtask::no_c(&fixtures(), xtask::PROTECTED),
        vec![
            // A build script with no `links`: it could run a compiler itself.
            "planted-build-script 0.0.0 has a build script that has not been reviewed",
            // No `links` and no build script, but an extern block and a C file.
            "planted-extern-block 0.0.0: src/lib.rs declares foreign functions",
            "planted-extern-block 0.0.0: src/lib.rs has a #[link] attribute",
            "planted-extern-block 0.0.0: src/planted.c is native code",
            "planted-native 0.0.0 has a build script that has not been reviewed",
            "planted-native links the native library planted_native",
            // Reached only through an optional feature: every feature is checked.
            "planted-optional-native 0.0.0 has a build script that has not been reviewed",
            "planted-optional-native links the native library planted_optional_native",
            // From outside the workspace, and not from crates.io.
            "planted-outside 0.0.0 has not been reviewed",
            "planted-outside 0.0.0 is not a crates.io crate",
        ]
    );
}

#[test]
fn every_planted_way_to_allow_unsafe_code_is_caught() {
    let meta = fixtures();
    let mut want = vec![
        // The attribute is there, but inside a block comment.
        format!(
            "{} does not say #![forbid(unsafe_code)]",
            lib_root(&meta, "planted-commented")
        ),
        format!(
            "{} does not say #![forbid(unsafe_code)]",
            lib_root(&meta, "planted-no-forbid")
        ),
        // The words "[lints] workspace = true" are there, but inside a string.
        "planted-in-a-string does not take the workspace's lints".to_string(),
        "planted-no-lints does not take the workspace's lints".to_string(),
    ];
    want.sort();
    assert_eq!(xtask::no_unsafe(&meta), want);
}

#[test]
fn this_repository_passes() {
    let meta = xtask::metadata(&here("../Cargo.toml")).expect("workspace metadata");
    assert_eq!(xtask::no_c(&meta, xtask::PROTECTED), Vec::<String>::new());
    assert_eq!(xtask::no_unsafe(&meta), Vec::<String>::new());
}
