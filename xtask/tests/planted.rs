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
    let meta = fixtures();
    assert_eq!(
        xtask::no_c(&meta, xtask::PROTECTED),
        vec![
            // A build script with no `links`: it could run a compiler itself.
            "planted-build-script 0.0.0 has a build script that has not been reviewed".to_string(),
            // No `links` and no build script, but an extern block and a C file.
            "planted-extern-block 0.0.0: src/lib.rs declares foreign functions".to_string(),
            "planted-extern-block 0.0.0: src/lib.rs has a #[link] attribute".to_string(),
            "planted-extern-block 0.0.0: src/planted.c is native code".to_string(),
            "planted-native 0.0.0 has a build script that has not been reviewed".to_string(),
            "planted-native links the native library planted_native".to_string(),
            // Reached only through an optional feature: every feature is checked.
            "planted-optional-native 0.0.0 has a build script that has not been reviewed"
                .to_string(),
            "planted-optional-native links the native library planted_optional_native".to_string(),
            // From outside the workspace, and not from crates.io.
            "planted-outside 0.0.0 has not been reviewed".to_string(),
            "planted-outside 0.0.0 is not a crates.io crate".to_string(),
            // Its library's source is outside its own directory, beyond the search.
            format!(
                "planted-src-outside 0.0.0: a target's source is outside the crate: {}",
                lib_root(&meta, "planted-src-outside")
            ),
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
        // Edition 2021 compiles `extern "C" {}` without `unsafe`, even under forbid.
        "planted-old-edition: target planted_old_edition is edition 2021, not 2024".to_string(),
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
