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
fn every_planted_way_to_override_the_lints_is_caught() {
    // A repository made for the test, planted with each way found to weaken the
    // lints without touching a manifest or a crate root (Codex review, rounds 6
    // and 7). --cap-lints overrides even forbid(unsafe_code).
    // Outside this repository, so its planted files are never part of the
    // repository's own scan, wherever Cargo's output directory is (found by Codex review).
    let root = std::env::temp_dir().join(format!("qgt-planted-overrides-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    };
    // A lint cap in the configuration, and an alias that passes one.
    write(
        ".cargo/config.toml",
        "[alias]\nxtask = \"run --quiet --locked --package xtask --\"\n\
         unchecked = \"rustc -p qso-graph-trust -- --cap-lints=allow\"\n\n\
         [build]\nrustflags = [\"--cap-lints=allow\"]\n",
    );
    // A second configuration file inside a crate.
    write("crates/lib/.cargo/config.toml", "[build]\nrustflags = []\n");
    // Workflows: a response file, another configuration, a wrapper, a native library.
    write(
        ".github/workflows/a.yml",
        "env:\n  RUSTFLAGS: \"@ci.rsp\"\n",
    );
    write(
        ".github/workflows/b.yml",
        "steps:\n  - run: cargo --config ci-flags.toml test\n",
    );
    write(
        ".github/workflows/c.yml",
        "env:\n  RUSTC_WORKSPACE_WRAPPER: scripts/w.sh\n",
    );
    write(
        ".github/workflows/d.yml",
        "env:\n  RUSTFLAGS: -l static=z\n",
    );
    let nested = root
        .join("crates/lib/.cargo/config.toml")
        .display()
        .to_string();
    let mut want = vec![
        ".cargo/config.toml has [build]: only [alias] is allowed".to_string(),
        format!(
            ".cargo/config.toml's [alias] must be exactly xtask = \"{}\"",
            xtask::XTASK_ALIAS
        ),
        format!("{nested} is a Cargo configuration file"),
        "workflow a.yml sets RUSTFLAGS: RUSTFLAGS: \"@ci.rsp\"".to_string(),
        "workflow b.yml mentions --config".to_string(),
        "workflow c.yml mentions RUSTC".to_string(),
        "workflow d.yml sets RUSTFLAGS: RUSTFLAGS: -l static=z".to_string(),
    ];
    want.sort();
    let got = xtask::no_lint_overrides(&root);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(got, want);
}

#[test]
fn the_canary_is_refused_here_and_compiles_under_a_lint_cap() {
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("canary");
    let root = here("..");
    // As this repository builds: refused.
    assert_eq!(xtask::canary(&root, &target.join("plain"), &[]), Ok(()));
    // PLANTED: a lint cap in the environment. The canary must notice it compiled.
    assert_eq!(
        xtask::canary(
            &root,
            &target.join("capped"),
            &[("RUSTFLAGS", "--cap-lints=allow")]
        ),
        Err("the canary compiled: something in this build weakens forbid(unsafe_code)".to_string())
    );
}

#[test]
fn this_repository_passes() {
    let meta = xtask::metadata(&here("../Cargo.toml")).expect("workspace metadata");
    assert_eq!(xtask::no_c(&meta, xtask::PROTECTED), Vec::<String>::new());
    assert_eq!(xtask::no_unsafe(&meta), Vec::<String>::new());
    assert_eq!(xtask::no_lint_overrides(&here("..")), Vec::<String>::new());
}
