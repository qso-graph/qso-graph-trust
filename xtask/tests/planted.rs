// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Each policy check against a workspace planted with exactly what it must
//! catch (tests/policy-fixtures at the repository root), then against this repository, which must pass.

#![forbid(unsafe_code)]

use serde_json::Value;
use std::path::PathBuf;

fn here(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// A file of a fixture crate, from the crate's directory as Cargo reports it,
/// joined part by part, so the text is what the checks print on every platform:
/// canonicalize gives `\\?\` paths on Windows, which Cargo does not (found by
/// Codex review).
fn fixture(meta: &Value, package: &str, rel: &str) -> String {
    let manifest = meta["packages"]
        .as_array()
        .and_then(|ps| ps.iter().find(|p| p["name"] == package))
        .and_then(|p| p["manifest_path"].as_str())
        .unwrap_or_else(|| panic!("{package} is not a fixture crate"));
    let mut path = PathBuf::from(manifest);
    path.pop();
    for part in rel.split('/') {
        path.push(part);
    }
    path.display().to_string()
}

fn fixtures() -> Value {
    xtask::metadata(&here("../tests/policy-fixtures/Cargo.toml")).expect("fixture metadata")
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
        // unsafe in code only a release build compiles, and in an extern block.
        format!("{} uses unsafe", lib_root(&meta, "planted-cfg-gated")),
        format!("{} uses unsafe", lib_root(&meta, "planted-extern-block")),
        // Beside a comment-only Cargo.toml, which makes no package.
        fixture(&meta, "planted-decoy", "src/hidden/payload.rs") + " uses unsafe",
        // A real module in a directory named target.
        fixture(&meta, "planted-target-module", "target/mod.rs") + " uses unsafe",
        // Files of other kinds, which a path or include could compile.
        fixture(&meta, "planted-extern-block", "src/planted.c")
            + " is not a .rs, .toml or .md file",
        fixture(&meta, "planted-path-module", "src/release.inc")
            + " is not a .rs, .toml or .md file",
        // A crate root that is not a .rs file.
        lib_root(&meta, "planted-inc-root") + " is a crate root that is not a .rs file",
        fixture(&meta, "planted-inc-root", "src/library.inc") + " is not a .rs, .toml or .md file",
        // A lone # a macro joins to brackets passed separately: #[path] assembled.
        lib_root(&meta, "planted-assembled") + " defines a macro",
        lib_root(&meta, "planted-assembled") + " has a # that does not begin an attribute",
        // The # passed in as its own macro argument: the brackets still say path =.
        lib_root(&meta, "planted-passed-hash") + " defines a macro",
        // A whole attribute passed as a meta fragment: no macro of our own is allowed.
        lib_root(&meta, "planted-meta-macro") + " defines a macro",
        // A procedural macro can generate unsafe code from a string.
        "planted-proc-gen is a procedural macro crate".to_string(),
        // No shebangs, so no line can be dropped by misreading one: `#! /* c */ [`
        // and `#!` + U+200E + `[` are both attributes to Rust (Codex review).
        fixture(&meta, "planted-decoy", "src/shebang_trick.rs")
            + " begins with #! but not #![: no shebangs in a workspace crate",
        fixture(&meta, "planted-decoy", "src/lrm.rs")
            + " begins with #! but not #![: no shebangs in a workspace crate",
        lib_root(&meta, "planted-shebang")
            + " begins with #! but not #![: no shebangs in a workspace crate",
        // A source file that is not UTF-8: a finding, not empty text that scans clean.
        fixture(&meta, "planted-decoy", "src/not_utf8.rs")
            + " cannot be read as UTF-8 text: stream did not contain valid UTF-8",
        // The library root of the planted crate whose source sits outside it.
        lib_root(&meta, "planted-src-outside") + " is a crate root outside its crate",
        // Excluded by the workspace, but inside a crate, so mod still loads it.
        fixture(&meta, "planted-excluded-inside", "src/hidden/mod.rs") + " uses unsafe",
        // A module from a file the scan would not read.
        format!("{} uses #[path]", lib_root(&meta, "planted-path-module")),
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
    // repository's own scan, wherever Cargo's output directory is; and freshly
    // created, so removing it afterwards removes nothing else (found by Codex review).
    let root = xtask::fresh_temp_dir("qgt-planted-overrides").expect("a fresh directory");
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
    // A nightly toolchain, which allows cargo-features, and profile flags with them.
    write(
        "rust-toolchain.toml",
        "[toolchain]\nchannel = \"nightly-2026-10-01\"\n",
    );
    write(
        "Cargo.toml",
        "cargo-features = [\"profile-rustflags\"]\n\n[workspace]\n\n\
         [profile.dev.package.qso-graph-trust]\nrustflags = [\"--cap-lints=allow\"]\n",
    );
    // An extensionless toolchain file, which rustup reads first, and one in a crate.
    write("rust-toolchain", "nightly\n");
    write(
        "crates/lib/rust-toolchain.toml",
        "[toolchain]\nchannel = \"nightly\"\n",
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
        .join("crates")
        .join("lib")
        .join(".cargo")
        .join("config.toml")
        .display()
        .to_string();
    let mut want =
        vec![
        ".cargo/config.toml has [build]: only [alias] is allowed".to_string(),
        format!(
            ".cargo/config.toml's [alias] must be exactly xtask = \"{}\"",
            xtask::XTASK_ALIAS
        ),
        format!("{nested} is a Cargo configuration file"),
        format!("{} is a toolchain file", root.join("rust-toolchain").display()),
        format!(
            "{} is a toolchain file",
            root.join("crates").join("lib").join("rust-toolchain.toml").display()
        ),
        "Cargo.toml has cargo-features".to_string(),
        "Cargo.toml sets profile.dev.package.qso-graph-trust.rustflags".to_string(),
        "rust-toolchain.toml must name an exact stable release, not Some(\"nightly-2026-10-01\")"
            .to_string(),
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
    let root = here("..");
    // As this repository builds: refused.
    assert_eq!(xtask::canary(&root, &[]), Ok(()));
    // PLANTED: a lint cap in the environment. The canary must notice it compiled.
    assert_eq!(
        xtask::canary(&root, &[("RUSTFLAGS", "--cap-lints=allow")]),
        Err("the canary compiled: something in this build weakens forbid(unsafe_code)".to_string())
    );
    // unsafe_code forced to a warning: the workspace's forbid still wins in a
    // real build of the library, so it is refused (checked against rustc 1.99.1).
    // A warning beside another error is not taken for a refusal either:
    // refused_by_unsafe_code's own test.
    assert_eq!(
        xtask::canary(&root, &[("RUSTFLAGS", "--force-warn=unsafe_code")]),
        Ok(())
    );
}

/// A symbolic link in a workspace crate is refused: it can point anywhere, and the
/// canary's copy would not follow it (found by Codex review). Made here, in a fresh
/// temp directory, because a committed link is not a link on every Windows checkout.
#[cfg(unix)]
#[test]
fn a_symbolic_link_in_a_crate_is_caught() {
    let dir = xtask::fresh_temp_dir("qgt-planted-link").expect("a fresh directory");
    std::fs::create_dir(dir.join("src")).expect("mkdir");
    std::fs::write(dir.join("src").join("entry.rs"), "pub fn f() {}\n").expect("write");
    std::os::unix::fs::symlink("entry.rs", dir.join("src").join("main.rs")).expect("link");
    let found = xtask::unsafe_tokens_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        found,
        vec![format!(
            "{} is a symbolic link",
            dir.join("src").join("main.rs").display()
        )]
    );
}

#[test]
fn this_repository_passes() {
    let meta = xtask::metadata(&here("../Cargo.toml")).expect("workspace metadata");
    assert_eq!(xtask::no_c(&meta, xtask::PROTECTED), Vec::<String>::new());
    assert_eq!(xtask::no_unsafe(&meta), Vec::<String>::new());
    assert_eq!(
        xtask::unreviewed_in(&meta, xtask::SHIPPED),
        Vec::<String>::new()
    );
    assert_eq!(xtask::no_lint_overrides(&here("..")), Vec::<String>::new());
    assert_eq!(xtask::pinned_compiler(&here("..")), Vec::<String>::new());
}
