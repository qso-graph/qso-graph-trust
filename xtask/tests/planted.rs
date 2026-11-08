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
/// canonicalize gives `\\?\` paths on Windows, which Cargo does not (found in
/// review).
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
/// the expected text is right on Windows too (found in review).
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
            // From outside the workspace, and not from crates.io (reviewing
            // crates.io crates is cargo-vet's).
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
        // Unstable features, and the unstable `macro` (found in review).
        lib_root(&meta, "planted-decl-macro") + " enables an unstable feature",
        fixture(&meta, "planted-decl-macro", "src/generated.rs") + " defines a macro",
        // A procedural macro can generate unsafe code from a string.
        "planted-proc-gen is a procedural macro crate".to_string(),
        // No shebangs, so no line can be dropped by misreading one: `#! /* c */ [`
        // and `#!` + U+200E + `[` are both attributes to Rust (found in review).
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
fn every_planted_network_path_or_type_is_caught() {
    let scan = |s: &str| xtask::network_tokens(s.parse().expect("Rust tokens"));
    for planted in [
        "use std::{net};",
        "use std::net as n;",
        "std::os::unix::net::UnixStream",
        "use std::{io, net::{TcpListener}};",
        "core::net::IpAddr",
        "use std :: /* spacing */ net :: *;",
        "use std::{os::{unix::{net as n}}};",
        "use std::{r#net};",
        "r#net::connect()",
        "#[cfg(any())] mod disabled { use std::{net}; }",
        "consume!(std::net)",
    ] {
        assert!(
            scan(planted).contains(&"uses network path segment net"),
            "missed {planted}"
        );
    }
    for name in [
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "UnixStream",
        "UnixListener",
        "UnixDatagram",
        "ToSocketAddrs",
        "SocketAddr",
        "SocketAddrV4",
        "SocketAddrV6",
        "IpAddr",
    ] {
        for planted in [
            format!("use provider::{{{name} as Alias}};"),
            format!("#[cfg(any())] fn f(_: r#{name}) {{}}"),
        ] {
            assert_eq!(scan(&planted).len(), 1, "missed {planted}");
        }
    }
    // Identifier tokens count, not matching prose, longer identifiers or local
    // bindings. A use's alias is not one of its source path segments.
    for clean in [
        "// std::net::TcpStream\nconst S: &str = \"use std::{net}; UdpSocket\";",
        "/// TcpStream and core::net::IpAddr\nfn f() {}",
        "fn f() { let net = 1; consume(net); }",
        "use std::io as net;",
        "use std::io; fn f() { let net = 1; }",
        "struct TcpStreamBuffer; mod network {}",
    ] {
        assert!(scan(clean).is_empty(), "refused {clean}");
    }
}

#[test]
fn network_policy_scans_library_and_binding_but_allows_cli() {
    let root = xtask::fresh_temp_dir("qso-graph-trust-planted-network").expect("fresh directory");
    let names = [
        "qso-graph-trust",
        xtask::UNSAFE_BINDING,
        "qso-graph-trust-cli",
    ];
    let mut packages = Vec::new();
    for name in names {
        let dir = root.join(name);
        std::fs::create_dir_all(dir.join("src")).expect("mkdir");
        std::fs::write(dir.join("Cargo.toml"), "[package]\n").expect("manifest");
        std::fs::write(dir.join("src/lib.rs"), "pub fn clean() {}\n").expect("source");
        packages.push(serde_json::json!({
            "id": name,
            "name": name,
            "manifest_path": dir.join("Cargo.toml"),
        }));
    }
    let meta = serde_json::json!({
        "workspace_root": root,
        "workspace_members": names,
        "packages": packages,
        "resolve": {"nodes": [
            {"id": "qso-graph-trust", "deps": [
                {"pkg": xtask::UNSAFE_BINDING, "dep_kinds": [{"kind": null}]}
            ]},
            {"id": xtask::UNSAFE_BINDING, "deps": []},
            {"id": "qso-graph-trust-cli", "deps": []},
        ]},
    });
    assert!(xtask::no_network(&meta).is_empty());
    // An unreferenced file in a nested directory is scanned even if no current
    // build would compile it. Each plant is removed before the next one.
    for name in names {
        let dir = root.join(name).join("src").join("disabled");
        std::fs::create_dir(&dir).expect("mkdir");
        let path = dir.join("payload.rs");
        for planted in [
            "use std::{net};",
            "use std::net as n;",
            "std::os::unix::net::UnixStream",
            "use std::{io, net::{TcpListener}};",
            "core::net::IpAddr",
        ] {
            std::fs::write(&path, format!("#[cfg(any())] mod disabled {{ {planted} }}"))
                .expect("plant");
            let findings = xtask::no_network(&meta);
            if name == "qso-graph-trust-cli" {
                assert!(findings.is_empty(), "CLI must be allowed: {findings:?}");
            } else {
                assert!(
                    findings.contains(&format!("{} uses network path segment net", path.display())),
                    "missed {name}: {planted}: {findings:?}"
                );
            }
            std::fs::remove_file(&path).expect("remove plant");
            assert!(xtask::no_network(&meta).is_empty());
        }
    }
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn every_planted_way_to_override_the_lints_is_caught() {
    // A repository made for the test, planted with each way found to weaken the
    // lints without touching a manifest or a crate root (found in
    // review). --cap-lints overrides even forbid(unsafe_code).
    // Outside this repository, so its planted files are never part of the
    // repository's own scan, wherever Cargo's output directory is; and freshly
    // created, so removing it afterwards removes nothing else (found in review).
    let root =
        xtask::fresh_temp_dir("qso-graph-trust-planted-overrides").expect("a fresh directory");
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
         [profile.dev.package.qso-graph-trust]\nrustflags = [\"--cap-lints=allow\"]\n\n\
         [patch.crates-io]\nlibc = { path = \"crates/libc\" }\n",
    );
    // An extensionless toolchain file, which rustup reads first, and one in a crate.
    write("rust-toolchain", "nightly\n");
    write(
        "crates/lib/rust-toolchain.toml",
        "[toolchain]\nchannel = \"nightly\"\n",
    );
    // A second configuration file inside a crate, and one whose name differs only
    // in case, which Windows and macOS read as the same (found in review).
    write("crates/lib/.cargo/config.toml", "[build]\nrustflags = []\n");
    write(
        "crates/other/.CARGO/config.toml",
        "[target.x86_64-pc-windows-msvc]\nrustflags = [\"-l\", \"user32\"]\n",
    );
    write(
        "crates/other/RUST-TOOLCHAIN.toml",
        "[toolchain]\nchannel = \"nightly\"\n",
    );
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
    // The Windows build's one line is allowed in binaries.yml, and only there and only exactly.
    write(
        ".github/workflows/binaries.yml",
        &format!("steps:\n  - run: |\n      {}\n", xtask::WINDOWS_CRT_STATIC),
    );
    write(
        ".github/workflows/e.yml",
        &format!("steps:\n  - run: |\n      {}\n", xtask::WINDOWS_CRT_STATIC),
    );
    write(
        ".github/workflows/f.yml",
        "steps:\n  - run: |\n      export RUSTFLAGS=\"-C target-feature=+crt-static --cap-lints=allow\"\n",
    );
    let nested = root
        .join("crates")
        .join("lib")
        .join(".cargo")
        .join("config.toml")
        .display()
        .to_string();
    let other = root.join("crates").join("other");
    let mut want =
        vec![
        format!(
            "{} is a Cargo configuration file",
            other.join(".CARGO").join("config.toml").display()
        ),
        format!("{} is a toolchain file", other.join("RUST-TOOLCHAIN.toml").display()),
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
        // A patch consumers would not see (found in review).
        "Cargo.toml has [patch]".to_string(),
        "Cargo.toml sets profile.dev.package.qso-graph-trust.rustflags".to_string(),
        "rust-toolchain.toml must name an exact stable release, not Some(\"nightly-2026-10-01\")"
            .to_string(),
        "workflow a.yml sets RUSTFLAGS: RUSTFLAGS: \"@ci.rsp\"".to_string(),
        "workflow b.yml mentions --config".to_string(),
        "workflow c.yml mentions RUSTC".to_string(),
        "workflow d.yml sets RUSTFLAGS: RUSTFLAGS: -l static=z".to_string(),
        format!("workflow e.yml sets RUSTFLAGS: {}", xtask::WINDOWS_CRT_STATIC),
        "workflow f.yml mentions cap-lints".to_string(),
        "workflow f.yml sets RUSTFLAGS: export RUSTFLAGS=\"-C target-feature=+crt-static --cap-lints=allow\""
            .to_string(),
    ];
    want.sort();
    let got = xtask::no_lint_overrides(&root);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(got, want);
}

/// A planted repository that passes the lint-override check, for the fuzzers' cases.
fn clean_repository(name: &str) -> PathBuf {
    let root = xtask::fresh_temp_dir(name).expect("a fresh directory");
    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    };
    write(
        ".cargo/config.toml",
        &format!("[alias]\nxtask = \"{}\"\n", xtask::XTASK_ALIAS),
    );
    write("rust-toolchain.toml", "[toolchain]\nchannel = \"1.99.1\"\n");
    write("Cargo.toml", "[workspace]\n");
    root
}

#[test]
fn the_fuzzers_toolchain_is_allowed_at_exactly_fuzz_and_nowhere_else() {
    let root = clean_repository("qso-graph-trust-planted-fuzz-toolchain");
    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    };
    let nightly = "[toolchain]\nchannel = \"nightly-2026-10-30\"\n";
    // The one exception, and Cargo's output for its workspace, which is not walked.
    write("fuzz/rust-toolchain.toml", nightly);
    write("fuzz/target/rust-toolchain.toml", nightly);
    assert_eq!(xtask::no_lint_overrides(&root), Vec::<String>::new());
    // A name that merely begins with fuzz, a folder inside fuzz, a fuzz folder inside a crate,
    // another folder's target, and a Cargo configuration in fuzz: each still caught.
    write("fuzzx/rust-toolchain.toml", nightly);
    write("fuzz/sub/rust-toolchain.toml", nightly);
    write("crates/lib/fuzz/rust-toolchain.toml", nightly);
    write("fuzzx/target/rust-toolchain.toml", nightly);
    write("fuzz/rust-toolchain", "nightly\n");
    write("fuzz/.cargo/config.toml", "[build]\nrustflags = []\n");
    let toolchain = |rel: &[&str]| {
        let mut path = root.clone();
        for part in rel {
            path = path.join(part);
        }
        path.display().to_string()
    };
    let mut want = vec![
        format!(
            "{} is a toolchain file",
            toolchain(&["fuzzx", "rust-toolchain.toml"])
        ),
        format!(
            "{} is a toolchain file",
            toolchain(&["fuzz", "sub", "rust-toolchain.toml"])
        ),
        format!(
            "{} is a toolchain file",
            toolchain(&["crates", "lib", "fuzz", "rust-toolchain.toml"])
        ),
        format!(
            "{} is a toolchain file",
            toolchain(&["fuzzx", "target", "rust-toolchain.toml"])
        ),
        format!(
            "{} is a toolchain file",
            toolchain(&["fuzz", "rust-toolchain"])
        ),
        format!(
            "{} is a Cargo configuration file",
            toolchain(&["fuzz", ".cargo", "config.toml"])
        ),
    ];
    want.sort();
    let got = xtask::no_lint_overrides(&root);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(got, want);
}

#[test]
fn every_planted_way_to_stretch_the_fuzzers_exception_is_caught() {
    let root = clean_repository("qso-graph-trust-planted-fuzzers");
    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    };
    let manifest = "[package]\nname = \"f\"\npublish = false\n\n[package.metadata]\n\
                    cargo-fuzz = true\n\n[workspace]\nmembers = [\".\"]\n\n[dependencies]\n\
                    libfuzzer-sys = \"=0.4.13\"\nqso-graph-trust = { path = \"../crates/lib\" }\n";
    let target = "#![no_main]\n#![forbid(unsafe_code)]\nfuzz_target!(|d: &[u8]| { let _ = d; });\n";
    write(
        "fuzz/rust-toolchain.toml",
        "[toolchain]\nchannel = \"nightly-2026-10-30\"\n",
    );
    write("fuzz/Cargo.toml", manifest);
    write(
        "fuzz/src/lib.rs",
        "#![forbid(unsafe_code)]\npub fn f() {}\n",
    );
    write("fuzz/fuzz_targets/a.rs", target);
    assert_eq!(xtask::fuzzers(&root), Vec::<String>::new());
    // A floating nightly; a manifest published, in the root's workspace, not cargo-fuzz's, with a
    // floating dependency; unsafe code in a target and in the shared code; a target that does not
    // forbid it.
    write(
        "fuzz/rust-toolchain.toml",
        "[toolchain]\nchannel = \"nightly\"\n",
    );
    write(
        "fuzz/Cargo.toml",
        "[package]\nname = \"f\"\n\n[dependencies]\nlibfuzzer-sys = \"0.4\"\n",
    );
    write(
        "fuzz/fuzz_targets/b.rs",
        "#![no_main]\n#![forbid(unsafe_code)]\nfn f() { unsafe {} }\n",
    );
    write("fuzz/fuzz_targets/c.rs", "#![no_main]\nfn f() {}\n");
    write(
        "fuzz/src/lib.rs",
        "#![forbid(unsafe_code)]\n#[path = \"x.txt\"] mod x;\n",
    );
    let file = |rel: &[&str]| {
        let mut path = root.join("fuzz");
        for part in rel {
            path = path.join(part);
        }
        path.display().to_string()
    };
    let mut want = vec![
        "fuzz/rust-toolchain.toml must name a dated nightly, not Some(\"nightly\")".to_string(),
        "fuzz/Cargo.toml is not a workspace of its own".to_string(),
        "fuzz/Cargo.toml does not say publish = false".to_string(),
        "fuzz/Cargo.toml is not a cargo-fuzz crate".to_string(),
        "fuzz/Cargo.toml: libfuzzer-sys is not pinned with = or a path in this repository"
            .to_string(),
        format!("{} uses unsafe", file(&["fuzz_targets", "b.rs"])),
        format!(
            "{} does not say #![forbid(unsafe_code)]",
            file(&["fuzz_targets", "c.rs"])
        ),
        format!("{} uses #[path]", file(&["src", "lib.rs"])),
    ];
    want.sort();
    let got = xtask::fuzzers(&root);
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
        xtask::canary(
            &root,
            &[
                ("RUSTFLAGS", "--cap-lints=allow"),
                // Cargo prefers this one when it is set at all (found in review).
                ("CARGO_ENCODED_RUSTFLAGS", "--cap-lints=allow"),
            ]
        ),
        Err("the canary compiled: something in this build weakens forbid(unsafe_code)".to_string())
    );
    // unsafe_code forced to a warning: the workspace's forbid still wins in a
    // real build of the library, so it is refused (checked against rustc 1.99.1).
    // A warning beside another error is not taken for a refusal either:
    // refused_by_unsafe_code's own test.
    assert_eq!(
        xtask::canary(
            &root,
            &[
                ("RUSTFLAGS", "--force-warn=unsafe_code"),
                ("CARGO_ENCODED_RUSTFLAGS", "--force-warn=unsafe_code"),
            ]
        ),
        Ok(())
    );
}

/// A symbolic link in a workspace crate is refused: it can point anywhere, and the
/// canary's copy would not follow it (found in review). Made here, in a fresh
/// temp directory, because a committed link is not a link on every Windows checkout.
#[cfg(unix)]
#[test]
fn a_symbolic_link_in_a_crate_is_caught() {
    let dir = xtask::fresh_temp_dir("qso-graph-trust-planted-link").expect("a fresh directory");
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

/// A fixture program's root as Cargo reports it.
fn program_root(meta: &Value, package: &str, program: &str) -> String {
    meta["packages"]
        .as_array()
        .and_then(|ps| ps.iter().find(|p| p["name"] == package))
        .and_then(|p| p["targets"].as_array())
        .and_then(|ts| ts.iter().find(|t| t["name"] == program))
        .and_then(|t| t["src_path"].as_str())
        .unwrap_or_else(|| panic!("{package} has no program {program}"))
        .to_string()
}

#[test]
fn every_planted_program_without_the_wiping_allocator_is_caught() {
    let meta = fixtures();
    let missing = |package: &str, program: &str| {
        format!(
            "{} does not install the wiping allocator",
            program_root(&meta, package, program)
        )
    };
    let no_dependency = |package: &str| {
        format!(
            "{package} does not depend on zeroizing-alloc =0.1.1 from crates.io by its own name"
        )
    };
    let mut expected = vec![
        missing("planted-alloc-missing", "planted-alloc-missing"),
        no_dependency("planted-alloc-missing"),
        // Behind a cfg, so one build has none.
        missing("planted-alloc-cfg", "planted-alloc-cfg"),
        no_dependency("planted-alloc-cfg"),
        // A library another language loads, with an allocator that wipes nothing.
        missing("planted-alloc-other", "planted_alloc_other"),
        no_dependency("planted-alloc-other"),
        // Found in review: the control's name in another package, and a program named like it.
        missing("planted-alloc-control", "qgt-custody-unwiped"),
        missing("planted-alloc-control", "qgt-custody-unwiped-too"),
        no_dependency("planted-alloc-control"),
        // Found in review: an example, which cargo install --example installs.
        missing("planted-alloc-example", "sign"),
        no_dependency("planted-alloc-example"),
        // Found in review: another crate renamed into the allocator's name, behind a correct line.
        no_dependency("planted-alloc-renamed"),
    ];
    expected.sort();
    // The program that installs it as required passes.
    assert_eq!(xtask::wiping_allocator(&meta), expected);
}

#[test]
fn the_allocator_must_be_exactly_the_wiping_one() {
    let wiped = "#[global_allocator]\nstatic A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);";
    assert!(xtask::installs_wiping_allocator(wiped));
    for planted in [
        // Not the allocator: no #[global_allocator].
        "static A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);",
        // Switched off for some builds.
        "#[cfg_attr(test, global_allocator)]\nstatic A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);",
        // Over an allocator other than the system's.
        "#[global_allocator]\nstatic A: ::zeroizing_alloc::ZeroAlloc<::other::Alloc> = ::zeroizing_alloc::ZeroAlloc(::other::Alloc);",
        // Found in review: relative paths, which a local module of the same name answers, here one
        // that makes the line install the plain system allocator.
        "mod zeroizing_alloc { pub type ZeroAlloc<T> = T; }\n#[global_allocator]\nstatic A: zeroizing_alloc::ZeroAlloc<std::alloc::System> = zeroizing_alloc::ZeroAlloc(std::alloc::System);",
        // This crate put behind the name with a raw identifier, aliasing the allocator to plain
        // System (found in review).
        "extern crate self as r#zeroizing_alloc;\npub type ZeroAlloc<T> = T;\n#[global_allocator]\nstatic A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);",
        // Another crate put behind the name.
        "extern crate other as zeroizing_alloc;\n#[global_allocator]\nstatic A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);",
        // Only in a comment or a string.
        "// #[global_allocator] static A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);",
        "const S: &str = \"#[global_allocator] static A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);\";",
        // Inside a module the check does not read, or a file that does not parse.
        "mod m {\n#[global_allocator]\nstatic A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);\n}",
        "#[global_allocator] static A: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> = ::zeroizing_alloc::ZeroAlloc(::std::alloc::System)",
    ] {
        assert!(!xtask::installs_wiping_allocator(planted), "{planted}");
    }
}

#[test]
fn this_repository_passes() {
    let meta = xtask::metadata(&here("../Cargo.toml")).expect("workspace metadata");
    // The no-C check per shipping platform, as the policy runs it (found in
    // review: unfiltered, it would refuse a dependency only another platform uses).
    for target in xtask::SHIPPING_TARGETS {
        let per = xtask::metadata_for(&here("../Cargo.toml"), Some(target)).expect("metadata");
        assert_eq!(
            xtask::no_c(&per, xtask::PROTECTED),
            Vec::<String>::new(),
            "{target}"
        );
        assert_eq!(xtask::no_network(&per), Vec::<String>::new(), "{target}");
    }
    assert_eq!(xtask::no_unsafe(&meta), Vec::<String>::new());
    assert_eq!(xtask::no_network(&meta), Vec::<String>::new());
    assert_eq!(
        xtask::unreviewed_in(&meta, xtask::SHIPPED),
        Vec::<String>::new()
    );
    assert_eq!(xtask::no_lint_overrides(&here("..")), Vec::<String>::new());
    assert_eq!(xtask::pinned_compiler(&here("..")), Vec::<String>::new());
    assert_eq!(xtask::wiping_allocator(&meta), Vec::<String>::new());
    assert_eq!(xtask::fuzzers(&here("..")), Vec::<String>::new());
}
