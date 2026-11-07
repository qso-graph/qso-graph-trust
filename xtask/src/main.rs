// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `cargo xtask policy`: the repository's policy checks (see the library's docs).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

/// Every freed block is wiped, as in every program the workspace builds (AGENTS.md).
#[global_allocator]
static ALLOCATOR: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> =
    ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    match (args.first().map(String::as_str), args.len()) {
        (Some("policy"), 1) => {}
        (Some("consumer"), 2) => return consumer(&root_dir, &PathBuf::from(&args[1])),
        (Some("canary"), 1) => {
            return match xtask::canary(&root_dir, &[]) {
                Ok(()) => {
                    println!("canary: unsafe code was refused: pass");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("canary: FAIL: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        _ => {
            eprintln!(
                "usage: cargo xtask policy | cargo xtask canary | cargo xtask consumer <Cargo.toml>"
            );
            return ExitCode::from(2);
        }
    }
    let root = root_dir.join("Cargo.toml");
    let meta = match xtask::metadata(&root) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("policy: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut failed = false;
    for (check, problems) in [
        (
            "no C in the library",
            on_shipping_targets(&root, |meta| xtask::no_c(meta, xtask::PROTECTED)),
        ),
        (
            "dependency sources",
            xtask::unreviewed_in(&meta, xtask::SHIPPED),
        ),
        ("no unsafe code", xtask::no_unsafe(&meta)),
        (
            "no networking in the library",
            on_shipping_targets(&root, xtask::no_network),
        ),
        ("no lint overrides", xtask::no_lint_overrides(&root_dir)),
        ("the pinned compiler", xtask::pinned_compiler(&root_dir)),
        ("the wiping allocator", xtask::wiping_allocator(&meta)),
    ] {
        if problems.is_empty() {
            println!("policy: {check}: pass");
        } else {
            failed = true;
            for p in problems {
                eprintln!("policy: {check}: FAIL: {p}");
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `cargo xtask consumer <Cargo.toml>`: run from a checkout of one of QG Trust's releases, the
/// library's checks against another program's build of it (QSO Graph Desktop's `QGD-LTW-0001`):
/// that release, the versions it was reviewed with, no C but AWS-LC's, and every program wiping
/// what it frees.
fn consumer(root_dir: &std::path::Path, manifest: &std::path::Path) -> ExitCode {
    let commit = match std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root_dir)
        .output()
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => {
            eprintln!("consumer: cannot read this checkout's commit");
            return ExitCode::FAILURE;
        }
    };
    let reviewed = match xtask::locked(&root_dir.join("Cargo.lock")) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("consumer: {e}");
            return ExitCode::FAILURE;
        }
    };
    let meta = match xtask::metadata(manifest) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("consumer: {e}");
            return ExitCode::FAILURE;
        }
    };
    for added in xtask::consumer_added(&meta, &reviewed) {
        println!(
            "consumer: {added}: not in QG Trust's lock file, brought by this build's features"
        );
    }
    let mut failed = false;
    for (check, problems) in [
        (
            "this release of QG Trust",
            xtask::consumer_source(&meta, &commit),
        ),
        (
            "the versions QG Trust was reviewed with",
            on_shipping_targets(manifest, |meta| xtask::consumer_versions(meta, &reviewed)),
        ),
        (
            "no C in the library",
            on_shipping_targets(manifest, xtask::consumer_no_c),
        ),
        ("the wiping allocator", xtask::wiping_allocator(&meta)),
    ] {
        if problems.is_empty() {
            println!("consumer: {check}: pass");
        } else {
            failed = true;
            for p in problems {
                eprintln!("consumer: {check}: FAIL: {p}");
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// A dependency-graph check once per shipping platform, on its own tree with
/// every feature enabled.
fn on_shipping_targets(
    root: &std::path::Path,
    check: impl Fn(&serde_json::Value) -> Vec<String>,
) -> Vec<String> {
    let mut problems = Vec::new();
    for target in xtask::SHIPPING_TARGETS {
        match xtask::metadata_for(root, Some(target)) {
            Ok(meta) => problems.extend(check(&meta).into_iter().map(|p| format!("{target}: {p}"))),
            Err(e) => problems.push(format!("{target}: {e}")),
        }
    }
    problems
}
