// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `cargo xtask policy`: the repository's policy checks (see the library's docs).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    match (args.first().map(String::as_str), args.len()) {
        (Some("policy"), 1) => {}
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
            eprintln!("usage: cargo xtask policy | cargo xtask canary");
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
        ("no C in the library", no_c_on_shipping_targets(&root)),
        (
            "dependency sources",
            xtask::unreviewed_in(&meta, xtask::SHIPPED),
        ),
        ("no unsafe code", xtask::no_unsafe(&meta)),
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

/// The no-C check once per platform QGT ships for, each on that platform's own
/// dependency tree.
fn no_c_on_shipping_targets(root: &std::path::Path) -> Vec<String> {
    let mut problems = Vec::new();
    for target in xtask::SHIPPING_TARGETS {
        match xtask::metadata_for(root, Some(target)) {
            Ok(meta) => problems.extend(
                xtask::no_c(&meta, xtask::PROTECTED)
                    .into_iter()
                    .map(|p| format!("{target}: {p}")),
            ),
            Err(e) => problems.push(format!("{target}: {e}")),
        }
    }
    problems
}
