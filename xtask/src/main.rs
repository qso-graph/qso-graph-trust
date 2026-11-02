// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `cargo xtask policy`: the repository's policy checks (see the library's docs).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("policy") || args.len() > 1 {
        eprintln!("usage: cargo xtask policy");
        return ExitCode::from(2);
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    let meta = match xtask::metadata(&root) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("policy: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut failed = false;
    for (check, problems) in [
        ("no C in the library", xtask::no_c(&meta, xtask::PROTECTED)),
        ("no unsafe code", xtask::no_unsafe(&meta)),
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
