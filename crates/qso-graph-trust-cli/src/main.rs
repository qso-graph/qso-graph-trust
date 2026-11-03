// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `qg-trust`, QSO Graph Trust's command line. Its tqsl-compatible options arrive in
//! phase 4 (qso-graph-desktop#173); until then it reports its version and says
//! plainly that it signs nothing yet.

#![forbid(unsafe_code)]

use std::process::ExitCode;

/// tqsl's exit code for a command syntax error (TQSL 2.8.7, apps/tqslapp.h),
/// kept so a logger that calls `tqsl` today reads the same meaning.
const EXIT_SYNTAX: u8 = 10;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, code) = run(&args);
    if code == 0 {
        println!("{out}");
    } else {
        eprintln!("{out}");
    }
    ExitCode::from(code)
}

/// What `qg-trust` prints for these arguments, and its exit code.
fn run(args: &[String]) -> (String, u8) {
    match args.first().map(String::as_str) {
        Some("-v" | "--version") if args.len() == 1 => {
            (format!("qg-trust {}", qso_graph_trust::VERSION), 0)
        }
        Some("-h" | "--help") if args.len() == 1 => (
            "qg-trust: QSO Graph Trust's command line. It signs nothing yet: signing arrives \
             with qso-graph-desktop#173.\n\nUsage: qg-trust --version | --help"
                .to_string(),
            0,
        ),
        _ => (
            "qg-trust: signing is not implemented yet (qso-graph-desktop#173); \
             try qg-trust --help"
                .to_string(),
            EXIT_SYNTAX,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{EXIT_SYNTAX, run};

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn version_names_the_library_version() {
        let (out, code) = run(&args(&["--version"]));
        assert_eq!(code, 0);
        assert_eq!(out, format!("qg-trust {}", qso_graph_trust::VERSION));
        assert_eq!(run(&args(&["-v"])).0, out);
    }

    #[test]
    fn anything_else_is_refused_with_tqsls_syntax_code() {
        for a in [&[][..], &["-x", "log.adi"][..], &["--version", "extra"][..]] {
            assert_eq!(run(&args(a)).1, EXIT_SYNTAX, "{a:?}");
        }
    }
}
