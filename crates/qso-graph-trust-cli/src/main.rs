// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `qg-trust`, QSO Graph Trust's command line. It signs an ADIF log into the `.tq8` LoTW accepts,
//! with the certificate, key and station location taken from a TQSL backup, and takes TQSL's own
//! option letters and exit codes wherever they mean the same thing ([`cli`]).

#![forbid(unsafe_code)]

mod cli;

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::time::SystemTime;

use qso_graph_trust::certificate::Trust;
use zeroize::Zeroizing;

/// Every freed block is wiped, whichever library allocated it: no key data is left in freed
/// memory (AGENTS.md). `cargo xtask policy` refuses a program without exactly this.
#[global_allocator]
static ALLOCATOR: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> =
    ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let trust = Trust::lotw();
    let mut ask = ask_password;
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let code = cli::run(
        &args,
        &mut cli::Env {
            trust: &trust,
            now: SystemTime::now(),
            ask_password: &mut ask,
            out: &mut out,
            err: &mut err,
        },
    );
    let _ = out.flush();
    let _ = err.flush();
    ExitCode::from(code)
}

/// The key's password, asked for when it is needed and never taken from the command line: at the
/// terminal with what is typed hidden, or, with no terminal (a logger running `qg-trust`), one line
/// from standard input.
fn ask_password(prompt: &str) -> std::io::Result<Zeroizing<Vec<u8>>> {
    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt).map(|p| Zeroizing::new(p.into_bytes()));
    }
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let trimmed = line.trim_end_matches(['\n', '\r']);
    Ok(Zeroizing::new(trimmed.as_bytes().to_vec()))
}
