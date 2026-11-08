// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `qg-trust`, QSO Graph Trust's command line. It keeps certificates, keys and station locations in
//! QG Trust's store, with keys in the OS credential store, signs ADIF logs into the `.tq8` LoTW
//! accepts and uploads them ([`commands`]), and takes TQSL's own option letters and exit codes
//! wherever they mean the same thing, for loggers ([`cli`]).

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod transport;

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::time::SystemTime;

use std::cell::OnceCell;
use std::path::PathBuf;

use qso_graph_trust::certificate::Trust;
use qso_graph_trust::store::{self, KeyBackend, Store, StoreError};
use zeroize::Zeroizing;

/// Every freed block is wiped, whichever library allocated it: no key data is left in freed
/// memory (AGENTS.md). `cargo xtask policy` refuses a program without exactly this.
#[global_allocator]
static ALLOCATOR: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> =
    ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let trust = Trust::lotw();
    let mut ask = ask_password;
    let choice_out = anstream::AutoStream::choice(&std::io::stdout());
    let choice_err = anstream::AutoStream::choice(&std::io::stderr());
    let mut out = anstream::AutoStream::new(std::io::stdout().lock(), choice_out);
    let mut err = anstream::AutoStream::new(std::io::stderr().lock(), choice_err);
    let opened = OnceCell::new();
    let open_store = || open_store(&opened);
    let mut upload = transport::upload;
    let code = cli::run(
        &args,
        &mut cli::Env {
            trust: &trust,
            now: SystemTime::now(),
            color_out: choice_out != anstream::ColorChoice::Never,
            color_err: choice_err != anstream::ColorChoice::Never,
            ask_password: &mut ask,
            out: &mut out,
            err: &mut err,
            store: &open_store,
            upload: &mut upload,
            trace: cli::Trace::off(),
        },
    );
    let _ = out.flush();
    let _ = err.flush();
    ExitCode::from(code)
}

/// QG Trust's store, in `QG_TRUST_STORE` if that names a folder, otherwise the folder QSO Graph
/// Desktop shares. Opened once, the first time a command needs it, with keys in the OS
/// credential store.
fn open_store(opened: &OnceCell<Store>) -> Result<&Store, StoreError> {
    if let Some(store) = opened.get() {
        return Ok(store);
    }
    let dir = std::env::var_os("QG_TRUST_STORE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(store::default_dir)
        .ok_or(StoreError::Invalid(
            "no home folder to keep the store in; set QG_TRUST_STORE",
        ))?;
    let (store, report) = Store::open(&dir, KeyBackend::Os)?;
    let missing = report.missing_keys.len() + report.missing_request_keys.len();
    if missing > 0 {
        eprintln!(
            "qg-trust: {missing} key{} named in the store {} not in this computer's credential store",
            if missing == 1 { "" } else { "s" },
            if missing == 1 { "is" } else { "are" }
        );
    }
    Ok(opened.get_or_init(|| store))
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
    let trimmed = line.strip_suffix('\n').unwrap_or(&line);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    Ok(Zeroizing::new(trimmed.as_bytes().to_vec()))
}
