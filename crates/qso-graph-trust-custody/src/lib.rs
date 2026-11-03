// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! What the custody test's programs do: sign the corpus log as a QG Trust program would, from
//! reading the key file to writing the `.tq8`, then wait while the test reads their memory.
//!
//! `qgt-custody KEY_FILE CERTIFICATE ADIF PASSWORD_FILE live|done`
//!
//! - `live`: wait with the key unlocked, so the test can prove it finds a key that is there.
//! - `done`: sign, drop everything, then wait: no key data may be left.
//!
//! The password comes from a file, never the command line (AGENTS.md); an empty file means none.
//! The program prints `ready` when it is waiting and exits when a line arrives on its input.

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::time::SystemTime;

use qso_graph_trust::certificate::Certificate;
use qso_graph_trust::qso::Qso;
use qso_graph_trust::records;
use qso_graph_trust::signed_log::{sign_log, tq8};
use qso_graph_trust::signing::KeyEntry;
use qso_graph_trust::station::StationLocation;
use zeroize::Zeroizing;

/// Runs the program; see the module documentation.
pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [key_file, cert_file, adif_file, password_file, mode] = &args[..] else {
        eprintln!("usage: qgt-custody KEY_FILE CERTIFICATE ADIF PASSWORD_FILE live|done");
        return ExitCode::from(2);
    };
    let live = match mode.as_str() {
        "live" => true,
        "done" => false,
        _ => return ExitCode::from(2),
    };
    match sign(key_file, cert_file, adif_file, password_file, live) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qgt-custody: {e}");
            ExitCode::FAILURE
        }
    }
}

fn sign(
    key_file: &str,
    cert_file: &str,
    adif_file: &str,
    password_file: &str,
    live: bool,
) -> Result<(), String> {
    let read = |path: &str| std::fs::read(path).map_err(|e| format!("{path}: {e}"));
    // As any caller would: the file's bytes in an ordinary buffer, freed when done with.
    let key_bytes = read(key_file)?;
    let password_bytes = Zeroizing::new(read(password_file)?);
    let password = (!password_bytes.is_empty()).then_some(password_bytes.as_slice());

    let entry = KeyEntry::read_key_file(&key_bytes)
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or("the key file holds no key")?;
    let signer = entry.unlock(password).map_err(|e| e.to_string())?;
    let cert = Certificate::from_pem_or_der(&read(cert_file)?).map_err(|e| e.to_string())?;
    let station = StationLocation::new(&[
        ("CALL", "QG0TEST"),
        ("DXCC", "291"),
        ("US_STATE", "KS"),
        ("US_COUNTY", "Sedgwick"),
        ("GRIDSQUARE", "EM17"),
        ("CQZ", "4"),
        ("ITUZ", "7"),
    ])
    .map_err(|e| e.to_string())?;
    let qsos = records::parse(&read(adif_file)?)
        .map_err(|e| e.to_string())?
        .iter()
        .map(Qso::from_adif)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let log =
        sign_log(&cert, &signer, &station, &qsos, SystemTime::now()).map_err(|e| e.to_string())?;
    let gz = tq8(&log);

    if live {
        wait()?;
        // Kept alive until the test has looked.
        drop((entry, signer, password_bytes, key_bytes));
    } else {
        // Everything that held key data, freed last so nothing allocated after can reuse its
        // memory before the test looks: the key file's buffer is the control's evidence.
        drop((entry, signer, log, gz, password_bytes));
        drop(key_bytes);
        wait()?;
    }
    Ok(())
}

/// Says `ready`, then waits for a line on the input.
fn wait() -> Result<(), String> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "ready")
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(())
}
