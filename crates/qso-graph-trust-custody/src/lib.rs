// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! What the custody test's programs do: sign the corpus log as a QG Trust program would, from
//! reading the key file to writing the `.tq8`, then wait while the test reads their memory.
//!
//! `qgt-custody KEY_FILE CERTIFICATE ADIF PASSWORD_FILE SECRETS_FILE live|done|export-passwords|export-keys`
//!
//! - `live`: wait with the key unlocked, so the test can prove it finds a key that is there.
//! - `done`: sign, drop everything, then wait: no key data may be left.
//! - `export-passwords`: deliberately keep copies of both generated export passwords.
//! - `export-keys`: after the first scan, accept both derived keys over stdin and keep them.
//!
//! The password comes from a file, never the command line (AGENTS.md); an empty file means none.
//! The program prints `ready` when it is waiting and exits when a line arrives on its input.

#![forbid(unsafe_code)]

use std::io::{BufRead, Read, Write};
use std::process::ExitCode;
use std::time::SystemTime;

use qso_graph_trust::certificate::{Certificate, Trust};
use qso_graph_trust::export::Password;
use qso_graph_trust::qso::Qso;
use qso_graph_trust::records;
use qso_graph_trust::signed_log::{sign_log, tq8};
use qso_graph_trust::signing::KeyEntry;
use qso_graph_trust::station::StationLocation;
use qso_graph_trust::store::{KeyBackend, Store};
use qso_graph_trust::tbk::BackedUpCertificate;
use zeroize::Zeroizing;

/// Runs the program; see the module documentation.
pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [
        key_file,
        cert_file,
        adif_file,
        password_file,
        secrets_file,
        mode,
    ] = &args[..]
    else {
        eprintln!(
            "usage: qgt-custody KEY_FILE CERTIFICATE ADIF PASSWORD_FILE SECRETS_FILE live|done|export-passwords|export-keys"
        );
        return ExitCode::from(2);
    };
    if !matches!(
        mode.as_str(),
        "live" | "done" | "export-passwords" | "export-keys"
    ) {
        return ExitCode::from(2);
    }
    match sign(
        key_file,
        cert_file,
        adif_file,
        password_file,
        secrets_file,
        mode,
    ) {
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
    secrets_file: &str,
    mode: &str,
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

    // Exercise the backup's derived keys, plaintext, provider contexts and restored credential
    // buffers too. They must leave no private values behind when the external memory scan runs.
    let leaks = exercise_export(
        key_file,
        cert_file,
        password,
        secrets_file,
        mode == "export-passwords",
    )?;

    if mode == "live" {
        wait()?;
        // Kept alive until the test has looked.
        drop((entry, signer, password_bytes, key_bytes));
    } else {
        // Everything that held key data, freed last so nothing allocated after can reuse its
        // memory before the test looks: the key file's buffer is the control's evidence.
        drop((entry, signer, log, gz, password_bytes));
        drop(key_bytes);
        wait()?;
        if mode == "export-keys" {
            // Test-only planted leaks: the parent derives these from the recorded passwords and
            // salt after the first scan, then sends them over stdin, never on a command line.
            let mut keys = Zeroizing::new(vec![0; 64]);
            std::io::stdin()
                .lock()
                .read_exact(&mut keys)
                .map_err(|e| e.to_string())?;
            wait()?;
            std::hint::black_box(&keys);
        }
    }
    std::hint::black_box(&leaks);
    Ok(())
}

struct ExportFolder(std::path::PathBuf);
impl Drop for ExportFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn exercise_export(
    key_file: &str,
    cert_file: &str,
    password: Option<&[u8]>,
    secrets_file: &str,
    leak_passwords: bool,
) -> Result<Vec<Zeroizing<Vec<u8>>>, String> {
    let path = std::env::temp_dir().join(format!("qgt-custody-export-{}", std::process::id()));
    std::fs::create_dir(&path).map_err(|e| e.to_string())?;
    let folder = ExportFolder(path);
    let read = |p: &std::path::Path| std::fs::read(p).map_err(|e| e.to_string());
    let certificate = Certificate::from_pem_or_der(&read(std::path::Path::new(cert_file))?)
        .map_err(|e| e.to_string())?;
    let key_bytes = Zeroizing::new(read(std::path::Path::new(key_file))?);
    let key = KeyEntry::read_key_file(&key_bytes)
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or("missing key")?;
    let entry = BackedUpCertificate {
        callsign: certificate.callsign().into(),
        dxcc: certificate.dxcc(),
        serial: certificate.serial().unwrap_or(-1),
        certificate: Some(certificate),
        key: Some(key),
    };
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).map_err(|e| e.to_string())?;
    store
        .add_certificate_with_key(&entry, password)
        .map_err(|e| e.to_string())?;
    let export_password = Password::generate().map_err(|e| e.to_string())?;
    let part = store
        .export_part(&export_password)
        .map_err(|e| e.to_string())?;
    // The corpus's immediate issuer is a generated test CA, explicitly trusted by this test only.
    let issuer =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/tqsl/pki/ca.pem");
    let trust = Trust::with_roots(&[&read(&issuer)?]).map_err(|e| e.to_string())?;
    store
        .restore_part(&part, &export_password, &trust)
        .map_err(|e| e.to_string())?;
    // Wrong-password authentication failure must wipe its provider and temporary buffers as well.
    let wrong = Password::generate().map_err(|e| e.to_string())?;
    if store.restore_part(&part, &wrong, &trust).is_ok() {
        return Err("wrong password accepted".into());
    }
    // This unpublished custody crate alone writes test secrets. The parent created an owner-only
    // directory; it reads this file only after taking the memory snapshot, and removes it.
    // Fixed test framing: generated password (20), failed-open password (20), actual salt (16).
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(secrets_file)
        .map_err(|e| e.to_string())?;
    file.write_all(export_password.expose_secret().as_bytes())
        .and_then(|()| file.write_all(wrong.expose_secret().as_bytes()))
        .and_then(|()| file.write_all(&part[13..29]))
        .map_err(|e| e.to_string())?;
    if leak_passwords {
        Ok(vec![
            Zeroizing::new(export_password.expose_secret().as_bytes().to_vec()),
            Zeroizing::new(wrong.expose_secret().as_bytes().to_vec()),
        ])
    } else {
        Ok(Vec::new())
    }
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
