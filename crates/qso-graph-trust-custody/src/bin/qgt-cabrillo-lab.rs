// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Offline differential driver. Writes private comparison artifacts, never diagnostic field values.
#![forbid(unsafe_code)]

use qso_graph_trust::certificate::Certificate;
use qso_graph_trust::options::SigningOptions;
use qso_graph_trust::qso::Qso;
use qso_graph_trust::records;
use qso_graph_trust::signed_log::sign_log_with_options;
use qso_graph_trust::signing::KeyEntry;
use qso_graph_trust::station::StationLocation;
use std::fmt::Write;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

#[global_allocator]
static ALLOCATOR: ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> =
    ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("expected INPUT OUTPUT_PREFIX CORPUS".into());
    }
    let prefix = Path::new(&args[1]);
    let corpus = Path::new(&args[2]);
    let bytes = Zeroizing::new(std::fs::read(&args[0])?);
    let mut report = Zeroizing::new(String::new());
    let records = match records::parse(&bytes) {
        Ok(r) => r,
        Err(err) => {
            std::fs::write(prefix.with_extension("refusal"), err.to_string())?;
            let kind = match err {
                records::RecordError::Cabrillo { problem, .. } => problem.kind(),
                _ => "unexpected_reader_error",
            };
            std::fs::write(
                prefix.with_extension("records"),
                format!("REFUSED\t{kind}\n"),
            )?;
            std::fs::write(prefix.with_extension("tq7"), b"")?;
            return Ok(());
        }
    };
    let options = SigningOptions {
        ignore_log_callsigns: true,
        ..SigningOptions::default()
    };
    let cert =
        Certificate::from_pem_or_der(&std::fs::read(corpus.join("tqsl/1024/tqsl/certs/user"))?)?;
    let entry = KeyEntry::read_key_file(&Zeroizing::new(std::fs::read(
        corpus.join("tqsl/1024/tqsl/keys/QG0TEST"),
    )?))?
    .remove(0);
    let key = entry.unlock(None)?;
    let station = StationLocation::new(&[
        ("CALL", "QG0TEST"),
        ("DXCC", "291"),
        ("US_STATE", "KS"),
        ("US_COUNTY", "Sedgwick"),
        ("GRIDSQUARE", "EM17"),
        ("CQZ", "4"),
        ("ITUZ", "7"),
    ])?;
    let mut qsos = Vec::new();
    let (first, last) = cert.qso_dates();
    for record in &records {
        let q = match Qso::from_adif_with_options(record, &options) {
            Ok(q) => q,
            Err(_) => {
                let err = record
                    .cabrillo_conversion_error()
                    .ok_or("unexpected input format")?;
                std::fs::write(
                    prefix.with_extension("records"),
                    b"REFUSED\tqso_conversion\n",
                )?;
                std::fs::write(prefix.with_extension("refusal"), err.to_string())?;
                std::fs::write(prefix.with_extension("tq7"), b"")?;
                return Ok(());
            }
        };
        writeln!(
            report,
            "{}\t{}\t{}\t{}\t{}\t{}",
            q.call(),
            q.band(),
            q.mode(),
            q.date(),
            q.time(),
            record.text("FREQ").unwrap_or("")
        )?;
        if (first..=last).contains(&q.date()) {
            qsos.push(q);
        }
    }
    std::fs::write(prefix.with_extension("records"), report.as_bytes())?;
    let signed = if qsos.is_empty() {
        Vec::new()
    } else {
        sign_log_with_options(
            &cert,
            &key,
            &station,
            &qsos,
            cert.validity().0 + Duration::from_secs(3600),
            &options,
        )?
    };
    std::fs::write(prefix.with_extension("tq7"), signed)?;
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("Cabrillo comparison driver failed");
        std::process::exit(1);
    }
}
