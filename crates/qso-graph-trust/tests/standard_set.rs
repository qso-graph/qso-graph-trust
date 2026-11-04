// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The standard test set (tests/corpus/standard, made by scripts/make-standard-set.sh;
//! qso-graph-desktop#172): three certificates from a test CA, seven station locations, a log for each
//! signed by tqsllib 2.8.7. For every location, QG Trust signs the same log with the same key and must
//! write tqsllib's `.tq7` exactly, but for the identification line: parks, a two-park value, three
//! counties, three grids and South Carolina's zones, which the first corpus does not have.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use qso_graph_trust::certificate::Certificate;
use qso_graph_trust::options::SigningOptions;
use qso_graph_trust::qso::Qso;
use qso_graph_trust::records;
use qso_graph_trust::signed_log::{sign_log, sign_log_with_options};
use qso_graph_trust::signing::KeyEntry;
use qso_graph_trust::station::StationLocation;

fn set(file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/standard")
        .join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The set's locations, as tests/tqsllib/make-standard-set.sh gave them to tqsllib.
const LOCATIONS: [(&str, &str, &str, &str, &str); 7] = [
    ("KC4QPQ-HOME", "KC4QPQ", "Charleston", "FM02", ""),
    ("KC4QPQ-MN35", "KC4QPQ", "Charleston", "FM02", "MN35"),
    ("KC4QPQ-NS09", "KC4QPQ", "Charleston", "FM02", "NS09"),
    ("KC4QPQ-NP12", "KC4QPQ", "Richland", "EM93", "NP12"),
    ("KC4QPQ-TR10-MP06", "KC4QPQ", "York", "EM95", "TR10,MP06"),
    ("KN4YU-CLUB", "KN4YU", "Charleston", "FM02", ""),
    ("W4W-EVENT", "W4W", "Charleston", "FM02", ""),
];

/// The user certificate for this call, from tqsllib's store of all three.
fn certificate(call: &str) -> Certificate {
    let store = String::from_utf8(set("tqsl/certs/user")).expect("PEM text");
    let end = "-----END CERTIFICATE-----";
    store
        .split_inclusive(end)
        .filter(|pem| pem.contains("BEGIN CERTIFICATE"))
        .filter_map(|pem| Certificate::from_pem_or_der(pem.trim_start().as_bytes()).ok())
        .find(|c| c.callsign() == call)
        .unwrap_or_else(|| panic!("no certificate for {call}"))
}

fn without_ident(log: &[u8]) -> &[u8] {
    assert!(log.starts_with(b"<TQSL_IDENT:"));
    &log[log.iter().position(|&b| b == b'\n').expect("a first line") + 1..]
}

#[test]
fn every_location_signs_as_tqsllib() {
    for (name, call, county, grid, park) in LOCATIONS {
        let mut fields = vec![
            ("CALL", call),
            ("DXCC", "291"),
            ("US_STATE", "SC"),
            ("US_COUNTY", county),
            ("GRIDSQUARE", grid),
            ("CQZ", "5"),
            ("ITUZ", "8"),
        ];
        if !park.is_empty() {
            fields.push(("US_PARK", park));
        }
        let station = StationLocation::new(&fields).unwrap_or_else(|e| panic!("{name}: {e}"));

        let password = set(&format!("keys/{call}.password"));
        let entry = KeyEntry::read_key_file(&set(&format!("tqsl/keys/{call}")))
            .expect("the key file")
            .remove(0);
        assert_eq!(entry.is_encrypted(), !password.is_empty(), "{name}");
        let signer = entry
            .unlock((!password.is_empty()).then_some(password.as_slice()))
            .unwrap_or_else(|e| panic!("{name}: {e}"));

        let cert = certificate(call);
        let qsos: Vec<Qso> = records::parse(&set(&format!("adif/{name}.adi")))
            .expect("ADIF")
            .iter()
            .map(|r| Qso::from_adif(r).expect("a QSO"))
            .collect();
        // Signed an hour after the certificate came into force: W4W's is in force for 30 days only,
        // so the test never depends on the day it runs.
        let at = cert.validity().0 + Duration::from_secs(3600);
        let ours =
            sign_log(&cert, &signer, &station, &qsos, at).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            ours,
            sign_log_with_options(
                &cert,
                &signer,
                &station,
                &qsos,
                at,
                &SigningOptions::default()
            )
            .expect("default options")
        );
        let theirs = set(&format!("signed/{name}.tq7"));
        assert_eq!(
            String::from_utf8_lossy(without_ident(&ours)),
            String::from_utf8_lossy(without_ident(&theirs)),
            "{name}"
        );
    }
}
