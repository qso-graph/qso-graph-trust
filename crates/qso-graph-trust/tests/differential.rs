// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! QG Trust's signatures against tqsllib 2.8.7's own, byte for byte (qso-graph-desktop#171, Gate B).
//! The corpus is tqsllib's output (tests/corpus/tqsl, made by scripts/make-tqsl-corpus.sh): each
//! case's key file, and the test log it signed. For every QSO, QG Trust signs the SIGNDATA tqsllib
//! signed, with the same key, and must write exactly tqsllib's SIGN_LOTW_V2.0. Then the whole log:
//! from the ADIF log and the station location tqsllib was given, QG Trust's `.tq7` must be
//! tqsllib's, every record and byte, but for the identification line, which names the program.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::SystemTime;

use qso_graph_trust::certificate::Certificate;
use qso_graph_trust::options::SigningOptions;
use qso_graph_trust::qso::Qso;
use qso_graph_trust::records::{self, Record};
use qso_graph_trust::signed_log::{LogError, sign_log, sign_log_with_options, tq8};
use qso_graph_trust::signing::{KeyEntry, KeyError, tqsl_base64};
use qso_graph_trust::station::StationLocation;

fn corpus(case: &str, file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/tqsl")
        .join(case)
        .join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn key(case: &str) -> KeyEntry {
    let mut keys =
        KeyEntry::read_key_file(&corpus(case, "tqsl/keys/QG0TEST")).expect("the key file");
    assert_eq!(keys.len(), 1, "{case}: one key");
    keys.remove(0)
}

/// Each tCONTACT record tqsllib signed: its SIGNDATA and its SIGN_LOTW_V2.0, as written.
fn contacts(case: &str) -> Vec<(Vec<u8>, String)> {
    let records = records::parse(&corpus(case, "qg0test-small.tq7")).expect("the signed log");
    let contacts: Vec<&Record> = records
        .iter()
        .filter(|r| r.text("Rec_Type") == Some("tCONTACT"))
        .collect();
    assert_eq!(contacts.len(), 6, "{case}: the six test QSOs");
    contacts
        .iter()
        .map(|r| {
            let data = r.get("SIGNDATA").expect("SIGNDATA").to_vec();
            let sig = r
                .text("SIGN_LOTW_V2.0")
                .expect("SIGN_LOTW_V2.0")
                .to_string();
            (data, sig)
        })
        .collect()
}

/// Every signature in the case, signed again by QG Trust, is tqsllib's exactly.
fn signs_as_tqsllib(case: &str, password: Option<&[u8]>, signature_chars: usize) {
    let signer = key(case).unlock(password).expect("unlocks");
    for (data, theirs) in contacts(case) {
        let ours = tqsl_base64(&signer.sign(&data).expect("signs"));
        assert_eq!(ours.len(), signature_chars, "{case}");
        assert_eq!(ours, theirs, "{case}: {}", String::from_utf8_lossy(&data));
    }
}

#[test]
fn a_1024_bit_key_signs_as_tqsllib() {
    signs_as_tqsllib("1024", None, 175);
}

#[test]
fn a_password_protected_key_signs_as_tqsllib() {
    signs_as_tqsllib("1024-password", Some(b"qgt-key"), 175);
}

#[test]
fn a_protected_key_needs_its_password() {
    let entry = key("1024-password");
    assert!(entry.is_encrypted());
    assert_eq!(entry.unlock(None).err(), Some(KeyError::PasswordNeeded));
    assert_eq!(
        entry.unlock(Some(b"not-it")).err(),
        Some(KeyError::WrongPassword)
    );
    assert!(!key("1024").is_encrypted());
}

#[test]
fn signing_the_same_data_again_gives_the_same_signature() {
    // PKCS#1 v1.5 is deterministic, and blinding with fresh randomness each time must not change it.
    let signer = key("1024").unlock(None).expect("unlocks");
    let (data, _) = contacts("1024").remove(0);
    assert_eq!(
        signer.sign(&data).expect("signs"),
        signer.sign(&data).expect("signs")
    );
}

#[test]
fn a_different_key_does_not_match() {
    let wrong = key("1024-password")
        .unlock(Some(b"qgt-key"))
        .expect("unlocks");
    let (data, theirs) = contacts("1024").remove(0);
    assert_ne!(tqsl_base64(&wrong.sign(&data).expect("signs")), theirs);
}

#[test]
fn an_unlocked_key_prints_nothing_of_itself() {
    // The signer must never expose its key through Debug.
    let signer = key("1024").unlock(None).expect("unlocks");
    assert_eq!(format!("{signer:?}"), "TqslKey(..)");
    assert_eq!(format!("{signer:#?}"), "TqslKey(..)");
}

/// The station location tests/tqsllib/make-corpus.sh gave tqsllib.
fn kansas() -> StationLocation {
    StationLocation::new(&[
        ("CALL", "QG0TEST"),
        ("DXCC", "291"),
        ("US_STATE", "KS"),
        ("US_COUNTY", "Sedgwick"),
        ("GRIDSQUARE", "EM17"),
        ("CQZ", "4"),
        ("ITUZ", "7"),
    ])
    .expect("the corpus location")
}

fn test_log() -> Vec<Qso> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/adif/qg0test-small.adi");
    let adif = std::fs::read(path).expect("the test log");
    records::parse(&adif)
        .expect("ADIF")
        .iter()
        .map(|r| Qso::from_adif(r).expect("a QSO"))
        .collect()
}

/// A signed log without its first line, the identification, which names the program that wrote it.
fn without_ident(log: &[u8]) -> &[u8] {
    assert!(log.starts_with(b"<TQSL_IDENT:"));
    let newline = log.iter().position(|&b| b == b'\n').expect("a first line");
    &log[newline + 1..]
}

fn writes_the_log_tqsllib_wrote(case: &str, password: Option<&[u8]>) {
    let signer = key(case).unlock(password).expect("unlocks");
    let cert =
        Certificate::from_pem_or_der(&corpus(case, "tqsl/certs/user")).expect("the certificate");
    let ours = sign_log(&cert, &signer, &kansas(), &test_log(), SystemTime::now()).expect("signs");
    assert_eq!(
        ours,
        sign_log_with_options(
            &cert,
            &signer,
            &kansas(),
            &test_log(),
            SystemTime::now(),
            &SigningOptions::default()
        )
        .expect("default options")
    );
    // The .tq8 is the same log, gzipped: unzipped, it is this log exactly.
    let gz = tq8(&ours);
    let unzipped =
        miniz_oxide::inflate::decompress_to_vec_with_limit(&gz[10..gz.len() - 8], ours.len());
    assert_eq!(unzipped.ok().as_deref(), Some(ours.as_slice()));
    let theirs = corpus(case, "qg0test-small.tq7");
    let (ours, theirs) = (without_ident(&ours), without_ident(&theirs));
    assert_eq!(
        String::from_utf8_lossy(ours),
        String::from_utf8_lossy(theirs),
        "{case}"
    );
    assert_eq!(ours, theirs, "{case}");
}

#[test]
fn the_signed_log_is_tqsllibs() {
    writes_the_log_tqsllib_wrote("1024", None);
}

#[test]
fn the_signed_log_from_a_protected_key_is_tqsllibs() {
    writes_the_log_tqsllib_wrote("1024-password", Some(b"qgt-key"));
}

#[test]
fn a_log_is_not_signed_with_another_certificates_key() {
    let other = key("1024-password")
        .unlock(Some(b"qgt-key"))
        .expect("unlocks");
    let cert =
        Certificate::from_pem_or_der(&corpus("1024", "tqsl/certs/user")).expect("the certificate");
    assert_eq!(
        sign_log(&cert, &other, &kansas(), &test_log(), SystemTime::now()),
        Err(LogError::KeyNotCertificates)
    );
}

#[test]
fn a_log_is_signed_only_for_the_certificates_station_and_dates() {
    let signer = key("1024").unlock(None).expect("unlocks");
    let cert =
        Certificate::from_pem_or_der(&corpus("1024", "tqsl/certs/user")).expect("the certificate");
    let sign =
        |station: &StationLocation, qsos: &[Qso], now| sign_log(&cert, &signer, station, qsos, now);
    let qsos = test_log();
    let elsewhere =
        StationLocation::new(&[("CALL", "KC4QPQ"), ("DXCC", "291"), ("US_STATE", "SC")])
            .expect("location");
    assert!(matches!(
        sign(&elsewhere, &qsos, SystemTime::now()),
        Err(LogError::CallNotCertificates { .. })
    ));
    let canada = StationLocation::new(&[("CALL", "QG0TEST"), ("DXCC", "1")]).expect("location");
    assert!(matches!(
        sign(&canada, &qsos, SystemTime::now()),
        Err(LogError::DxccNotCertificates { .. })
    ));
    assert_eq!(
        sign(&kansas(), &qsos, SystemTime::UNIX_EPOCH),
        Err(LogError::CertificateNotInForce)
    );
    assert_eq!(
        sign(&kansas(), &[], SystemTime::now()),
        Err(LogError::Empty)
    );
    let adif = |date: &str, extra: &str| {
        let record = format!(
            "<CALL:5>KN4YU<QSO_DATE:8>{date}<TIME_ON:4>1900<BAND:3>20m<MODE:2>CW{extra}<EOR>"
        );
        Qso::from_adif(&records::parse(record.as_bytes()).expect("ADIF")[0]).expect("a QSO")
    };
    let early = [qsos[0].clone(), qsos[1].clone(), adif("20191231", "")];
    assert_eq!(
        sign(&kansas(), &early, SystemTime::now()),
        Err(LogError::QsoOutsideCertificate { index: 2 })
    );
    // Found in review: a QSO naming another station was signed for this one.
    let other = [
        qsos[0].clone(),
        adif("20261101", "<STATION_CALLSIGN:7>QG1TEST"),
    ];
    assert_eq!(
        sign(&kansas(), &other, SystemTime::now()),
        Err(LogError::QsoFromAnotherStation {
            index: 1,
            field: "STATION_CALLSIGN",
            value: "QG1TEST".into()
        })
    );
    let ours = [adif(
        "20261101",
        "<STATION_CALLSIGN:7>QG0TEST<MY_DXCC:3>291<MY_GRIDSQUARE:4>EM17<MY_STATE:2>KS<MY_CNTY:11>KS,Sedgwick",
    )];
    assert!(sign(&kansas(), &ours, SystemTime::now()).is_ok());
}
