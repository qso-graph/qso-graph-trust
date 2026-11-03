// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! QG Trust's signatures against tqsllib 2.8.7's own, byte for byte (qso-graph-desktop#171, Gate B).
//! The corpus is tqsllib's output (tests/corpus/tqsl, made by scripts/make-tqsl-corpus.sh): each
//! case's key file, and the test log it signed. For every QSO, QG Trust signs the SIGNDATA tqsllib
//! signed, with the same key, and must write exactly tqsllib's SIGN_LOTW_V2.0.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use qso_graph_trust::records::{self, Record};
use qso_graph_trust::signing::{KeyEntry, KeyError, tqsl_base64};

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
    // rsa's own key types derive an unredacted Debug (rsa 0.9.10 src/key.rs:37); TqslKey's must not.
    let signer = key("1024").unlock(None).expect("unlocks");
    assert_eq!(format!("{signer:?}"), "TqslKey(..)");
    assert_eq!(format!("{signer:#?}"), "TqslKey(..)");
}
