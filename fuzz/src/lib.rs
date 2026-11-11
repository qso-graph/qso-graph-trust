// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! What the fuzz targets share: the test corpus's certificates, key and station location, loaded
//! once, and the checks each target makes of what the library accepts (docs/decisions/0012).
//! Every target drives the library's public entry points as `qg-trust` does, and holds test keys
//! only.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use qso_graph_trust::certificate::{Certificate, Trust};
use qso_graph_trust::import::ImportError;
use qso_graph_trust::options::{QthHandling, SigningOptions};
use qso_graph_trust::qso::Qso;
use qso_graph_trust::records::{self, Record};
use qso_graph_trust::signed_log::LogError;
use qso_graph_trust::signing::tqsl_base64;
use qso_graph_trust::station::{StationLocation, fields_for};
use qso_graph_trust::store::{DuplicateChoice, KeyBackend, Store, StoreError};
use qso_graph_trust::tbk::{self, Backup};

/// The largest input any target reads: the library bounds each format itself, far above this; a
/// fuzzer's inputs stay small so each run is quick (CI passes `-max_len` too).
pub const MAX_INPUT: usize = 256 * 1024;

/// A file of the test corpus, `tests/corpus/<path>`.
pub fn corpus(path: &str) -> Vec<u8> {
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/corpus")
        .join(path);
    std::fs::read(&file).unwrap_or_else(|e| panic!("test corpus {}: {e}", file.display()))
}

/// The test roots, PEM: every root the corpus's certificates chain to but `roots/new-root.pem`,
/// which a file must bring and the operator confirm, as a new ARRL root would be. Read once.
fn test_roots() -> &'static [Vec<u8>] {
    static ROOTS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        ["pki/root.pem", "standard/pki/root.pem", "tqsl/pki/root.pem"]
            .iter()
            .map(|p| corpus(p))
            .collect()
    })
}

/// The trust every import is made under: the test roots only.
pub fn test_trust() -> &'static Trust {
    static TRUST: OnceLock<Trust> = OnceLock::new();
    TRUST.get_or_init(|| {
        let refs: Vec<&[u8]> = test_roots().iter().map(Vec::as_slice).collect();
        Trust::with_roots(&refs).expect("test roots")
    })
}

/// Every CA certificate in the corpus, DER: the only CAs a fuzzed file can use, since a fuzzer
/// cannot forge the test roots' signatures. Read once.
pub fn test_authorities() -> &'static [Vec<u8>] {
    static AUTHORITIES: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    AUTHORITIES.get_or_init(|| {
        [
            "pki/ca.pem",
            "standard/pki/ca.pem",
            "tqsl/pki/ca.pem",
            "roots/new-ca.pem",
        ]
        .iter()
        .map(|p| der_of(&corpus(p)))
        .collect()
    })
}

/// A PEM certificate's DER.
fn der_of(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).expect("PEM text");
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&body)
}

fn base64_decode(text: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
    {
        let v = TABLE.iter().position(|&t| t == b).expect("base64") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// Where every fuzz process keeps its store folders: one parent, so what a run leaves behind is
/// in one place. libFuzzer ends a run with `exit`, so a process cannot remove its own folder;
/// instead, the first store a process makes removes folders there older than a day.
fn store_parent() -> &'static std::path::Path {
    static PARENT: OnceLock<std::path::PathBuf> = OnceLock::new();
    PARENT.get_or_init(|| {
        let parent = std::env::temp_dir().join("qgt-fuzz");
        let day = std::time::Duration::from_secs(24 * 60 * 60);
        for entry in std::fs::read_dir(&parent).into_iter().flatten().flatten() {
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > day);
            if stale {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        parent
    })
}

/// A store folder of this process's own, emptied: a fresh store for each input, so one input's
/// import never changes what the next one meets.
pub fn fresh_store(name: &str) -> Store {
    let dir = store_parent().join(format!("{name}-{}", std::process::id()));
    match std::fs::remove_file(dir.join("store.xml")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("{}: {e}", dir.display()),
    }
    Store::open(&dir, KeyBackend::Memory).expect("test store").0
}

/// The signer every ADIF input is signed with, as `qg-trust` would sign it: KC4QPQ's certificate and
/// key from the standard set's `.tbk`, in a store with the memory key backend, and its home station
/// location, at a time inside the certificate.
pub struct Signer {
    store: Store,
    id: String,
    certificate: Certificate,
    station: StationLocation,
    now: SystemTime,
}

/// The signer, made once per process.
pub fn signer() -> &'static Signer {
    static SIGNER: OnceLock<Signer> = OnceLock::new();
    SIGNER.get_or_init(|| {
        let trust = Trust::with_roots(&[&corpus("standard/pki/root.pem")]).expect("test root");
        let backup = tbk::read(&corpus("standard/standard.tbk"), &trust).expect("test backup");
        let entry = backup
            .certificates
            .iter()
            .find(|c| c.callsign == "KC4QPQ")
            .expect("KC4QPQ");
        let certificate = entry.certificate.clone().expect("certificate");
        let station = backup
            .locations
            .iter()
            .find(|l| l.name == "KC4QPQ-HOME")
            .expect("home")
            .station
            .clone();
        let store = fresh_store("signer");
        let id = store
            .add_certificate_with_key(entry, Some(&corpus("standard/keys/KC4QPQ.password")))
            .expect("test key");
        let now = certificate.validity().0 + Duration::from_secs(3600);
        Signer {
            store,
            id,
            certificate,
            station,
            now,
        }
    })
}

/// The log handling settings for an input, chosen by its length so every one is reached and an
/// input always meets the same settings: seconds, bad calls, the log's callsigns and its QTH.
pub fn options_for(data: &[u8]) -> SigningOptions {
    let n = data.len();
    SigningOptions {
        exact_station: n & 32 != 0,
        adif_modes: Vec::new(),
        ignore_seconds: n & 1 != 0,
        allow_bad_calls: n & 2 != 0,
        ignore_log_callsigns: n & 4 != 0,
        qth: match (n >> 3) % 3 {
            0 => QthHandling::Refuse,
            1 => QthHandling::Ignore,
            _ => QthHandling::FromLog,
        },
    }
}

/// A QSO the signer refuses and leaves out, by its place in the list given, as `qg-trust` does.
fn refused(e: &LogError) -> Option<usize> {
    match e {
        LogError::QsoOutsideCertificate { index }
        | LogError::QsoFromAnotherStation { index, .. }
        | LogError::Location { index, .. } => Some(*index),
        _ => None,
    }
}

/// Sign a log as `qg-trust` signs one (crates/qso-graph-trust-cli/src/commands.rs, `sign`): read its
/// records; make a QSO of each the library accepts and leave out each it refuses; leave out QSOs the
/// certificate's dates do not cover; then prepare against the store, choose the new QSOs and sign
/// them with the store's key, leaving out each QSO the signer names and trying again. Whatever is
/// signed is then checked: no signature for an invalid record.
pub fn sign_like_the_cli(data: &[u8]) {
    let s = signer();
    let options = options_for(data);
    let Ok(records) = records::parse(data) else {
        return;
    };
    let mut accepted = Vec::new();
    for record in &records {
        match Qso::from_adif_with_options(record, &options) {
            Ok(qso) => accepted.push(qso),
            Err(_) if record.source_line().is_some() => return,
            Err(_) => {}
        }
    }
    let (first, last) = s.certificate.qso_dates();
    let mut qsos: Vec<Qso> = accepted
        .iter()
        .filter(|q| (first..=last).contains(&q.date()))
        .cloned()
        .collect();
    loop {
        if qsos.is_empty() {
            return;
        }
        let plan = match s
            .store
            .prepare_signing_with_options(&qsos, &s.station, &options)
        {
            Ok(p) => p,
            Err(StoreError::Log(e)) => match refused(&e) {
                Some(i) => {
                    qsos.remove(i);
                    continue;
                }
                None => return,
            },
            Err(e) => panic!("the store failed preparing a log: {e}"),
        };
        let selection = plan
            .choose(DuplicateChoice::NewOnly)
            .expect("not cancelled");
        if selection.qsos().is_empty() {
            return;
        }
        let picked = plan.new_indices().to_vec();
        let result = s
            .store
            .with_key(&s.id, |key| selection.sign(&s.certificate, key, s.now))
            .expect("the test key");
        match result {
            Ok(signed) => {
                check_signed(signed.tq8(), &accepted, &options);
                return;
            }
            Err(e) => match refused(&e) {
                Some(i) => {
                    qsos.remove(picked[i]);
                }
                None => return,
            },
        }
    }
}

/// The invariant: a signed log is one `qg-trust` uploads, and every QSO in it is one the library
/// accepted from the log, which reads back from the signed record and passes the library's checks
/// again, signed over exactly its station's and its own fields, with the certificate's key.
fn check_signed(tq8: &[u8], accepted: &[Qso], options: &SigningOptions) {
    let s = signer();
    assert!(
        qso_graph_trust::upload::check_signed_log(tq8).is_ok(),
        "QG Trust signed a log its own upload check refuses"
    );
    let tq7 = qso_graph_trust::gzip::decompress(tq8, 64 * 1024 * 1024).expect("the signed log");
    let records = records::parse(&tq7).expect("the signed log reads as records");
    let allowed: BTreeSet<String> = accepted.iter().map(Qso::sign_data).collect();
    let (first, last) = s.certificate.qso_dates();
    let mut stations: Vec<(Vec<u8>, StationLocation)> = Vec::new();
    let mut contacts = 0;
    for record in &records {
        match record.get("Rec_Type") {
            Some(b"tSTATION") => {
                let station = station_of(record);
                assert_eq!(
                    station.call(),
                    s.certificate.callsign(),
                    "signed for another call"
                );
                assert_eq!(
                    station.dxcc(),
                    s.certificate.dxcc(),
                    "signed for another entity"
                );
                let uid = record.get("STATION_UID").expect("STATION_UID").to_vec();
                stations.push((uid, station));
            }
            Some(b"tCONTACT") => {
                contacts += 1;
                let qso = reread(record, options);
                assert!(
                    (first..=last).contains(&qso.date()),
                    "a QSO signed outside the certificate's dates"
                );
                assert!(
                    allowed.contains(&qso.sign_data()),
                    "a signed QSO that is not one the library accepted from the log"
                );
                let uid = record.get("STATION_UID").expect("STATION_UID");
                let station = &stations
                    .iter()
                    .rev()
                    .find(|(u, _)| u.as_slice() == uid)
                    .expect("the QSO's station")
                    .1;
                let sign_data = (station.sign_data() + &qso.sign_data()).to_ascii_uppercase();
                assert_eq!(
                    record.text("SIGNDATA"),
                    Some(sign_data.as_str()),
                    "what was signed is not the station's and the QSO's fields"
                );
                // PKCS#1 v1.5 is deterministic: the key signs the same bytes the same way.
                let expected = s
                    .store
                    .with_key(&s.id, |key| key.sign(sign_data.as_bytes()))
                    .expect("the test key")
                    .expect("signing");
                assert_eq!(
                    record.get("SIGN_LOTW_V2.0"),
                    Some(tqsl_base64(&expected).as_bytes()),
                    "the signature is not the certificate's key's over what was signed"
                );
            }
            _ => {}
        }
    }
    assert!(contacts > 0, "a signed log with no QSOs");
    assert!(
        contacts <= accepted.len(),
        "more QSOs signed than the library accepted"
    );
}

/// A tSTATION record as a station location, checked again as the library checks one: every field
/// a location for its entity may give, as the record gives it.
fn station_of(record: &Record) -> StationLocation {
    let dxcc = record
        .text("DXCC")
        .and_then(|d| d.parse().ok())
        .expect("a signed station's DXCC");
    let given: Vec<(&str, &str)> = fields_for(dxcc)
        .into_iter()
        .filter_map(|name| record.text(name).map(|v| (name, v)))
        .collect();
    StationLocation::new(&given)
        .unwrap_or_else(|e| panic!("a signed log's station location is not one: {e}"))
}

/// A tCONTACT record read back as a QSO: its fields written as the ADIF record they came from, and
/// read with the same settings. The library must accept it.
fn reread(record: &Record, options: &SigningOptions) -> Qso {
    let text = |name: &str| record.text(name).map(str::to_string);
    let date = text("QSO_DATE").expect("QSO_DATE").replace('-', "");
    let time: String = text("QSO_TIME")
        .expect("QSO_TIME")
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let mut adif = String::new();
    for name in [
        "CALL",
        "BAND",
        "MODE",
        "FREQ",
        "FREQ_RX",
        "BAND_RX",
        "PROP_MODE",
        "SAT_NAME",
    ] {
        if let Some(v) = text(name) {
            adif.push_str(&format!("<{name}:{}>{v}", v.len()));
        }
    }
    adif.push_str(&format!("<QSO_DATE:{}>{date}", date.len()));
    adif.push_str(&format!("<TIME_ON:{}>{time}<eor>", time.len()));
    let again = records::parse(adif.as_bytes()).expect("a signed QSO's fields read as ADIF");
    Qso::from_adif_with_options(&again[0], options)
        .unwrap_or_else(|e| panic!("a signed QSO the library refuses when read again: {e}"))
}

/// Import a `.tq6` or `.p12` as `qg-trust import` does: once, and when the file brings a root not
/// trusted yet, again confirming that root's fingerprint, each into a fresh store. Whatever is
/// imported is checked: each certificate is in the store and verifies under the store's trust, and
/// has a key only where the format can carry one.
pub fn import_like_the_cli(
    kind: &str,
    import: impl Fn(&Store, &Trust, Option<&str>) -> Result<Vec<(String, bool)>, ImportError>,
    keys: bool,
) {
    let trust = test_trust();
    let store = fresh_store(kind);
    let imported = match import(&store, trust, None) {
        Err(ImportError::UntrustedRoot { fingerprint, .. }) => {
            let store = fresh_store(kind);
            let result = import(&store, trust, Some(&fingerprint));
            if let Ok(imported) = result {
                check_imported(&store, trust, &imported, keys);
            }
            return;
        }
        Err(_) => return,
        Ok(imported) => imported,
    };
    check_imported(&store, trust, &imported, keys);
}

fn check_imported(store: &Store, trust: &Trust, imported: &[(String, bool)], keys: bool) {
    assert!(!imported.is_empty(), "an import that imported nothing");
    let trust = store.trust_with(trust).expect("the store's trust");
    let authorities = test_authorities();
    let stored = store.certificates().expect("the store's certificates");
    for (id, has_key) in imported {
        let entry = stored
            .iter()
            .find(|c| &c.id == id)
            .expect("an imported certificate is in the store");
        entry
            .certificate
            .verify(&trust, authorities)
            .unwrap_or_else(|e| panic!("an imported certificate does not verify: {e}"));
        assert_eq!(
            *has_key,
            entry.key_name.is_some(),
            "the import misreports its key"
        );
        if *has_key {
            assert!(keys, "a key imported from a file that carries none");
            // The key is the certificate's and signs: what with_key unlocks must match it.
            let matches = store
                .with_key(id, |key| {
                    key.matches_public_key(entry.certificate.public_key_der())
                        && key.sign(b"QGT FUZZ").is_ok()
                })
                .expect("the imported key");
            assert!(matches, "an imported key is not its certificate's");
        }
    }
}

/// Read a `.tbk` both ways, and check whatever is accepted hangs together: every certificate chains
/// to the trust used, every key is its certificate's, for its call and entity, and one without a
/// password unlocks and signs; every station location is one the library accepts.
pub fn read_tbk(data: &[u8]) {
    let trust = test_trust();
    if let Ok(backup) = tbk::read(data, trust) {
        check_backup(&backup, trust);
    }
    if let Ok(backup) = tbk::read_trusting_roots(data, trust) {
        // Its own roots may be trusted, by the library's rules; verifying under all of them is
        // weaker, and must still hold.
        let roots: Vec<&[u8]> = test_roots()
            .iter()
            .chain(&backup.roots)
            .map(Vec::as_slice)
            .collect();
        let own = Trust::with_roots(&roots).expect("roots the library read");
        check_backup(&backup, &own);
    }
}

fn check_backup(backup: &Backup, trust: &Trust) {
    for entry in &backup.certificates {
        if let Some(cert) = &entry.certificate {
            cert.verify(trust, &backup.authorities)
                .unwrap_or_else(|e| panic!("a backup's certificate does not verify: {e}"));
            assert_eq!(
                cert.callsign(),
                entry.callsign,
                "a certificate for another call"
            );
            assert_eq!(cert.dxcc(), entry.dxcc, "a certificate for another entity");
        }
        let Some(key) = &entry.key else { continue };
        assert_eq!(key.callsign(), entry.callsign, "a key for another call");
        if let Some(d) = key.request_dxcc() {
            assert_eq!(d, entry.dxcc, "a key for another entity");
        }
        if let Some(cert) = &entry.certificate {
            assert_eq!(
                key.public_key_der().as_deref(),
                Some(cert.public_key_der()),
                "a key that is not its certificate's"
            );
        }
        if !key.is_encrypted() {
            let unlocked = key
                .unlock(None)
                .expect("a backup's key with no password unlocks");
            if let Some(cert) = &entry.certificate {
                assert!(unlocked.matches_public_key(cert.public_key_der()));
            }
            assert!(
                unlocked.sign(b"QGT FUZZ").is_ok(),
                "an accepted key cannot sign"
            );
        }
    }
    for location in &backup.locations {
        let fields: Vec<(&str, &str)> = location.station.fields().collect();
        let again = StationLocation::new(&fields)
            .unwrap_or_else(|e| panic!("a backup's station location, read again: {e}"));
        assert_eq!(
            again, location.station,
            "a station location changes when read again"
        );
    }
}
