// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::certificate::Certificate;
use crate::station::StationLocation;
use crate::store::{KeyBackend, KeyStore, KeyStoreError, MemoryKeyStore};
use crate::tbk;

struct Folder(PathBuf);
impl Folder {
    fn new() -> Self {
        let path = std::env::temp_dir().join(keys::new_name("qgt-part-test-").expect("random"));
        fs::create_dir(&path).expect("test folder");
        Self(path)
    }
    fn store(&self) -> Store {
        Store::open(&self.0, KeyBackend::Memory).expect("open").0
    }
}
impl Drop for Folder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn corpus(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus/standard")
            .join(name),
    )
    .expect("test corpus")
}
fn trust() -> Trust {
    // This generated CA directly signs the test callsign certificates. It is not production trust.
    Trust::with_roots(&[&corpus("pki/ca.pem")]).expect("test CA")
}
fn populate(store: &Store) {
    let backup = tbk::read(
        &corpus("standard.tbk"),
        &Trust::with_roots(&[&corpus("pki/root.pem")]).expect("test root"),
    )
    .expect("backup");
    for cert in &backup.certificates {
        let password = Zeroizing::new(corpus(&format!("keys/{}.password", cert.callsign)));
        store
            .add_certificate_with_key(cert, (!password.is_empty()).then_some(password.as_slice()))
            .expect("import");
    }
    for location in backup.locations {
        store
            .add_location(&location.name, &location.station)
            .expect("location");
    }
}
fn existing(store: &Store) {
    let location = StationLocation::new(&[("CALL", "QG0TEST"), ("DXCC", "291")]).expect("location");
    store.add_location("replace me", &location).expect("add");
}
fn snapshot(store: &Store) -> Zeroizing<Vec<u8>> {
    store.part_plaintext().expect("snapshot")
}
fn assert_unchanged(store: &Store, before: &[u8]) {
    assert!(snapshot(store).as_slice() == before);
}

#[test]
fn complete_roundtrip_replaces_existing_content_and_preserves_signatures() {
    let source_folder = Folder::new();
    let source = source_folder.store();
    populate(&source);
    // Public-only certificates belong in the part too.
    let public = Certificate::from_pem_or_der(include_bytes!(
        "../../../../../tests/corpus/pki/user-1024.pem"
    ))
    .expect("certificate");
    source.add_certificate(&public).expect("public certificate");
    let trust = Trust::with_roots(&[
        &corpus("pki/ca.pem"),
        include_bytes!("../../../../../tests/corpus/pki/ca.pem"),
    ])
    .expect("test roots");
    let password = Password::generate().expect("random");
    let bytes = source.export_part(&password).expect("export");
    let target_folder = Folder::new();
    let target = target_folder.store();
    populate(&target);
    existing(&target);
    let old_names = target.keys.names().expect("old keys");
    let report = target
        .restore_part(
            &bytes,
            &Password::from_typed(password.expose_secret()).expect("typed"),
            &trust,
        )
        .expect("restore");
    assert_eq!(
        report.certificates,
        source.certificates().expect("certs").len()
    );
    assert_eq!(report.keys + 1, report.certificates);
    assert_eq!(
        report.locations,
        source.locations().expect("locations").len()
    );
    assert_eq!(
        target.locations().expect("locations"),
        source.locations().expect("locations")
    );
    for (a, b) in source
        .certificates()
        .expect("certs")
        .iter()
        .zip(target.certificates().expect("certs"))
    {
        assert_eq!(a.id, b.id);
        assert_eq!(a.certificate.der(), b.certificate.der());
        if a.key_name.is_some() {
            assert_ne!(a.key_name, b.key_name);
            let a_sig = source
                .with_key(&a.id, |k| k.sign(b"restore test"))
                .expect("key")
                .expect("sign");
            let b_sig = target
                .with_key(&b.id, |k| k.sign(b"restore test"))
                .expect("key")
                .expect("sign");
            assert_eq!(a_sig, b_sig);
        } else {
            assert!(b.key_name.is_none());
        }
    }
    for name in old_names {
        assert!(!target.keys.exists(&name).expect("removed"));
    }
    // Restoring onto the source uses new names without overwriting or deleting active keys.
    source
        .restore_part(&bytes, &password, &trust)
        .expect("self restore");
    for c in source.certificates().expect("certs") {
        if c.key_name.is_some() {
            source.with_key(&c.id, |_| ()).expect("key");
        }
    }
}

#[test]
fn wrong_password_and_tampering_refuse_without_changing_existing_keys_or_file() {
    let folder = Folder::new();
    let store = folder.store();
    populate(&store);
    let before = snapshot(&store);
    let file_before = fs::read(folder.0.join("store.xml")).expect("file");
    let password = Password::generate().expect("random");
    let bytes = store.export_part(&password).expect("export");
    let wrong = Password::generate().expect("random");
    let err = store
        .restore_part(&bytes, &wrong, &trust())
        .expect_err("wrong password");
    let expected = format!("{err:?}: {err}");
    for index in [
        0,
        8,
        9,
        13,
        28,
        29,
        40,
        41,
        bytes.len() - 17,
        bytes.len() - 1,
    ] {
        let mut altered = bytes.clone();
        altered[index] ^= 1;
        let err = store
            .restore_part(&altered, &password, &trust())
            .expect_err("altered");
        assert_eq!(format!("{err:?}: {err}"), expected);
        assert_unchanged(&store, &before);
        assert_eq!(
            fs::read(folder.0.join("store.xml")).expect("file"),
            file_before
        );
    }
    let wrong_part = export::seal("other", &before, &password).expect("seal");
    let err = store
        .restore_part(&wrong_part, &password, &trust())
        .expect_err("part name");
    assert_eq!(format!("{err:?}: {err}"), expected);
    assert_unchanged(&store, &before);
}

#[test]
fn every_certificate_key_and_location_is_validated_before_mutating() {
    let source_folder = Folder::new();
    let source = source_folder.store();
    populate(&source);
    let original = snapshot(&source);
    let password = Password::generate().expect("random");
    let target_folder = Folder::new();
    let target = target_folder.store();
    populate(&target);
    existing(&target);
    let before = snapshot(&target);
    // Plant an additional certificate from an unrelated test CA. Earlier valid keys must not be put.
    let other = Certificate::from_pem_or_der(include_bytes!(
        "../../../../../tests/corpus/pki/user-1024.pem"
    ))
    .expect("certificate");
    source
        .add_certificate(&other)
        .expect("plant untrusted cert");
    let bytes = source.export_part(&password).expect("export");
    assert!(matches!(
        target.restore_part(&bytes, &password, &trust()),
        Err(PartError::Invalid)
    ));
    assert_unchanged(&target, &before);
    source
        .delete_certificate(
            &source
                .certificates()
                .expect("certs")
                .last()
                .expect("planted")
                .id,
        )
        .expect("remove plant");
    let mut input = &original[MAGIC.len()..];
    let xml = take_record(&mut input, MAX_FILE_LEN).expect("XML");
    let key_offset = original.len() - input.len() + 4;
    let mut bad_key = original.clone();
    bad_key[key_offset] ^= 1;
    let mut invalid_inputs = vec![bad_key];
    // A valid RSA key from another certificate is rejected just as malformed DER is.
    let mut swapped = original.clone();
    let mut record_input = input;
    let first = take_record(&mut record_input, MAX_KEY_LEN).expect("key");
    let mut second_offset = original.len() - record_input.len() + 4;
    let second = take_record(&mut record_input, MAX_KEY_LEN).expect("second key");
    if first.len() == second.len() {
        swapped[key_offset..key_offset + first.len()].copy_from_slice(second);
    } else {
        // Replace a complete framed record, preserving the remainder exactly.
        second_offset -= 4;
        let mut replacement = Zeroizing::new(Vec::with_capacity(original.len() + second.len()));
        replacement.extend_from_slice(&original[..key_offset - 4]);
        replacement.extend_from_slice(&(second.len() as u32).to_be_bytes());
        replacement.extend_from_slice(second);
        replacement.extend_from_slice(&original[second_offset..]);
        swapped = replacement;
    }
    invalid_inputs.push(swapped);
    // Invalid location, unsupported signed-QSO content, and future plaintext version.
    let xml_start = MAGIC.len() + 4;
    for (good, bad) in [
        (
            "<field name=\"DXCC\">291</field>",
            "<field name=\"DXCC\">999</field>",
        ),
        (
            "<signed-qsos version=\"1\"/>",
            "<signed-qsos version=\"2\"/>",
        ),
    ] {
        let text = std::str::from_utf8(xml).expect("XML");
        let index = text.find(good).expect("fixture field");
        assert_eq!(good.len(), bad.len());
        let mut altered = original.clone();
        altered[xml_start + index..xml_start + index + bad.len()].copy_from_slice(bad.as_bytes());
        invalid_inputs.push(altered);
    }
    let mut version = original.clone();
    version[MAGIC.len() - 1] = 2;
    invalid_inputs.push(version);
    let mut trailing = Zeroizing::new(Vec::with_capacity(original.len() + 1));
    trailing.extend_from_slice(&original);
    trailing.push(0);
    invalid_inputs.push(trailing);
    for invalid in invalid_inputs {
        let bytes = export::seal(LOTW_PART, &invalid, &password).expect("seal plant");
        let err = target
            .restore_part(&bytes, &password, &trust())
            .expect_err("validation");
        assert!(matches!(err, PartError::Invalid));
        assert_eq!(
            format!("{err:?}: {err}"),
            "Invalid: the export part contents are invalid"
        );
        assert_unchanged(&target, &before);
    }
    // Without any planted case the same credentials and location restore successfully.
    target
        .restore_part(
            &export::seal(LOTW_PART, &original, &password).expect("seal"),
            &password,
            &trust(),
        )
        .expect("valid restore");
}

#[derive(Default)]
struct FailingKeys {
    inner: MemoryKeyStore,
    puts: AtomicUsize,
    fail_at: AtomicUsize,
    deletes: AtomicUsize,
    fail_delete: AtomicBool,
}
impl KeyStore for FailingKeys {
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError> {
        let count = self.puts.fetch_add(1, Ordering::Relaxed) + 1;
        if count == self.fail_at.load(Ordering::Relaxed) {
            return Err(KeyStoreError::Unavailable);
        }
        self.inner.put(name, der)
    }
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        self.inner.get(name)
    }
    fn delete(&self, name: &str) -> Result<(), KeyStoreError> {
        self.deletes.fetch_add(1, Ordering::Relaxed);
        if self.fail_delete.load(Ordering::Relaxed) {
            return Err(KeyStoreError::AccessDenied);
        }
        self.inner.delete(name)
    }
    fn exists(&self, name: &str) -> Result<bool, KeyStoreError> {
        self.inner.exists(name)
    }
    fn names(&self) -> Result<Vec<String>, KeyStoreError> {
        self.inner.names()
    }
}

#[test]
fn staged_keys_roll_back_on_backend_or_file_failure_and_survive_post_rename_failure() {
    let source_folder = Folder::new();
    let source = source_folder.store();
    populate(&source);
    let password = Password::generate().expect("random");
    let bytes = source.export_part(&password).expect("export");
    let folder = Folder::new();
    let keys = Arc::new(FailingKeys::default());
    let store = Store::open_with_keys(&folder.0, Box::new(keys.clone()))
        .expect("open")
        .0;
    populate(&store);
    existing(&store);
    let before = snapshot(&store);
    let names = keys.names().expect("names");
    keys.fail_at
        .store(keys.puts.load(Ordering::Relaxed) + 2, Ordering::Relaxed);
    assert!(matches!(
        store.restore_part(&bytes, &password, &trust()),
        Err(PartError::Store(StoreError::KeyStore(_)))
    ));
    assert_eq!(keys.names().expect("rollback"), names);
    assert_unchanged(&store, &before);
    keys.fail_at.store(0, Ordering::Relaxed);
    fs::create_dir(folder.0.join("store.xml.partial")).expect("block replacement");
    assert!(matches!(
        store.restore_part(&bytes, &password, &trust()),
        Err(PartError::Store(StoreError::Io(_)))
    ));
    assert_eq!(keys.names().expect("rollback"), names);
    assert_unchanged(&store, &before);
    fs::remove_dir(folder.0.join("store.xml.partial")).expect("unblock");
    // A backend refusing cleanup is reported, and every staged key still gets a cleanup attempt.
    keys.fail_at
        .store(keys.puts.load(Ordering::Relaxed) + 3, Ordering::Relaxed);
    keys.fail_delete.store(true, Ordering::Relaxed);
    let deletes = keys.deletes.load(Ordering::Relaxed);
    assert!(matches!(
        store.restore_part(&bytes, &password, &trust()),
        Err(PartError::Store(StoreError::Rollback { .. }))
    ));
    assert_eq!(keys.deletes.load(Ordering::Relaxed), deletes + 2);
    assert_unchanged(&store, &before);
    keys.fail_at.store(0, Ordering::Relaxed);
    keys.fail_delete.store(false, Ordering::Relaxed);
    for name in keys.names().expect("orphans") {
        if !names.contains(&name) {
            keys.delete(&name).expect("remove planted orphan");
        }
    }
    assert_eq!(keys.names().expect("cleaned"), names);
    store.fail_sync.store(true, Ordering::Relaxed);
    assert!(matches!(
        store.restore_part(&bytes, &password, &trust()),
        Err(PartError::Store(StoreError::Durability(_)))
    ));
    for c in store.certificates().expect("certs") {
        store
            .with_key(&c.id, |_| ())
            .expect("published keys survive");
    }
    for name in names {
        assert!(keys.exists(&name).expect("old keys survive"));
    }
    store.fail_sync.store(false, Ordering::Relaxed);
    store
        .restore_part(&bytes, &password, &trust())
        .expect("success without fault");
}

#[test]
fn empty_store_roundtrips_and_missing_keys_cannot_export() {
    let folder = Folder::new();
    let store = folder.store();
    let password = Password::generate().expect("random");
    let bytes = store.export_part(&password).expect("empty export");
    assert_eq!(
        store
            .restore_part(&bytes, &password, &trust())
            .expect("empty restore"),
        RestoreReport {
            certificates: 0,
            keys: 0,
            locations: 0
        }
    );
    populate(&store);
    let key = store.keys.names().expect("names").remove(0);
    store.keys.delete(&key).expect("plant missing key");
    assert!(matches!(
        store.export_part(&password),
        Err(PartError::Store(StoreError::NotFound))
    ));
    let typed = Password::from_typed(password.expose_secret()).expect("typed");
    assert!(matches!(
        store.export_part(&typed),
        Err(PartError::Export(ExportError::Password))
    ));
}
