// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use zeroize::Zeroizing;

use super::*;
use crate::certificate::Trust;
use crate::qso::Qso;
use crate::records;
use crate::signed_log::sign_log;
use crate::tbk;

// Only crate-internal tests retain backend handles, to observe ordering and plant lost keys.
// Public callers select a backend kind and cannot keep an object that reads its secrets.
impl<K: KeyStore> KeyStore for Arc<K> {
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError> {
        self.as_ref().put(name, der)
    }
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        self.as_ref().get(name)
    }
    fn delete(&self, name: &str) -> Result<(), KeyStoreError> {
        self.as_ref().delete(name)
    }
    fn exists(&self, name: &str) -> Result<bool, KeyStoreError> {
        self.as_ref().exists(name)
    }
    fn names(&self) -> Result<Vec<String>, KeyStoreError> {
        self.as_ref().names()
    }
}

fn open<K: KeyStore + 'static>(
    dir: &Path,
    keys: &Arc<K>,
) -> Result<(Store, OpenReport), StoreError> {
    Store::open_with_keys(dir, Box::new(Arc::clone(keys)))
}

struct Folder(PathBuf);
impl Folder {
    fn new() -> Self {
        let path = std::env::temp_dir().join(keys::new_name("qgt-store-test-").expect("random"));
        fs::create_dir(&path).expect("test folder");
        Self(path)
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
fn backup() -> tbk::Backup {
    tbk::read(
        &corpus("standard.tbk"),
        &Trust::with_roots(&[&corpus("pki/root.pem")]).expect("test root"),
    )
    .expect("test backup")
}
fn station() -> StationLocation {
    StationLocation::new(&[("CALL", "QG0TEST"), ("DXCC", "291"), ("GRIDSQUARE", "EM17")])
        .expect("station")
}
fn empty_xml() -> String {
    format::write(&Data::default()).expect("empty store")
}

#[test]
fn names_are_random_lowercase_version_four_uuids() {
    let a = keys::new_name("key:").expect("name");
    let b = keys::new_name("key:").expect("name");
    assert_ne!(a, b);
    assert_eq!(a.len(), 40);
    assert!(keys::valid_name(&a, "key:"));
    assert!(keys::valid_name(&b, "key:"));
    for invalid in [a.to_uppercase(), "key:operator".into(), "".into()] {
        assert!(!keys::valid_name(&invalid, "key:"));
    }
    let mut wrong_version = a.clone().into_bytes();
    wrong_version[18] = b'3';
    assert!(!keys::valid_name(
        std::str::from_utf8(&wrong_version).expect("ASCII"),
        "key:"
    ));
    let mut wrong_variant = a.into_bytes();
    wrong_variant[23] = b'7';
    assert!(!keys::valid_name(
        std::str::from_utf8(&wrong_variant).expect("ASCII"),
        "key:"
    ));
}

#[test]
fn memory_credentials_are_wiped_types_and_deletion_is_final() {
    let keys = Arc::new(MemoryKeyStore::new());
    let name = keys::new_name("key:").expect("name");
    keys.put(&name, &[1, 2, 3]).expect("put");
    assert_eq!(keys.put(&name, &[4]), Err(KeyStoreError::AlreadyExists));
    let secret: Zeroizing<Vec<u8>> = keys.get(&name).expect("get").expect("present");
    assert_eq!(&*secret, &[1, 2, 3]);
    assert!(keys.exists(&name).expect("exists"));
    keys.delete(&name).expect("delete");
    keys.delete(&name).expect("idempotent");
    assert!(!keys.exists(&name).expect("exists"));
    assert!(keys.get(&name).expect("get").is_none());
    assert!(keys.names().expect("names").is_empty());
    assert_eq!(keys.put("callsign", &[1]), Err(KeyStoreError::InvalidInput));
    assert_eq!(
        keys.put(&name, &vec![0; MAX_KEY_LEN + 1]),
        Err(KeyStoreError::InvalidInput)
    );
}

#[test]
fn public_memory_backend_is_fresh_and_owned_by_each_store() {
    let folder = Folder::new();
    let (store, report) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    assert_eq!(report, OpenReport::default());
    let backup = backup();
    let entry = &backup.certificates[0];
    let password = corpus(&format!("keys/{}.password", entry.callsign));
    let id = store
        .add_certificate_with_key(entry, (!password.is_empty()).then_some(password.as_slice()))
        .expect("import");
    let (other, report) = Store::open(&folder.0, KeyBackend::Memory).expect("another backend");
    assert_eq!(report.missing_keys, std::slice::from_ref(&id));
    assert!(matches!(
        other.with_key(&id, |_| ()),
        Err(StoreError::NotFound)
    ));
    store
        .with_key(&id, |_| ())
        .expect("original still owns its key");
    drop(store);
    let (reopened, report) = Store::open(&folder.0, KeyBackend::Memory).expect("reopen");
    assert_eq!(report.missing_keys, std::slice::from_ref(&id));
    assert!(matches!(
        reopened.with_key(&id, |_| ()),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn every_section_round_trips_and_stored_keys_sign_the_same_logs() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (store, report) = open(&folder.0, &keys).expect("open");
    assert_eq!(report, OpenReport::default());
    let backup = backup();
    let mut ids = Vec::new();
    for cert in &backup.certificates {
        let password = corpus(&format!("keys/{}.password", cert.callsign));
        let password = (!password.is_empty()).then_some(password.as_slice());
        ids.push(
            store
                .add_certificate_with_key(cert, password)
                .expect("import"),
        );
    }
    for l in &backup.locations {
        store.add_location(&l.name, &l.station).expect("location");
    }
    let (reopened, report) = open(&folder.0, &keys).expect("reopen");
    assert_eq!(report, OpenReport::default());
    let certs = reopened.certificates().expect("certificates");
    assert_eq!(certs.len(), backup.certificates.len());
    for (a, b) in certs.iter().zip(&backup.certificates) {
        assert_eq!(
            a.certificate.der(),
            b.certificate.as_ref().expect("cert").der()
        );
        assert!(keys::valid_name(
            a.key_name.as_ref().expect("key name"),
            "key:"
        ));
        let secret = keys
            .get(a.key_name.as_ref().expect("key name"))
            .expect("backend")
            .expect("DER");
        assert!(secret.len() <= MAX_KEY_LEN);
        assert_ne!(secret.first(), Some(&b'-'));
    }
    let locations = reopened.locations().expect("locations");
    for (a, b) in locations.iter().zip(&backup.locations) {
        assert_eq!((&a.name, &a.station), (&b.name, &b.station));
        let i = backup
            .certificates
            .iter()
            .position(|c| c.callsign == a.station.call())
            .expect("cert");
        let cert = &backup.certificates[i];
        let password = corpus(&format!("keys/{}.password", cert.callsign));
        let direct = cert
            .key
            .as_ref()
            .expect("key")
            .unlock((!password.is_empty()).then_some(password.as_slice()))
            .expect("unlocked");
        let qsos: Vec<Qso> = records::parse(&corpus(&format!("adif/{}.adi", a.name)))
            .expect("ADIF")
            .iter()
            .map(|r| Qso::from_adif(r).expect("QSO"))
            .collect();
        let cert = cert.certificate.as_ref().expect("certificate");
        let at = cert.validity().0 + Duration::from_secs(3600);
        let expected = sign_log(cert, &direct, &a.station, &qsos, at).expect("direct signature");
        let actual = reopened
            .with_key(&ids[i], |key| sign_log(cert, key, &a.station, &qsos, at))
            .expect("stored key")
            .expect("stored signature");
        assert_eq!(actual, expected);
    }
    assert!(
        fs::read_to_string(folder.0.join("store.xml"))
            .expect("file")
            .contains("<signed-qsos version=\"1\"/>")
    );
    for id in ids {
        reopened.delete_certificate(&id).expect("delete");
    }
    assert!(keys.names().expect("names").is_empty());
    assert!(reopened.certificates().expect("certificates").is_empty());
}

#[test]
fn public_certificates_and_location_mutations_preserve_exact_names() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (store, _) = open(&folder.0, &keys).expect("open");
    let backup = backup();
    let cert = backup.certificates[0].certificate.as_ref().expect("cert");
    let id = store.add_certificate(cert).expect("public certificate");
    assert!(store.certificates().expect("list")[0].key_name.is_none());
    assert!(matches!(
        store.with_key(&id, |_| ()),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.add_certificate(cert),
        Err(StoreError::AlreadyExists)
    ));
    let name = "<&\"'>\t\r\n日本";
    store.add_location(name, &station()).expect("escaped name");
    assert!(matches!(
        store.add_location(name, &station()),
        Err(StoreError::AlreadyExists)
    ));
    let other = &backup.locations[0].station;
    store.replace_location(name, other).expect("replace");
    assert_eq!(
        store.locations().expect("read"),
        [StoredLocation {
            name: name.into(),
            station: other.clone()
        }]
    );
    store.delete_location(name).expect("delete");
    assert!(store.locations().expect("list").is_empty());
    assert!(matches!(
        store.replace_location(name, other),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.delete_location(name),
        Err(StoreError::NotFound)
    ));
    store.delete_certificate(&id).expect("delete public cert");
    assert!(matches!(
        store.delete_certificate(&id),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn newer_versions_are_refused_on_open_and_before_any_mutation() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (store, _) = open(&folder.0, &keys).expect("open");
    let text = empty_xml().replacen("qgt-store version=\"2\"", "qgt-store version=\"3\"", 1);
    fs::write(folder.0.join("store.xml"), &text).expect("plant");
    assert!(matches!(
        open(&folder.0, &keys),
        Err(StoreError::NewerVersion {
            found: 3,
            supported: 2
        })
    ));
    assert!(matches!(
        store.add_location("home", &station()),
        Err(StoreError::NewerVersion {
            found: 3,
            supported: 2
        })
    ));
    assert!(matches!(
        store.add_certificate_with_key(&backup().certificates[0], None),
        Err(StoreError::NewerVersion { .. })
    ));
    assert!(keys.names().expect("names").is_empty());
    assert_eq!(
        fs::read_to_string(folder.0.join("store.xml")).expect("unchanged"),
        text
    );
    fs::write(folder.0.join("store.xml"), empty_xml()).expect("remove planted version");
    store
        .add_location("home", &station())
        .expect("v1 still works");
}

#[test]
fn planted_bad_files_are_refused_and_not_rewritten() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let path = folder.0.join("store.xml");
    let valid = empty_xml();
    let location = "<location name=\"home\"><field name=\"CALL\">QG0TEST</field><field name=\"DXCC\">291</field></location>";
    let location_xml = |s: &str| valid.replace("<locations>\n", &format!("<locations>{s}\n"));
    let cases = [
        valid.replace("<locations>", "<locations>\u{1}"),
        location_xml(&location.replace("home", "bad&#0;")),
        location_xml(&format!("{location}{location}")),
        location_xml(&location.replace("home", &"n".repeat(MAX_NAME_LEN + 1))),
        location_xml(&location.replace("291", "9999")),
        location_xml(&location.replace("QG0TEST", &"A".repeat(crate::station::MAX_LEN + 1))),
        location_xml(&location.repeat(MAX_LOCATIONS + 1)),
        location_xml(&format!(
            "<location name=\"home\">{}</location>",
            "<field name=\"DXCC\">291</field>".repeat(crate::station::MAX_FIELDS + 1)
        )),
        valid.replace(
            "<certificates>",
            &format!(
                "<certificates>{}",
                "<certificate/>".repeat(MAX_CERTIFICATES + 1)
            ),
        ),
        valid.replace("<locations>", "<locations surprise=\"1\">"),
        valid.replace(
            "<signed-qsos version=\"1\"/>",
            "<signed-qsos version=\"1\"><qso/></signed-qsos>",
        ),
        valid.replace(
            "<signed-qsos version=\"1\"/>",
            "<signed-qsos version=\"2\"/>",
        ),
        valid.replace("<locations>", "<locations/><locations>"),
        valid.replacen("qgt-store version=\"2\"", "qgt-store version=\"0\"", 1),
    ];
    for text in cases {
        fs::write(&path, &text).expect("plant");
        assert!(open(&folder.0, &keys).is_err());
        assert_eq!(fs::read_to_string(&path).expect("untouched"), text);
        fs::write(&path, &valid).expect("remove planted case");
        assert!(open(&folder.0, &keys).is_ok());
    }
    let file = File::create(&path).expect("plant oversize");
    file.set_len(MAX_FILE_LEN as u64 + 1).expect("sparse file");
    assert!(matches!(
        open(&folder.0, &keys),
        Err(StoreError::Limit("file bytes"))
    ));
    assert_eq!(
        fs::metadata(&path).expect("unchanged").len(),
        MAX_FILE_LEN as u64 + 1
    );
    fs::write(&path, valid).expect("remove oversize");
    let (store, _) = open(&folder.0, &keys).expect("valid again");
    let before = fs::read(&path).expect("before");
    for name in ["bad\0", "bad\u{fffe}", "bad\u{ffff}", ""] {
        assert!(store.add_location(name, &station()).is_err());
        assert_eq!(fs::read(&path).expect("unchanged"), before);
    }
}

// Observe ordering at the backend boundary, and inject a deterministic write failure even when
// tests run as root (read-only permission tests would not fail there).
struct ObservedKeys {
    inner: MemoryKeyStore,
    folder: PathBuf,
    fail_write: bool,
    fail_delete: bool,
    deny_put: std::sync::atomic::AtomicBool,
    calls: Mutex<Vec<&'static str>>,
}
impl ObservedKeys {
    fn new(folder: &Path, fail_write: bool, fail_delete: bool) -> Self {
        Self {
            inner: MemoryKeyStore::new(),
            folder: folder.into(),
            fail_write,
            fail_delete,
            deny_put: std::sync::atomic::AtomicBool::new(false),
            calls: Mutex::new(Vec::new()),
        }
    }
    fn file_does_not_name(&self, name: &str) {
        assert!(
            !fs::read_to_string(self.folder.join("store.xml"))
                .unwrap_or_default()
                .contains(name)
        );
    }
}
impl KeyStore for ObservedKeys {
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError> {
        self.file_does_not_name(name);
        self.calls.lock().expect("calls").push("put");
        if self.deny_put.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(KeyStoreError::AccessDenied);
        }
        self.inner.put(name, der)?;
        if self.fail_write {
            fs::create_dir(self.folder.join("store.xml.partial"))
                .expect("inject failure after put");
        }
        Ok(())
    }
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        self.calls.lock().expect("calls").push("get");
        self.inner.get(name)
    }
    fn delete(&self, name: &str) -> Result<(), KeyStoreError> {
        self.file_does_not_name(name);
        self.calls.lock().expect("calls").push("delete");
        if self.fail_delete {
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
fn keys_precede_the_file_and_failed_writes_roll_them_back() {
    let backup = backup();
    let entry = &backup.certificates[0];
    let password = corpus(&format!("keys/{}.password", entry.callsign));
    let password = (!password.is_empty()).then_some(password.as_slice());
    for fail in [false, true] {
        let folder = Folder::new();
        let keys = Arc::new(ObservedKeys::new(&folder.0, fail, false));
        let (store, _) = open(&folder.0, &keys).expect("open");
        store
            .add_location("home", &station())
            .expect("existing file");
        let before = fs::read(folder.0.join("store.xml")).expect("before");
        let result = store.add_certificate_with_key(entry, password);
        if fail {
            assert!(matches!(result, Err(StoreError::Io(_))));
            assert!(keys.names().expect("rolled back").is_empty());
            assert_eq!(
                fs::read(folder.0.join("store.xml")).expect("unchanged"),
                before
            );
            fs::remove_dir(folder.0.join("store.xml.partial")).expect("remove injection");
            store
                .add_location("works again", &station())
                .expect("failure removed");
        } else {
            let id = result.expect("added");
            store.delete_certificate(&id).expect("file before key");
        }
        assert_eq!(*keys.calls.lock().expect("calls"), ["put", "delete"]);
    }
}

#[test]
fn failed_cleanup_and_delete_are_reported_as_orphans() {
    let backup = backup();
    let entry = &backup.certificates[0];
    let password = corpus(&format!("keys/{}.password", entry.callsign));
    let password = (!password.is_empty()).then_some(password.as_slice());
    for fail_write in [true, false] {
        let folder = Folder::new();
        let keys = Arc::new(ObservedKeys::new(&folder.0, fail_write, true));
        let (store, _) = open(&folder.0, &keys).expect("open");
        let result = store.add_certificate_with_key(entry, password);
        if fail_write {
            assert!(matches!(result, Err(StoreError::Rollback { .. })));
        } else {
            assert!(matches!(
                store.delete_certificate(&result.expect("add")),
                Err(StoreError::KeyStore(KeyStoreError::AccessDenied))
            ));
        }
        let (_, report) = open(&folder.0, &keys).expect("report");
        assert_eq!(report.orphaned_keys, keys.names().expect("one orphan"));
        assert_eq!(report.orphaned_keys.len(), 1);
        assert!(report.missing_keys.is_empty());
        assert!(
            store
                .certificates()
                .expect("file no longer names key")
                .is_empty()
        );
    }
}

#[test]
fn failed_sync_after_rename_keeps_an_imported_key() {
    let folder = Folder::new();
    let keys = Arc::new(ObservedKeys::new(&folder.0, false, false));
    let (store, _) = open(&folder.0, &keys).expect("open");
    let backup = backup();
    let entry = &backup.certificates[0];
    let password = corpus(&format!("keys/{}.password", entry.callsign));
    store
        .fail_sync
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        store
            .add_certificate_with_key(entry, (!password.is_empty()).then_some(password.as_slice())),
        Err(StoreError::Durability(_))
    ));
    assert_eq!(*keys.calls.lock().expect("calls"), ["put"]);
    let certs = store.certificates().expect("renamed file is visible");
    assert_eq!(certs.len(), 1);
    assert!(
        keys.exists(certs[0].key_name.as_ref().expect("key name"))
            .expect("key retained")
    );
    assert_eq!(
        open(&folder.0, &keys).expect("report").1,
        OpenReport::default()
    );
    assert!(!folder.0.join("store.xml.partial").exists());
    store
        .fail_sync
        .store(false, std::sync::atomic::Ordering::Relaxed);
    store
        .delete_certificate(&certs[0].id)
        .expect("sync restored");
    assert_eq!(*keys.calls.lock().expect("calls"), ["put", "delete"]);
}

#[test]
fn failed_sync_after_rename_prevents_credential_deletion() {
    let folder = Folder::new();
    let keys = Arc::new(ObservedKeys::new(&folder.0, false, false));
    let (store, _) = open(&folder.0, &keys).expect("open");
    let backup = backup();
    let entry = &backup.certificates[0];
    let password = corpus(&format!("keys/{}.password", entry.callsign));
    let id = store
        .add_certificate_with_key(entry, (!password.is_empty()).then_some(password.as_slice()))
        .expect("import");
    let key_name = store.certificates().expect("certificates")[0]
        .key_name
        .clone()
        .expect("name");
    store
        .fail_sync
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        store.delete_certificate(&id),
        Err(StoreError::Durability(_))
    ));
    assert_eq!(*keys.calls.lock().expect("no delete"), ["put"]);
    assert!(keys.exists(&key_name).expect("key retained"));
    assert!(store.certificates().expect("renamed file").is_empty());
    assert!(!folder.0.join("store.xml.partial").exists());
    let (_, report) = open(&folder.0, &keys).expect("report retained orphan");
    assert_eq!(report.orphaned_keys, [key_name]);
    assert!(report.missing_keys.is_empty());
}

#[cfg(windows)]
#[test]
fn windows_sync_reopens_the_renamed_file_with_write_access() {
    let folder = Folder::new();
    let path = folder.0.join("store.xml");
    fs::write(&path, empty_xml()).expect("renamed file");
    let original = fs::metadata(&path).expect("metadata").permissions();
    let mut read_only = original.clone();
    read_only.set_readonly(true);
    fs::set_permissions(&path, read_only).expect("plant write-access failure");
    let result = sync_replacement(&folder.0);
    fs::set_permissions(&path, original).expect("remove planted failure");
    assert!(result.is_err());
    sync_replacement(&folder.0).expect("writable file can be synced");
}

#[test]
fn open_reports_missing_and_orphaned_keys_without_reading_or_removing_secrets() {
    let folder = Folder::new();
    let keys = Arc::new(ObservedKeys::new(&folder.0, false, false));
    let (store, _) = open(&folder.0, &keys).expect("open");
    let entry = &backup().certificates[0];
    let password = corpus(&format!("keys/{}.password", entry.callsign));
    let id = store
        .add_certificate_with_key(entry, (!password.is_empty()).then_some(password.as_slice()))
        .expect("add");
    let certs = store.certificates().expect("certificates");
    keys.inner
        .delete(certs[0].key_name.as_ref().expect("key name"))
        .expect("simulate lost key");
    let orphan = keys::new_name("key:").expect("name");
    keys.inner
        .put(&orphan, &[1])
        .expect("simulate interrupted import");
    let before = fs::read(folder.0.join("store.xml")).expect("before");
    let (_, report) = open(&folder.0, &keys).expect("open");
    assert_eq!(
        report,
        OpenReport {
            missing_request_keys: Vec::new(),
            missing_keys: vec![id.clone()],
            orphaned_keys: vec![orphan.clone()]
        }
    );
    assert_eq!(
        fs::read(folder.0.join("store.xml")).expect("untouched"),
        before
    );
    assert!(keys.exists(&orphan).expect("orphan untouched"));
    assert_eq!(*keys.calls.lock().expect("no reads"), ["put"]);
    assert!(matches!(
        store.with_key(&id, |_| ()),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn malformed_or_mismatched_credentials_cannot_sign_or_be_imported() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (store, _) = open(&folder.0, &keys).expect("open");
    let mut backup = backup();
    let entry = &backup.certificates[0];
    let password = corpus(&format!("keys/{}.password", entry.callsign));
    let password = (!password.is_empty()).then_some(password.as_slice());
    let id = store
        .add_certificate_with_key(entry, password)
        .expect("add");
    let certs = store.certificates().expect("certs");
    let name = certs[0].key_name.as_ref().expect("name");
    keys.delete(name).expect("simulate replacement");
    keys.put(name, &[1, 2]).expect("bad DER");
    assert!(matches!(
        store.with_key(&id, |_| panic!("must not sign")),
        Err(StoreError::Key(_))
    ));
    store.delete_certificate(&id).expect("delete");
    backup.certificates[0].certificate = backup.certificates[1].certificate.clone();
    assert!(
        store
            .add_certificate_with_key(&backup.certificates[0], password)
            .is_err()
    );
    assert!(keys.names().expect("none stored").is_empty());
}

#[test]
fn independent_writers_wait_for_the_lock_and_reload_the_current_file() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (a, _) = open(&folder.0, &keys).expect("writer a");
    let (b, _) = open(&folder.0, &keys).expect("writer b");
    let lock = a.lock().expect("hold lock externally");
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            started_tx.send(()).expect("started");
            b.add_location("second", &station()).expect("second writer");
            done_tx.send(()).expect("done");
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("thread started");
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(lock);
        a.add_location("first", &station()).expect("first writer");
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("writer unblocked");
    });
    let locations = a.locations().expect("both updates survive");
    assert_eq!(locations.len(), 2);
    assert!(locations.iter().any(|l| l.name == "first"));
    assert!(locations.iter().any(|l| l.name == "second"));
    assert!(!folder.0.join("store.xml.partial").exists());
}

#[cfg(unix)]
#[test]
fn whole_file_replacement_changes_inode_and_creates_owner_only_files() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (store, _) = open(&folder.0, &keys).expect("open");
    store.add_location("one", &station()).expect("first");
    let before = fs::metadata(folder.0.join("store.xml")).expect("metadata");
    store.add_location("two", &station()).expect("second");
    let after = fs::metadata(folder.0.join("store.xml")).expect("metadata");
    assert_ne!(before.ino(), after.ino());
    for name in ["store.xml", "store.lock"] {
        assert_eq!(
            fs::metadata(folder.0.join(name))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(!folder.0.join("store.xml.partial").exists());
    fs::write(folder.0.join("store.xml.partial"), "interrupted write")
        .expect("plant stale partial");
    store
        .add_location("three", &station())
        .expect("recover stale partial");
    assert!(!folder.0.join("store.xml.partial").exists());
}

#[test]
fn first_use_creates_a_nested_directory_and_accepts_later_writes() {
    let folder = Folder::new();
    let nested = folder.0.join("first/second/store");
    let (store, report) = Store::open(&nested, KeyBackend::Memory).expect("create nested folder");
    assert_eq!(report, OpenReport::default());
    store.add_location("home", &station()).expect("first write");
    let (reopened, _) = Store::open(&nested, KeyBackend::Memory).expect("existing directory");
    assert_eq!(reopened.locations().expect("locations")[0].name, "home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [
            folder.0.join("first"),
            folder.0.join("first/second"),
            nested.clone(),
        ] {
            assert_eq!(
                fs::metadata(path).expect("directory").permissions().mode() & 0o777,
                0o700
            );
        }
        for name in ["store.xml", "store.lock"] {
            assert_eq!(
                fs::metadata(nested.join(name))
                    .expect("file")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    assert!(!nested.join("store.xml.partial").exists());
}

#[cfg(unix)]
#[test]
fn a_store_beneath_an_execute_only_ancestor_opens_and_writes() {
    use std::os::unix::fs::PermissionsExt;

    struct RestorePermissions(PathBuf);
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    let folder = Folder::new();
    let ancestor = folder.0.join("ancestor");
    let existing = ancestor.join("existing");
    fs::create_dir_all(&existing).expect("existing ancestors");
    let _restore = RestorePermissions(ancestor.clone());
    // 0711 permits other users only traversal. Also remove the owner's read bit so this
    // regression exercises the permission failure without needing another user or root.
    for mode in [0o711, 0o111] {
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(mode)).expect("permissions");
        let nested = existing.join(format!("store-{mode:o}"));
        let (store, _) = Store::open(&nested, KeyBackend::Memory).expect("create store");
        store.add_location("home", &station()).expect("first write");
        let (reopened, _) = Store::open(&nested, KeyBackend::Memory).expect("reopen store");
        reopened
            .add_location("away", &station())
            .expect("later write");
        assert_eq!(reopened.locations().expect("locations").len(), 2);
    }
}

#[cfg(unix)]
#[test]
fn first_use_syncs_each_parent_and_retries_an_interrupted_directory_sync() {
    use std::cell::RefCell;
    let folder = Folder::new();
    let first = folder.0.join("first");
    let second = first.join("second");
    let nested = second.join("store");
    let observed = RefCell::new(Vec::new());
    create_directory(&nested, |parent| {
        assert!(parent == first || parent == second || parent == nested);
        sync_directory(parent)?;
        observed.borrow_mut().push(parent.to_path_buf());
        // Persist the recovery marker before creating the next descendant.
        if observed.borrow().len() == 1 {
            assert!(!second.exists());
        }
        Ok(())
    })
    .expect("durable creation");
    assert_eq!(
        *observed.borrow(),
        [
            first.clone(),
            first.clone(),
            second.clone(),
            second.clone(),
            nested.clone(),
            first.clone(),
            second.clone(),
            nested.clone()
        ]
    );
    create_directory(&nested, |parent| {
        assert_eq!(parent, nested, "completed ancestors must not be reopened");
        sync_directory(parent)?;
        Ok(())
    })
    .expect("markers were cleared after successful creation");

    for stage in ["parent", "leaf", "unmarked-leaf", "cleanup"] {
        let first = folder.0.join(stage);
        let second = first.join("second");
        let interrupted = second.join("store");
        let result = create_directory(&interrupted, |parent| {
            assert!(parent == first || parent == second || parent == interrupted);
            let fail = match stage {
                "parent" => parent == first && second.exists(),
                "leaf" | "unmarked-leaf" => parent == interrupted,
                "cleanup" => parent == first && !first.join(".qgt-directory-pending").exists(),
                _ => unreachable!(),
            };
            if fail {
                return Err(io::Error::other("injected directory sync failure"));
            }
            sync_directory(parent)
        });
        assert!(result.is_err());
        assert!(second.is_dir());
        assert_eq!(interrupted.exists(), stage != "parent");
        if stage == "unmarked-leaf" {
            // Plant the state left by interruption immediately after mkdir, before its marker.
            fs::remove_file(interrupted.join(".qgt-directory-pending")).expect("unmarked child");
        }
        let retried = RefCell::new(Vec::new());
        create_directory(&interrupted, |parent| {
            // Cleanup already synced the top directory before removing its marker.
            assert!(parent != folder.0 && (stage != "cleanup" || parent != first));
            sync_directory(parent)?;
            retried.borrow_mut().push(parent.to_path_buf());
            Ok(())
        })
        .expect("retry must complete only the marked directory chain");
        let retried = retried.borrow();
        assert_eq!(
            retried.first(),
            Some(if stage == "cleanup" { &second } else { &first })
        );
        assert!(retried.contains(&second));
        assert!(retried.contains(&interrupted));
        let (store, _) = Store::open(&interrupted, KeyBackend::Memory).expect("recovered store");
        store
            .add_location("home", &station())
            .expect("write after recovery");
    }
}

#[test]
fn platform_default_folder_uses_the_shared_service_path() {
    let env = |name: &str| match name {
        "HOME" => Some(PathBuf::from("/home/test")),
        "XDG_DATA_HOME" => Some(PathBuf::from("/data")),
        "APPDATA" => Some(PathBuf::from("C:/AppData")),
        _ => None,
    };
    #[cfg(target_os = "windows")]
    assert_eq!(
        default_dir_from(env),
        Some(PathBuf::from("C:/AppData/qso-graph/trust"))
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        default_dir_from(env),
        Some(PathBuf::from(
            "/home/test/Library/Application Support/io.qso-graph.trust"
        ))
    );
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        assert_eq!(
            default_dir_from(env),
            Some(PathBuf::from("/data/qso-graph-trust"))
        );
        let no_xdg = |name: &str| {
            if name == "XDG_DATA_HOME" {
                None
            } else {
                env(name)
            }
        };
        assert_eq!(
            default_dir_from(no_xdg),
            Some(PathBuf::from("/home/test/.local/share/qso-graph-trust"))
        );
        let relative_xdg = |name: &str| {
            if name == "XDG_DATA_HOME" {
                Some(PathBuf::from("relative"))
            } else {
                env(name)
            }
        };
        assert_eq!(default_dir_from(relative_xdg), default_dir_from(no_xdg));
    }
    assert_eq!(default_dir_from(|_| None), None);
}

mod requests;

mod signed;
