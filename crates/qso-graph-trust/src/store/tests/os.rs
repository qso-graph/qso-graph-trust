// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;

/// Track names before any write, including writes that fail or are rolled back. Cleanup never
/// enumerates/deletes the test service wholesale, and runs when an assertion unwinds too.
struct TestCredentials {
    inner: OsKeyStore,
    names: Mutex<Vec<String>>,
}

impl TestCredentials {
    fn new() -> Self {
        Self {
            inner: OsKeyStore::new(true),
            names: Mutex::new(Vec::new()),
        }
    }
}

impl KeyStore for TestCredentials {
    fn orphan_detection(&self) -> OrphanDetection {
        self.inner.orphan_detection()
    }
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError> {
        // A pre-existing collision belongs to someone else: never add it to our cleanup list.
        if !self.inner.exists(name)? {
            self.names
                .lock()
                .map_err(|_| KeyStoreError::Unavailable)?
                .push(name.into());
        }
        self.inner.put(name, der)
    }
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        self.inner.get(name)
    }
    fn delete(&self, name: &str) -> Result<(), KeyStoreError> {
        self.inner.delete(name)
    }
    fn exists(&self, name: &str) -> Result<bool, KeyStoreError> {
        self.inner.exists(name)
    }
    fn names(&self) -> Result<Vec<String>, KeyStoreError> {
        self.inner.names()
    }
}

impl Drop for TestCredentials {
    fn drop(&mut self) {
        let names = self
            .names
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for name in names {
            let _ = self.inner.delete(name);
        }
    }
}

// Run on a host with its OS credential service available:
// QGT_OS_KEYSTORE_TEST=1 cargo test -p qso-graph-trust os_round_trip -- --ignored
#[test]
#[ignore = "requires QGT_OS_KEYSTORE_TEST=1 and a working OS credential service"]
fn os_round_trip_uses_only_test_service_and_reports_lost_and_orphaned_keys() {
    assert!(
        std::env::var("QGT_OS_KEYSTORE_TEST").is_ok_and(|v| v == "1"),
        "OS test requires explicit opt-in"
    );
    let folder = Folder::new();
    let keys = Arc::new(TestCredentials::new());

    // Binary secrets round-trip without UTF-8/password conversion. Existing entries are refused.
    let raw = keys::new_name("key:").expect("random name");
    keys.put(&raw, &[0, 255, 128]).expect("write bytes");
    assert!(keys.get(&raw).expect("read").expect("present").as_slice() == [0, 255, 128]);
    assert_eq!(keys.put(&raw, &[1]), Err(KeyStoreError::AlreadyExists));
    assert!(
        keys.get(&raw)
            .expect("read unchanged")
            .expect("present")
            .as_slice()
            == [0, 255, 128]
    );
    // Exercise reading a replacement written through the same default byte API, TEST_SERVICE only.
    keyring::Entry::new(TEST_SERVICE, &raw)
        .and_then(|entry| entry.set_secret(&[128, 0, 255]))
        .map_err(|_| KeyStoreError::Unavailable)
        .expect("replace test bytes");
    assert!(
        keys.get(&raw)
            .expect("read replacement")
            .expect("present")
            .as_slice()
            == [128, 0, 255]
    );
    assert!(keys.exists(&raw).expect("present"));
    let capability = keys.orphan_detection();
    match capability {
        OrphanDetection::Available => assert!(keys.names().expect("names").contains(&raw)),
        OrphanDetection::Unavailable => {
            assert_eq!(keys.names(), Err(KeyStoreError::EnumerationUnavailable))
        }
    }
    let (_, report) = Store::open(&folder.0, KeyBackend::OsTest).expect("report orphan");
    assert_eq!(report.orphan_detection, capability);
    assert_eq!(
        report.orphaned_keys.contains(&raw),
        capability == OrphanDetection::Available
    );
    keys.delete(&raw).expect("delete");
    keys.delete(&raw).expect("idempotent delete");
    assert!(!keys.exists(&raw).expect("absent"));
    assert!(keys.get(&raw).expect("missing read").is_none());

    let (store, _) = open(&folder.0, &keys).expect("open tracked test backend");
    let backup = backup();
    let entry = &backup.certificates[0];
    let password = Zeroizing::new(corpus(&format!("keys/{}.password", entry.callsign)));
    let id = store
        .add_certificate_with_key(entry, (!password.is_empty()).then_some(password.as_slice()))
        .expect("import");
    let old_name = store.certificates().expect("certificates")[0]
        .key_name
        .clone()
        .expect("key name");
    let (reopened, report) = Store::open(&folder.0, KeyBackend::OsTest).expect("persistent reopen");
    assert_eq!(report.orphan_detection, capability);
    assert!(!report.missing_keys.contains(&id));
    assert!(!report.orphaned_keys.contains(&old_name));
    reopened
        .with_key(&id, |_| ())
        .expect("stored key matches certificate");

    // Whole-store replacement stages fresh credentials, replaces the file, then deletes old keys.
    let export_password = crate::export::Password::generate().expect("test password");
    let encrypted = store
        .export_part(&export_password)
        .expect("encrypted export");
    let trust = Trust::with_roots(&[&corpus("pki/ca.pem")]).expect("test CA");
    store
        .restore_part(&encrypted, &export_password, &trust)
        .expect("replace store");
    let new_name = store.certificates().expect("replaced certificates")[0]
        .key_name
        .clone()
        .expect("new key name");
    assert_ne!(old_name, new_name);
    assert!(!keys.exists(&old_name).expect("old key removed"));
    reopened
        .with_key(&id, |_| ())
        .expect("reloaded replacement key");
    store.delete_certificate(&id).expect("delete certificate");
    assert!(store.certificates().expect("deleted record").is_empty());
    assert!(!keys.exists(&new_name).expect("deleted credential"));

    let id = store
        .add_certificate_with_key(entry, (!password.is_empty()).then_some(password.as_slice()))
        .expect("import again");
    let name = store.certificates().expect("certificate")[0]
        .key_name
        .clone()
        .expect("key name");
    keys.delete(&name).expect("simulate lost credential");
    let (missing, report) = Store::open(&folder.0, KeyBackend::OsTest).expect("report missing key");
    assert_eq!(report.orphan_detection, capability);
    assert!(report.missing_keys.contains(&id));
    assert!(matches!(
        missing.with_key(&id, |_| ()),
        Err(StoreError::NotFound)
    ));
}

// Exercise Store's Windows capability branch on Linux without pretending to run a Windows store.
struct NamedKeysOnly {
    inner: MemoryKeyStore,
    checked: Mutex<Vec<String>>,
}

impl KeyStore for NamedKeysOnly {
    fn orphan_detection(&self) -> OrphanDetection {
        OrphanDetection::Unavailable
    }
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError> {
        self.inner.put(name, der)
    }
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        self.inner.get(name)
    }
    fn delete(&self, name: &str) -> Result<(), KeyStoreError> {
        self.inner.delete(name)
    }
    fn exists(&self, name: &str) -> Result<bool, KeyStoreError> {
        self.checked
            .lock()
            .expect("checked names")
            .push(name.into());
        self.inner.exists(name)
    }
    fn names(&self) -> Result<Vec<String>, KeyStoreError> {
        panic!("Store must never enumerate a backend with unavailable orphan detection")
    }
}

#[test]
fn unavailable_orphan_detection_still_checks_only_file_named_keys() {
    let folder = Folder::new();
    let keys = Arc::new(NamedKeysOnly {
        inner: MemoryKeyStore::new(),
        checked: Mutex::new(Vec::new()),
    });
    let (store, report) = open(&folder.0, &keys).expect("open without enumeration");
    assert_eq!(report.orphan_detection, OrphanDetection::Unavailable);
    let backup = backup();
    let entry = &backup.certificates[0];
    let password = Zeroizing::new(corpus(&format!("keys/{}.password", entry.callsign)));
    let id = store
        .add_certificate_with_key(entry, (!password.is_empty()).then_some(password.as_slice()))
        .expect("import");
    let name = store.certificates().expect("certificate")[0]
        .key_name
        .clone()
        .expect("key name");
    let orphan = keys::new_name("key:").expect("orphan name");
    keys.inner
        .put(&orphan, &[1])
        .expect("plant unknown credential");
    keys.checked.lock().expect("checked").clear();
    let (_, report) = open(&folder.0, &keys).expect("check named keys");
    assert_eq!(report.orphan_detection, OrphanDetection::Unavailable);
    assert!(report.orphaned_keys.is_empty());
    assert!(report.missing_keys.is_empty());
    assert_eq!(
        keys.checked
            .lock()
            .expect("only the named key was checked")
            .as_slice(),
        std::slice::from_ref(&name)
    );
    keys.delete(&name).expect("plant missing key");
    keys.checked.lock().expect("checked").clear();
    let (_, report) = open(&folder.0, &keys).expect("report missing key without enumeration");
    assert_eq!(report.missing_keys, [id]);
    assert_eq!(report.orphan_detection, OrphanDetection::Unavailable);
    assert_eq!(
        keys.checked
            .lock()
            .expect("only named missing key checked")
            .as_slice(),
        std::slice::from_ref(&name)
    );
    let request_id = keys::new_name("request:").expect("request identifier");
    let request_key = keys::new_name("key:").expect("request credential name");
    let certificate = entry.certificate.as_ref().expect("test certificate");
    let mut data = store.read().expect("public records");
    data.pending_requests.push(PendingRequest {
        id: request_id.clone(),
        callsign: certificate.callsign().into(),
        dxcc: certificate.dxcc(),
        public_key_der: certificate.public_key_der().to_vec(),
        created_at: 1_700_000_000,
        key_name: request_key.clone(),
    });
    store
        .replace(&format::write(&data).expect("fixture XML"))
        .expect("plant missing pending key");
    keys.checked.lock().expect("checked").clear();
    let (_, report) = open(&folder.0, &keys).expect("check certificate and pending credentials");
    assert_eq!(report.missing_request_keys, [request_id]);
    assert_eq!(report.orphan_detection, OrphanDetection::Unavailable);
    assert_eq!(
        *keys
            .checked
            .lock()
            .expect("only file named credentials checked"),
        [name, request_key]
    );
    assert!(keys.inner.exists(&orphan).expect("orphan untouched"));
}
