// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;
use crate::qso::Date;
use crate::request::{Authorization, CallKind, CertificateRequest};
use base64ct::{Base64, Encoding};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::Digest;
use x509_cert::der::{Decode, DecodePem, Encode};

fn generated() -> GeneratedRequest {
    CertificateRequest {
        callsign: " QG0TEST ".into(),
        dxcc: 291,
        qso_not_before: Date::from_iso("2020-01-01").expect("date"),
        qso_not_after: None,
        name: "QGT Test Operator".into(),
        address1: "1 No Place".into(),
        address2: String::new(),
        city: "City".into(),
        state: "ST".into(),
        postal_code: String::new(),
        country: "USA".into(),
        email: "test@example.invalid".into(),
        provider: String::new(),
        provider_unit: String::new(),
        kind: CallKind::Personal,
    }
    .generate(Authorization::New)
    .expect("request")
}

fn response(request: &GeneratedRequest) -> Certificate {
    // Only generated corpus test keys and a test CA, never an operator's certificate.
    let mut cert =
        x509_cert::Certificate::from_pem(corpus("../tqsl/1024/tqsl/certs/user")).expect("template");
    cert.tbs_certificate.subject_public_key_info =
        x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(request.public_key_der())
            .expect("SPKI");
    let ca = RsaPrivateKey::from_pkcs8_pem(
        &String::from_utf8(corpus("../tqsl/pki/ca.key")).expect("PEM"),
    )
    .expect("test CA");
    let signature = ca
        .sign(
            Pkcs1v15Sign::new::<sha2::Sha256>(),
            &sha2::Sha256::digest(cert.tbs_certificate.to_der().expect("TBS")),
        )
        .expect("sign");
    cert.signature = x509_cert::der::asn1::BitString::from_bytes(&signature).expect("bits");
    let cert = Certificate::from_pem_or_der(&cert.to_der().expect("DER")).expect("response");
    cert.verify(
        &Trust::with_roots(&[&corpus("../tqsl/pki/root.pem")]).expect("trust"),
        &[
            x509_cert::Certificate::from_pem(corpus("../tqsl/pki/ca.pem"))
                .expect("CA")
                .to_der()
                .expect("DER"),
        ],
    )
    .expect("test response chains");
    cert
}

#[test]
fn pending_metadata_and_custody_survive_request_drop_and_reopen() {
    let folder = Folder::new();
    let keys = Arc::new(ObservedKeys::new(&folder.0, false, false));
    let (store, _) = open(&folder.0, &keys).expect("open");
    let request = generated();
    let cert = response(&request);
    let id = store.store_request(&request).expect("store");
    let pending = store.pending_requests().expect("list");
    assert_eq!(pending.len(), 1);
    let p = &pending[0];
    assert_eq!(p.id, id);
    assert_eq!(p.callsign, "QG0TEST");
    assert_eq!(p.dxcc, 291);
    assert_eq!(p.created_at, request.created_at);
    assert_eq!(p.public_key_der, request.public_key_der());
    assert!(keys::valid_name(&p.key_name, "key:"));
    let xml = fs::read_to_string(folder.0.join("store.xml")).expect("file");
    assert!(xml.contains("<qgt-store version=\"1\">"));
    assert!(xml.contains(&Base64::encode_string(request.public_key_der())));
    assert!(!xml.contains(&Base64::encode_string(&request.private)));
    assert!(!xml.contains("PRIVATE KEY"));
    assert!(matches!(
        store.store_request(&request),
        Err(StoreError::AlreadyExists)
    ));
    drop(request);
    drop(store);
    let (store, report) = open(&folder.0, &keys).expect("reopen");
    assert_eq!(report, OpenReport::default());
    assert_eq!(store.pending_requests().expect("list"), pending);
    assert_eq!(
        *keys.calls.lock().expect("no secret reads on open or list"),
        ["put"]
    );
    let cert_id = store
        .add_requested_certificate(&cert)
        .expect("attach by identity");
    assert!(store.pending_requests().expect("list").is_empty());
    assert_eq!(
        store.certificates().expect("certs")[0].key_name.as_deref(),
        Some(p.key_name.as_str())
    );
    drop(store);
    let (store, report) = open(&folder.0, &keys).expect("reopen attached");
    assert_eq!(report, OpenReport::default());
    store
        .with_key(&cert_id, |key| {
            assert!(key.matches_public_key(cert.public_key_der()));
            key.sign(b"requested certificate test").expect("sign")
        })
        .expect("key available");
    assert!(matches!(
        store.add_requested_certificate(&cert),
        Err(StoreError::AlreadyExists)
    ));
    assert!(matches!(
        store.abandon_request(&id),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn mismatched_responses_and_bad_credentials_leave_pending_state_untouched() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (store, _) = open(&folder.0, &keys).expect("open");
    let request = generated();
    let cert = response(&request);
    store.store_request(&request).expect("store");
    let pending = store.pending_requests().expect("list");
    let name = &pending[0].key_name;
    let path = folder.0.join("store.xml");
    let original = fs::read_to_string(&path).expect("file");
    let wrong_spki = Certificate::from_pem_or_der(&corpus("../tqsl/1024/tqsl/certs/user"))
        .expect("wrong response");
    assert!(matches!(
        store.add_requested_certificate(&wrong_spki),
        Err(StoreError::NotFound)
    ));
    // Same SPKI, valid but different call or DXCC must also refuse attachment.
    for edited in [
        original.replace("QG0TEST", "QG1TEST"),
        original.replace("dxcc=\"291\"", "dxcc=\"1\""),
    ] {
        fs::write(&path, &edited).expect("plant identity mismatch");
        assert!(matches!(
            store.add_requested_certificate(&cert),
            Err(StoreError::NotFound)
        ));
        assert_eq!(fs::read_to_string(&path).expect("untouched"), edited);
        fs::write(&path, &original).expect("restore");
    }
    let other = generated();
    for bad_der in [
        None,
        Some(b"not a key".as_slice()),
        Some(other.private.as_slice()),
    ] {
        keys.delete(name).expect("remove key");
        if let Some(der) = bad_der {
            keys.put(name, der).expect("plant key");
        }
        assert!(store.add_requested_certificate(&cert).is_err());
        assert_eq!(fs::read_to_string(&path).expect("untouched"), original);
        keys.delete(name).expect("remove bad key");
        keys.put(name, &request.private).expect("restore key");
    }
    // Pre-rename replacement failure preserves both pending record and key; retry succeeds.
    fs::create_dir(folder.0.join("store.xml.partial")).expect("plant failed write");
    assert!(matches!(
        store.add_requested_certificate(&cert),
        Err(StoreError::Io(_))
    ));
    assert_eq!(fs::read_to_string(&path).expect("untouched"), original);
    assert!(keys.exists(name).expect("key remains"));
    fs::remove_dir(folder.0.join("store.xml.partial")).expect("restore");
    store
        .add_requested_certificate(&cert)
        .expect("corrected attachment");
}

#[test]
fn request_writes_roll_back_or_retain_keys_in_the_same_order_as_imports() {
    let request = generated();
    for fail_delete in [false, true] {
        let folder = Folder::new();
        let keys = Arc::new(ObservedKeys::new(&folder.0, true, fail_delete));
        let (store, _) = open(&folder.0, &keys).expect("open");
        let result = store.store_request(&request);
        if fail_delete {
            assert!(matches!(result, Err(StoreError::Rollback { .. })));
            assert_eq!(
                open(&folder.0, &keys)
                    .expect("reopen")
                    .1
                    .orphaned_keys
                    .len(),
                1
            );
        } else {
            assert!(matches!(result, Err(StoreError::Io(_))));
            assert!(keys.names().expect("rolled back").is_empty());
        }
        assert!(store.pending_requests().expect("no record").is_empty());
        assert_eq!(*keys.calls.lock().expect("calls"), ["put", "delete"]);
        fs::remove_dir(folder.0.join("store.xml.partial")).expect("restore");
        // Retry uses the same generated key, with an ordinary backend sharing this folder.
        let (retry, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open retry");
        retry.store_request(&request).expect("retry");
    }
    let folder = Folder::new();
    let keys = Arc::new(ObservedKeys::new(&folder.0, false, false));
    let (store, _) = open(&folder.0, &keys).expect("open");
    store
        .fail_sync
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        store.store_request(&request),
        Err(StoreError::Durability(_))
    ));
    assert_eq!(store.pending_requests().expect("visible").len(), 1);
    assert_eq!(*keys.calls.lock().expect("calls"), ["put"]);
    assert_eq!(
        open(&folder.0, &keys).expect("reopen").1,
        OpenReport::default()
    );
    // Attachment after rename also retains its credential.
    let cert = response(&request);
    assert!(matches!(
        store.add_requested_certificate(&cert),
        Err(StoreError::Durability(_))
    ));
    assert!(store.pending_requests().expect("visible").is_empty());
    let id = store.certificates().expect("visible cert")[0].id.clone();
    store.with_key(&id, |_| ()).expect("key retained");
}

#[test]
fn abandonment_writes_file_before_key_deletion_and_reports_missing_keys() {
    let request = generated();
    for fail_delete in [false, true] {
        let folder = Folder::new();
        let keys = Arc::new(ObservedKeys::new(&folder.0, false, fail_delete));
        let (store, _) = open(&folder.0, &keys).expect("open");
        let id = store.store_request(&request).expect("store");
        let name = store.pending_requests().expect("list")[0].key_name.clone();
        fs::create_dir(folder.0.join("store.xml.partial")).expect("plant failed write");
        assert!(matches!(store.abandon_request(&id), Err(StoreError::Io(_))));
        assert!(keys.exists(&name).expect("not deleted"));
        assert_eq!(store.pending_requests().expect("unchanged").len(), 1);
        fs::remove_dir(folder.0.join("store.xml.partial")).expect("restore");
        let result = store.abandon_request(&id);
        if fail_delete {
            assert!(matches!(
                result,
                Err(StoreError::KeyStore(KeyStoreError::AccessDenied))
            ));
        } else {
            result.expect("abandon");
        }
        assert!(store.pending_requests().expect("removed").is_empty());
        let (_, report) = open(&folder.0, &keys).expect("reopen");
        assert_eq!(
            report.orphaned_keys,
            if fail_delete { vec![name] } else { vec![] }
        );
        assert_eq!(*keys.calls.lock().expect("calls"), ["put", "delete"]);
    }
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (store, _) = open(&folder.0, &keys).expect("open");
    let id = store.store_request(&request).expect("store");
    let name = store.pending_requests().expect("list")[0].key_name.clone();
    keys.delete(&name).expect("plant missing key");
    let (_, report) = open(&folder.0, &keys).expect("reopen");
    assert_eq!(report.missing_request_keys, std::slice::from_ref(&id));
    assert!(report.orphaned_keys.is_empty());
    keys.put(&name, &request.private).expect("restore");
    assert_eq!(
        open(&folder.0, &keys).expect("reopen").1,
        OpenReport::default()
    );
    store
        .fail_sync
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        store.abandon_request(&id),
        Err(StoreError::Durability(_))
    ));
    assert!(
        store
            .pending_requests()
            .expect("visible removal")
            .is_empty()
    );
    assert!(keys.exists(&name).expect("sync failure retains key"));
    assert_eq!(
        open(&folder.0, &keys).expect("reopen").1.orphaned_keys,
        [name]
    );
}

#[test]
fn optional_pending_section_is_bounded_strict_and_backward_readable() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("old empty folder");
    fs::write(folder.0.join("store.xml"), empty_xml()).expect("old v1 file");
    assert!(
        store
            .pending_requests()
            .expect("no optional section")
            .is_empty()
    );
    store.store_request(&generated()).expect("store");
    let path = folder.0.join("store.xml");
    let valid = fs::read_to_string(&path).expect("file");
    let data = format::read(&valid).expect("valid");
    let record_start = valid.find("    <request ").expect("record");
    let record_end = valid.find("</request>").expect("end") + "</request>".len();
    let record = &valid[record_start..record_end];
    let duplicate_spki = record
        .replace(
            &data.pending_requests[0].id,
            &keys::new_name("request:").expect("id"),
        )
        .replace(
            &data.pending_requests[0].key_name,
            &keys::new_name("key:").expect("name"),
        );
    let spki = Base64::encode_string(&data.pending_requests[0].public_key_der);
    let mut non_rsa = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(
        &data.pending_requests[0].public_key_der,
    )
    .expect("SPKI");
    non_rsa.algorithm.oid = x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    for bad in [
        valid.replace("QG0TEST", "qg0test"),
        valid.replace("dxcc=\"291\"", "dxcc=\"999999\""),
        valid.replace("dxcc=\"291\"", "dxcc=\"invalid\""),
        valid.replace("created=\"", "created=\"invalid"),
        valid.replace(&data.pending_requests[0].id, "request:not-a-uuid"),
        valid.replace(&data.pending_requests[0].key_name, "key:operator"),
        valid.replace("<request ", "<request surprise=\"1\" "),
        valid.replace("<pending-requests>", "<pending-requests surprise=\"1\">"),
        valid.replace("<pending-requests>", "<pending-requests>text"),
        valid.replace("</request>", "<unknown/></request>"),
        valid.replace(
            "</pending-requests>",
            &format!("{record}</pending-requests>"),
        ),
        valid.replace(
            "</pending-requests>",
            &format!("{duplicate_spki}</pending-requests>"),
        ),
        valid.replace("</qgt-store>", "<pending-requests/></qgt-store>"),
        valid.replace(
            &spki,
            &Base64::encode_string(&non_rsa.to_der().expect("non-RSA SPKI")),
        ),
        valid.replace(&spki, "%%%"),
        valid.replace(&spki, "AAAA"),
        valid.replace(&spki, &"A".repeat(513)),
        valid.replace(record, &record.repeat(MAX_PENDING_REQUESTS + 1)),
    ] {
        fs::write(&path, &bad).expect("plant");
        assert!(store.pending_requests().is_err());
        assert!(store.abandon_request(&data.pending_requests[0].id).is_err());
        assert_eq!(fs::read_to_string(&path).expect("untouched"), bad);
        fs::write(&path, &valid).expect("restore");
        assert_eq!(
            store.pending_requests().expect("corrected"),
            data.pending_requests
        );
    }
    // Credentials cannot be shared by a certificate and a request, even in hand-edited XML.
    let mut data = data;
    data.certificates.push(StoredCertificate {
        id: keys::new_name("cert:").expect("id"),
        certificate: Certificate::from_pem_or_der(&corpus("../tqsl/1024/tqsl/certs/user"))
            .expect("cert"),
        key_name: Some(data.pending_requests[0].key_name.clone()),
    });
    assert!(format::read(&format::write(&data).expect("encode planted data")).is_err());
    data.certificates[0].key_name = None;
    format::read(&format::write(&data).expect("encode corrected data"))
        .expect("no shared credential");
}

#[test]
fn backend_denial_leaves_the_request_retryable_and_does_not_publish_metadata() {
    let folder = Folder::new();
    let keys = Arc::new(ObservedKeys::new(&folder.0, false, false));
    let (store, _) = open(&folder.0, &keys).expect("open");
    let request = generated();
    keys.deny_put
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        store.store_request(&request),
        Err(StoreError::KeyStore(KeyStoreError::AccessDenied))
    ));
    assert!(keys.names().expect("no keys").is_empty());
    assert!(store.pending_requests().expect("no metadata").is_empty());
    keys.deny_put
        .store(false, std::sync::atomic::Ordering::Relaxed);
    store.store_request(&request).expect("retry same request");
    let pending = store.pending_requests().expect("metadata");
    let der = keys
        .get(&pending[0].key_name)
        .expect("get")
        .expect("stored key");
    TqslKey::from_pkcs8_der(&der, request.public_key_der()).expect("same generated key");
}

#[test]
fn request_mutations_wait_for_the_os_lock_and_reload_pending_records() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (store, _) = open(&folder.0, &keys).expect("open");
    let store = Arc::new(store);
    let request = generated();
    let response = response(&request);
    let lock = owner_file()
        .create(true)
        .truncate(false)
        .open(folder.0.join("store.lock"))
        .expect("lock file");
    lock.lock().expect("hold lock");
    let worker_store = Arc::clone(&store);
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(()).expect("started");
        let result = worker_store.store_request(&request);
        tx.send(()).expect("finished");
        result
    });
    rx.recv_timeout(Duration::from_secs(5)).expect("started");
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    lock.unlock().expect("release");
    let request_id = worker.join().expect("worker").expect("store");
    let (other, report) = open(&folder.0, &keys).expect("independent writer");
    assert_eq!(report, OpenReport::default());
    other
        .add_requested_certificate(&response)
        .expect("reload and attach");
    assert!(
        store
            .pending_requests()
            .expect("reload after attachment")
            .is_empty()
    );
    assert!(matches!(
        store.abandon_request(&request_id),
        Err(StoreError::NotFound)
    ));
    assert_eq!(store.certificates().expect("reload certificates").len(), 1);
}

#[test]
fn export_restores_pending_keys_and_can_attach_the_response_after_reopening() {
    use crate::export::Password;

    let source_folder = Folder::new();
    let (source, _) = Store::open(&source_folder.0, KeyBackend::Memory).expect("source");
    let attached = generated();
    source.store_request(&attached).expect("attached request");
    source
        .add_requested_certificate(&response(&attached))
        .expect("attach");
    let request = generated();
    let cert = response(&request);
    source.store_request(&request).expect("pending request");
    let pending = source.pending_requests().expect("pending");
    let password = Password::generate().expect("password");
    let bytes = source.export_part(&password).expect("export");
    drop((request, attached, source));

    let target_folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (target, _) = open(&target_folder.0, &keys).expect("target");
    target
        .store_request(&generated())
        .expect("old pending request");
    let old_names = keys.names().expect("old keys");
    let trust = Trust::with_roots(&[&corpus("../tqsl/pki/ca.pem")]).expect("CA");
    let report = target
        .restore_part(&bytes, &password, &trust)
        .expect("restore");
    assert_eq!(report.certificates, 1);
    assert_eq!(report.keys, 2);
    for old in old_names {
        assert!(!keys.exists(&old).expect("old pending key removed"));
    }
    let mut expected = pending.clone();
    let restored = target.pending_requests().expect("restored pending");
    assert_ne!(restored[0].key_name, pending[0].key_name);
    expected[0].key_name = restored[0].key_name.clone();
    assert_eq!(restored, expected);
    // Self-restore also refreshes pending credential names without deleting active keys.
    target
        .restore_part(&bytes, &password, &trust)
        .expect("self restore");
    drop(target);
    let (target, report) = open(&target_folder.0, &keys).expect("reopen");
    assert_eq!(report, OpenReport::default());
    let cert_id = target
        .add_requested_certificate(&cert)
        .expect("attach after restore");
    assert!(target.pending_requests().expect("consumed").is_empty());
    target
        .with_key(&cert_id, |key| {
            assert!(key.matches_public_key(cert.public_key_der()));
            key.sign(b"restored pending request").expect("sign")
        })
        .expect("restored private key");
}

#[test]
fn pending_export_keys_are_required_and_validated_before_destination_mutation() {
    use crate::export::{self, LOTW_PART, Password};
    use crate::store::PartError;

    let source_folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let (source, _) = open(&source_folder.0, &keys).expect("source");
    let attached = generated();
    source.store_request(&attached).expect("attached request");
    source
        .add_requested_certificate(&response(&attached))
        .expect("attach");
    let request = generated();
    source.store_request(&request).expect("request");
    let pending = source.pending_requests().expect("pending");
    let name = &pending[0].key_name;
    let password = Password::generate().expect("password");
    let original = source.part_plaintext().expect("plaintext");
    assert!(original.starts_with(b"QGT-STORE\x02"));
    let other = generated();
    keys.delete(name).expect("plant missing key");
    assert!(matches!(
        source.export_part(&password),
        Err(PartError::Store(StoreError::NotFound))
    ));
    keys.put(name, &other.private)
        .expect("plant mismatched key");
    assert!(matches!(
        source.export_part(&password),
        Err(PartError::Invalid)
    ));
    keys.delete(name).expect("remove plant");
    keys.put(name, &request.private).expect("restore key");
    source.export_part(&password).expect("export without plant");

    let target_folder = Folder::new();
    let target_keys = Arc::new(ObservedKeys::new(&target_folder.0, false, false));
    let (target, _) = open(&target_folder.0, &target_keys).expect("target");
    target
        .store_request(&generated())
        .expect("existing pending");
    let before = fs::read(target_folder.0.join("store.xml")).expect("before");
    let names = target_keys.names().expect("before keys");
    target_keys.calls.lock().expect("calls").clear();
    let trust = Trust::with_roots(&[&corpus("../tqsl/pki/ca.pem")]).expect("CA");
    let xml_end = 14 + u32::from_be_bytes(original[10..14].try_into().expect("length")) as usize;
    // Keep the earlier certificate key valid: rejecting the later pending key must still happen
    // before any of the destination's keys are staged.
    let pending_offset = xml_end
        + 4
        + u32::from_be_bytes(
            original[xml_end..xml_end + 4]
                .try_into()
                .expect("certificate key length"),
        ) as usize;
    let mut malformed = original.clone();
    malformed[pending_offset + 4] ^= 1;
    let mut wrong_key =
        Zeroizing::new(Vec::with_capacity(pending_offset + 4 + other.private.len()));
    wrong_key.extend_from_slice(&original[..pending_offset]);
    wrong_key.extend_from_slice(&(other.private.len() as u32).to_be_bytes());
    wrong_key.extend_from_slice(&other.private);
    let mut oversized = original.clone();
    oversized[pending_offset..pending_offset + 4]
        .copy_from_slice(&((MAX_KEY_LEN + 1) as u32).to_be_bytes());
    let mut legacy = original.clone();
    legacy[9] = 1;
    for invalid in [
        malformed,
        wrong_key,
        oversized,
        legacy,
        Zeroizing::new(original[..pending_offset].to_vec()),
    ] {
        let part = export::seal(LOTW_PART, &invalid, &password).expect("seal planted part");
        assert!(matches!(
            target.restore_part(&part, &password, &trust),
            Err(PartError::Invalid)
        ));
        assert_eq!(
            fs::read(target_folder.0.join("store.xml")).expect("unchanged"),
            before
        );
        assert_eq!(target_keys.names().expect("unchanged keys"), names);
        assert!(
            target_keys
                .calls
                .lock()
                .expect("no backend reads or mutations")
                .is_empty()
        );
    }
    // Pre-rename failure rolls back the newly staged pending key and preserves the old one.
    let valid = export::seal(LOTW_PART, &original, &password).expect("valid part");
    fs::create_dir(target_folder.0.join("store.xml.partial")).expect("plant write failure");
    assert!(matches!(
        target.restore_part(&valid, &password, &trust),
        Err(PartError::Store(StoreError::Io(_)))
    ));
    assert_eq!(target_keys.names().expect("rollback"), names);
    assert_eq!(
        fs::read(target_folder.0.join("store.xml")).expect("unchanged"),
        before
    );
    fs::remove_dir(target_folder.0.join("store.xml.partial")).expect("remove plant");
    target
        .fail_sync
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        target.restore_part(&valid, &password, &trust),
        Err(PartError::Store(StoreError::Durability(_)))
    ));
    assert_eq!(target.pending_requests().expect("visible").len(), 1);
    assert_eq!(
        target_keys.names().expect("both key sets retained").len(),
        3
    );
    for old in &names {
        assert!(target_keys.exists(old).expect("old key retained"));
    }
    target
        .fail_sync
        .store(false, std::sync::atomic::Ordering::Relaxed);
    target
        .restore_part(&valid, &password, &trust)
        .expect("restore without planted cases");
    let cert = response(&request);
    target
        .add_requested_certificate(&cert)
        .expect("restored pending key remains usable");
}
