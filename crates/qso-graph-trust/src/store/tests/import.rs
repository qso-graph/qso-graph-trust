// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;
use crate::import::{ImportError, MAX_IMPORT_LEN};
use crate::signing::KeyEntry;
use crate::store::{KeyBackend, PendingRequest};
use std::sync::Arc;
use std::time::Duration;
use std::time::UNIX_EPOCH;

fn file(name: &str) -> Vec<u8> {
    corpus(&format!("../tqsl/{name}"))
}
fn trust() -> Trust {
    Trust::with_roots(&[&file("pki/root.pem")]).expect("test root")
}
fn key() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let entry = KeyEntry::read_key_file(&file("1024/tqsl/keys/QG0TEST"))
        .expect("key")
        .remove(0);
    (
        entry.pkcs8_der(None).expect("DER"),
        entry.public_key_der().expect("SPKI"),
    )
}
use zeroize::Zeroizing;

#[test]
fn tq6_attaches_a_matching_pending_request_and_otherwise_loads_keyless() {
    for pending in [false, true] {
        let folder = Folder::new();
        let keys = Arc::new(ObservedKeys::new(&folder.0, false, false));
        let (store, _) = open(&folder.0, &keys).expect("store");
        if pending {
            // Plant the actual corpus key as a pending request, as if its CSR had been sent.
            let (der, public_key_der) = key();
            let name = keys::new_name("key:").expect("name");
            store.keys.put(&name, &der).expect("put");
            let mut data = store.read().expect("read");
            data.pending_requests.push(PendingRequest {
                id: keys::new_name("request:").expect("name"),
                callsign: "QG0TEST".into(),
                dxcc: 291,
                public_key_der,
                created_at: 1,
                key_name: name,
            });
            store
                .replace(&format::write(&data).expect("XML"))
                .expect("save");
        }
        let result = store
            .import_tq6(&file("1024/QG0TEST.tq6"), &trust())
            .expect("import");
        assert_eq!(result.len(), 1);
        assert_eq!(
            (result[0].has_key, result[0].attached_request),
            (pending, pending)
        );
        assert!(store.pending_requests().expect("list").is_empty());
        if pending {
            assert!(
                !store
                    .with_key(&result[0].id, |k| k.sign(b"test"))
                    .expect("stored signer")
                    .expect("signature")
                    .is_empty()
            );
        }
    }
}

#[test]
fn tq6_never_trusts_its_own_roots_and_validates_the_entire_file_before_storing() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    assert!(matches!(
        store.import_tq6(&file("1024/QG0TEST.tq6"), &Trust::lotw()),
        Err(ImportError::Certificate(_))
    ));
    assert!(store.certificates().expect("list").is_empty());
    let plain = crate::gzip::decompress(&file("1024/QG0TEST.tq6"), MAX_IMPORT_LEN).expect("XML");
    let text = String::from_utf8(plain.to_vec()).expect("text");
    let bad_cert = String::from_utf8(
        crate::gzip::decompress(&corpus("certs/W4W.tq6"), MAX_IMPORT_LEN)
            .expect("XML")
            .to_vec(),
    )
    .expect("text");
    // A valid first certificate followed by an untrusted one must leave no partial import.
    let start = bad_cert.find("-----BEGIN CERTIFICATE-----").expect("PEM");
    let end = bad_cert[start..]
        .find("-----END CERTIFICATE-----")
        .expect("PEM")
        + start
        + 25;
    let text = text.replace(
        "</tqslcerts>",
        &format!("<usercert>{}</usercert></tqslcerts>", &bad_cert[start..end]),
    );
    assert!(store.import_tq6(text.as_bytes(), &trust()).is_err());
    assert!(store.certificates().expect("list").is_empty());
}

#[test]
fn default_pkcs12_imports_for_both_corpus_key_password_cases_and_signs() {
    for case in ["1024", "1024-password"] {
        let folder = Folder::new();
        let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
        let imported = store
            .import_pkcs12(&file(&format!("{case}/QG0TEST.p12")), b"qgt-test", &trust())
            .expect("import");
        assert!(imported.has_key);
        assert!(!imported.attached_request);
        let expected = KeyEntry::read_key_file(&file(&format!("{case}/tqsl/keys/QG0TEST")))
            .expect("key")
            .remove(0)
            .unlock(Some(&file(&format!("{case}/key-password"))))
            .expect("unlock")
            .sign(b"test")
            .expect("signature");
        let signature = store
            .with_key(&imported.id, |key| key.sign(b"test"))
            .expect("signer")
            .expect("signature");
        assert_eq!(signature, expected);
        let xml = std::fs::read_to_string(folder.0.join("store.xml")).expect("XML");
        assert!(!xml.contains("qgt-test") && !xml.contains("PRIVATE KEY"));
    }
}

#[test]
fn wrong_password_tampering_and_rc2_are_refused_without_storage() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let bytes = file("1024/QG0TEST.p12");
    assert!(matches!(
        store.import_pkcs12(&bytes, b"wrong", &trust()),
        Err(ImportError::Authentication)
    ));
    let mut flipped = bytes;
    flipped[500] ^= 1;
    assert!(matches!(
        store.import_pkcs12(&flipped, b"qgt-test", &trust()),
        Err(ImportError::Authentication)
    ));
    assert!(matches!(
        store.import_pkcs12(&file("1024/QG0TEST-weak.p12"), b"qgt-test", &trust()),
        Err(ImportError::UnsupportedProtection)
    ));
    assert!(matches!(
        store.import_pkcs12(&file("1024/QG0TEST-weak.p12"), b"wrong", &trust()),
        Err(ImportError::Authentication)
    ));
    assert!(store.certificates().expect("list").is_empty());
    assert!(store.keys.names().expect("keys").is_empty());
}

#[test]
fn expiry_uses_validity_end_utc_dates_and_a_strict_threshold() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    store
        .import_tq6(&file("1024/QG0TEST.tq6"), &trust())
        .expect("import");
    let cert = store.certificates().expect("list").remove(0);
    let end = cert.certificate.validity().1;
    let day = Duration::from_secs(86_400);
    for days in [61, 60] {
        assert!(
            store
                .expiring_certificates(end - day * days, 60)
                .expect("expiry")
                .is_empty()
        );
    }
    let warning = store
        .expiring_certificates(end - day * 59, 60)
        .expect("expiry")
        .remove(0);
    assert_eq!(warning.days_left, 59);
    assert!(!warning.expired);
    assert_eq!(warning.expires_at, end);
    assert_eq!(warning.id, cert.id);
    // QSO end is 2099 but X.509 validity ends in 2126: QSO end never warns.
    assert!(
        store
            .expiring_certificates(UNIX_EPOCH + Duration::from_secs(4_102_444_800), 60)
            .expect("expiry")
            .is_empty()
    );
    let on = store
        .expiring_certificates(end, 60)
        .expect("expiry")
        .remove(0);
    assert_eq!(on.days_left, 0);
    assert!(!on.expired);
    assert!(
        store
            .expiring_certificates(end, 0)
            .expect("expiry")
            .is_empty()
    );
    let after = store
        .expiring_certificates(end + day, 0)
        .expect("expiry")
        .remove(0);
    assert_eq!(after.days_left, -1);
    assert!(after.expired);
}

#[test]
fn tq6_bounds_and_nesting_are_refused() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    assert!(matches!(
        store.import_tq6(&vec![0; MAX_IMPORT_LEN + 1], &trust()),
        Err(ImportError::Limit)
    ));
    assert!(
        store
            .import_tq6("<x>".repeat(20).as_bytes(), &trust())
            .is_err()
    );
    let bytes = file("1024/QG0TEST.tq6");
    assert!(
        store
            .import_tq6(&bytes[..bytes.len() - 1], &trust())
            .is_err()
    );
    assert!(store.certificates().expect("list").is_empty());
}

#[test]
fn a_missing_pending_key_does_not_downgrade_to_a_keyless_import() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("store");
    let (_, public_key_der) = key();
    let name = keys::new_name("key:").expect("name");
    let mut data = store.read().expect("read");
    data.pending_requests.push(PendingRequest {
        id: keys::new_name("request:").expect("name"),
        callsign: "QG0TEST".into(),
        dxcc: 291,
        public_key_der,
        created_at: 1,
        key_name: name,
    });
    store
        .replace(&format::write(&data).expect("XML"))
        .expect("save");
    let before = std::fs::read(folder.0.join("store.xml")).expect("before");
    assert!(matches!(
        store.import_tq6(&file("1024/QG0TEST.tq6"), &trust()),
        Err(ImportError::Store(StoreError::NotFound))
    ));
    assert_eq!(
        std::fs::read(folder.0.join("store.xml")).expect("after"),
        before
    );
    // With a different DXCC it is not this certificate's request: keyless import succeeds and
    // preserves the unrelated pending record. Matching uses all three identity fields.
    data.pending_requests[0].dxcc = 1;
    store
        .replace(&format::write(&data).expect("XML"))
        .expect("save");
    let report = store
        .import_tq6(&file("1024/QG0TEST.tq6"), &trust())
        .expect("keyless");
    assert!(!report[0].has_key);
    assert_eq!(store.pending_requests().expect("pending").len(), 1);
}

#[test]
fn an_unused_untrusted_tq6_root_is_rejected_and_a_bounded_bundle_loads_whole() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("store");
    let plain = crate::gzip::decompress(&file("1024/QG0TEST.tq6"), MAX_IMPORT_LEN).expect("XML");
    let plain = String::from_utf8(plain.to_vec()).expect("text");
    let root = String::from_utf8(corpus("pki/root.pem")).expect("root PEM");
    let with_root = plain.replace(
        "</tqslcerts>",
        &format!("<rootcert>{root}</rootcert></tqslcerts>"),
    );
    assert!(matches!(
        store.import_tq6(with_root.as_bytes(), &trust()),
        Err(ImportError::Certificate(_))
    ));
    assert!(store.certificates().expect("list").is_empty());
    // Count includes all supplied authorities, even duplicates. The actual certificate still
    // chains, so the only refusal one item beyond the bound is the item limit.
    let ca = String::from_utf8(file("pki/ca.pem")).expect("PEM");
    let additions = format!("<cacert>{ca}</cacert>").repeat(crate::import::MAX_IMPORT_ITEMS - 3);
    let at_limit = plain.replace("</tqslcerts>", &format!("{additions}</tqslcerts>"));
    let too_many = at_limit.replace(
        "</tqslcerts>",
        &format!("<cacert>{ca}</cacert></tqslcerts>"),
    );
    assert!(matches!(
        store.import_tq6(too_many.as_bytes(), &trust()),
        Err(ImportError::Limit)
    ));
    assert!(store.certificates().expect("list").is_empty());
    store
        .import_tq6(at_limit.as_bytes(), &trust())
        .expect("at limit");
    assert_eq!(store.certificates().expect("list").len(), 1);
}
