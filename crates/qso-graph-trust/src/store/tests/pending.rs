// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;
use crate::import::ImportError;
use crate::signing::KeyError;

fn trust() -> Trust {
    Trust::with_roots(&[&corpus("pki/root.pem")]).expect("test root")
}
fn tqsl(name: &str) -> Vec<u8> {
    corpus(&format!("../tqsl/{name}"))
}
fn p12_password() -> Vec<u8> {
    corpus("../pki/p12-password")
}
type Snapshot = (Option<Vec<u8>>, Vec<(String, Zeroizing<Vec<u8>>)>);

fn snapshot(store: &Store) -> Snapshot {
    let file = match fs::read(store.dir.join("store.xml")) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => panic!("store file: {e}"),
    };
    let mut names = store.keys.names().expect("names");
    names.sort();
    (
        file,
        names
            .into_iter()
            .map(|name| {
                let der = store.keys.get(&name).expect("key").expect("present");
                (name, der)
            })
            .collect(),
    )
}
fn unlock_backup(pending: &mut PendingImport) {
    for index in 0..pending.preview().certificates.len() {
        let entry = &pending.preview().certificates[index];
        if entry.needs_password {
            let password = corpus(&format!("keys/{}.password", entry.callsign));
            pending
                .unlock_key(index, &password)
                .expect("right key password");
        }
    }
}

#[test]
fn inspection_and_cancellation_leave_public_bytes_and_all_credentials_identical() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    for populated in [false, true] {
        if populated {
            let mut pending = store
                .inspect_tbk(&corpus("standard.tbk"), &trust())
                .expect("inspect");
            unlock_backup(&mut pending);
            store
                .commit(
                    pending,
                    ImportChoices {
                        store_locations: true,
                        ..Default::default()
                    },
                )
                .expect("commit");
        }
        let before = snapshot(&store);
        let pending = store
            .inspect_tq6(&corpus("certs/KN4YU.tq6"), &trust())
            .expect("tq6");
        assert!(
            snapshot(&store) == before,
            "store bytes or credentials changed"
        );
        drop(pending);
        let pending = store
            .inspect_pkcs12(
                &tqsl("1024-password/QG0TEST.p12"),
                &p12_password(),
                &Trust::with_roots(&[&tqsl("pki/root.pem")]).expect("root"),
            )
            .expect("p12");
        assert!(
            snapshot(&store) == before,
            "store bytes or credentials changed"
        );
        drop(pending);
        let mut pending = store
            .inspect_tbk(&corpus("standard.tbk"), &trust())
            .expect("tbk");
        unlock_backup(&mut pending);
        assert!(
            snapshot(&store) == before,
            "store bytes or credentials changed"
        );
        drop(pending);
        assert!(
            snapshot(&store) == before,
            "store bytes or credentials changed"
        );
    }
}

#[test]
fn backup_commit_matches_preview_and_returns_locations_for_desktop_to_place() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let mut pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("inspect");
    let preview = pending.preview();
    assert_eq!(preview.certificates.len(), 3);
    assert!(
        preview
            .certificates
            .iter()
            .all(|c| c.disposition == ImportDisposition::New
                && c.file_has_key
                && !c.key_present
                && !c.serial.is_empty()
                && c.qso_dates.is_some()
                && c.validity.is_some())
    );
    assert_eq!(
        preview
            .certificates
            .iter()
            .filter(|c| c.needs_password)
            .count(),
        2
    );
    let identities: Vec<_> = preview
        .certificates
        .iter()
        .map(|c| {
            (
                c.callsign.clone(),
                c.dxcc,
                c.serial.clone(),
                c.qso_dates,
                c.validity,
            )
        })
        .collect();
    let signed = preview.signed_qsos;
    let locations: Vec<_> = preview
        .locations
        .iter()
        .map(|l| (l.name.clone(), l.station.clone()))
        .collect();
    unlock_backup(&mut pending);
    let report = store
        .commit(pending, ImportChoices::default())
        .expect("commit");
    let actual: Vec<_> = store
        .certificates()
        .expect("certs")
        .iter()
        .map(|c| {
            (
                c.certificate.callsign().to_string(),
                c.certificate.dxcc(),
                c.certificate.serial_number().to_vec(),
                Some(c.certificate.qso_dates()),
                Some(c.certificate.validity()),
            )
        })
        .collect();
    assert_eq!(actual, identities);
    assert!(
        report
            .certificates
            .iter()
            .all(|c| c.has_key && !c.already_here)
    );
    assert_eq!(report.signed_qsos_added, signed);
    assert_eq!(
        report
            .locations
            .iter()
            .map(|l| (l.name.clone(), l.station.clone()))
            .collect::<Vec<_>>(),
        locations
    );
    assert_eq!(report.locations_added, 0);
    assert!(store.locations().expect("locations").is_empty());
    for c in &report.certificates {
        store
            .with_key(&c.id, |k| k.sign(b"preview"))
            .expect("key")
            .expect("sign");
    }
    let pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("again");
    assert!(
        pending
            .preview()
            .certificates
            .iter()
            .all(|c| c.disposition == ImportDisposition::Present && c.key_present)
    );
}

#[test]
fn changing_or_deleting_the_source_after_inspection_cannot_change_commit() {
    for delete in [false, true] {
        let folder = Folder::new();
        let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
        let path = folder.0.join("input.p12");
        fs::write(&path, tqsl("1024-password/QG0TEST.p12")).expect("source");
        let bytes = fs::read(&path).expect("read");
        let trust = Trust::with_roots(&[&tqsl("pki/root.pem")]).expect("root");
        let pending = store
            .inspect_pkcs12(&bytes, &p12_password(), &trust)
            .expect("inspect");
        drop(bytes);
        let expected = pending.preview().certificates[0].clone();
        if delete {
            fs::remove_file(path).expect("delete source");
        } else {
            fs::write(path, b"planted different input").expect("change source");
        }
        let report = store
            .commit(pending, ImportChoices::default())
            .expect("same inspected data");
        let actual = store.certificates().expect("certs");
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].certificate.callsign(), expected.callsign);
        assert_eq!(actual[0].certificate.serial_number(), expected.serial);
        store
            .with_key(&report.certificates[0].id, |k| k.sign(b"same key"))
            .expect("key")
            .expect("sign");
    }
}

#[test]
fn certificate_addition_and_deletion_between_inspect_and_commit_refuse_every_write() {
    for delete in [false, true] {
        let folder = Folder::new();
        let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
        let existing = if delete {
            Some(
                store
                    .add_certificate(backup().certificates[0].certificate.as_ref().expect("cert"))
                    .expect("existing"),
            )
        } else {
            None
        };
        let pending = store
            .inspect_pkcs12(
                &tqsl("1024/QG0TEST.p12"),
                &p12_password(),
                &Trust::with_roots(&[&tqsl("pki/root.pem")]).expect("root"),
            )
            .expect("inspect");
        if let Some(id) = existing {
            store.delete_certificate(&id).expect("plant deletion");
        } else {
            store
                .add_certificate(backup().certificates[0].certificate.as_ref().expect("cert"))
                .expect("plant addition");
        }
        let before = snapshot(&store);
        assert!(matches!(
            store.commit(pending, ImportChoices::default()),
            Err(ImportError::Conflict)
        ));
        assert!(
            snapshot(&store) == before,
            "store bytes or credentials changed"
        );
        // Remove the conflict by inspecting the current store; the same import now succeeds.
        let pending = store
            .inspect_pkcs12(
                &tqsl("1024/QG0TEST.p12"),
                &p12_password(),
                &Trust::with_roots(&[&tqsl("pki/root.pem")]).expect("root"),
            )
            .expect("inspect again");
        store
            .commit(pending, ImportChoices::default())
            .expect("no conflict");
    }
}

#[test]
fn each_backup_key_requires_its_own_password_and_one_wrong_key_blocks_the_whole_commit() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let before = snapshot(&store);
    let mut pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("inspect");
    let protected: Vec<_> = pending
        .preview()
        .certificates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.needs_password)
        .map(|(i, c)| (i, c.callsign.clone(), c.serial.clone()))
        .collect();
    assert_eq!(protected.len(), 2);
    let first = corpus(&format!("keys/{}.password", protected[0].1));
    let second = corpus(&format!("keys/{}.password", protected[1].1));
    assert_ne!(first, second);
    pending
        .unlock_key(protected[0].0, &first)
        .expect("first right");
    assert!(
        matches!(pending.unlock_key(protected[1].0, &first), Err(ImportError::KeyAt { index, error: KeyError::WrongPassword }) if index == protected[1].0)
    );
    assert!(pending.preview().certificates[protected[1].0].needs_password);
    assert!(
        snapshot(&store) == before,
        "store bytes or credentials changed"
    );
    assert!(
        matches!(store.commit(pending, ImportChoices { store_locations: true, ..Default::default() }), Err(ImportError::KeyAt { index, error: KeyError::PasswordNeeded }) if index == protected[1].0)
    );
    assert!(
        snapshot(&store) == before,
        "store bytes or credentials changed"
    );
    let mut pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("inspect again");
    pending.unlock_key(protected[0].0, &first).expect("first");
    pending
        .unlock_key(protected[1].0, &second)
        .expect("second right");
    store
        .commit(
            pending,
            ImportChoices {
                store_locations: true,
                ..Default::default()
            },
        )
        .expect("all checked");
    assert_eq!(store.certificates().expect("certs").len(), 3);
    assert_eq!(store.locations().expect("locations").len(), 7);
}

#[test]
fn a_new_root_requires_its_explicit_fingerprint_at_commit_for_every_format() {
    for kind in ["tq6", "p12", "tbk"] {
        for accept in [None, Some("wrong"), Some("right")] {
            let folder = Folder::new();
            let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
            let mut pending = match kind {
                "tq6" => store.inspect_tq6(&tqsl("1024/QG0TEST.tq6"), &Trust::lotw()),
                "p12" => {
                    store.inspect_pkcs12(&tqsl("1024/QG0TEST.p12"), &p12_password(), &Trust::lotw())
                }
                _ => store.inspect_tbk(&corpus("standard.tbk"), &Trust::lotw()),
            }
            .expect("inspect without trusting root");
            if kind == "tbk" {
                unlock_backup(&mut pending);
            }
            assert_eq!(pending.preview().roots.len(), 1);
            let fingerprint = pending.preview().roots[0]
                .fingerprint
                .replace(':', "")
                .to_ascii_lowercase();
            let accepted: Vec<&str> = match accept {
                None => vec![],
                Some("wrong") => vec!["not a fingerprint"],
                _ => vec![&fingerprint],
            };
            let before = snapshot(&store);
            let result = store.commit(
                pending,
                ImportChoices {
                    accept_roots: &accepted,
                    ..Default::default()
                },
            );
            match accept {
                None => {
                    assert!(matches!(result, Err(ImportError::UntrustedRoot { .. })));
                    assert!(
                        snapshot(&store) == before,
                        "store bytes or credentials changed"
                    );
                }
                Some("wrong") => {
                    assert!(matches!(result, Err(ImportError::RootMismatch { .. })));
                    assert!(
                        snapshot(&store) == before,
                        "store bytes or credentials changed"
                    );
                }
                _ => {
                    let report = result.expect("explicit acceptance");
                    assert_eq!(report.roots.len(), 1);
                    assert!(!report.certificates.is_empty());
                }
            }
        }
    }
}

#[test]
fn an_untrusted_certificate_is_previewed_with_its_refusal_reason() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    // Plant the wrong trust with no root in the input, then restore the intended test trust.
    for right_trust in [false, true] {
        let trust = if right_trust {
            Trust::with_roots(&[&corpus("../roots/new-ca.pem")]).expect("test issuer")
        } else {
            Trust::lotw()
        };
        let input = format!(
            "<tqsldata><tqslcerts><usercert>{}</usercert></tqslcerts></tqsldata>",
            String::from_utf8(corpus("../roots/user-a.pem")).expect("test PEM")
        );
        let pending = store
            .inspect_tq6(input.as_bytes(), &trust)
            .expect("public preview");
        let before = snapshot(&store);
        if !right_trust {
            assert!(pending.preview().roots.is_empty());
            assert!(
                matches!(&pending.preview().certificates[0].disposition, ImportDisposition::Refused { reason } if !reason.is_empty())
            );
            assert!(matches!(
                store.commit(pending, ImportChoices::default()),
                Err(ImportError::Refused {
                    index: 0,
                    reason: crate::import::ImportRefusal::Certificate
                })
            ));
            assert!(
                snapshot(&store) == before,
                "store bytes or credentials changed"
            );
        } else {
            assert_eq!(
                pending.preview().certificates[0].disposition,
                ImportDisposition::New
            );
            store
                .commit(pending, ImportChoices::default())
                .expect("valid chain");
        }
    }
}

#[test]
fn publication_failure_rolls_back_every_staged_key_and_public_section() {
    for fail in [true, false] {
        let folder = Folder::new();
        // A directory planted at the temporary file's path refuses publication after key staging.
        let keys = Arc::new(ObservedKeys::new(&folder.0, false, false));
        let (store, _) = open(&folder.0, &keys).expect("open");
        let mut pending = store
            .inspect_tbk(&corpus("standard.tbk"), &trust())
            .expect("inspect");
        unlock_backup(&mut pending);
        let before = snapshot(&store);
        if fail {
            fs::create_dir(folder.0.join("store.xml.partial")).expect("plant publication failure");
        }
        let result = store.commit(
            pending,
            ImportChoices {
                store_locations: true,
                ..Default::default()
            },
        );
        if fail {
            assert!(result.is_err());
            assert!(
                snapshot(&store) == before,
                "store bytes or credentials changed"
            );
        } else {
            assert!(result.is_ok());
            assert_eq!(store.keys.names().expect("keys").len(), 3);
        }
    }
}

#[test]
fn missing_credentials_and_committing_to_another_store_are_conflicts() {
    let folder = Folder::new();
    let other_folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let (other, _) = Store::open(&other_folder.0, KeyBackend::Memory).expect("other");
    let mut pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("inspect");
    unlock_backup(&mut pending);
    store
        .commit(pending, ImportChoices::default())
        .expect("populate");
    let mut pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("inspect");
    unlock_backup(&mut pending);
    let before = snapshot(&other);
    assert!(matches!(
        other.commit(pending, ImportChoices::default()),
        Err(ImportError::Conflict)
    ));
    assert!(snapshot(&other) == before, "wrong store changed");
    let mut pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("inspect");
    unlock_backup(&mut pending);
    let name = store.certificates().expect("certs")[0]
        .key_name
        .clone()
        .expect("key name");
    let der = store.keys.get(&name).expect("key").expect("present");
    store.keys.delete(&name).expect("plant missing credential");
    let before = snapshot(&store);
    assert!(matches!(
        store.commit(pending, ImportChoices::default()),
        Err(ImportError::Conflict)
    ));
    assert!(
        snapshot(&store) == before,
        "missing credential caused writes"
    );
    store.keys.put(&name, &der).expect("remove planted fault");
    let mut pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("inspect again");
    unlock_backup(&mut pending);
    store
        .commit(pending, ImportChoices::default())
        .expect("no conflict");
}

#[test]
fn oversized_key_password_is_refused_before_unlock_and_can_be_corrected() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let mut pending = store
        .inspect_tbk(&corpus("standard.tbk"), &trust())
        .expect("inspect");
    let index = pending
        .preview()
        .certificates
        .iter()
        .position(|c| c.needs_password)
        .expect("protected key");
    let password: Vec<u8> = p12_password()
        .into_iter()
        .cycle()
        .take(crate::import::MAX_PASSWORD_LEN + 1)
        .collect();
    assert!(matches!(
        pending.unlock_key(index, &password),
        Err(ImportError::Limit)
    ));
    assert!(pending.preview().certificates[index].needs_password);
    unlock_backup(&mut pending);
    store
        .commit(pending, ImportChoices::default())
        .expect("corrected passwords");
}

struct FailSecondKey {
    inner: MemoryKeyStore,
    puts: std::sync::atomic::AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}
impl KeyStore for FailSecondKey {
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError> {
        if self.puts.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 1
            && self.fail.load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(KeyStoreError::AccessDenied);
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

#[test]
fn failure_staging_the_second_key_rolls_back_the_first_without_publication() {
    let folder = Folder::new();
    let keys = Arc::new(FailSecondKey {
        inner: MemoryKeyStore::new(),
        puts: std::sync::atomic::AtomicUsize::new(0),
        fail: std::sync::atomic::AtomicBool::new(true),
    });
    let (store, _) = open(&folder.0, &keys).expect("open");
    for fail in [true, false] {
        let mut pending = store
            .inspect_tbk(&corpus("standard.tbk"), &trust())
            .expect("inspect");
        unlock_backup(&mut pending);
        let before = snapshot(&store);
        let result = store.commit(
            pending,
            ImportChoices {
                store_locations: true,
                ..Default::default()
            },
        );
        if fail {
            assert!(matches!(
                result,
                Err(ImportError::Store(StoreError::KeyStore(
                    KeyStoreError::AccessDenied
                )))
            ));
            assert!(snapshot(&store) == before, "partial key staging survived");
            keys.fail.store(false, std::sync::atomic::Ordering::Relaxed);
        } else {
            assert!(result.is_ok());
            assert_eq!(store.keys.names().expect("keys").len(), 3);
        }
    }
}

#[test]
fn an_already_present_p12_still_checks_root_choices_and_performs_no_write() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let trust = Trust::with_roots(&[&tqsl("pki/root.pem")]).expect("test root");
    store
        .import_pkcs12(&tqsl("1024/QG0TEST.p12"), &p12_password(), &trust, None)
        .expect("first import");
    let before = snapshot(&store);
    let pending = store
        .inspect_pkcs12(&tqsl("1024/QG0TEST.p12"), &p12_password(), &trust)
        .expect("inspect");
    assert!(matches!(
        store.commit(
            pending,
            ImportChoices {
                accept_roots: &["not a fingerprint"],
                ..Default::default()
            }
        ),
        Err(ImportError::RootMismatch { .. })
    ));
    assert!(
        snapshot(&store) == before,
        "invalid root choice changed the store"
    );
    // A planted publication failure proves a present-only commit never attempts replacement.
    fs::create_dir(folder.0.join("store.xml.partial")).expect("plant failed publication");
    assert!(matches!(
        store.import_pkcs12(&tqsl("1024/QG0TEST.p12"), &p12_password(), &trust, None),
        Err(ImportError::Store(StoreError::AlreadyExists))
    ));
    assert!(
        snapshot(&store) == before,
        "duplicate import changed the store"
    );
}

#[test]
fn refusal_previews_do_not_expose_an_issuer_email() {
    use x509_cert::der::{Decode, Encode, EncodePem, pem::LineEnding};
    let backup = backup();
    let issuer = backup
        .roots
        .iter()
        .filter_map(|der| x509_cert::Certificate::from_der(der).ok())
        .find(|c| c.tbs_certificate.subject.to_string().contains('@'))
        .expect("corpus authority with email");
    let mut leaf = x509_cert::Certificate::from_der(
        backup.certificates[0]
            .certificate
            .as_ref()
            .expect("cert")
            .der(),
    )
    .expect("leaf");
    // Plant an email-bearing issuer in the certificate, whose signature now cannot verify.
    leaf.tbs_certificate.issuer = issuer.tbs_certificate.subject;
    let cert = Certificate::from_pem_or_der(&leaf.to_der().expect("DER")).expect("LoTW fields");
    assert!(
        cert.verify(&Trust::lotw(), &[])
            .expect_err("bad issuer")
            .to_string()
            .contains('@')
    );
    let bytes = format!(
        "<tqsldata><tqslcerts><usercert>{}</usercert></tqslcerts></tqsldata>",
        leaf.to_pem(LineEnding::LF).expect("PEM")
    );
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let pending = store
        .inspect_tq6(bytes.as_bytes(), &Trust::lotw())
        .expect("preview");
    assert!(matches!(
        pending.preview().certificates[0].disposition,
        ImportDisposition::Refused { .. }
    ));
    assert!(
        !format!("{:?}", pending.preview()).contains('@'),
        "issuer email leaked into preview"
    );
    let before = snapshot(&store);
    let p12 = crate::pkcs12::tests::with_certificate_issuer(leaf.tbs_certificate.issuer);
    let p12_pending = store
        .inspect_pkcs12(&p12, &p12_password(), &Trust::lotw())
        .expect("authenticated preview");
    for error in [
        store
            .commit(pending, ImportChoices::default())
            .expect_err("refused"),
        store
            .import_tq6(bytes.as_bytes(), &Trust::lotw(), None)
            .expect_err("refused wrapper"),
        store
            .commit(p12_pending, ImportChoices::default())
            .expect_err("refused p12"),
        store
            .import_pkcs12(&p12, &p12_password(), &Trust::lotw(), None)
            .expect_err("refused p12 wrapper"),
    ] {
        // Exact representations exclude all certificate details, including nested public fields.
        assert!(
            error.to_string()
                == "import entry 0: the certificate does not chain to a trusted LoTW root",
            "commit error was not redacted"
        );
        assert!(
            format!("{error:?}") == "Refused { index: 0, reason: Certificate }",
            "nested error was not redacted"
        );
        assert!(std::error::Error::source(&error).is_none());
        assert!(
            snapshot(&store) == before,
            "store bytes or credentials changed"
        );
    }
    // The normal corpus certificate, without that planted issuer, is accepted under test trust.
    let pending = store
        .inspect_tq6(&corpus("certs/KC4QPQ.tq6"), &trust())
        .expect("normal certificate");
    assert_eq!(
        pending.preview().certificates[0].disposition,
        ImportDisposition::New
    );
}

#[test]
fn a_changed_request_key_cannot_be_attached_even_with_the_same_public_snapshot() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let key = crate::signing::KeyEntry::read_key_file(&tqsl("1024/tqsl/keys/QG0TEST"))
        .expect("key")
        .remove(0);
    let der = key.pkcs8_der(None).expect("DER");
    let name = keys::new_name("key:").expect("name");
    store.keys.put(&name, &der).expect("request credential");
    let mut data = store.read().expect("data");
    data.pending_requests.push(PendingRequest {
        id: keys::new_name("request:").expect("ID"),
        callsign: "QG0TEST".into(),
        dxcc: 291,
        public_key_der: key.public_key_der().expect("SPKI"),
        created_at: 1,
        key_name: name.clone(),
    });
    store
        .replace(&format::write(&data).expect("XML"))
        .expect("request");
    let trust = Trust::with_roots(&[&tqsl("pki/root.pem")]).expect("test root");
    let pending = store
        .inspect_tq6(&tqsl("1024/QG0TEST.tq6"), &trust)
        .expect("inspect");
    assert!(pending.preview().certificates[0].key_present);
    let wrong = backup()
        .certificates
        .into_iter()
        .filter_map(|c| c.key)
        .find(|k| !k.is_encrypted())
        .expect("other unprotected test key")
        .pkcs8_der(None)
        .expect("wrong DER");
    store.keys.delete(&name).expect("remove original");
    store
        .keys
        .put(&name, &wrong)
        .expect("plant changed credential");
    let before = snapshot(&store);
    assert!(matches!(
        store.commit(pending, ImportChoices::default()),
        Err(ImportError::Conflict)
    ));
    assert!(
        snapshot(&store) == before,
        "changed request key caused writes"
    );
    store.keys.delete(&name).expect("remove planted credential");
    store.keys.put(&name, &der).expect("restore original");
    let pending = store
        .inspect_tq6(&tqsl("1024/QG0TEST.tq6"), &trust)
        .expect("inspect again");
    let report = store
        .commit(pending, ImportChoices::default())
        .expect("attach checked request");
    assert!(report.certificates[0].attached_request);
    assert!(store.pending_requests().expect("requests").is_empty());
}

#[test]
fn commit_waits_for_the_store_lock() {
    // Exercise delayed startup, including a delay beyond the former five-second deadline.
    for delay in [Duration::from_millis(150), Duration::from_secs(6)] {
        let folder = Folder::new();
        let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
        let pending = store
            .inspect_tq6(&corpus("certs/KC4QPQ.tq6"), &trust())
            .expect("inspect");
        let lock = store.lock().expect("plant held lock");
        let (send, receive) = mpsc::channel();
        let (events, observed) = mpsc::channel();
        *store.lock_observer.lock().expect("observer") = Some(events.clone());
        let store_ref = &store;
        std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(delay);
                let result = store_ref.commit(pending, ImportChoices::default());
                // A missing lock sends completion first, regardless of the worker's startup delay.
                events.send(false).expect("completion observed");
                send.send(result).expect("send");
            });
            // Watchdogs diagnose hangs; event ordering and WouldBlock establish the invariant.
            assert!(
                observed
                    .recv_timeout(Duration::from_secs(120))
                    .expect("lock attempt or completion"),
                "commit completed without a blocked lock acquisition"
            );
            assert!(matches!(receive.try_recv(), Err(mpsc::TryRecvError::Empty)));
            assert!(!store.dir.join("store.xml").exists());
            drop(lock);
            receive
                .recv_timeout(Duration::from_secs(120))
                .expect("lock released")
                .expect("committed");
        });
    }
}

#[test]
fn the_owned_pending_value_spans_ui_commands_and_keeps_its_store_identity() {
    fn owned<T: Send + Sync + 'static>(_: &T) {}
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let pending = store
        .inspect_tq6(&corpus("certs/KC4QPQ.tq6"), &trust())
        .expect("inspect");
    owned(&pending);
    // The owned value can be retained in application state while the Store itself moves.
    let moved_store = store;
    moved_store
        .commit(pending, ImportChoices::default())
        .expect("same instance after move");
    let pending = moved_store
        .inspect_tq6(&corpus("certs/KN4YU.tq6"), &trust())
        .expect("another preview");
    drop(moved_store);
    let (reopened, _) = Store::open(&folder.0, KeyBackend::Memory).expect("reopen");
    let before = snapshot(&reopened);
    assert!(matches!(
        reopened.commit(pending, ImportChoices::default()),
        Err(ImportError::Conflict)
    ));
    assert!(
        snapshot(&reopened) == before,
        "reopened store committed a different instance's plan"
    );
    let pending = reopened
        .inspect_tq6(&corpus("certs/KN4YU.tq6"), &trust())
        .expect("inspect again");
    reopened
        .commit(pending, ImportChoices::default())
        .expect("fresh instance's plan");
}
