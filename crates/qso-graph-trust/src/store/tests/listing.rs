// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The read-only listing: it writes nothing, never asks a credential store, and refuses what the
//! store refuses.

use super::*;
use crate::store::{KeyBackend, ListedCertificate, Listing};

fn names(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(dir)
        .expect("folder")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    found
}

#[test]
fn a_missing_folder_is_an_empty_listing_and_stays_missing() {
    let folder = Folder::new();
    let missing = folder.0.join("not-there").join("deeper");
    let listing = Listing::read(&missing).expect("empty");
    assert!(listing.certificates().is_empty());
    assert_eq!(
        listing.trusted_roots(),
        Store::open(&folder.0, KeyBackend::Memory)
            .expect("store")
            .0
            .trusted_roots()
            .expect("roots")
    );
    assert!(!missing.exists());
    assert!(!folder.0.join("not-there").exists());
}

#[test]
fn an_existing_empty_folder_gains_nothing() {
    let folder = Folder::new();
    let before = fs::metadata(&folder.0).expect("meta");
    assert!(
        Listing::read(&folder.0)
            .expect("empty")
            .certificates()
            .is_empty()
    );
    assert!(names(&folder.0).is_empty());
    assert_eq!(
        before.modified().expect("time"),
        fs::metadata(&folder.0)
            .expect("meta")
            .modified()
            .expect("time")
    );
}

#[test]
fn a_populated_folder_is_left_byte_for_byte_as_it_was() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    store
        .add_certificate_with_key(&backup().certificates[0], password(0).as_deref())
        .expect("import");
    let before = names(&folder.0);
    let text = fs::read(folder.0.join("store.xml")).expect("file");
    let stamp = fs::metadata(folder.0.join("store.xml"))
        .expect("meta")
        .modified()
        .expect("time");
    Listing::read(&folder.0).expect("listing");
    assert_eq!(names(&folder.0), before);
    assert_eq!(fs::read(folder.0.join("store.xml")).expect("file"), text);
    assert_eq!(
        fs::metadata(folder.0.join("store.xml"))
            .expect("meta")
            .modified()
            .expect("time"),
        stamp
    );
}

fn password(index: usize) -> Option<Vec<u8>> {
    let entry = &backup().certificates[index];
    let password = corpus(&format!("keys/{}.password", entry.callsign));
    (!password.is_empty()).then_some(password)
}

#[test]
fn certificates_list_with_whether_the_file_records_a_key() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let backup = backup();
    let keyed = store
        .add_certificate_with_key(&backup.certificates[0], password(0).as_deref())
        .expect("with key");
    let cert = backup.certificates[1].certificate.as_ref().expect("cert");
    let bare = store.add_certificate(cert).expect("without key");
    let full = store.certificates().expect("list");
    let listing = Listing::read(&folder.0).expect("listing");
    let got: Vec<(&str, bool)> = listing
        .certificates()
        .iter()
        .map(|c| (c.id.as_str(), c.has_key))
        .collect();
    assert_eq!(got.len(), 2);
    assert!(got.contains(&(keyed.as_str(), true)));
    assert!(got.contains(&(bare.as_str(), false)));
    for (listed, stored) in listing.certificates().iter().zip(&full) {
        assert_eq!(listed.id, stored.id);
        assert_eq!(listed.certificate.der(), stored.certificate.der());
        assert_eq!(listed.has_key, stored.key_name.is_some());
    }
}

#[test]
fn has_key_is_what_the_file_records_and_no_credential_store_is_asked() {
    let folder = Folder::new();
    let (store, _) = Store::open(&folder.0, KeyBackend::Memory).expect("open");
    let id = store
        .add_certificate_with_key(&backup().certificates[0], password(0).as_deref())
        .expect("import");
    drop(store);
    // The planted case: reopened, the full store asks its credential store and finds the key gone.
    let (_, report) = Store::open(&folder.0, KeyBackend::Memory).expect("reopen");
    assert_eq!(report.missing_keys, std::slice::from_ref(&id));
    // The listing never asks, so it still shows the key as recorded.
    let listing = Listing::read(&folder.0).expect("listing");
    assert!(listing.certificates()[0].has_key);
    // And structurally: it takes a path and nothing that reaches a credential backend, and the
    // types it returns name no credential.
    let _: fn(&Path) -> Result<Listing, StoreError> = |p| Listing::read(p);
    let ListedCertificate { id, .. } = listing.certificates()[0].clone();
    assert!(!id.is_empty());
}

#[test]
fn the_listing_source_never_names_a_credential_store() {
    // A control for the check below: a planted line must be caught.
    let touches = |src: &str| {
        ["KeyStore", "KeyBackend", "keys::", "key_name", ".keys"]
            .iter()
            .any(|word| src.contains(word))
    };
    assert!(touches("let k: Box<dyn KeyStore> = todo!();"));
    assert!(touches("store.keys.get(name)"));
    // The listing's code, without its docs and comments.
    let code: String = include_str!("../listing.rs")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| !l.contains("compile_fail"))
        .collect::<Vec<_>>()
        .join("\n");
    let code = code.replace("c.key_name.is_some()", "");
    assert!(!touches(&code), "listing.rs reaches for a credential");
}

#[test]
fn a_file_the_store_refuses_is_refused_the_same_way() {
    let folder = Folder::new();
    let text = empty_xml().replacen("qgt-store version=\"3\"", "qgt-store version=\"4\"", 1);
    fs::write(folder.0.join("store.xml"), &text).expect("plant");
    let listing = Listing::read(&folder.0).expect_err("newer");
    let store = Store::open(&folder.0, KeyBackend::Memory)
        .err()
        .expect("newer");
    assert!(matches!(
        listing,
        StoreError::NewerVersion {
            found: 4,
            supported: 3
        }
    ));
    assert_eq!(listing.to_string(), store.to_string());
    for bad in [
        "not xml".to_string(),
        empty_xml().replacen("qgt-store", "other", 2),
        String::from_utf8_lossy(&[0xff, 0xfe]).into_owned(),
    ] {
        fs::write(folder.0.join("store.xml"), bad).expect("plant");
        let listing = Listing::read(&folder.0).expect_err("invalid");
        let store = Store::open(&folder.0, KeyBackend::Memory)
            .err()
            .expect("invalid");
        assert_eq!(listing.to_string(), store.to_string());
        assert!(!matches!(listing, StoreError::NewerVersion { .. }));
    }
    // Not UTF-8, and over the size limit, are refused as the store refuses them.
    fs::write(folder.0.join("store.xml"), [0xff, 0xfe, 0x00]).expect("plant");
    assert!(matches!(
        Listing::read(&folder.0),
        Err(StoreError::Invalid("not UTF-8"))
    ));
    fs::write(folder.0.join("store.xml"), vec![b' '; MAX_FILE_LEN + 1]).expect("plant");
    assert!(matches!(
        Listing::read(&folder.0),
        Err(StoreError::Limit("file bytes"))
    ));
    // A store.xml that is a folder is an I/O error, not an empty store.
    fs::remove_file(folder.0.join("store.xml")).expect("remove");
    fs::create_dir(folder.0.join("store.xml")).expect("dir");
    assert!(matches!(Listing::read(&folder.0), Err(StoreError::Io(_))));
}
