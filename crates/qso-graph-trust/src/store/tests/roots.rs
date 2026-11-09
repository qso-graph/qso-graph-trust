// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Roots a file brings: when one is accepted, what the store keeps, and what never is. The test
//! roots are in tests/corpus/roots (scripts/make-root-cases.sh), never ARRL's.

use super::*;
use crate::certificate::{Trust, fingerprint};
use crate::export::{self, LOTW_PART, Password};
use crate::import::ImportError;
use crate::store::{KeyBackend, PartError, RootKind, RootSource, TrustedRoot};
use x509_cert::der::{DecodePem, Encode};

fn roots_file(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus/roots")
            .join(name),
    )
    .expect("a root test case")
}
fn pem(name: &str) -> String {
    String::from_utf8(roots_file(&format!("{name}.pem")))
        .expect("PEM")
        .trim()
        .to_string()
}
fn der(name: &str) -> Vec<u8> {
    x509_cert::Certificate::from_pem(pem(name).as_bytes())
        .and_then(|c| c.to_der())
        .expect("DER")
}
fn fp(name: &str) -> String {
    fingerprint(&der(name))
}
/// A `.tq6` as plain XML, its elements as `(tag, case)`.
fn tq6(parts: &[(&str, &str)]) -> Vec<u8> {
    let mut xml = String::from("<?xml version=\"1.0\"?>\n<tqsldata><tqslcerts>\n");
    for (tag, name) in parts {
        xml.push_str(&format!("<{tag}>\n{}\n</{tag}>\n", pem(name)));
    }
    xml.push_str("</tqslcerts></tqsldata>\n");
    xml.into_bytes()
}
fn new_root_tq6(user: &str) -> Vec<u8> {
    tq6(&[
        ("rootcert", "new-root"),
        ("cacert", "new-ca"),
        ("usercert", user),
    ])
}
fn memory(folder: &Folder) -> Store {
    Store::open(&folder.0, KeyBackend::Memory).expect("store").0
}
fn accepted(store: &Store) -> Vec<TrustedRoot> {
    store
        .trusted_roots()
        .expect("roots")
        .into_iter()
        .filter(|r| r.source != RootSource::BuiltIn)
        .collect()
}

#[test]
fn a_tq6_under_a_new_root_is_refused_until_its_fingerprint_is_confirmed() {
    let folder = Folder::new();
    let store = memory(&folder);
    let lotw = Trust::lotw();
    let file = new_root_tq6("user-a");
    // Named, with the fingerprint to confirm, and nothing imported.
    match store.import_tq6(&file, &lotw, None) {
        Err(ImportError::UntrustedRoot {
            subject,
            fingerprint,
        }) => {
            assert_eq!(subject, "QGT New Test Root");
            assert_eq!(fingerprint, fp("new-root"));
        }
        other => panic!("not refused for its root: {other:?}"),
    }
    assert!(store.certificates().expect("list").is_empty());
    assert!(accepted(&store).is_empty());
    // A fingerprint that is not this root's is refused, never ignored; so is one that is not a
    // fingerprint at all.
    match store.import_tq6(&file, &lotw, Some(&fp("other-root"))) {
        Err(ImportError::RootMismatch { given }) => assert_eq!(given, fp("other-root")),
        other => panic!("a wrong fingerprint was not refused: {other:?}"),
    }
    assert!(matches!(
        store.import_tq6(&file, &lotw, Some("not a fingerprint")),
        Err(ImportError::RootMismatch { given }) if given.is_empty()
    ));
    assert!(store.certificates().expect("list").is_empty());
    assert!(accepted(&store).is_empty());
    // The right one, as typed in lowercase without colons, imports it and keeps the root and its
    // CA in the same write.
    let typed = fp("new-root").replace(':', "").to_ascii_lowercase();
    let imported = store
        .import_tq6(&file, &lotw, Some(&typed))
        .expect("confirmed");
    assert_eq!(imported.len(), 1);
    let kept = accepted(&store);
    assert_eq!(kept.len(), 2);
    assert_eq!(
        (kept[0].kind, kept[0].source, kept[0].fingerprint.as_str()),
        (RootKind::Root, RootSource::Tq6, fp("new-root").as_str())
    );
    assert_eq!(
        (kept[1].kind, kept[1].fingerprint.as_str()),
        (RootKind::Ca, fp("new-ca").as_str())
    );
    assert!(kept[0].accepted_at.is_some());
    // The store's trust now holds it: a later certificate under it needs no confirming.
    let user_b = Certificate::from_pem_or_der(pem("user-b").as_bytes()).expect("user-b");
    assert!(user_b.verify(&lotw, &[]).is_err());
    assert_eq!(user_b.verify(&store.trust().expect("trust"), &[]), Ok(()));
    let later = store
        .import_tq6(&new_root_tq6("user-b"), &lotw, None)
        .expect("no confirmation needed");
    assert!(!later[0].already_here);
    // It is kept: the file says so, and a store reopened from it still trusts the root.
    let xml = fs::read_to_string(folder.0.join("store.xml")).expect("file");
    assert!(xml.contains("<qgt-store version=\"3\">"));
    assert!(xml.contains("<root source=\"tq6\" accepted=\""));
    drop(store);
    let reopened = memory(&folder);
    assert_eq!(accepted(&reopened), kept);
    assert!(
        reopened
            .import_tq6(&new_root_tq6("user-a"), &lotw, None)
            .expect("still trusted")[0]
            .already_here
    );
}

#[test]
fn only_a_self_signed_ca_a_certificate_in_the_file_chains_to_may_be_accepted() {
    let folder = Folder::new();
    let store = memory(&folder);
    let lotw = Trust::lotw();
    let refused = |file: &[u8], root: &str| {
        // Not offered, and not taken when its fingerprint is given.
        let plain = store.import_tq6(file, &lotw, None);
        assert!(
            matches!(
                plain,
                Err(ImportError::Refused {
                    index: 0,
                    reason: crate::import::ImportRefusal::Certificate
                })
            ),
            "{root}: {plain:?}"
        );
        assert!(matches!(
            store.import_tq6(file, &lotw, Some(&fp(root))),
            Err(ImportError::RootMismatch { .. })
        ));
        assert!(store.certificates().expect("list").is_empty());
        assert!(accepted(&store).is_empty(), "{root} was kept");
    };
    // A root no certificate in the file uses is never taken, nor is the import with it.
    refused(
        &tq6(&[
            ("rootcert", "new-root"),
            ("rootcert", "other-root"),
            ("cacert", "new-ca"),
            ("usercert", "user-a"),
        ]),
        "other-root",
    );
    // A self-signed "root" that is not a CA, though a certificate names it as issuer.
    refused(
        &tq6(&[("rootcert", "noca-root"), ("usercert", "user-noca")]),
        "noca-root",
    );
    // A CA posing as the root: it is not self-signed.
    refused(
        &tq6(&[("rootcert", "new-ca"), ("usercert", "user-a")]),
        "new-ca",
    );
    // The unit beneath: no root found in any of these.
    let users = [der("user-a")];
    assert!(crate::certificate::file_roots(&users, &[der("other-root")], &lotw).is_empty());
    assert!(crate::certificate::file_roots(&users, &[der("new-ca")], &lotw).is_empty());
    assert!(
        crate::certificate::file_roots(&[der("user-noca")], &[der("noca-root")], &lotw).is_empty()
    );
    let found = crate::certificate::file_roots(&users, &[der("new-root"), der("new-ca")], &lotw);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].authorities, vec![der("new-ca")]);
}

#[test]
fn a_p12_under_a_new_root_is_confirmed_the_same_way() {
    let folder = Folder::new();
    let store = memory(&folder);
    let p12 = roots_file("user-a.p12");
    let password = corpus("../pki/p12-password");
    assert!(matches!(
        store.import_pkcs12(&p12, &password, &Trust::lotw(), None),
        Err(ImportError::UntrustedRoot { fingerprint, .. }) if fingerprint == fp("new-root")
    ));
    assert!(matches!(
        store.import_pkcs12(&p12, &password, &Trust::lotw(), Some(&fp("new-ca"))),
        Err(ImportError::RootMismatch { .. })
    ));
    assert!(store.certificates().expect("list").is_empty());
    let imported = store
        .import_pkcs12(&p12, &password, &Trust::lotw(), Some(&fp("new-root")))
        .expect("confirmed");
    assert!(imported.has_key);
    let kept = accepted(&store);
    assert_eq!(
        (kept[0].source, kept[0].fingerprint.as_str()),
        (RootSource::P12, fp("new-root").as_str())
    );
}

/// A TQSL backup holding user-a, keyless, with the roots and CA given.
fn backup_with(roots: &[&str]) -> Vec<u8> {
    let mut xml = String::from("<?xml version=\"1.0\"?>\n<TQSL_Configuration><Certificates>");
    for r in roots {
        xml.push_str(&format!("<RootCert>{}</RootCert>", pem(r)));
    }
    xml.push_str(&format!(
        "<CACert>{}</CACert><UserCert CallSign=\"QG0TEST\" dxcc=\"291\" serial=\"1\">\
         <SignedCert>{}</SignedCert></UserCert></Certificates></TQSL_Configuration>",
        pem("new-ca"),
        pem("user-a")
    ));
    xml.into_bytes()
}

#[test]
fn a_tqsl_backups_new_root_is_trusted_without_asking_and_reported() {
    let folder = Folder::new();
    let store = memory(&folder);
    let lotw = Trust::lotw();
    let bytes = backup_with(&["new-root", "other-root"]);
    // Read as before, a backup's roots establish nothing.
    assert!(matches!(
        tbk::read(&bytes, &lotw),
        Err(tbk::TbkError::Certificate { .. })
    ));
    let backup = tbk::read_trusting_roots(&bytes, &lotw).expect("the operator's own backup");
    let added = store
        .trust_backup_roots(&backup, &lotw)
        .expect("roots kept");
    assert_eq!(added.len(), 1);
    assert_eq!(
        (added[0].subject.as_str(), added[0].fingerprint.as_str()),
        ("QGT New Test Root", fp("new-root").as_str())
    );
    // The root no certificate uses is not kept; the CA under the new one is.
    let kept: Vec<String> = accepted(&store)
        .into_iter()
        .map(|r| r.fingerprint)
        .collect();
    assert_eq!(kept, vec![fp("new-root"), fp("new-ca")]);
    assert!(accepted(&store).iter().all(|r| r.source == RootSource::Tbk));
    // Again: nothing new to report.
    assert!(
        store
            .trust_backup_roots(&backup, &lotw)
            .expect("again")
            .is_empty()
    );
    store
        .add_certificate(backup.certificates[0].certificate.as_ref().expect("cert"))
        .expect("certificate");
    // A backup whose certificates use none of its roots keeps none.
    let other = Folder::new();
    let other = memory(&other);
    let unused = tbk::read_trusting_roots(&backup_with(&["other-root"]), &lotw);
    assert!(unused.is_err());
    assert!(accepted(&other).is_empty());
}

/// A keyless store's part plaintext with its XML changed: the magic and version (decision 0009),
/// the XML's length, then the XML.
fn reframed(store: &Store, change: impl Fn(&str) -> String) -> Vec<u8> {
    const MAGIC: &[u8] = b"QGT-STORE\x02";
    let plaintext = store.part_plaintext().expect("plaintext");
    let rest = plaintext.strip_prefix(MAGIC).expect("magic");
    let len = u32::from_be_bytes(rest[..4].try_into().expect("length")) as usize;
    assert_eq!(
        rest.len(),
        4 + len,
        "a keyless store's part is its XML alone"
    );
    let xml = change(std::str::from_utf8(&rest[4..]).expect("XML"));
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(xml.len() as u32).to_be_bytes());
    out.extend_from_slice(xml.as_bytes());
    out
}

#[test]
fn an_export_part_carries_accepted_roots_and_an_older_part_still_restores() {
    let source_folder = Folder::new();
    let source = memory(&source_folder);
    let lotw = Trust::lotw();
    source
        .import_tq6(&new_root_tq6("user-a"), &lotw, Some(&fp("new-root")))
        .expect("confirmed");
    let password = Password::generate().expect("random");
    let part = source.export_part(&password).expect("export");
    // A store that has never seen the root restores it, and says so.
    let folder = Folder::new();
    let store = memory(&folder);
    let report = store
        .restore_part(&part, &password, &lotw)
        .expect("restored");
    assert_eq!(report.certificates, 1);
    assert_eq!(report.roots.len(), 1);
    assert_eq!(
        (report.roots[0].fingerprint.as_str(), report.roots[0].source),
        (fp("new-root").as_str(), RootSource::Part)
    );
    let kept: Vec<String> = accepted(&store)
        .into_iter()
        .map(|r| r.fingerprint)
        .collect();
    assert_eq!(kept, vec![fp("new-root"), fp("new-ca")]);
    // Restored again onto itself, nothing is new.
    let again = store.restore_part(&part, &password, &lotw).expect("again");
    assert!(again.roots.is_empty());
    assert_eq!(accepted(&store).len(), 2);
    // A part without the roots its certificates need does not restore.
    let stripped = reframed(&source, |xml| {
        let start = xml.find("  <roots>").expect("roots in the part");
        let end = xml.find("  </roots>\n").expect("end") + "  </roots>\n".len();
        xml[..start].to_string() + &xml[end..]
    });
    let sealed = export::seal(LOTW_PART, &stripped, &password).expect("seal");
    let fresh = Folder::new();
    assert!(matches!(
        memory(&fresh).restore_part(&sealed, &password, &lotw),
        Err(PartError::Invalid)
    ));
    // An older part, store version 2 inside, with nothing under a new root, still restores.
    let old_folder = Folder::new();
    let old_store = memory(&old_folder);
    old_store
        .add_location("home", &station())
        .expect("a location");
    let old = reframed(&old_store, |xml| {
        assert!(!xml.contains("<roots>"));
        xml.replacen("qgt-store version=\"3\"", "qgt-store version=\"2\"", 1)
    });
    let sealed = export::seal(LOTW_PART, &old, &password).expect("seal");
    let report = memory(&fresh)
        .restore_part(&sealed, &password, &lotw)
        .expect("an older part");
    assert_eq!((report.locations, report.roots.len()), (1, 0));
}

#[test]
fn version_two_reads_version_three_is_written_and_its_roots_are_read_back() {
    let folder = Folder::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let path = folder.0.join("store.xml");
    let v2 = empty_xml().replacen("qgt-store version=\"3\"", "qgt-store version=\"2\"", 1);
    fs::write(&path, &v2).expect("a version 2 store");
    let (store, _) = open(&folder.0, &keys).expect("version 2 reads");
    assert!(accepted(&store).is_empty());
    store
        .import_tq6(
            &new_root_tq6("user-a"),
            &Trust::lotw(),
            Some(&fp("new-root")),
        )
        .expect("confirmed");
    let v3 = fs::read_to_string(&path).expect("written");
    assert!(v3.contains("<qgt-store version=\"3\">"));
    let (reread, _) = open(&folder.0, &keys).expect("version 3 reads");
    assert_eq!(accepted(&reread).len(), 2);
    // Planted: each is refused, and the file is left as it is.
    let entry = |tag: &str, source: &str, name: &str| {
        format!(
            "<{tag} source=\"{source}\" accepted=\"1\">{}</{tag}>",
            base64ct::Base64::encode_string(&der(name))
        )
    };
    use base64ct::Encoding;
    let roots = |inner: &str| {
        empty_xml().replacen(
            "</qgt-store>",
            &format!("  <roots>{inner}</roots>\n</qgt-store>"),
            1,
        )
    };
    let cases = [
        // Roots in a version 2 file.
        roots(&entry("root", "tq6", "new-root")).replacen(
            "qgt-store version=\"3\"",
            "qgt-store version=\"2\"",
            1,
        ),
        // A CA kept as a root, a root that is not a CA, an unknown source, the same twice.
        roots(&entry("root", "tq6", "new-ca")),
        roots(&entry("root", "tq6", "noca-root")),
        roots(&entry("root", "web", "new-root")),
        roots(&(entry("root", "tq6", "new-root") + &entry("root", "tbk", "new-root"))),
        roots(&entry("root", "tq6", "new-root").replace("accepted=\"1\"", "accepted=\"x\"")),
        // More than the limit.
        roots(&entry("root", "tq6", "new-root").repeat(MAX_ROOTS + 1)),
    ];
    for text in cases {
        fs::write(&path, &text).expect("plant");
        assert!(open(&folder.0, &keys).is_err(), "{text}");
        assert_eq!(fs::read_to_string(&path).expect("untouched"), text);
    }
    fs::write(&path, roots(&entry("root", "part", "new-root"))).expect("valid");
    let (store, _) = open(&folder.0, &keys).expect("a valid roots section");
    assert_eq!(accepted(&store)[0].source, RootSource::Part);
}

/// LoTW's four, as `lotw::arrl` gives their fingerprints.
const BUILT_IN: [(RootKind, &str, &str); 4] = [
    (
        RootKind::Root,
        "Logbook of the World Root CA",
        "2E:35:F9:6E:F1:86:26:DC:90:1A:2C:F3:1B:FB:56:DA:FA:DC:70:30:D7:33:D9:B3:07:D0:DB:8E:87:C7:9A:0F",
    ),
    (
        RootKind::Root,
        "Logbook of the World Root CA",
        "0F:B9:62:75:EA:CA:03:EF:29:FF:50:9D:9E:54:5B:1F:38:61:F4:46:8F:06:87:BE:CC:59:3E:D0:06:04:B2:E6",
    ),
    (
        RootKind::Ca,
        "Logbook of the World Production CA",
        "A6:89:D0:B4:ED:C4:F1:AF:DD:2C:62:C5:01:C8:13:6E:1F:35:4C:9D:7D:ED:06:4D:91:C9:D6:2A:F8:BD:EC:93",
    ),
    (
        RootKind::Ca,
        "Logbook of the World Production CA",
        "98:EA:7D:C6:B1:4D:8E:A6:A5:B7:26:83:0D:45:E2:B5:A5:E0:ED:5B:5D:B9:B1:26:E8:AD:13:2D:33:5D:9A:8C",
    ),
];

#[test]
fn the_list_holds_lotws_four_built_in_certificates_and_they_cannot_be_removed() {
    let folder = Folder::new();
    let store = memory(&folder);
    let list = store.trusted_roots().expect("list");
    assert_eq!(list.len(), 4);
    for (r, (kind, subject, fingerprint)) in list.iter().zip(BUILT_IN) {
        assert_eq!(
            (r.kind, r.subject.as_str(), r.fingerprint.as_str()),
            (kind, subject, fingerprint)
        );
        assert_eq!((r.source, r.accepted_at), (RootSource::BuiltIn, None));
        assert!(matches!(
            store.remove_root(fingerprint),
            Err(StoreError::BuiltInRoot)
        ));
    }
    // The 2023 root and CA's serials, as arrl.rs gives them.
    assert_eq!(list[1].serial, "B6DC0911164D9C51");
    assert_eq!(list[3].serial, "0A");
    assert_eq!(store.trusted_roots().expect("unchanged"), list);
}

#[test]
fn an_accepted_root_is_removed_with_the_cas_kept_under_it() {
    let folder = Folder::new();
    let store = memory(&folder);
    let lotw = Trust::lotw();
    store
        .import_tq6(&new_root_tq6("user-a"), &lotw, Some(&fp("new-root")))
        .expect("confirmed");
    assert_eq!(accepted(&store).len(), 2);
    let removed = store.remove_root(&fp("new-root")).expect("removed");
    assert_eq!(removed.fingerprint, fp("new-root"));
    assert!(accepted(&store).is_empty());
    assert_eq!(store.trusted_roots().expect("list").len(), 4);
    assert!(matches!(
        store.remove_root(&fp("new-root")),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.remove_root("not a fingerprint"),
        Err(StoreError::Invalid(_))
    ));
    // Asked again, as at first.
    assert!(matches!(
        store.import_tq6(&new_root_tq6("user-b"), &lotw, None),
        Err(ImportError::UntrustedRoot { .. })
    ));
}

#[test]
fn a_listing_gives_the_same_trusted_roots_as_the_store() {
    let folder = Folder::new();
    let store = memory(&folder);
    assert_eq!(
        crate::store::Listing::read(&folder.0)
            .expect("listing")
            .trusted_roots(),
        store.trusted_roots().expect("roots")
    );
    store
        .import_tq6(
            &new_root_tq6("user-a"),
            &Trust::lotw(),
            Some(&fp("new-root")),
        )
        .expect("accepted");
    let listed = crate::store::Listing::read(&folder.0).expect("listing");
    let full = store.trusted_roots().expect("roots");
    assert_eq!(listed.trusted_roots(), full);
    assert_eq!(
        listed
            .trusted_roots()
            .iter()
            .filter(|r| r.source == RootSource::Tq6)
            .count(),
        2
    );
    assert!(full.iter().any(|r| r.source == RootSource::BuiltIn));
}
