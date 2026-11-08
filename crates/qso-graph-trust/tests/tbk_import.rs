// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! TQSL's backup of the standard test set, imported (qso-graph-desktop#172, Gate C): every
//! certificate, key and location comes through whole, and signing with only what came through gives
//! tqsllib's own signed logs. A backup that does not hang together is refused.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use qso_graph_trust::certificate::{CertificateError, Trust};
use qso_graph_trust::gzip;
use qso_graph_trust::qso::Qso;
use qso_graph_trust::records;
use qso_graph_trust::signed_log::sign_log;
use qso_graph_trust::tbk::{self, TbkError};

/// The standard set's test root: the only root these tests trust, never LoTW's.
fn test_root() -> Trust {
    Trust::with_roots(&[&set("pki/root.pem")]).expect("the test root")
}

/// A backup read against the test root.
fn read(bytes: &[u8]) -> Result<tbk::Backup, TbkError> {
    tbk::read(bytes, &test_root())
}

fn set(file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/standard")
        .join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The backup's XML, changed as `edit` says, gzipped again as TQSL would.
fn edited(edit: impl Fn(String) -> String) -> Vec<u8> {
    let xml = gzip::decompress(&set("standard.tbk"), tbk::MAX_TBK_LEN).expect("TQSL's backup");
    let xml = String::from_utf8(xml.to_vec()).expect("text");
    gzip::compress(edit(xml).as_bytes())
}

#[test]
fn every_certificate_key_and_location_comes_through() {
    let backup = read(&set("standard.tbk")).expect("TQSL's backup reads");
    let calls: Vec<&str> = backup
        .certificates
        .iter()
        .map(|c| c.callsign.as_str())
        .collect();
    assert_eq!(calls, ["KC4QPQ", "KN4YU", "W4W"]);
    // ARRL-style serials, as TQSL wrote them and as each certificate holds them.
    let serials: Vec<i64> = backup.certificates.iter().map(|c| c.serial).collect();
    assert_eq!(serials, [10001, 10002, 10003]);
    for c in &backup.certificates {
        assert_eq!(
            c.certificate.as_ref().and_then(|cert| cert.serial()),
            Some(c.serial)
        );
    }
    for c in &backup.certificates {
        let cert = c.certificate.as_ref().expect("its certificate");
        let key = c.key.as_ref().expect("its key");
        assert_eq!(
            (cert.callsign(), cert.dxcc(), c.dxcc),
            (c.callsign.as_str(), 291, 291)
        );
        // Whether the set gave this key a password: only that, never the password, is compared,
        // and nothing taken from the password's file is printed.
        let protected = !set(&format!("keys/{}.password", c.callsign)).is_empty();
        assert!(key.is_encrypted() == protected);
    }
    let names: Vec<&str> = backup.locations.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "KC4QPQ-HOME",
            "KC4QPQ-MN35",
            "KC4QPQ-NS09",
            "KC4QPQ-NP12",
            "KC4QPQ-TR10-MP06",
            "KN4YU-CLUB",
            "W4W-EVENT"
        ]
    );
    let park = &backup.locations[4].station;
    assert_eq!(
        (
            park.get("US_PARK"),
            park.get("US_COUNTY"),
            park.get("GRIDSQUARE")
        ),
        (Some("TR10,MP06"), Some("York"), Some("EM95"))
    );
    assert_eq!(backup.signed_qsos.len(), 21);
    assert!(!backup.roots.is_empty() && !backup.authorities.is_empty());
    assert!(backup.not_read.is_empty());
    // TQSL's own settings in the set (window, first run, no update check): none changes signing.
    assert_eq!(backup.preferences, tbk::Preferences::default());
    assert!(
        backup
            .settings_not_taken
            .contains(&"/MainWindowWidth".to_string())
    );
}

#[test]
fn signing_with_what_was_imported_gives_tqsllibs_logs() {
    let backup = read(&set("standard.tbk")).expect("TQSL's backup reads");
    for location in &backup.locations {
        let call = location.station.call();
        let entry = backup
            .certificates
            .iter()
            .find(|c| c.callsign == call)
            .expect("its certificate");
        let cert = entry.certificate.as_ref().expect("a certificate");
        let password = set(&format!("keys/{call}.password"));
        let signer = entry
            .key
            .as_ref()
            .expect("a key")
            .unlock((!password.is_empty()).then_some(password.as_slice()))
            .unwrap_or_else(|e| panic!("{call}: {e}"));
        let qsos: Vec<Qso> = records::parse(&set(&format!("adif/{}.adi", location.name)))
            .expect("ADIF")
            .iter()
            .map(|r| Qso::from_adif(r).expect("a QSO"))
            .collect();
        let at = cert.validity().0 + Duration::from_secs(3600);
        let ours = sign_log(cert, &signer, &location.station, &qsos, at).expect("signs");
        let theirs = set(&format!("signed/{}.tq7", location.name));
        let body =
            |log: &[u8]| log[log.iter().position(|&b| b == b'\n').expect("a line") + 1..].to_vec();
        assert_eq!(
            String::from_utf8_lossy(&body(&ours)),
            String::from_utf8_lossy(&body(&theirs)),
            "{}",
            location.name
        );
    }
}

#[test]
fn a_backup_read_twice_reads_the_same() {
    // Gzipped as TQSL writes it, or the XML itself: the same backup.
    let xml = gzip::decompress(&set("standard.tbk"), tbk::MAX_TBK_LEN).expect("TQSL's backup");
    let plain = read(&xml).expect("plain XML reads");
    let zipped = read(&set("standard.tbk")).expect("gzip reads");
    assert_eq!(plain.locations.len(), zipped.locations.len());
    assert_eq!(plain.signed_qsos, zipped.signed_qsos);
}

#[test]
fn a_backup_that_does_not_hang_together_is_refused() {
    // KN4YU's key put in KC4QPQ's entry: a key that is not its certificate's.
    let swapped = edited(|xml| {
        let key = |call: &str| {
            let at = xml
                .find(&format!("<UserCert CallSign=\"{call}\""))
                .expect("entry");
            let start = at + xml[at..].find("<PrivateKey>").expect("key");
            let end = at + xml[at..].find("</PrivateKey>").expect("key end");
            (start, end)
        };
        let (a, b) = (key("KC4QPQ"), key("KN4YU"));
        let theirs = xml[b.0..b.1].to_string();
        format!("{}{}{}", &xml[..a.0], theirs, &xml[a.1..])
    });
    assert!(matches!(
        read(&swapped),
        Err(TbkError::Mismatch { .. }) | Err(TbkError::Key { .. })
    ));

    // A serial that is not the certificate's.
    let serial = edited(|xml| xml.replacen("serial=\"10002\"", "serial=\"10009\"", 1));
    assert!(
        matches!(read(&serial), Err(TbkError::Mismatch { callsign, .. }) if callsign == "KN4YU")
    );

    // A certificate under another call's name.
    let renamed = edited(|xml| {
        xml.replacen(
            "<UserCert CallSign=\"KN4YU\"",
            "<UserCert CallSign=\"KC4QPQ\"",
            1,
        )
    });
    assert!(matches!(read(&renamed), Err(TbkError::Mismatch { .. })));

    // A location LoTW would not accept, and two with one name.
    let county = edited(|xml| xml.replacen("US_COUNTY=\"York\"", "US_COUNTY=\"Nowhere\"", 1));
    assert!(
        matches!(read(&county), Err(TbkError::Location { name, .. }) if name == "KC4QPQ-TR10-MP06")
    );
    let twice = edited(|xml| xml.replacen("name=\"KN4YU-CLUB\"", "name=\"KC4QPQ-HOME\"", 1));
    assert!(matches!(
        read(&twice),
        Err(TbkError::RepeatedLocation { .. })
    ));

    // Entities that expand (billion laughs) need a DTD, which is refused.
    let laughs = edited(|xml| {
        xml.replacen(
            "<TQSL_Configuration>",
            "<!DOCTYPE TQSL_Configuration [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><TQSL_Configuration>",
            1,
        )
    });
    assert!(matches!(read(&laughs), Err(TbkError::Xml { .. })));

    // Not a backup, damaged, or cut short.
    assert_eq!(
        read(&gzip::compress(b"<other/>")).err(),
        Some(TbkError::NotABackup)
    );
    let mut damaged = set("standard.tbk");
    let n = damaged.len();
    damaged[n - 8] ^= 1;
    assert!(matches!(read(&damaged), Err(TbkError::Gzip(_))));
    let cut = set("standard.tbk")[..n / 2].to_vec();
    assert!(read(&cut).is_err());
}

#[test]
fn an_imported_key_prints_nothing_of_itself() {
    let backup = read(&set("standard.tbk")).expect("TQSL's backup reads");
    let shown = format!("{backup:?}");
    // No key's text, from any entry: the PEM markers and the record's field names never appear.
    for marker in ["PRIVATE KEY", "PRIVATE_KEY", "BEGIN"] {
        assert!(!shown.contains(marker), "{marker}");
    }
}

/// A backup of one QG0TEST certificate from the first corpus, with the key file of `key_case`; its
/// serial is random and too large for tqsllib's `long`, so TQSL writes it as -1. Both cases are
/// QG0TEST, with different keys.
fn one_entry(key_case: &str) -> Vec<u8> {
    let corpus = |case: &str, file: &str| {
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus/tqsl")
                .join(case)
                .join(file),
        )
        .expect("the corpus")
    };
    use base64ct::{Base64, Encoding};
    let cert = String::from_utf8(corpus("1024", "tqsl/certs/user")).expect("PEM");
    let ca = String::from_utf8(
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/tqsl/pki/ca.pem"),
        )
        .expect("the corpus CA"),
    )
    .expect("PEM");
    let key = Base64::encode_string(&corpus(key_case, "tqsl/keys/QG0TEST"));
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<TQSL_Configuration><Certificates><CACert>{}</CACert><UserCert CallSign=\"QG0TEST\" dxcc=\"291\" serial=\"-1\">\
         <SignedCert>{}</SignedCert><PrivateKey>{key}</PrivateKey></UserCert></Certificates></TQSL_Configuration>",
        ca.trim(),
        cert.trim()
    );
    gzip::compress(xml.as_bytes())
}

#[test]
fn a_key_must_be_its_certificates_own() {
    let corpus_root = Trust::with_roots(&[&std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/tqsl/pki/root.pem"),
    )
    .expect("the corpus root")])
    .expect("a root");
    let read = |bytes: &[u8]| tbk::read(bytes, &corpus_root);
    let ours = read(&one_entry("1024")).expect("the certificate's own key");
    assert!(ours.certificates[0].key.is_some());
    // The same call, another key: refused by the key check itself, not the call check.
    assert_eq!(
        read(&one_entry("1024-password")).err(),
        Some(TbkError::Mismatch {
            callsign: "QG0TEST".into(),
            what: "the key is not the certificate's"
        })
    );
}

#[test]
fn only_a_trusted_root_makes_a_certificate_trusted() {
    // TQSL's own backup of the set, against LoTW's pinned root: the test CA is no LoTW CA, and the
    // test root the backup carries establishes nothing.
    assert!(matches!(
        tbk::read(&set("standard.tbk"), &Trust::lotw()),
        Err(TbkError::Certificate {
            error: CertificateError::Untrusted { .. },
            ..
        })
    ));
    // A certificate whose signature is changed (found in review: fields alone were checked).
    let forged = edited(|xml| {
        let at = xml.find("<UserCert CallSign=\"KN4YU\"").expect("entry");
        let end = at + xml[at..].find("-----END CERTIFICATE-----").expect("end");
        // The last base64 line before END ends inside the signature: change one character of it.
        let line_start = xml[..end - 1].rfind('\n').expect("a line") + 1;
        let c = xml.as_bytes()[line_start];
        let swapped = if c == b'A' { 'B' } else { 'A' };
        format!(
            "{}{}{}",
            &xml[..line_start],
            swapped,
            &xml[line_start + 1..]
        )
    });
    assert!(matches!(
        read(&forged),
        Err(TbkError::Certificate { callsign, error: CertificateError::Untrusted { .. } }) if callsign == "KN4YU"
    ));
}

/// A backup of one key waiting for its certificate: KN4YU's, its entry's entity `dxcc`, and the key
/// record changed as `edit` says.
fn pending(dxcc: &str, edit: impl Fn(String) -> String) -> Vec<u8> {
    use base64ct::{Base64, Encoding};
    let record = String::from_utf8(set("tqsl/keys/KN4YU")).expect("a key record");
    let key = Base64::encode_string(edit(record).as_bytes());
    let xml = format!(
        "<TQSL_Configuration><Certificates><UserCert CallSign=\"KN4YU\" dxcc=\"{dxcc}\" serial=\"0\">\
         <PrivateKey>{key}</PrivateKey></UserCert></Certificates></TQSL_Configuration>"
    );
    gzip::compress(xml.as_bytes())
}

#[test]
fn a_key_waiting_for_its_certificate_must_name_its_entity() {
    let backup = read(&pending("291", |r| r)).expect("a pending key");
    assert!(backup.certificates[0].certificate.is_none() && backup.certificates[0].key.is_some());
    // Found in review: a pending key was reported for any entity.
    let other = |r: Result<tbk::Backup, TbkError>| matches!(r, Err(TbkError::Mismatch { .. }));
    assert!(other(read(&pending("1", |r| r))));
    assert!(other(read(
        &pending("1", |r| r.replace("<TQSL_CRQ_DXCC_ENTITY:3>291", ""))
    )));
    // An entity that is there but not a number is refused, not taken as missing.
    assert!(matches!(
        read(&pending("291", |r| r.replace(
            "<TQSL_CRQ_DXCC_ENTITY:3>291",
            "<TQSL_CRQ_DXCC_ENTITY:3>2\u{ff}1"
        ))),
        Err(TbkError::Key { .. })
    ));
}

#[test]
fn settings_that_change_what_is_signed_are_taken_and_where_logs_go_never() {
    let settings = r#"<TQSLSettings>
<Setting name="IgnoreSeconds" group="/" Type="Int" Value="1"/>
<Setting name="BadCalls" group="/" Type="Int" Value="1"/>
<Setting name="IgnoreADIFCallsign" group="/" Type="Int" Value="0"/>
<Setting name="LogVerify" group="/" Type="Int" Value="2"/>
<Setting name="DIGI!SLASH!X" group="/modeMap" Type="String" Value="DATA"/>
<Setting name="CW" group="/modeMap" Type="String" Value="SSB"/>
<Setting name="NOPE" group="/modeMap" Type="String" Value="NOTAMODE"/>
<Setting name="ARRL-VHF" group="/cabrilloMap" Type="String" Value="1;7"/>
<Setting name="BAD-TYPE" group="/cabrilloMap" Type="String" Value="2;7"/>
<Setting name="BAD-FIELD" group="/cabrilloMap" Type="String" Value="0;5"/>
<Setting name="UploadURL" group="/LogUpload" Type="String" Value="https://example.invalid/steal"/>
<Setting name="VerifyCA" group="/LogUpload" Type="Int" Value="0"/>
<Setting name="ProxyHost" group="/Proxy" Type="String" Value="evil.invalid"/>
</TQSLSettings>"#;
    let backup = read(&edited(|xml| {
        let start = xml.find("<TQSLSettings>").expect("settings");
        let end = xml.find("</TQSLSettings>").expect("settings end") + "</TQSLSettings>".len();
        format!("{}{settings}{}", &xml[..start], &xml[end..])
    }))
    .expect("reads");
    let p = &backup.preferences;
    assert!(p.ignore_seconds && p.allow_bad_calls && !p.ignore_log_callsigns);
    assert_eq!(p.qth, tbk::QthHandling::FromLog);
    // A custom mode is taken; one renaming a standard mode, or to a mode LoTW does not have, is not.
    assert_eq!(p.adif_modes, [("DIGI/X".to_string(), "DATA".to_string())]);
    assert_eq!(p.cabrillo_contests, [("ARRL-VHF".to_string(), 1, 7)]);
    for never in [
        "/LogUpload/UploadURL",
        "/LogUpload/VerifyCA",
        "/Proxy/ProxyHost",
        "/modeMap/CW",
        "/modeMap/NOPE",
        "/cabrilloMap/BAD-TYPE",
        "/cabrilloMap/BAD-FIELD",
    ] {
        assert!(
            backup.settings_not_taken.contains(&never.to_string()),
            "{never}"
        );
    }
}

#[test]
fn a_protected_key_is_checked_as_far_as_it_can_be_without_its_password() {
    // Found in review: a key that only starts like an encrypted one was taken.
    let fake = "<CALLSIGN:5>KN4YU<PUBLIC_KEY:1>x<PRIVATE_KEY:37>-----BEGIN ENCRYPTED PRIVATE KEY-----<TQSL_CRQ_DXCC_ENTITY:3>291<eor>";
    assert!(matches!(
        read(&pending("291", |_| fake.to_string())),
        Err(TbkError::Key { .. })
    ));
    // A real protected key, its envelope whole: taken, to be unlocked with its password.
    let backup = read(&set("standard.tbk")).expect("TQSL's backup reads");
    let kc4qpq = backup
        .certificates
        .iter()
        .find(|c| c.callsign == "KC4QPQ")
        .expect("KC4QPQ");
    assert!(kc4qpq.key.as_ref().is_some_and(|k| k.is_encrypted()));
}
