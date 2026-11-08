// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;
use std::path::Path;

use base64ct::{Base64, Encoding};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::Digest;
use x509_cert::der::{DecodePem, Encode};

use crate::records;
use crate::signing::KeyEntry;

fn corpus(path: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus")
            .join(path),
    )
    .expect("test corpus")
}

fn request(call: &str) -> CertificateRequest {
    CertificateRequest {
        callsign: call.into(),
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
}

fn fixture_key(path: &str) -> KeyEntry {
    KeyEntry::read_key_file(&corpus(path))
        .expect("key file")
        .remove(0)
}

// records::parse deliberately accepts ADIF fields with lengths only. TQSL's request-kind
// markers have no length; normalize only those three markers before using the shared reader.
fn parse_tq5(tq5: &str) -> Vec<records::Record> {
    let mut text = tq5.to_owned();
    for marker in ["NEW", "ADDITIONAL", "RENEWAL"] {
        text = text.replace(
            &format!("<TQSL_CRQ_{marker}>"),
            &format!("<TQSL_CRQ_{marker}:0>"),
        );
    }
    records::parse(text.as_bytes()).expect("request framing")
}

fn csr_in(tq5: &str) -> CertReq {
    let records = parse_tq5(tq5);
    CertReq::from_pem(records[0].get("TQSL_CRQ_REQUEST").expect("CSR")).expect("PKCS#10")
}

fn verify_csr(csr: &CertReq) {
    let public = RsaPublicKey::from_public_key_der(&csr.info.public_key.to_der().expect("SPKI"))
        .expect("RSA");
    let digest = sha2::Sha256::digest(csr.info.to_der().expect("info"));
    public
        .verify(
            Pkcs1v15Sign::new::<sha2::Sha256>(),
            &digest,
            csr.signature.as_bytes().expect("signature"),
        )
        .expect("CSR signature verifies independently");
    let mut changed = digest.to_vec();
    changed[0] ^= 1;
    assert!(
        public
            .verify(
                Pkcs1v15Sign::new::<sha2::Sha256>(),
                &changed,
                csr.signature.as_bytes().expect("signature")
            )
            .is_err()
    );
}

#[test]
fn same_test_key_reproduces_tqsllib_requests_except_identification() {
    // Differential test: these are tqsllib's *actual* requests, not DER constructed by this test.
    // Reusing each test key also makes its PKCS#1 v1.5 signature deterministic, so compare every
    // byte except the identification field, including the CSR signature. TQSL's tqsl_trim
    // makes the spaced variants equivalent to each corpus input before both encodings.
    for (prefix, call, password) in [
        ("tqsl/1024", "QG0TEST", None),
        ("tqsl/1024-password", "QG0TEST", Some(b"qgt-key".as_slice())),
        ("standard", "KC4QPQ", Some(b"qgt-kc4qpq".as_slice())),
        ("standard", "KN4YU", None),
        ("standard", "W4W", Some(b"qgt-w4w".as_slice())),
    ] {
        let path = if prefix == "standard" {
            format!("{prefix}/requests/{call}.tq5")
        } else {
            format!("{prefix}/{call}.tq5")
        };
        let theirs = String::from_utf8(corpus(&path)).expect("request text");
        let entry = fixture_key(&format!("{prefix}/tqsl/keys/{call}"));
        let private = entry.pkcs8_der(password).expect("fixture key unlocks");
        let public = entry.public_key_der().expect("SPKI");
        let req = request(call);
        let mut spaced_name = req.clone();
        spaced_name.name = "  QGT   Test  Operator   ".into();
        let mut spaced_address = req.clone();
        spaced_address.address1 = "   1  No   Place  ".into();
        for req in [req, spaced_name, spaced_address] {
            req.validate().expect("valid request");
            let csr = req.csr(&private, &public).expect("CSR");
            assert_eq!(csr, csr_in(&theirs), "{prefix}/{call}");
            verify_csr(&csr);
            let ours = req.frame(&csr, Authorization::New, None).expect("frame");
            let old_ident = parse_tq5(&theirs)[0]
                .text("TQSL_IDENT")
                .expect("ident")
                .to_owned();
            let mut normalized = String::new();
            field(&mut normalized, "TQSL_IDENT", &old_ident);
            let mut ours_ident = String::new();
            let current = parse_tq5(&ours)[0]
                .text("TQSL_IDENT")
                .expect("ident")
                .to_owned();
            field(&mut ours_ident, "TQSL_IDENT", &current);
            assert_eq!(
                ours.replace(&ours_ident, &normalized),
                theirs,
                "{prefix}/{call}"
            );
        }
    }
}

#[test]
fn fresh_key_is_lotw_shaped_csr_verifies_and_only_public_values_are_returned() {
    let req = request("QG0TEST");
    let generated = req.generate(Authorization::New).expect("request");
    assert_eq!(format!("{generated:?}"), "GeneratedRequest(..)");
    assert!(!generated.tq5().contains("PRIVATE KEY"));
    assert!(generated.tq5().contains(&format!(
        "QSO Graph Trust Lib: V{} Config: V{}.{}",
        crate::VERSION,
        crate::lotw::CONFIG_VERSION.0,
        crate::lotw::CONFIG_VERSION.1
    )));
    TqslKey::from_pkcs8_der(&generated.private, generated.public_key_der())
        .expect("LoTW shape and matching public key");
    let csr = csr_in(generated.tq5());
    verify_csr(&csr);
    let theirs = csr_in(&String::from_utf8(corpus("tqsl/1024/QG0TEST.tq5")).expect("fixture"));
    assert_eq!(csr.info.subject, theirs.info.subject);
    assert_eq!(csr.info.attributes, theirs.info.attributes);
    assert_eq!(csr.info.version, theirs.info.version);
    assert_eq!(csr.algorithm, theirs.algorithm);
    assert_eq!(
        csr.info.public_key.algorithm,
        theirs.info.public_key.algorithm
    );
    assert_ne!(csr.info.public_key, theirs.info.public_key);
    let ours_fields = parse_tq5(generated.tq5());
    let their_fields =
        parse_tq5(&String::from_utf8(corpus("tqsl/1024/QG0TEST.tq5")).expect("text"));
    let public_fields = |r: &records::Record| {
        r.fields
            .iter()
            .filter(|f| !["TQSL_CRQ_REQUEST", "TQSL_IDENT"].contains(&f.name.as_str()))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        public_fields(&ours_fields[0]),
        public_fields(&their_fields[0])
    );
    let second = req.generate(Authorization::New).expect("second request");
    assert_ne!(generated.public_key_der(), second.public_key_der());
}

#[test]
fn additional_and_renewal_sign_the_complete_der_with_the_existing_key() {
    let certificate =
        Certificate::from_pem_or_der(&corpus("tqsl/1024/tqsl/certs/user")).expect("certificate");
    let entry = fixture_key("tqsl/1024/tqsl/keys/QG0TEST");
    let key = entry.unlock(None).expect("key");
    let public = RsaPublicKey::from_public_key_der(certificate.public_key_der()).expect("public");
    for renewal in [false, true] {
        let mut req = request(if renewal { "QG0TEST" } else { "QG1TEST" });
        req.qso_not_after = Date::from_iso("2026-11-04");
        let auth = if renewal {
            Authorization::Renewal {
                certificate: &certificate,
                key: &key,
            }
        } else {
            Authorization::Additional {
                certificate: &certificate,
                key: &key,
            }
        };
        let generated = req.generate(auth).expect("signed request");
        let records = parse_tq5(generated.tq5());
        let record = &records[0];
        let names = record
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "TQSL_IDENT",
                if renewal {
                    "TQSL_CRQ_RENEWAL"
                } else {
                    "TQSL_CRQ_ADDITIONAL"
                },
                "TQSL_CRQ_PROVIDER",
                "TQSL_CRQ_PROVIDER_UNIT",
                "TQSL_CRQ_EMAIL",
                "TQSL_CRQ_NAME",
                "TQSL_CRQ_ADDRESS1",
                "TQSL_CRQ_ADDRESS2",
                "TQSL_CRQ_CITY",
                "TQSL_CRQ_STATE",
                "TQSL_CRQ_POSTAL",
                "TQSL_CRQ_COUNTRY",
                "TQSL_CRQ_DXCC_ENTITY",
                "TQSL_CRQ_QSO_NOT_BEFORE",
                "TQSL_CRQ_QSO_NOT_AFTER",
                "TQSL_CRQ_REQUEST",
                "TQSL_CRQ_SIGNATURE",
                "TQSL_CRQ_SIGNATURE_CERT_ISSUER",
                "TQSL_CRQ_SIGNATURE_CERT_SERIAL"
            ]
        );
        assert_eq!(record.text("TQSL_CRQ_QSO_NOT_AFTER"), Some("2026-11-04"));
        assert_eq!(record.text("TQSL_CRQ_SIGNATURE_CERT_SERIAL"), Some("-1"));
        assert_eq!(
            record.text("TQSL_CRQ_SIGNATURE_CERT_ISSUER"),
            Some("/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Test CA")
        );
        let b64 = record.text("TQSL_CRQ_SIGNATURE").expect("signature");
        let sig = Base64::decode_vec(&b64.lines().collect::<String>()).expect("base64");
        assert_eq!(b64, tqsl_base64(&sig));
        let csr = csr_in(generated.tq5());
        verify_csr(&csr);
        let der = csr.to_der().expect("DER");
        public
            .verify(
                Pkcs1v15Sign::new::<sha1::Sha1>(),
                &sha1::Sha1::digest(&der),
                &sig,
            )
            .expect("old key authorizes full DER");
        assert!(
            public
                .verify(
                    Pkcs1v15Sign::new::<sha1::Sha1>(),
                    &sha1::Sha1::digest(record.get("TQSL_CRQ_REQUEST").expect("PEM")),
                    &sig
                )
                .is_err()
        );
        assert!(
            public
                .verify(
                    Pkcs1v15Sign::new::<sha1::Sha1>(),
                    &sha1::Sha1::digest(csr.info.to_der().expect("info")),
                    &sig
                )
                .is_err()
        );
    }
}

#[test]
fn bad_inputs_are_refused_and_corrected_inputs_pass() {
    let good = request("QG0TEST");
    good.validate().expect("valid");
    let mut bad = good.clone();
    bad.dxcc = 999_999;
    assert_eq!(
        bad.generate(Authorization::New).err(),
        Some(RequestError::Invalid("DXCC_ENTITY"))
    );
    bad.dxcc = good.dxcc;
    bad.validate().expect("corrected");
    bad.qso_not_after = Date::from_iso("2019-12-31");
    assert_eq!(bad.validate(), Err(RequestError::Invalid("QSO_NOT_AFTER")));
    bad.qso_not_after = Some(good.qso_not_before);
    bad.validate().expect("same first and last date is allowed");
    assert!(Date::from_iso("2026-02-29").is_none());
    assert!(Date::from_iso("2024-02-29").is_some());
    assert!(Date::from_iso("0000-01-01").is_none());
    for invalid in ["<", ">", "\n", "\r", "\0", "\t", "\u{000b}", "\u{000c}"] {
        for index in 0..11 {
            let mut bad = good.clone();
            let fields = [
                &mut bad.provider,
                &mut bad.provider_unit,
                &mut bad.email,
                &mut bad.name,
                &mut bad.address1,
                &mut bad.address2,
                &mut bad.city,
                &mut bad.state,
                &mut bad.postal_code,
                &mut bad.country,
                &mut bad.callsign,
            ];
            fields
                .into_iter()
                .nth(index)
                .expect("field")
                .push_str(invalid);
            assert!(
                matches!(bad.validate(), Err(RequestError::Invalid(_))),
                "field {index}: {invalid:?}"
            );
        }
    }
    for (index, (field, _, max, required)) in good.text_fields().into_iter().enumerate() {
        let mut bad = good.clone();
        let fields = [
            &mut bad.provider,
            &mut bad.provider_unit,
            &mut bad.email,
            &mut bad.name,
            &mut bad.address1,
            &mut bad.address2,
            &mut bad.city,
            &mut bad.state,
            &mut bad.postal_code,
            &mut bad.country,
            &mut bad.callsign,
        ];
        *fields.into_iter().nth(index).expect("field") = "x".repeat(max + 1);
        assert_eq!(bad.validate(), Err(RequestError::Invalid(field)));
        if required {
            let mut bad = good.clone();
            for empty in ["", "   "] {
                let fields = [
                    &mut bad.provider,
                    &mut bad.provider_unit,
                    &mut bad.email,
                    &mut bad.name,
                    &mut bad.address1,
                    &mut bad.address2,
                    &mut bad.city,
                    &mut bad.state,
                    &mut bad.postal_code,
                    &mut bad.country,
                    &mut bad.callsign,
                ];
                *fields.into_iter().nth(index).expect("field") = empty.into();
                assert_eq!(bad.validate(), Err(RequestError::Invalid(field)));
                assert_eq!(
                    bad.generate(Authorization::New).err(),
                    Some(RequestError::Invalid(field))
                );
            }
        }
    }
    for email in [
        "no-at.invalid",
        "test@invalid",
        "test.example@invalid",
        "tést@example.invalid",
    ] {
        let mut bad = good.clone();
        bad.email = email.into();
        assert_eq!(bad.validate(), Err(RequestError::Invalid("EMAIL")));
    }
    for call in ["qg0test", "QG*TEST", "/QG0TEST"] {
        let mut bad = good.clone();
        bad.callsign = call.into();
        assert_eq!(bad.validate(), Err(RequestError::Invalid("CALLSIGN")));
    }
}

#[test]
fn mismatched_signers_and_changed_renewal_identity_are_refused() {
    let certificate =
        Certificate::from_pem_or_der(&corpus("tqsl/1024/tqsl/certs/user")).expect("certificate");
    let entry = fixture_key("tqsl/1024/tqsl/keys/QG0TEST");
    let key = entry.unlock(None).expect("key");
    let wrong = fixture_key("tqsl/1024-password/tqsl/keys/QG0TEST")
        .unlock(Some(b"qgt-key"))
        .expect("wrong key");
    let req = request("QG0TEST");
    for auth in [
        Authorization::Additional {
            certificate: &certificate,
            key: &wrong,
        },
        Authorization::Renewal {
            certificate: &certificate,
            key: &wrong,
        },
    ] {
        assert_eq!(req.generate(auth).err(), Some(RequestError::SignerMismatch));
    }
    let auth = Authorization::Renewal {
        certificate: &certificate,
        key: &key,
    };
    let mut changed = req.clone();
    changed.callsign = "QG1TEST".into();
    assert_eq!(
        changed.generate(auth).err(),
        Some(RequestError::SignerMismatch)
    );
    changed = req;
    changed.dxcc = 1;
    assert_eq!(
        changed.generate(auth).err(),
        Some(RequestError::SignerMismatch)
    );
}

#[test]
fn kinds_are_wizard_intent_and_do_not_invent_tq5_fields() {
    let mut req = request("QG0TEST");
    let entry = fixture_key("tqsl/1024/tqsl/keys/QG0TEST");
    let csr = req
        .csr(
            &entry.pkcs8_der(None).expect("key"),
            &entry.public_key_der().expect("public"),
        )
        .expect("CSR");
    let personal = req.frame(&csr, Authorization::New, None).expect("frame");
    for kind in [
        CallKind::Club,
        CallKind::Dxpedition,
        CallKind::SpecialEvent,
        CallKind::Former,
        CallKind::Replacing,
        CallKind::QslManager,
    ] {
        req.kind = kind;
        req.validate().expect("kind");
        assert_eq!(
            req.frame(&csr, Authorization::New, None).expect("frame"),
            personal
        );
    }
}

#[test]
fn normalization_uses_c_locale_whitespace_and_preserves_other_characters() {
    assert_eq!(normalize_text(" \t\n\u{000b}\u{000c}\r"), "");
    assert_eq!(
        normalize_text(" \tAlpha\n\u{000b}  Beta\u{000c}\rGamma "),
        "Alpha Beta Gamma"
    );
    // Unicode whitespace is not C-locale isspace; retain it, including at the ends.
    assert_eq!(
        normalize_text("\u{00a0}André  Test\u{2003}"),
        "\u{00a0}André Test\u{2003}"
    );
}

#[test]
fn optional_fields_dates_trimming_and_openssl_subject_encoding() {
    let mut req = request("QG0TEST");
    req.provider = "  Test   Provider  ".into();
    req.provider_unit = "  Test   Unit  ".into();
    req.callsign = "  QG0TEST   ".into();
    req.name = "  André   Test  ".into();
    req.address1 = "  1   No  Place  ".into();
    req.address2 = "  Suite   2  ".into();
    req.city = "  Test   City  ".into();
    req.state = "  Test   State  ".into();
    req.country = "  Test   Country  ".into();
    req.postal_code = "  123   45  ".into();
    req.email = "  test@example.invalid   ".into();
    req.qso_not_after = Date::from_iso("2026-11-04");
    let generated = req.generate(Authorization::New).expect("request");
    let records = parse_tq5(generated.tq5());
    for (field, value) in [
        ("PROVIDER", "Test Provider"),
        ("PROVIDER_UNIT", "Test Unit"),
        ("NAME", "André Test"),
        ("ADDRESS1", "1 No Place"),
        ("ADDRESS2", "Suite 2"),
        ("CITY", "Test City"),
        ("STATE", "Test State"),
        ("COUNTRY", "Test Country"),
        ("POSTAL", "123 45"),
        ("EMAIL", "test@example.invalid"),
        ("QSO_NOT_AFTER", "2026-11-04"),
    ] {
        assert_eq!(records[0].text(&format!("TQSL_CRQ_{field}")), Some(value));
    }
    let csr = csr_in(generated.tq5());
    let common_name = csr.info.subject.0[1].0.iter().next().expect("CN");
    assert_eq!(
        common_name.value.value(),
        latin1_utf8("André Test").as_bytes()
    );
    verify_csr(&csr);
}

#[test]
fn issuer_uses_openssl_oneline_escaping_and_multivalued_rdn_separator() {
    // Expected spelling checked against OpenSSL's X509_NAME_oneline (`-nameopt compat`),
    // the routine tqsl_getCertificateIssuer calls, rather than RFC 4514 name formatting.
    let mut cert =
        x509_cert::Certificate::from_pem(corpus("tqsl/1024/tqsl/certs/user")).expect("template");
    let attr = |oid, value: &str| AttributeTypeAndValue {
        oid: ObjectIdentifier::new_unwrap(oid),
        value: Any::encode_from(&Utf8StringRef::new(value).expect("UTF-8")).expect("value"),
    };
    cert.tbs_certificate.issuer = RdnSequence(vec![
        RelativeDistinguishedName(SetOfVec::try_from(vec![attr("2.5.4.10", "A/B")]).expect("RDN")),
        RelativeDistinguishedName(SetOfVec::try_from(vec![attr("2.5.4.3", "C+D")]).expect("RDN")),
        RelativeDistinguishedName(SetOfVec::try_from(vec![attr("2.5.4.11", "Jöhn")]).expect("RDN")),
        RelativeDistinguishedName(
            SetOfVec::try_from(vec![attr("2.5.4.10", "A"), attr("2.5.4.3", "B")]).expect("RDN"),
        ),
    ]);
    let certificate =
        Certificate::from_pem_or_der(&cert.to_der().expect("DER")).expect("certificate");
    assert_eq!(
        issuer(&certificate).expect("issuer"),
        "/O=A\\/B/CN=C\\+D/OU=J\\xC3\\xB6hn/CN=B+O=A"
    );
    // tqsllib supplies only 256 bytes; OpenSSL stops before the first complete entry that
    // cannot fit. It must not skip that entry and then resume with a later one.
    cert.tbs_certificate.issuer.0.insert(
        1,
        RelativeDistinguishedName(
            SetOfVec::try_from(vec![attr("2.5.4.11", &"x".repeat(256))]).expect("RDN"),
        ),
    );
    let certificate =
        Certificate::from_pem_or_der(&cert.to_der().expect("DER")).expect("certificate");
    assert_eq!(issuer(&certificate).expect("issuer"), "/O=A\\/B");
}

#[test]
fn a_clock_before_the_epoch_cannot_create_pending_metadata() {
    use std::time::{Duration, UNIX_EPOCH};
    assert_eq!(
        creation_time(UNIX_EPOCH - Duration::from_secs(1)),
        Err(RequestError::Clock)
    );
    assert_eq!(creation_time(UNIX_EPOCH), Ok(0));
    assert_eq!(
        creation_time(UNIX_EPOCH + Duration::from_secs(123)),
        Ok(123)
    );
}
