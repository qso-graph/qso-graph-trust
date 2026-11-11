// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;
use std::time::Duration;

#[test]
fn boundary_collision_is_retried_and_random_failure_is_returned() {
    let payload = format!("binary\0qgt-{}\r\n", "00".repeat(16));
    let mut attempts = 0;
    let boundary = boundary_with(payload.as_bytes(), |out| {
        out.fill(attempts);
        attempts += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(boundary, format!("qgt-{}", "01".repeat(16)));
    assert_eq!(
        boundary_with(b"", |_| Err(Error::Random)),
        Err(Error::Random)
    );
}

#[test]
fn filename_uses_tqsls_utc_format() {
    for (seconds, expected) in [
        (0, "19700101-0000"),
        (951_827_696, "20000229-1234"),
        (4_107_542_400, "21000301-0000"),
    ] {
        assert_eq!(
            filename(UNIX_EPOCH + Duration::from_secs(seconds), "log.tq8"),
            format!("<TQSLUpl {expected}> log.tq8")
        );
    }
    assert_eq!(
        filename(UNIX_EPOCH - Duration::from_secs(1), "log.tq8"),
        filename(UNIX_EPOCH, "log.tq8")
    );
}

#[test]
fn an_upload_is_named_by_its_file_and_never_its_folder() {
    assert_eq!(upload_name("us12223.tq8"), "us12223.tq8");
    assert_eq!(upload_name("/Users/someone/logs/us7831.tq8"), "us7831.tq8");
    assert_eq!(upload_name("C:\\Logs\\Field Day.TQ8"), "Field_Day.TQ8");
    assert_eq!(upload_name("contest.adi"), "contest.adi.tq8");
    // Nothing that could end the header's quoted filename, or start a new line, survives.
    assert_eq!(upload_name("a\"b\r\nX: y.tq8"), "a_b__X__y.tq8");
    assert_eq!(upload_name(""), "log.tq8");
    assert_eq!(upload_name("/logs/"), "log.tq8");
    assert_eq!(upload_name(".."), "log.tq8");
    assert_eq!(upload_name(&"x".repeat(200)).len(), 64 + 4);
}

#[test]
fn a_named_upload_sends_that_name() {
    let request =
        super::UploadRequest::try_named(b"signed", "/home/someone/us12223.tq8").expect("request");
    let head = String::from_utf8_lossy(request.body()).to_string();
    assert!(head.contains("> us12223.tq8\"\r\n"), "{head}");
    assert!(!head.contains("someone"), "{head}");
}

#[test]
fn only_a_signed_log_is_one_to_upload() {
    use super::{NotASignedLog, check_signed_log};
    let corpus = |f: &str| {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus/standard")
                .join(f),
        )
        .expect(f)
    };
    let tq7 = corpus("signed/W4W-EVENT.tq7");
    let tq8 = crate::signed_log::tq8(&tq7);
    assert_eq!(check_signed_log(&tq8), Ok(tq8.clone()));
    // Found in review: a key in gzip's comment field, which decompressing skips. What is returned
    // to upload is the checked log alone, gzipped afresh.
    let mut commented = tq8[..10].to_vec();
    commented[3] |= 0x10; // FCOMMENT
    commented.extend_from_slice(b"-----BEGIN PRIVATE KEY-----MIIC-----END PRIVATE KEY-----\0");
    commented.extend_from_slice(&tq8[10..]);
    let sent = check_signed_log(&commented).expect("the log itself is a signed log");
    assert_eq!(sent, tq8);
    assert!(!sent.windows(11).any(|w| w == b"PRIVATE KEY"));
    // And data after the gzip stream.
    let mut trailing = tq8.clone();
    trailing.extend_from_slice(b"-----BEGIN PRIVATE KEY-----");
    if let Ok(sent) = check_signed_log(&trailing) {
        assert_eq!(sent, tq8);
    }
    // A TQSL backup is gzip too, and holds private keys.
    assert_eq!(
        check_signed_log(&corpus("standard.tbk")),
        Err(NotASignedLog)
    );
    // Not gzip, gzip of something else, and a signed log with no QSO.
    assert_eq!(check_signed_log(&tq7), Err(NotASignedLog));
    assert_eq!(
        check_signed_log(&crate::signed_log::tq8(&corpus("adif/W4W-EVENT.adi"))),
        Err(NotASignedLog)
    );
    let text = String::from_utf8(tq7.clone()).expect("text");
    let header: String = text
        .split("<Rec_Type:8>tCONTACT")
        .next()
        .expect("head")
        .into();
    assert_eq!(
        check_signed_log(&crate::signed_log::tq8(header.as_bytes())),
        Err(NotASignedLog)
    );
    // Found in review: a field that no signed log has, and text after the last record.
    let planted = |text: String| check_signed_log(&crate::signed_log::tq8(text.as_bytes()));
    assert_eq!(
        planted(text.replacen(
            "<Rec_Type:8>tCONTACT",
            "<Rec_Type:8>tCONTACT\n<PRIVATE_KEY:4>TEST",
            1
        )),
        Err(NotASignedLog)
    );
    assert_eq!(
        planted(format!(
            "{text}\n-----BEGIN PRIVATE KEY-----\nMIIC\n-----END PRIVATE KEY-----\n"
        )),
        Err(NotASignedLog)
    );
    // A key's base64 where a certificate goes is not a certificate.
    let start = text.find("<CERTIFICATE:").expect("certificate");
    let end = start + text[start..].find("<eor>").expect("end");
    assert_eq!(
        planted(format!(
            "{}<CERTIFICATE:8>TUlJQ2Rn{}",
            &text[..start],
            &text[end..]
        )),
        Err(NotASignedLog)
    );
    // Found in review: a key where the signed data goes. What was signed must be the QSO's own
    // fields, so a PEM there is refused.
    let pem = String::from_utf8(
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus/pki/user-1024.key.pem"),
        )
        .expect("test key"),
    )
    .expect("text");
    let sd = text.find("<SIGNDATA:").expect("signdata");
    let sd_end = sd + text[sd..].find('\n').expect("line");
    assert_eq!(
        planted(format!(
            "{}<SIGNDATA:{}>{pem}{}",
            &text[..sd],
            pem.len(),
            &text[sd_end..]
        )),
        Err(NotASignedLog)
    );
    assert_eq!(
        planted(format!(
            "<TQSL_IDENT:4>TEST\n<Rec_Type:8>tCONTACT\n<SIGNDATA:{}>{pem}<eor>\n",
            pem.len()
        )),
        Err(NotASignedLog)
    );
    // Not bounded by a record count: more records than the ADIF reader takes still pass.
    let head = &text[..text.find("<Rec_Type:8>tCONTACT").expect("contact")];
    let contact = &text[text.find("<Rec_Type:8>tCONTACT").expect("contact")..];
    let contact = &contact[..contact.find("<eor>").expect("end") + 5];
    let mut big = String::from(head);
    for _ in 0..(crate::records::MAX_RECORDS + 1) {
        big.push_str(contact);
        big.push('\n');
    }
    assert!(planted(big).is_ok());
}

#[test]
fn every_signature_is_nonempty_base64_of_its_own_certificates_modulus_length() {
    use pkcs8::der::{
        Decode, Encode, Tag,
        asn1::{AnyRef, BitString, UintRef},
    };
    let tq7 = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus/tqsl/1024/qg0test-small.tq7"),
    )
    .unwrap();
    let text = String::from_utf8(tq7).unwrap();
    let check = |text: &str| check_signed_log(&crate::gzip::compress(text.as_bytes()));
    assert!(check(&text).is_ok());
    fn replace_field(text: &str, name: &str, value: &str) -> String {
        let start = text.find(&format!("<{name}:")).unwrap();
        let close = start + text[start..].find('>').unwrap();
        let len: usize = text[start + 1..close]
            .split(':')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let mut result = text.to_owned();
        result.replace_range(
            start..close + 1 + len,
            &format!("<{name}:{}>{value}", value.len()),
        );
        result
    }
    for bad in [
        String::new(),
        " \n\r".to_owned(),
        "!".repeat(172),
        Base64::encode_string(&[0; 127]),
        Base64::encode_string(&[0; 129]),
        "A".repeat(172),
        "AA=A".repeat(43),
    ] {
        assert!(check(&replace_field(&text, lotw::SIGNATURE_FIELD, &bad)).is_err());
    }
    let records = crate::records::parse(text.as_bytes()).unwrap();
    let cert_text = records[0].text("CERTIFICATE").unwrap();
    let der = Base64::decode_vec(
        &cert_text
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    )
    .unwrap();
    let mut cert = x509_cert::Certificate::from_der(&der).unwrap();
    // A synthetic public certificate with a 2048-bit modulus. This check deliberately does not
    // verify certificate/signature cryptography; it must bind length to the referenced certificate.
    let n = [0x81; 256];
    let integers = [
        UintRef::new(&n).unwrap().to_der().unwrap(),
        UintRef::new(&[1, 0, 1]).unwrap().to_der().unwrap(),
    ]
    .concat();
    let public = AnyRef::new(Tag::Sequence, &integers)
        .unwrap()
        .to_der()
        .unwrap();
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key = BitString::from_bytes(&public).unwrap();
    let cert_b64 = crate::signing::tqsl_base64(&cert.to_der().unwrap());
    assert_eq!(rsa_signature_len(cert_b64.as_bytes()).unwrap(), 256);
    let cert_at = text.find("<Rec_Type:5>tCERT").unwrap();
    let cert_end = cert_at + text[cert_at..].find("<eor>").unwrap() + 5;
    let repeated = format!(
        "{}{}{}",
        &text[..cert_end],
        &text[cert_at..cert_end],
        &text[cert_end..]
    );
    assert!(
        check(&repeated).is_err(),
        "certificate identifiers must identify one certificate"
    );
    assert!(check(&replace_field(&text, "CERT_UID", "")).is_err());
    let at = text.find("<Rec_Type:8>tSTATION").unwrap();
    let second_cert = format!(
        "<Rec_Type:5>tCERT<CERT_UID:1>2<CERTIFICATE:{}>{cert_b64}<eor>\n",
        cert_b64.len()
    );
    let changed = format!(
        "{}{}{}",
        &text[..at],
        second_cert,
        replace_field(&text[at..], "CERT_UID", "2")
    );
    assert!(
        check(&changed).is_err(),
        "128-byte signatures cannot name the 256-byte certificate"
    );
    let mut changed = changed;
    // Replace all signatures, keeping the exact QSO/station SIGNDATA untouched.
    let mut start = 0;
    while let Some(relative) = changed[start..].find("<SIGN_LOTW_V2.0:") {
        let at = start + relative;
        let value = crate::signing::tqsl_base64(&[0; 256]);
        let suffix = replace_field(&changed[at..], lotw::SIGNATURE_FIELD, &value);
        changed.replace_range(at.., &suffix);
        start = at + format!("<SIGN_LOTW_V2.0:{}>", value.len()).len() + value.len();
    }
    assert!(
        check(&changed).is_ok(),
        "length is read from the signing certificate, not hardcoded"
    );
    let at = changed.find("<Rec_Type:8>tSTATION").unwrap();
    let unknown = format!(
        "{}{}",
        &changed[..at],
        replace_field(&changed[at..], "CERT_UID", "9")
    );
    assert!(
        check(&unknown).is_err(),
        "the station must name an existing certificate"
    );
}
