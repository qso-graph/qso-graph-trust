// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;
use crate::signing::{KeyEntry, KeyError};
use x509_cert::der::{DecodePem, Encode};

fn file(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus")
            .join(name),
    )
    .expect("test file")
}
fn trust() -> Trust {
    Trust::with_roots(&[&file("tqsl/pki/root.pem")]).expect("root")
}
fn tlv(tag: u8, value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() + 6));
    out.push(tag);
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let len = (value.len() as u32).to_be_bytes();
        let start = len.iter().position(|b| *b != 0).expect("length");
        out.push(128 | (4 - start) as u8);
        out.extend_from_slice(&len[start..]);
    }
    out.extend_from_slice(value);
    out
}
fn concat(pieces: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(pieces.iter().map(|p| p.len()).sum()));
    for piece in pieces {
        out.extend_from_slice(piece);
    }
    out
}
fn seq(pieces: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    tlv(0x30, &concat(pieces))
}
fn data(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    seq(&[&tlv(6, DATA), &tlv(0xa0, &tlv(4, bytes))])
}
fn bag(oid: &[u8], value: &[u8]) -> Zeroizing<Vec<u8>> {
    seq(&[&tlv(6, oid), &tlv(0xa0, value)])
}
fn cert_bag() -> Zeroizing<Vec<u8>> {
    let der = x509_cert::Certificate::from_pem(file("tqsl/1024/tqsl/certs/user"))
        .expect("cert")
        .to_der()
        .expect("DER");
    bag(
        CERT_BAG,
        &seq(&[&tlv(6, X509_BAG), &tlv(0xa0, &tlv(4, &der))]),
    )
}
fn authority_bag() -> Zeroizing<Vec<u8>> {
    let der = x509_cert::Certificate::from_pem(file("tqsl/pki/ca.pem"))
        .expect("CA")
        .to_der()
        .expect("DER");
    bag(
        CERT_BAG,
        &seq(&[&tlv(6, X509_BAG), &tlv(0xa0, &tlv(4, &der))]),
    )
}
fn pfx(auth: &[u8]) -> Zeroizing<Vec<u8>> {
    let password = bmp(b"qgt-test").expect("password");
    let key = kdf::<Sha256>(&password, b"test-salt", 2048, 3, 32);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC");
    Mac::update(&mut mac, auth);
    let digest = mac.finalize().into_bytes();
    let info = seq(&[&seq(&[&tlv(6, SHA256), &tlv(5, &[])]), &tlv(4, &digest)]);
    let mac = seq(&[&info, &tlv(4, b"test-salt"), &tlv(2, &[8, 0])]);
    seq(&[&tlv(2, &[3]), &data(auth), &mac])
}
fn key_bag(name: &str, password: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let key = KeyEntry::read_key_file(&file(name)).expect("key").remove(0);
    bag(KEY_BAG, &key.pkcs8_der(password).expect("DER"))
}

#[test]
fn pkcs12_sha1_3des_pbe_loads_and_matches_the_corpus_key() {
    // The weak corpus has RC2 certificates, refused by policy. Keep its actual 3DES shrouded
    // keybag unchanged but put the same certificates in a plaintext safe, then authenticate it.
    let bytes = file("tqsl/1024/QG0TEST-weak.p12");
    let mut outer = sequence(&bytes).expect("PFX");
    outer.uint().expect("version");
    let mut safe = outer.sequence().expect("safe");
    safe.value(6).expect("OID");
    let mut auth =
        sequence(one(safe.value(0xa0).expect("content"), 4).expect("octets")).expect("auth");
    auth.sequence().expect("RC2 content");
    let key_content = auth.0;
    let public = seq(&[&cert_bag(), &authority_bag()]);
    let auth = seq(&[&data(&public), key_content]);
    let imported = read(&pfx(&auth), b"qgt-test", &trust()).expect("3DES import");
    let expected = KeyEntry::read_key_file(&file("tqsl/1024/tqsl/keys/QG0TEST"))
        .expect("key")
        .remove(0)
        .unlock(None)
        .expect("unlock")
        .sign(b"test")
        .expect("sign");
    assert_eq!(
        signing::TqslKey::from_pkcs8_der(&imported.key, imported.certificate.public_key_der())
            .expect("key")
            .sign(b"test")
            .expect("sign"),
        expected
    );
}

#[test]
fn authenticated_key_certificate_mismatch_is_refused() {
    let safe = seq(&[
        &cert_bag(),
        &authority_bag(),
        &key_bag(
            "standard/tqsl/keys/W4W",
            Some(&file("standard/keys/W4W.password")),
        ),
    ]);
    let auth = seq(&[&data(&safe)]);
    assert!(matches!(
        read(&pfx(&auth), b"qgt-test", &trust()),
        Err(ImportError::Key(KeyError::PublicKeyMismatch))
    ));
}

#[test]
fn nested_bags_counts_and_der_sizes_are_bounded() {
    let mut safe = seq(&[
        &cert_bag(),
        &authority_bag(),
        &key_bag("tqsl/1024/tqsl/keys/QG0TEST", None),
    ]);
    // The planted nesting is accepted at the limit, then refused one level past it.
    for _ in 0..MAX_DEPTH {
        safe = seq(&[&bag(SAFE_BAG, &safe)]);
    }
    let accepted = pfx(&seq(&[&data(&safe)]));
    assert!(read(&accepted, b"qgt-test", &trust()).is_ok());
    safe = seq(&[&bag(SAFE_BAG, &safe)]);
    assert!(matches!(
        read(&pfx(&seq(&[&data(&safe)])), b"qgt-test", &trust()),
        Err(ImportError::Limit)
    ));
    let certs = concat(
        &(0..=MAX_IMPORT_ITEMS)
            .map(|_| cert_bag())
            .collect::<Vec<_>>()
            .iter()
            .map(|b| b.as_slice())
            .collect::<Vec<_>>(),
    );
    assert!(matches!(
        read(
            &pfx(&seq(&[&data(&tlv(0x30, &certs))])),
            b"qgt-test",
            &trust()
        ),
        Err(ImportError::Limit)
    ));
    assert!(matches!(
        read(&vec![0; MAX_IMPORT_LEN + 1], b"", &trust()),
        Err(ImportError::Limit)
    ));
    for der in [
        &[0x30, 0x80, 0, 0][..],
        &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff][..],
        &[0x30, 0x81, 1, 0][..],
    ] {
        assert!(sequence(der).is_err());
    }
    let attrs = tlv(0x30, &tlv(0x30, &[0x30, 0]));
    assert!(attributes(&attrs, MAX_DEPTH - 3, &mut 0).is_ok());
    assert!(matches!(
        attributes(&attrs, MAX_DEPTH - 2, &mut 0),
        Err(ImportError::Limit)
    ));
}

#[test]
fn absurd_kdf_counts_are_refused_before_deriving() {
    let mut budget = MAX_WORK;
    assert!(work(MAX_ITERATIONS, 1, &mut budget).is_ok());
    for count in [0, MAX_ITERATIONS + 1, u32::MAX] {
        assert!(matches!(
            work(count, 1, &mut budget),
            Err(ImportError::Limit)
        ));
    }
    // Plant absurd counts in both MAC data and encryption parameters; otherwise valid structures.
    let mac = concat(&[
        &seq(&[&seq(&[&tlv(6, SHA1)]), &tlv(4, &[0; 20])]),
        &tlv(4, b"salt"),
        &tlv(2, &[0x7f, 0xff, 0xff, 0xff]),
    ]);
    assert!(matches!(
        verify_mac(&mac, b"test", b"", &mut budget),
        Err(ImportError::Limit)
    ));
    let algorithm = concat(&[
        &tlv(6, PBE_3DES),
        &seq(&[&tlv(4, b"salt"), &tlv(2, &[0x7f, 0xff, 0xff, 0xff])]),
    ]);
    assert!(matches!(
        decrypt(&algorithm, &[0; 8], b"", b"", &mut budget),
        Err(ImportError::Limit)
    ));
    let pbkdf2 = &[42, 134, 72, 134, 247, 13, 1, 5, 12];
    let aes256 = &[96, 134, 72, 1, 101, 3, 4, 1, 42];
    let params = seq(&[
        &seq(&[
            &tlv(6, pbkdf2),
            &seq(&[&tlv(4, b"salt"), &tlv(2, &[0x7f, 0xff, 0xff, 0xff])]),
        ]),
        &seq(&[&tlv(6, aes256), &tlv(4, &[0; 16])]),
    ]);
    let algorithm = concat(&[&tlv(6, PBES2), &params]);
    assert!(matches!(
        decrypt(&algorithm, &[0; 16], b"", b"", &mut budget),
        Err(ImportError::Limit)
    ));
    assert!(matches!(work(1, 1, &mut 0), Err(ImportError::Limit)));
}

#[test]
fn password_encoding_and_missing_mac_are_explicit() {
    assert_eq!(&*bmp(b"").expect("empty password"), &[0, 0]);
    assert_eq!(&*bmp("aé".as_bytes()).expect("BMP"), &[0, 97, 0, 233, 0, 0]);
    assert!(bmp(&[255]).is_err());
    assert!(bmp("🔑".as_bytes()).is_err());
    assert!(matches!(
        bmp(&vec![b'a'; MAX_PASSWORD_LEN + 1]),
        Err(ImportError::Limit)
    ));
    let missing = seq(&[&tlv(2, &[3]), &data(&seq(&[]))]);
    assert!(matches!(
        read(&missing, b"", &trust()),
        Err(ImportError::Authentication)
    ));
}
