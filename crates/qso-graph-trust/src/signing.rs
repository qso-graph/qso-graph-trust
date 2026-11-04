// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Signing a QSO record as LoTW accepts it: RSA PKCS#1 v1.5 over SHA-1, the `SIGN_LOTW_V2.0` field,
//! as tqsllib signs (TQSL 2.8.7 `src/openssl_cert.cpp:2215`, `EVP_SignInit(ctx, EVP_sha1())`).
//!
//! The key is read from tqsllib's key file (`keys/<call>`), plain or protected by a password, and
//! once unlocked it can only sign: nothing here returns it, prints it or puts it in an error.
//! The RSA itself is AWS-LC's, through QG Trust's one binding (`qso-graph-trust-awslc`,
//! docs/decisions/0006): constant-time, and it overwrites every block it frees, so neither the key's
//! numbers nor their temporaries are left in memory.
//! Every buffer here that holds key text is wiped when dropped (`Zeroizing`), and a protected key's
//! encryption parameters are checked before any work is done with the password, so a crafted file
//! cannot ask for unbounded memory or time (found by Codex review).

use std::fmt;

use base64ct::{Base64, Encoding};
use pkcs8::der::Decode;
use qso_graph_trust_awslc::RsaKey;
use zeroize::Zeroizing;

use crate::protected_key::{Envelope, Parameters};
use crate::records::{self, Record, RecordError};

/// One key from a tqsllib key file, still locked: its call and public key, and the private key as
/// stored. [`KeyEntry::unlock`] turns it into a [`TqslKey`] that can sign.
#[derive(Clone)]
pub struct KeyEntry {
    callsign: String,
    request_dxcc: Option<u32>,
    public_key_pem: String,
    private_key_pem: Zeroizing<String>,
}

impl fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntry")
            .field("callsign", &self.callsign)
            .field("encrypted", &self.is_encrypted())
            .finish_non_exhaustive()
    }
}

/// A key that can sign. It cannot be read back out.
pub struct TqslKey {
    key: RsaKey,
}

impl fmt::Debug for TqslKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TqslKey(..)")
    }
}

/// Why a key could not be read, unlocked or used. It never holds a password or any key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The key file is not in tqsllib's record format.
    File(RecordError),
    /// A record in the key file lacks this field.
    MissingField(&'static str),
    /// A record in the key file gives this field more than once.
    RepeatedField(&'static str),
    /// The private key is not PKCS#8 PEM as tqsllib writes it.
    NotAKey,
    /// The key is protected and no password was given.
    PasswordNeeded,
    /// The password does not unlock the key.
    WrongPassword,
    /// The key is not an RSA key.
    NotRsa,
    /// The key file is larger than any key file tqsllib writes ([`MAX_KEY_FILE_LEN`]).
    FileTooLarge,
    /// The key is not one LoTW uses: RSA with a 1024-bit modulus, two different 512-bit primes and
    /// the public exponent 65537, as tqsllib makes them.
    NotLotwKey,
    /// The key file's PUBLIC_KEY is not the public half of its PRIVATE_KEY.
    PublicKeyMismatch,
    /// The key is protected in a way QG Trust does not accept: a scheme other than PBES2 with
    /// PBKDF2, a hash or cipher tqsllib never uses, or more PBKDF2 iterations than the limit.
    UnsupportedProtection,
    /// The signature could not be made.
    Signing,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(e) => write!(f, "the key file could not be read: {e}"),
            Self::MissingField(name) => write!(f, "the key file has no {name}"),
            Self::RepeatedField(name) => write!(f, "the key file gives {name} more than once"),
            Self::NotAKey => f.write_str("the key file does not hold a private key"),
            Self::PasswordNeeded => f.write_str("this key is protected: its password is needed"),
            Self::WrongPassword => f.write_str("the password does not unlock this key"),
            Self::NotRsa => f.write_str("the key is not an RSA key"),
            Self::FileTooLarge => f.write_str("the key file is too large to be one"),
            Self::NotLotwKey => f.write_str("the key is not the kind LoTW uses"),
            Self::PublicKeyMismatch => {
                f.write_str("the key file's public key does not belong to its private key")
            }
            Self::UnsupportedProtection => {
                f.write_str("the key is protected in a way QG Trust does not accept")
            }
            Self::Signing => f.write_str("the record could not be signed"),
        }
    }
}

impl std::error::Error for KeyError {}

const ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

/// The largest key file read: one key file holds a key per certificate request, each a few KiB.
pub const MAX_KEY_FILE_LEN: usize = 1024 * 1024;

/// PBKDF2 and CBC through the binding's AWS-LC API. Parameters are bounded before any
/// provider work; derived keys, provider key schedules and plaintext are wiped when dropped.
pub(crate) fn decrypt(
    params: &Parameters<'_>,
    password: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    if !params.accepted() {
        return Err(KeyError::UnsupportedProtection);
    }
    let key = qso_graph_trust_awslc::import_pbkdf2(
        params.digest,
        password,
        params.salt,
        std::num::NonZeroU32::new(params.iteration_count).ok_or(KeyError::UnsupportedProtection)?,
        params.key_len,
    );
    qso_graph_trust_awslc::import_cbc_decrypt(params.cipher, &key, params.iv, ciphertext)
        .map_err(|_| KeyError::WrongPassword)
}

/// The most PBKDF2 iterations accepted. tqsllib 2.8.7 writes 2,048 (OpenSSL's default); a million
/// takes well under a second, so a crafted file cannot make unlocking take unbounded time.
pub const MAX_PBKDF2_ITERATIONS: u32 = 1_000_000;

impl KeyEntry {
    /// Every key in a tqsllib key file, in the order written: one per certificate request made.
    pub fn read_key_file(bytes: &[u8]) -> Result<Vec<KeyEntry>, KeyError> {
        if bytes.len() > MAX_KEY_FILE_LEN {
            return Err(KeyError::FileTooLarge);
        }
        records::parse(bytes)
            .map_err(KeyError::File)?
            .iter()
            .map(Self::from_record)
            .collect()
    }

    fn from_record(record: &Record) -> Result<KeyEntry, KeyError> {
        // A key field given twice is refused: QG Trust would read the first and tqsllib the last,
        // so the two could unlock different keys from one file (found by Codex review).
        for name in [
            "CALLSIGN",
            "PUBLIC_KEY",
            "PRIVATE_KEY",
            "TQSL_CRQ_DXCC_ENTITY",
        ] {
            if record
                .fields
                .iter()
                .filter(|f| f.name.eq_ignore_ascii_case(name))
                .count()
                > 1
            {
                return Err(KeyError::RepeatedField(name));
            }
        }
        let text = |name: &'static str| record.text(name).ok_or(KeyError::MissingField(name));
        // The DXCC entity the certificate was requested for, as tqsllib records it with the key.
        // Present but not text is not absent (found by Codex review).
        let request_dxcc = match record.get("TQSL_CRQ_DXCC_ENTITY") {
            None => None,
            Some(v) => Some(
                std::str::from_utf8(v)
                    .ok()
                    .and_then(|d| d.trim().parse().ok())
                    .ok_or(KeyError::NotAKey)?,
            ),
        };
        Ok(KeyEntry {
            callsign: text("CALLSIGN")?.to_string(),
            request_dxcc,
            public_key_pem: text("PUBLIC_KEY")?.to_string(),
            private_key_pem: Zeroizing::new(text("PRIVATE_KEY")?.to_string()),
        })
    }

    /// The call this key was made for.
    pub fn callsign(&self) -> &str {
        &self.callsign
    }

    /// The DXCC entity the key's certificate was requested for, if the key file records it.
    pub fn request_dxcc(&self) -> Option<u32> {
        self.request_dxcc
    }

    /// The public key, as PEM (SubjectPublicKeyInfo), for matching the key to its certificate.
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// The public key as DER (SubjectPublicKeyInfo), for comparing with a certificate's; `None` if
    /// the PEM is not a public key.
    pub fn public_key_der(&self) -> Option<Vec<u8>> {
        let (label, der) = pkcs8::der::pem::decode_vec(self.public_key_pem.as_bytes()).ok()?;
        (label == "PUBLIC KEY").then_some(der)
    }

    /// Checks what can be checked without the password: the public key is an RSA one, and a
    /// protected private key is an encrypted PKCS#8 envelope with a protection QG Trust accepts; a
    /// plain one is unlocked, which proves it whole. A protected key's private half is checked
    /// against its public half when it is first unlocked (found by Codex review: a protected key
    /// was taken on its PEM label alone).
    pub fn check(&self) -> Result<(), KeyError> {
        const RSA: pkcs8::ObjectIdentifier =
            pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        let spki = self.public_key_der().ok_or(KeyError::PublicKeyMismatch)?;
        let info = pkcs8::spki::SubjectPublicKeyInfoRef::from_der(&spki)
            .map_err(|_| KeyError::PublicKeyMismatch)?;
        if info.algorithm.oid != RSA {
            return Err(KeyError::NotRsa);
        }
        if !self.is_encrypted() {
            return self.unlock(None).map(drop);
        }
        let mut decoded = Zeroizing::new(vec![0u8; self.private_key_pem.len()]);
        let (label, der) = pkcs8::der::pem::decode(self.private_key_pem.as_bytes(), &mut decoded)
            .map_err(|_| KeyError::NotAKey)?;
        if label != "ENCRYPTED PRIVATE KEY" {
            return Err(KeyError::NotAKey);
        }
        let envelope = Envelope::from_der(der).map_err(|_| KeyError::NotAKey)?;
        let params = envelope
            .parameters()
            .map_err(|_| KeyError::UnsupportedProtection)?;
        if !params.accepted() {
            return Err(KeyError::UnsupportedProtection);
        }
        Ok(())
    }

    /// Whether the private key is protected by a password.
    pub fn is_encrypted(&self) -> bool {
        self.private_key_pem.trim_start().starts_with(ENCRYPTED)
    }

    /// Unlock the key for signing. A protected key needs its password; a plain one ignores it.
    pub fn unlock(&self, password: Option<&[u8]>) -> Result<TqslKey, KeyError> {
        crate::memory::scrub_after(|| {
            let der = self.pkcs8_der_inner(password)?;
            TqslKey::from_pkcs8_der_inner(
                &der,
                &self.public_key_der().ok_or(KeyError::PublicKeyMismatch)?,
            )
        })
    }

    // Kept inside the crate: only the credential-store handoff may obtain the DER, never a caller.
    pub(crate) fn pkcs8_der(
        &self,
        password: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        crate::memory::scrub_after(|| self.pkcs8_der_inner(password))
    }

    #[inline(never)]
    fn pkcs8_der_inner(&self, password: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        if self.is_encrypted() && password.is_none() {
            return Err(KeyError::PasswordNeeded);
        }
        // Decoded, and decrypted, into buffers wiped on every path: a key that fails to decode or
        // decrypt leaves no plaintext behind either (found by Codex review).
        let mut decoded = Zeroizing::new(vec![0u8; self.private_key_pem.len()]);
        let (label, der) = pkcs8::der::pem::decode(self.private_key_pem.as_bytes(), &mut decoded)
            .map_err(|_| KeyError::NotAKey)?;
        match label {
            "ENCRYPTED PRIVATE KEY" => {
                let password = password.ok_or(KeyError::PasswordNeeded)?;
                let info = Envelope::from_der(der).map_err(|_| KeyError::NotAKey)?;
                let params = info
                    .parameters()
                    .map_err(|_| KeyError::UnsupportedProtection)?;
                decrypt(&params, password, info.ciphertext)
            }
            "PRIVATE KEY" => Ok(Zeroizing::new(der.to_vec())),
            _ => Err(KeyError::NotAKey),
        }
    }
}

impl TqslKey {
    // A stored secret is checked again: the credential backend is not a source of trust.
    pub(crate) fn from_pkcs8_der(der: &[u8], spki: &[u8]) -> Result<Self, KeyError> {
        crate::memory::scrub_after(|| Self::from_pkcs8_der_inner(der, spki))
    }

    #[inline(never)]
    pub(crate) fn from_pkcs8_der_inner(der: &[u8], spki: &[u8]) -> Result<Self, KeyError> {
        let key = RsaKey::from_pkcs8_der(der).map_err(|_| KeyError::NotAKey)?;
        // A key LoTW uses, as tqsllib makes them: 1024 bits, e = 65537 (tqsl_new_rsa_key), two
        // different 512-bit factors, each passing AWS-LC's primality test. Anything else cannot
        // carry a LoTW certificate; unequal, equal or composite factors would sign with a modulus
        // anyone can factor, or hang (found by Codex review).
        if !key.is_lotw_shaped() {
            return Err(KeyError::NotLotwKey);
        }
        // The public key the file states is the private key's own, so a certificate matched by it
        // is this key's (found by Codex review).
        if !key.matches_public_key(spki) {
            return Err(KeyError::PublicKeyMismatch);
        }
        Ok(TqslKey { key })
    }
}

impl TqslKey {
    /// The signature over `data`, as the bytes tqsllib's `tqsl_signDataBlock` returns.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        crate::memory::scrub_after(|| self.key.sign_sha1(data).map_err(|_| KeyError::Signing))
    }

    /// Whether `spki_der`, a certificate's SubjectPublicKeyInfo, is this key's public key.
    pub fn matches_public_key(&self, spki_der: &[u8]) -> bool {
        self.key.matches_public_key(spki_der)
    }
}

/// A signature as tqsllib writes it into `SIGN_LOTW_V2.0`: base64 in lines of 64 characters, each
/// ended by a newline, the last one included (175 characters for a 1024-bit key's 128 bytes).
pub fn tqsl_base64(signature: &[u8]) -> String {
    let encoded = Base64::encode_string(signature);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 64 + 1);
    for line in encoded.as_bytes().chunks(64) {
        // Base64 output is ASCII, so each chunk is whole characters.
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::{
        EncryptedPrivateKeyInfo,
        pkcs5::{EncryptionScheme, pbes2},
    };
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    #[test]
    fn base64_is_wrapped_as_tqsllib_wraps_it() {
        let wrapped = tqsl_base64(&[0u8; 128]);
        let lines: Vec<usize> = wrapped.split('\n').map(str::len).collect();
        assert_eq!(lines, vec![64, 64, 44, 0]);
        assert_eq!(wrapped.len(), 175);
        assert_eq!(tqsl_base64(&[]), "");
    }

    #[test]
    fn a_key_entry_never_prints_its_key() {
        let entry = KeyEntry {
            request_dxcc: None,
            callsign: "QG0TEST".into(),
            public_key_pem: "public".into(),
            private_key_pem: Zeroizing::new("-----BEGIN PRIVATE KEY-----secret".into()),
        };
        let shown = format!("{entry:?}");
        assert!(
            !shown.contains("secret") && !shown.contains("public"),
            "{shown}"
        );
    }

    #[test]
    fn a_record_without_its_key_fields_is_refused() {
        let file = b"<CALLSIGN:7>QG0TEST\n<PUBLIC_KEY:1>x\n<eor>\n";
        assert_eq!(
            KeyEntry::read_key_file(file).map(|v| v.len()),
            Err(KeyError::MissingField("PRIVATE_KEY"))
        );
    }

    #[test]
    fn the_private_key_text_is_wiped_when_dropped() {
        fn wiped<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let entry = KeyEntry {
            request_dxcc: None,
            callsign: "QG0TEST".into(),
            public_key_pem: String::new(),
            private_key_pem: Zeroizing::new(String::new()),
        };
        wiped(&entry.private_key_pem);
    }

    /// A protected key whose encryption is `scheme`, as PEM, with ciphertext that is never reached.
    fn protected(scheme: EncryptionScheme<'_>) -> KeyEntry {
        use pkcs8::der::{Encode, pem::LineEnding};
        let info = EncryptedPrivateKeyInfo {
            encryption_algorithm: scheme,
            encrypted_data: &[0u8; 32],
        };
        let der = info.to_der().expect("DER");
        let pem = pkcs8::der::pem::encode_string("ENCRYPTED PRIVATE KEY", LineEnding::LF, &der)
            .expect("PEM");
        KeyEntry {
            request_dxcc: None,
            callsign: "QG0TEST".into(),
            public_key_pem: String::new(),
            private_key_pem: Zeroizing::new(pem),
        }
    }

    #[test]
    fn a_crafted_encryption_is_refused_before_any_work() {
        let (salt, iv) = ([7u8; 16], [9u8; 16]);
        // Codex review: scrypt with N = 2^30 would try to allocate about 1 TiB.
        let huge = pkcs8::pkcs5::scrypt::Params::new(30, 8, 1, 32).expect("params");
        let scrypt = pbes2::Parameters::scrypt_aes256cbc(huge, &salt, &iv).expect("scrypt");
        assert_eq!(
            protected(EncryptionScheme::Pbes2(scrypt))
                .unlock(Some(b"x"))
                .err(),
            Some(KeyError::UnsupportedProtection)
        );
        // PBKDF2 past QG Trust's limit, at the most pkcs5 will build (100,000,000, about a minute of
        // work per try): refused at once, with any password.
        let slow = pbes2::Parameters::pbkdf2_sha256_aes256cbc(
            pbes2::Pbkdf2Params::MAX_ITERATION_COUNT,
            &salt,
            &iv,
        )
        .expect("pbkdf2");
        assert_eq!(
            protected(EncryptionScheme::Pbes2(slow))
                .unlock(Some(b"x"))
                .err(),
            Some(KeyError::UnsupportedProtection)
        );
        // At the limit it is accepted: what is left to fail is only the password.
        let ok = pbes2::Parameters::pbkdf2_sha256_aes256cbc(MAX_PBKDF2_ITERATIONS, &salt, &iv)
            .expect("pbkdf2");
        use pkcs8::der::Encode;
        let encoded = ok.to_der().expect("parameters");
        assert!(
            Parameters::from_der(&encoded)
                .expect("parameters")
                .accepted()
        );
    }

    /// The test key's public half, as a key file states it.
    fn test_public_key() -> String {
        use rsa::pkcs8::EncodePublicKey;
        RsaPrivateKey::from_pkcs8_pem(include_str!("../../../tests/corpus/pki/user-1024.key.pem"))
            .expect("key")
            .to_public_key()
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .expect("PEM")
    }

    /// A key entry for `pem`, stating the test key's public key: right for the test key, plain or
    /// re-encrypted, and the check comes after the ones these tests aim at for any other.
    fn entry(pem: &str) -> KeyEntry {
        KeyEntry {
            request_dxcc: None,
            callsign: "QG0TEST".into(),
            public_key_pem: test_public_key(),
            private_key_pem: Zeroizing::new(pem.into()),
        }
    }

    #[test]
    fn a_key_protected_with_pbkdf2_hmac_sha1_unlocks_and_signs_the_same() {
        // Codex review: accepted, but pkcs8 lacked sha1-insecure, so the right password failed.
        // The test key re-encrypted the way older OpenSSL wrote TQSL's keys (PBKDF2, HMAC-SHA1).
        let plain = entry(include_str!("../../../tests/corpus/pki/user-1024.key.pem"));
        let sha1 = entry(include_str!(
            "../../../tests/corpus/pki/user-1024-pbkdf2-sha1.key.pem"
        ));
        assert!(sha1.is_encrypted());
        let data = b"4EM177SEDGWICKKS20MKC4QPQ14.074000FT82026-11-0118:30:00Z";
        let ours = sha1
            .unlock(Some(b"qgt-key"))
            .expect("unlocks")
            .sign(data)
            .expect("signs");
        assert_eq!(
            ours,
            plain
                .unlock(None)
                .expect("unlocks")
                .sign(data)
                .expect("signs")
        );
    }

    #[test]
    fn a_damaged_protected_key_is_refused() {
        // Codex review: with the right password, a damaged last block once left plaintext unwiped;
        // the decryption is now in place, in a wiped buffer, and the error is the same.
        let file = include_bytes!("../../../tests/corpus/tqsl/1024-password/tqsl/keys/QG0TEST");
        let pem = KeyEntry::read_key_file(file)
            .expect("key file")
            .remove(0)
            .private_key_pem;
        let (_, der) = pkcs8::der::pem::decode_vec(pem.as_bytes()).expect("PEM");
        let mut der = der;
        let last = der.len() - 9;
        der[last] ^= 0x80;
        let damaged = pkcs8::der::pem::encode_string(
            "ENCRYPTED PRIVATE KEY",
            pkcs8::der::pem::LineEnding::LF,
            &der,
        )
        .expect("PEM");
        assert_eq!(
            entry(&damaged).unlock(Some(b"qgt-key")).err(),
            Some(KeyError::WrongPassword)
        );
    }

    #[test]
    fn a_key_that_is_not_lotw_shaped_is_refused_before_it_can_sign() {
        use rsa::pkcs8::EncodePrivateKey;
        // Codex review: p = 3 and a 1022-bit q make a 1024-bit key that rsa accepts, whose CRT step
        // would then loop for over 2^1000 iterations. q from `openssl prime -generate -bits 1022`.
        let q = [
            "39241060f9dd871a47f383b6d93528e91ef2f26a23a18ac4c84be4a7de864fd4",
            "38956267fbd8af381f09420f73705ac1e2132bb74997b110e63688ec7fe57a23",
            "4ad07b484127addfa820c10871a478b17cc45b778ff3dd2570e7a69fa3fbb215",
            "e45b9f2cce85625caafe930ff7e6992e060b76e032f908075ba56c5c86e35fb7",
        ]
        .concat();
        let q = rsa::BigUint::parse_bytes(q.as_bytes(), 16).expect("q");
        let key =
            RsaPrivateKey::from_p_q(rsa::BigUint::from(3u32), q, rsa::BigUint::from(65_537u32))
                .expect("rsa accepts it");
        let pem = key.to_pkcs8_pem(pkcs8::LineEnding::LF).expect("PEM");
        assert_eq!(entry(&pem).unlock(None).err(), Some(KeyError::NotLotwKey));
        // A key of another size, however well made, is not LoTW's either.
        let other = RsaPrivateKey::new(&mut rand_core::OsRng, 1536).expect("key");
        let pem = other.to_pkcs8_pem(pkcs8::LineEnding::LF).expect("PEM");
        assert_eq!(entry(&pem).unlock(None).err(), Some(KeyError::NotLotwKey));
    }

    #[test]
    fn a_key_file_too_large_to_be_one_is_refused_unread() {
        assert_eq!(
            KeyEntry::read_key_file(&vec![b' '; MAX_KEY_FILE_LEN + 1]).err(),
            Some(KeyError::FileTooLarge)
        );
    }

    #[test]
    fn a_public_key_that_is_not_the_private_keys_is_refused() {
        // Codex review: certificate matching reads PUBLIC_KEY, so it must be the signing key's own.
        let file = |case: &str| -> Vec<u8> {
            std::fs::read(format!(
                "{}/../../tests/corpus/tqsl/{case}/tqsl/keys/QG0TEST",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect("key file")
        };
        let mine = KeyEntry::read_key_file(&file("1024"))
            .expect("key file")
            .remove(0);
        let other = KeyEntry::read_key_file(&file("1024-password"))
            .expect("key file")
            .remove(0);
        let crossed = KeyEntry {
            public_key_pem: other.public_key_pem.clone(),
            ..mine.clone()
        };
        assert!(mine.unlock(None).is_ok());
        assert_eq!(
            crossed.unlock(None).err(),
            Some(KeyError::PublicKeyMismatch)
        );
    }

    #[test]
    fn every_buffer_in_decryption_is_wiped() {
        fn wiped<T: zeroize::ZeroizeOnDrop>() {}
        wiped::<Zeroizing<Vec<u8>>>();
        // The provider-owned CBC schedules and its temporaries are checked by custody scans,
        // including AES-protected PKCS#12 imports, in debug and release.
    }

    /// A key file as a crafted one would be written, by hand through pkcs1 and pkcs8, from p, q
    /// and d: rsa will not write keys whose CRT values do not exist, but a file can carry any
    /// numbers. Its stated public key is n's and e's own, so only the shape check can refuse it.
    fn crafted(p: &rsa::BigUint, q: &rsa::BigUint, d: &rsa::BigUint) -> KeyEntry {
        use pkcs8::der::Encode;
        use rsa::pkcs8::EncodePublicKey;
        fn uint(b: &[u8]) -> pkcs8::der::asn1::UintRef<'_> {
            pkcs8::der::asn1::UintRef::new(b).expect("uint")
        }
        let e = rsa::BigUint::from(65_537u32);
        let n = p * q;
        let (nb, eb, db, pb, qb) = (
            n.to_bytes_be(),
            e.to_bytes_be(),
            d.to_bytes_be(),
            p.to_bytes_be(),
            q.to_bytes_be(),
        );
        let one = [1u8];
        let pkcs1_key = rsa::pkcs1::RsaPrivateKey {
            modulus: uint(&nb),
            public_exponent: uint(&eb),
            private_exponent: uint(&db),
            prime1: uint(&pb),
            prime2: uint(&qb),
            exponent1: uint(&one),
            exponent2: uint(&one),
            coefficient: uint(&one),
            other_prime_infos: None,
        }
        .to_der()
        .expect("PKCS#1");
        let info = pkcs8::PrivateKeyInfo::new(rsa::pkcs1::ALGORITHM_ID, &pkcs1_key);
        let pem = pkcs8::der::pem::encode_string(
            "PRIVATE KEY",
            pkcs8::LineEnding::LF,
            &info.to_der().expect("PKCS#8"),
        )
        .expect("PEM");
        let public = rsa::RsaPublicKey::new(n, e)
            .expect("public")
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .expect("PEM");
        KeyEntry {
            request_dxcc: None,
            callsign: "QG0TEST".into(),
            public_key_pem: public,
            private_key_pem: Zeroizing::new(pem),
        }
    }

    /// The inverse of 65537 modulo `m`.
    fn inverse_of_e(m: &rsa::BigUint) -> rsa::BigUint {
        use num_bigint_dig::ModInverse;
        rsa::BigUint::from(65_537u32)
            .mod_inverse(m)
            .and_then(|d| d.to_biguint())
            .expect("d")
    }

    #[test]
    fn a_key_with_composite_factors_does_not_unlock() {
        // Codex review's key: p = 3^323 and q = 7 * 3^321, both 512 bits, n of 1024 bits, d the
        // inverse of e modulo lcm(p - 1, q - 1, 2 * 3^643): rsa accepts it, and it would sign.
        let three_to = |k: u32| (0..k).fold(rsa::BigUint::from(1u32), |acc, _| acc * 3u32);
        let one = rsa::BigUint::from(1u32);
        let (p, q) = (three_to(323), rsa::BigUint::from(7u32) * three_to(321));
        assert_eq!((p.bits(), q.bits(), (&p * &q).bits()), (512, 512, 1024));
        let gcd = |mut a: rsa::BigUint, mut b: rsa::BigUint| {
            while b != rsa::BigUint::from(0u32) {
                let r = &a % &b;
                a = b;
                b = r;
            }
            a
        };
        let lcm = |a: rsa::BigUint, b: rsa::BigUint| &a * &b / gcd(a.clone(), b.clone());
        let lambda = lcm(
            lcm(&p - &one, &q - &one),
            rsa::BigUint::from(2u32) * three_to(643),
        );
        let d = inverse_of_e(&lambda);
        let entry = crafted(&p, &q, &d);
        assert!(
            RsaPrivateKey::from_pkcs8_pem(&entry.private_key_pem).is_ok(),
            "rsa reads it as a key"
        );
        // AWS-LC's parser refuses it before QG Trust's own shape check needs to: either way it
        // never signs.
        let refused = entry.unlock(None).err();
        assert!(
            matches!(refused, Some(KeyError::NotAKey | KeyError::NotLotwKey)),
            "{refused:?}"
        );
    }

    #[test]
    fn a_key_with_equal_primes_does_not_unlock() {
        use rsa::traits::PrivateKeyParts;
        // Codex review: p = q gives a 1024-bit modulus of two 512-bit primes, which rsa accepts,
        // and anyone can factor it with a square root. d is the inverse of e modulo p(p - 1).
        let real = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../../tests/corpus/pki/user-1024.key.pem"
        ))
        .expect("key");
        let p = real.primes()[0].clone();
        let d = inverse_of_e(&(&p * (&p - rsa::BigUint::from(1u32))));
        let refused = crafted(&p, &p, &d).unlock(None).err();
        assert!(
            matches!(refused, Some(KeyError::NotAKey | KeyError::NotLotwKey)),
            "{refused:?}"
        );
    }

    #[test]
    fn a_key_field_given_twice_is_refused() {
        let file =
            b"<CALLSIGN:7>QG0TEST\n<PUBLIC_KEY:1>a\n<PRIVATE_KEY:1>b\n<private_key:1>c\n<eor>\n";
        assert_eq!(
            KeyEntry::read_key_file(file).err(),
            Some(KeyError::RepeatedField("PRIVATE_KEY"))
        );
    }
}
