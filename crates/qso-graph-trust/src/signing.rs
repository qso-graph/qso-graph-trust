// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Signing a QSO record as LoTW accepts it: RSA PKCS#1 v1.5 over SHA-1, the `SIGN_LOTW_V2.0` field,
//! as tqsllib signs (TQSL 2.8.7 `src/openssl_cert.cpp:2215`, `EVP_SignInit(ctx, EVP_sha1())`).
//!
//! The key is read from tqsllib's key file (`keys/<call>`), plain or protected by a password, and
//! once unlocked it can only sign: nothing here returns it, prints it or puts it in an error.
//! Signing is blinded with the operating system's randomness, the defence against the timing leak
//! in RUSTSEC-2023-0071; a PKCS#1 v1.5 signature is the same either way (docs/decisions/0002).
//! Every buffer here that holds key text is wiped when dropped (`Zeroizing`), and a protected key's
//! encryption parameters are checked before any work is done with the password, so a crafted file
//! cannot ask for unbounded memory or time (found by Codex review).

use std::fmt;

use base64ct::{Base64, Encoding};
use pkcs8::pkcs5::EncryptionScheme;
use pkcs8::pkcs5::pbes2::{self, Kdf, Pbkdf2Prf};
use pkcs8::{DecodePrivateKey, EncryptedPrivateKeyInfo, der::Decode};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::records::{self, Record, RecordError};

/// One key from a tqsllib key file, still locked: its call and public key, and the private key as
/// stored. [`KeyEntry::unlock`] turns it into a [`TqslKey`] that can sign.
#[derive(Clone)]
pub struct KeyEntry {
    callsign: String,
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
    key: SigningKey<Sha1>,
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
    /// The private key is not PKCS#8 PEM as tqsllib writes it.
    NotAKey,
    /// The key is protected and no password was given.
    PasswordNeeded,
    /// The password does not unlock the key.
    WrongPassword,
    /// The key is not an RSA key.
    NotRsa,
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
            Self::NotAKey => f.write_str("the key file does not hold a private key"),
            Self::PasswordNeeded => f.write_str("this key is protected: its password is needed"),
            Self::WrongPassword => f.write_str("the password does not unlock this key"),
            Self::NotRsa => f.write_str("the key is not an RSA key"),
            Self::UnsupportedProtection => {
                f.write_str("the key is protected in a way QG Trust does not accept")
            }
            Self::Signing => f.write_str("the record could not be signed"),
        }
    }
}

impl std::error::Error for KeyError {}

const ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

/// The most PBKDF2 iterations accepted. tqsllib 2.8.7 writes 2,048 (OpenSSL's default); a million
/// takes well under a second, so a crafted file cannot make unlocking take unbounded time.
pub const MAX_PBKDF2_ITERATIONS: u32 = 1_000_000;

/// Whether a protected key's encryption is one QG Trust accepts, decided before any work is done
/// with the password: PBES2 with PBKDF2 (never scrypt, whose memory a file could set without bound),
/// HMAC-SHA1 or HMAC-SHA256, at most [`MAX_PBKDF2_ITERATIONS`], and 3DES or AES-CBC. tqsllib 2.8.7
/// writes PBES2, PBKDF2, HMAC-SHA256, 2,048 iterations and 3DES-CBC.
fn accepted(scheme: &EncryptionScheme<'_>) -> bool {
    let EncryptionScheme::Pbes2(params) = scheme else {
        return false;
    };
    let kdf_ok = match &params.kdf {
        Kdf::Pbkdf2(p) => {
            (1..=MAX_PBKDF2_ITERATIONS).contains(&p.iteration_count)
                && matches!(p.prf, Pbkdf2Prf::HmacWithSha1 | Pbkdf2Prf::HmacWithSha256)
        }
        // scrypt, and any kind a later pkcs5 adds: refused.
        _ => false,
    };
    let cipher_ok = matches!(
        params.encryption,
        pbes2::EncryptionScheme::DesEde3Cbc { .. }
            | pbes2::EncryptionScheme::Aes128Cbc { .. }
            | pbes2::EncryptionScheme::Aes256Cbc { .. }
    );
    kdf_ok && cipher_ok
}

impl KeyEntry {
    /// Every key in a tqsllib key file, in the order written: one per certificate request made.
    pub fn read_key_file(bytes: &[u8]) -> Result<Vec<KeyEntry>, KeyError> {
        records::parse(bytes)
            .map_err(KeyError::File)?
            .iter()
            .map(Self::from_record)
            .collect()
    }

    fn from_record(record: &Record) -> Result<KeyEntry, KeyError> {
        let text = |name: &'static str| record.text(name).ok_or(KeyError::MissingField(name));
        Ok(KeyEntry {
            callsign: text("CALLSIGN")?.to_string(),
            public_key_pem: text("PUBLIC_KEY")?.to_string(),
            private_key_pem: Zeroizing::new(text("PRIVATE_KEY")?.to_string()),
        })
    }

    /// The call this key was made for.
    pub fn callsign(&self) -> &str {
        &self.callsign
    }

    /// The public key, as PEM (SubjectPublicKeyInfo), for matching the key to its certificate.
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// Whether the private key is protected by a password.
    pub fn is_encrypted(&self) -> bool {
        self.private_key_pem.trim_start().starts_with(ENCRYPTED)
    }

    /// Unlock the key for signing. A protected key needs its password; a plain one ignores it.
    pub fn unlock(&self, password: Option<&[u8]>) -> Result<TqslKey, KeyError> {
        let key = if self.is_encrypted() {
            let password = password.ok_or(KeyError::PasswordNeeded)?;
            let (label, der) = pkcs8::der::pem::decode_vec(self.private_key_pem.as_bytes())
                .map_err(|_| KeyError::NotAKey)?;
            if label != "ENCRYPTED PRIVATE KEY" {
                return Err(KeyError::NotAKey);
            }
            let info = EncryptedPrivateKeyInfo::from_der(&der).map_err(|_| KeyError::NotAKey)?;
            if !accepted(&info.encryption_algorithm) {
                return Err(KeyError::UnsupportedProtection);
            }
            let document = info
                .decrypt(password)
                .map_err(|_| KeyError::WrongPassword)?;
            RsaPrivateKey::from_pkcs8_der(document.as_bytes()).map_err(|_| KeyError::NotRsa)?
        } else {
            RsaPrivateKey::from_pkcs8_pem(&self.private_key_pem).map_err(|_| KeyError::NotAKey)?
        };
        Ok(TqslKey {
            key: SigningKey::<Sha1>::new(key),
        })
    }
}

impl TqslKey {
    /// The signature over `data`, as the bytes tqsllib's `tqsl_signDataBlock` returns.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        let signature: Signature = self
            .key
            .try_sign_with_rng(&mut rand_core::OsRng, data)
            .map_err(|_| KeyError::Signing)?;
        Ok(signature.to_vec())
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
        assert!(accepted(&EncryptionScheme::Pbes2(ok)));
    }
}
