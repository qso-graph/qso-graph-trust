// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Signing a QSO record as LoTW accepts it: RSA PKCS#1 v1.5 over SHA-1, the `SIGN_LOTW_V2.0` field,
//! as tqsllib signs (TQSL 2.8.7 `src/openssl_cert.cpp:2215`, `EVP_SignInit(ctx, EVP_sha1())`).
//!
//! The key is read from tqsllib's key file (`keys/<call>`), plain or protected by a password, and
//! once unlocked it can only sign: nothing here returns it, prints it or puts it in an error.
//! Signing is blinded with the operating system's randomness, the defence against the timing leak
//! in RUSTSEC-2023-0071; a PKCS#1 v1.5 signature is the same either way (docs/decisions/0002).

use std::fmt;

use base64ct::{Base64, Encoding};
use pkcs8::{DecodePrivateKey, EncryptedPrivateKeyInfo, der::Decode};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha1::Sha1;

use crate::records::{self, Record, RecordError};

/// One key from a tqsllib key file, still locked: its call and public key, and the private key as
/// stored. [`KeyEntry::unlock`] turns it into a [`TqslKey`] that can sign.
#[derive(Clone)]
pub struct KeyEntry {
    callsign: String,
    public_key_pem: String,
    private_key_pem: String,
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
            Self::Signing => f.write_str("the record could not be signed"),
        }
    }
}

impl std::error::Error for KeyError {}

const ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

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
        let text = |name: &'static str| {
            record
                .text(name)
                .map(str::to_string)
                .ok_or(KeyError::MissingField(name))
        };
        Ok(KeyEntry {
            callsign: text("CALLSIGN")?,
            public_key_pem: text("PUBLIC_KEY")?,
            private_key_pem: text("PRIVATE_KEY")?,
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
            private_key_pem: "-----BEGIN PRIVATE KEY-----secret".into(),
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
}
