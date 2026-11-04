// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Password-protected export parts. Only a freshly generated password can seal a part; typed
//! passwords can open it. Save the generated password separately: it is never stored in the part.
//!
//! Version 1: `QGT-PART` (8 bytes), version (1 byte), PBKDF2 iterations (u32 big endian), salt
//! (16 bytes), nonce (12 bytes), ciphertext, GCM tag (16 bytes). AAD is magic || version || UTF-8
//! part name || iteration bytes || salt. The nonce is authenticated by GCM itself.
//!
//! Seal/open stay crate-private so no store API returns decrypted private keys. Applications use
//! [`crate::store::Store::export_part`] and [`crate::store::Store::restore_part`].
//!
//! ```compile_fail,E0603
//! use qso_graph_trust::export::open;
//! ```

use std::fmt;
use std::num::NonZeroU32;

use qso_graph_trust_awslc::{aes256_gcm_open, aes256_gcm_seal, pbkdf2_sha256, random};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"QGT-PART";
const VERSION: u8 = 1;
const HEADER: usize = 41;
const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// PBKDF2-HMAC-SHA-256 work factor for version 1.
// OWASP Password Storage Cheat Sheet, checked 2026-11-04: PBKDF2-HMAC-SHA256 >=600,000.
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
pub const ITERATIONS: u32 = 600_000;
// Version 1 has one fixed count. Reject before derivation, bounding both work and minimum strength.
const MIN_ITERATIONS: u32 = ITERATIONS;
const MAX_ITERATIONS: u32 = ITERATIONS;
/// Maximum plaintext part size (store XML plus bounded key records).
pub const MAX_PLAINTEXT_LEN: usize = 40 * 1024 * 1024;
/// The authenticated name of the LoTW store part.
pub const LOTW_PART: &str = "lotw";

/// An opaque, wiped password. Debug never prints it; disclosure for saving is explicit.
/// No constructor accepts caller-supplied entropy for sealing.
///
/// ```compile_fail
/// use qso_graph_trust::export::Password;
/// let password = Password::default();
/// ```
pub struct Password {
    secret: Zeroizing<String>,
    generated: bool,
}
impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(..)")
    }
}
impl Password {
    /// Generate 20 unbiased ASCII letters and digits, about 119 bits of entropy.
    pub fn generate() -> Result<Self, ExportError> {
        let mut secret = Zeroizing::new(String::with_capacity(20));
        let mut bytes = Zeroizing::new([0; 32]);
        while secret.len() < 20 {
            random(&mut *bytes).map_err(|_| ExportError::Random)?;
            for &byte in bytes.iter() {
                // 248 = 4 * 62: every alphabet index has exactly four preimages.
                if byte < 248 {
                    secret.push(char::from(ALPHABET[usize::from(byte % 62)]));
                    if secret.len() == 20 {
                        break;
                    }
                }
            }
        }
        Ok(Self {
            secret,
            generated: true,
        })
    }

    /// Accept a password for opening only. At least 20 ASCII alphanumeric characters are required.
    pub fn from_typed(text: &str) -> Result<Self, ExportError> {
        if text.len() < 20 || !text.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(ExportError::Password);
        }
        Ok(Self {
            secret: Zeroizing::new(text.to_owned()),
            generated: false,
        })
    }

    /// Reveal the password to display or save separately. Never log it or store it in the backup.
    pub fn expose_secret(&self) -> &str {
        &self.secret
    }

    pub(crate) fn require_generated(&self) -> Result<(), ExportError> {
        if self.generated {
            Ok(())
        } else {
            Err(ExportError::Password)
        }
    }
}

/// Fixed errors: malformed files, wrong passwords and authentication failures are indistinguishable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportError {
    /// Opening failed, for any input or authentication error.
    Open,
    /// A typed password is invalid, or sealing was attempted without a generated password.
    Password,
    /// The operating system's cryptographic randomness was unavailable.
    Random,
    /// The plaintext exceeded the part size limit or encryption failed.
    Seal,
}
impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "the export part could not be opened",
            Self::Password => "a valid generated export password is required for sealing; opening requires at least 20 ASCII letters or digits",
            Self::Random => "secure randomness is unavailable",
            Self::Seal => "the export part could not be sealed",
        })
    }
}
impl std::error::Error for ExportError {}

fn aad(part_name: &str, header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(29 + part_name.len());
    aad.extend_from_slice(&header[..9]);
    aad.extend_from_slice(part_name.as_bytes());
    aad.extend_from_slice(&header[9..29]);
    aad
}

/// Encrypt a part. Only library-generated passwords are accepted; only ciphertext is returned.
pub(crate) fn seal(
    part_name: &str,
    plaintext: &[u8],
    password: &Password,
) -> Result<Vec<u8>, ExportError> {
    password.require_generated()?;
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(ExportError::Seal);
    }
    let mut header = [0; HEADER];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[9..13].copy_from_slice(&ITERATIONS.to_be_bytes());
    random(&mut header[13..]).map_err(|_| ExportError::Random)?;
    let key = pbkdf2_sha256(
        password.secret.as_bytes(),
        &header[13..29],
        NonZeroU32::new(ITERATIONS).expect("nonzero count"),
    );
    let ciphertext = aes256_gcm_seal(
        &key,
        header[29..41].try_into().expect("nonce"),
        &aad(part_name, &header),
        plaintext,
    )
    .map_err(|_| ExportError::Seal)?;
    let mut out = Vec::with_capacity(HEADER + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Authenticate and decrypt a part. All malformed inputs and wrong passwords return `Open`.
pub(crate) fn open(
    part_name: &str,
    bytes: &[u8],
    password: &Password,
) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    open_with(part_name, bytes, password, pbkdf2_sha256)
}

fn open_with(
    part_name: &str,
    bytes: &[u8],
    password: &Password,
    derive: impl FnOnce(&[u8], &[u8], NonZeroU32) -> Zeroizing<[u8; 32]>,
) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    if bytes.len() < HEADER + 16
        || bytes.len() > HEADER + 16 + MAX_PLAINTEXT_LEN
        || &bytes[..8] != MAGIC
        || bytes[8] != VERSION
    {
        return Err(ExportError::Open);
    }
    let iterations = u32::from_be_bytes(bytes[9..13].try_into().expect("count"));
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(ExportError::Open);
    }
    let key = derive(
        password.secret.as_bytes(),
        &bytes[13..29],
        NonZeroU32::new(iterations).ok_or(ExportError::Open)?,
    );
    aes256_gcm_open(
        &key,
        bytes[29..41].try_into().expect("nonce"),
        &aad(part_name, bytes),
        &bytes[HEADER..],
    )
    .map_err(|_| ExportError::Open)
}

#[cfg(test)]
mod tests;
