// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Safe AWS-LC APIs for encrypted exports and legacy key imports. No native calls belong here.

use std::fmt;
use std::num::NonZeroU32;

use aws_lc_rs::{aead, pbkdf2};
use zeroize::Zeroizing;

/// A fixed failure category, with no key, password or plaintext attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionError;

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("encryption or authentication failed")
    }
}
impl std::error::Error for EncryptionError {}

/// Derive an AES-256 key in wiped memory using PBKDF2-HMAC-SHA-256.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> Zeroizing<Vec<u8>> {
    // Derive into the allocation itself: moving an inline array can leave an unwiped stack copy.
    let mut key = Zeroizing::new(vec![0; 32]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut key,
    );
    key
}

/// Seal with AES-256-GCM and authenticated associated data. The caller must never reuse a
/// `(key, nonce)` pair. The result includes the 16-byte tag and is wiped even on failure.
pub fn aes256_gcm_seal(
    key: &[u8],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| EncryptionError)?;
    let key = aead::LessSafeKey::new(key);
    // Reserve the tag before copying plaintext: growing a secret Vec could free an unwiped copy.
    let mut out = Zeroizing::new(Vec::with_capacity(
        plaintext.len().checked_add(16).ok_or(EncryptionError)?,
    ));
    out.extend_from_slice(plaintext);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        &mut *out,
    )
    .map_err(|_| EncryptionError)?;
    Ok(out)
}

/// Authenticate and open AES-256-GCM into wiped memory, including on authentication failure.
pub fn aes256_gcm_open(
    key: &[u8],
    nonce: [u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| EncryptionError)?;
    let key = aead::LessSafeKey::new(key);
    let mut out = Zeroizing::new(ciphertext.to_vec());
    let len = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut out,
        )
        .map_err(|_| EncryptionError)?
        .len();
    // The tail is the public tag, not secret plaintext.
    out.truncate(len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_gcm_matches_nist_vector_and_authenticates_aad() {
        // NIST GCM AES-256: all-zero key, 96-bit IV and one all-zero plaintext block.
        let expected = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
            0xd4, 0x8a, 0xb9, 0x19,
        ];
        let sealed = aes256_gcm_seal(&[0; 32], [0; 12], b"", &[0; 16]).expect("seal");
        assert_eq!(sealed.as_slice(), expected);
        assert_eq!(
            aes256_gcm_open(&[0; 32], [0; 12], b"", &sealed)
                .expect("open")
                .as_slice(),
            &[0; 16]
        );
        assert_eq!(
            aes256_gcm_open(&[0; 32], [0; 12], b"changed", &sealed).err(),
            Some(EncryptionError)
        );
        assert_eq!(
            aes256_gcm_open(&[0; 32], [0; 12], b"", &[]).err(),
            Some(EncryptionError)
        );
        let sealed = aes256_gcm_seal(&[1; 32], [2; 12], b"part", b"plaintext").expect("AAD seal");
        assert_eq!(
            aes256_gcm_open(&[1; 32], [2; 12], b"part", &sealed)
                .expect("AAD open")
                .as_slice(),
            b"plaintext"
        );
    }

    #[test]
    fn pbkdf2_hmac_sha256_known_answer() {
        let expected = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(
            pbkdf2_sha256(b"password", b"salt", NonZeroU32::new(1).expect("nonzero")).as_slice(),
            expected
        );
    }
}

/// CBC ciphers accepted only for decrypting legacy key imports.
#[derive(Clone, Copy, Debug)]
pub enum ImportCipher {
    /// AES with a 128-bit key.
    Aes128,
    /// AES with a 256-bit key.
    Aes256,
    /// Three-key Triple DES, for existing TQSL exports only.
    DesEde3,
}

/// Decrypt PKCS#7-padded CBC directly into wiped heap storage. Provider-owned key schedules are
/// wiped too. Using the safe AWS-LC API avoids RustCrypto CBC's unwiped parallel-block plaintext
/// copies on the stack (caught by the release custody test with an AES-protected PKCS#12 key).
#[allow(deprecated)] // 3DES is read-only interoperability with tqsllib, never new encryption.
pub fn import_cbc_decrypt(
    cipher: ImportCipher,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
    use aws_lc_rs::cipher::{self, DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey};
    use aws_lc_rs::iv::FixedLength;
    let (algorithm, context) = match cipher {
        ImportCipher::Aes128 => (
            &cipher::AES_128,
            DecryptionContext::Iv128(FixedLength::try_from(iv).map_err(|_| EncryptionError)?),
        ),
        ImportCipher::Aes256 => (
            &cipher::AES_256,
            DecryptionContext::Iv128(FixedLength::try_from(iv).map_err(|_| EncryptionError)?),
        ),
        ImportCipher::DesEde3 => (
            &cipher::DES_EDE3_FOR_LEGACY_USE_ONLY,
            DecryptionContext::Iv64(FixedLength::try_from(iv).map_err(|_| EncryptionError)?),
        ),
    };
    let key = UnboundCipherKey::new(algorithm, key).map_err(|_| EncryptionError)?;
    let key = PaddedBlockDecryptingKey::cbc_pkcs7(key).map_err(|_| EncryptionError)?;
    let mut out = Zeroizing::new(ciphertext.to_vec());
    let len = key
        .decrypt(&mut out, context)
        .map_err(|_| EncryptionError)?
        .len();
    out.truncate(len);
    Ok(out)
}
