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
use rsa::pkcs8::DecodePublicKey;
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

/// Whether a key is one LoTW uses, checked before it can sign: tqsllib 2.8.7 makes RSA keys of 1024
/// bits (`src/openssl_cert.cpp:653`) with the exponent 65537 (`tqsl_new_rsa_key`,
/// `BN_set_word(pubexp, 0x10001)`), whose two primes OpenSSL makes 512 bits each. Anything else
/// cannot carry a LoTW certificate, and very unequal primes would make rsa's CRT step loop for
/// longer than the age of the universe (found by Codex review).
fn lotw_shaped(key: &RsaPrivateKey) -> Result<(), KeyError> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    if shape_ok(key.n().bits(), key.e(), key.primes()) && key.primes().iter().all(is_prime) {
        Ok(())
    } else {
        Err(KeyError::NotLotwKey)
    }
}

/// The shape itself: a 1024-bit modulus, the exponent 65537, and two different 512-bit primes.
/// Equal primes make a modulus anyone can factor with a square root (found by Codex review).
fn shape_ok(modulus_bits: usize, e: &rsa::BigUint, primes: &[rsa::BigUint]) -> bool {
    modulus_bits == 1024
        && *e == rsa::BigUint::from(65_537u32)
        && primes.len() == 2
        && primes[0] != primes[1]
        && primes.iter().all(|p| p.bits() == 512)
}

/// Whether `p` is prime, as far as anyone can tell from a key that may have been crafted to fool the
/// test: neither QG Trust's checks nor rsa's test primality, and composite factors of the right
/// sizes would sign with a modulus anyone can factor (found by Codex review). num-bigint-dig's
/// Baillie-PSW test (`probably_prime` with no rounds of its own: its Miller-Rabin bases are
/// predictable, and its documentation says not to rely on them against crafted input), then 32
/// Miller-Rabin rounds with bases from the operating system's randomness, which a key file cannot
/// anticipate. A composite passes a random round with probability at most 1/4.
fn is_prime(p: &rsa::BigUint) -> bool {
    use num_bigint_dig::RandBigInt;
    use num_bigint_dig::prime::probably_prime;
    let one = rsa::BigUint::from(1u32);
    let two = rsa::BigUint::from(2u32);
    if !probably_prime(p, 0) {
        return false;
    }
    // Every value derived from p is wiped when dropped: p - 1 gives p back (found by Codex review).
    // Each squaring makes a new wiped value and drops the old one, wiped, rather than overwriting it.
    let minus_one = Zeroizing::new(p - &one);
    let s = minus_one.trailing_zeros().unwrap_or(0);
    let d = Zeroizing::new(&*minus_one >> s);
    let mut rng = rand_core::OsRng;
    'round: for _ in 0..32 {
        let a = rng.gen_biguint_range(&two, &minus_one);
        let mut x = Zeroizing::new(a.modpow(&d, p));
        if *x == one || x == minus_one {
            continue;
        }
        for _ in 1..s {
            let square = Zeroizing::new(&*x * &*x);
            x = Zeroizing::new(&*square % p);
            if x == minus_one {
                continue 'round;
            }
        }
        return false;
    }
    true
}

/// A protected key's PKCS#8 bytes: PBKDF2 then CBC decryption, done here rather than in pkcs5,
/// whose derived key sits in a buffer it never wipes (found by Codex review). The derived key, the
/// cipher's key schedule (the `zeroize` features of cbc, des and aes) and the plaintext are all
/// wiped when dropped, on success or failure. `accepted` has already bounded the parameters.
fn decrypt(
    params: &pbes2::Parameters<'_>,
    password: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
    let Kdf::Pbkdf2(kdf) = &params.kdf else {
        return Err(KeyError::UnsupportedProtection);
    };
    let key_len = match params.encryption {
        pbes2::EncryptionScheme::DesEde3Cbc { .. } => 24,
        pbes2::EncryptionScheme::Aes128Cbc { .. } => 16,
        pbes2::EncryptionScheme::Aes256Cbc { .. } => 32,
        _ => return Err(KeyError::UnsupportedProtection),
    };
    if kdf.key_length.is_some_and(|l| usize::from(l) != key_len) {
        return Err(KeyError::UnsupportedProtection);
    }
    let mut key = Zeroizing::new(vec![0u8; key_len]);
    match kdf.prf {
        Pbkdf2Prf::HmacWithSha1 => {
            pbkdf2::pbkdf2_hmac::<Sha1>(password, kdf.salt, kdf.iteration_count, &mut key)
        }
        Pbkdf2Prf::HmacWithSha256 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, kdf.salt, kdf.iteration_count, &mut key)
        }
        _ => return Err(KeyError::UnsupportedProtection),
    }
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let bad = |_| KeyError::WrongPassword;
    let len = match params.encryption {
        pbes2::EncryptionScheme::DesEde3Cbc { iv } => {
            cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, iv)
                .map_err(|_| KeyError::UnsupportedProtection)?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(bad)?
                .len()
        }
        pbes2::EncryptionScheme::Aes128Cbc { iv } => {
            cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, iv)
                .map_err(|_| KeyError::UnsupportedProtection)?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(bad)?
                .len()
        }
        pbes2::EncryptionScheme::Aes256Cbc { iv } => {
            cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, iv)
                .map_err(|_| KeyError::UnsupportedProtection)?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(bad)?
                .len()
        }
        _ => return Err(KeyError::UnsupportedProtection),
    };
    buf.truncate(len);
    Ok(buf)
}

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
        if self.is_encrypted() && password.is_none() {
            return Err(KeyError::PasswordNeeded);
        }
        // Decoded, and decrypted, into buffers wiped on every path: a key that fails to decode or
        // decrypt leaves no plaintext behind either (found by Codex review).
        let mut decoded = Zeroizing::new(vec![0u8; self.private_key_pem.len()]);
        let (label, der) = pkcs8::der::pem::decode(self.private_key_pem.as_bytes(), &mut decoded)
            .map_err(|_| KeyError::NotAKey)?;
        let key = match label {
            "ENCRYPTED PRIVATE KEY" => {
                let password = password.ok_or(KeyError::PasswordNeeded)?;
                let info = EncryptedPrivateKeyInfo::from_der(der).map_err(|_| KeyError::NotAKey)?;
                if !accepted(&info.encryption_algorithm) {
                    return Err(KeyError::UnsupportedProtection);
                }
                let EncryptionScheme::Pbes2(params) = &info.encryption_algorithm else {
                    return Err(KeyError::UnsupportedProtection);
                };
                let plain = decrypt(params, password, info.encrypted_data)?;
                RsaPrivateKey::from_pkcs8_der(&plain).map_err(|_| KeyError::NotRsa)?
            }
            "PRIVATE KEY" => RsaPrivateKey::from_pkcs8_der(der).map_err(|_| KeyError::NotAKey)?,
            _ => return Err(KeyError::NotAKey),
        };
        lotw_shaped(&key)?;
        // The public key the file states is the private key's own, so a certificate matched by it
        // is this key's (found by Codex review).
        let stated = rsa::RsaPublicKey::from_public_key_pem(&self.public_key_pem)
            .map_err(|_| KeyError::PublicKeyMismatch)?;
        if stated != key.to_public_key() {
            return Err(KeyError::PublicKeyMismatch);
        }
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
    fn a_key_with_equal_primes_is_refused() {
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        // Codex review: p = q gives a 1024-bit modulus of two 512-bit primes that rsa accepts.
        assert!(
            entry(include_str!("../../../tests/corpus/pki/user-1024.key.pem"))
                .unlock(None)
                .is_ok()
        );
        let key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../../tests/corpus/pki/user-1024.key.pem"
        ))
        .expect("key");
        let p = key.primes()[0].clone();
        assert!(
            shape_ok(key.n().bits(), key.e(), key.primes()),
            "the test key itself is LoTW-shaped"
        );
        let square = &p * &p;
        assert!(!shape_ok(square.bits(), key.e(), &[p.clone(), p]));
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
    fn composite_factors_of_the_right_size_are_refused() {
        use rsa::traits::PrivateKeyParts;
        // Codex review: p = 3^323 and q = 7 * 3^321 are both 512 bits, so they pass the size checks.
        let three_to = |k: u32| (0..k).fold(rsa::BigUint::from(1u32), |acc, _| acc * 3u32);
        let p = three_to(323);
        let q = rsa::BigUint::from(7u32) * three_to(321);
        assert_eq!((p.bits(), q.bits(), (&p * &q).bits()), (512, 512, 1024));
        assert!(shape_ok(
            1024,
            &rsa::BigUint::from(65_537u32),
            &[p.clone(), q.clone()]
        ));
        assert!(!is_prime(&p) && !is_prime(&q));
        // The test key's own primes are prime.
        let key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../../tests/corpus/pki/user-1024.key.pem"
        ))
        .expect("key");
        assert!(key.primes().iter().all(is_prime));
        // A Carmichael number, which fools Fermat's test, and its neighbours.
        assert!(!is_prime(&rsa::BigUint::from(561u32)));
        assert!(is_prime(&rsa::BigUint::from(65_537u32)));
    }

    #[test]
    fn primality_working_values_are_wiped() {
        fn wiped<T: zeroize::ZeroizeOnDrop>() {}
        wiped::<Zeroizing<rsa::BigUint>>();
    }

    #[test]
    fn every_buffer_in_decryption_is_wiped() {
        fn wiped<T: zeroize::ZeroizeOnDrop>() {}
        wiped::<Zeroizing<Vec<u8>>>();
        wiped::<cbc::Decryptor<des::TdesEde3>>();
        wiped::<cbc::Decryptor<aes::Aes256>>();
    }

    #[test]
    fn a_key_with_composite_factors_does_not_unlock() {
        use num_bigint_dig::ModInverse;
        use rsa::pkcs8::EncodePublicKey;
        // Codex review's key: n = 3^644 * 7 from p = 3^323 and q = 7 * 3^321, with d the inverse of
        // e modulo lcm(p - 1, q - 1, 2 * 3^643), so rsa's own checks accept it and it would sign.
        let three_to = |k: u32| (0..k).fold(rsa::BigUint::from(1u32), |acc, _| acc * 3u32);
        let one = rsa::BigUint::from(1u32);
        let (p, q) = (three_to(323), rsa::BigUint::from(7u32) * three_to(321));
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
        let e = rsa::BigUint::from(65_537u32);
        let d = e
            .clone()
            .mod_inverse(&lambda)
            .and_then(|d| d.to_biguint())
            .expect("d");
        let key = RsaPrivateKey::from_components(
            &p * &q,
            e.clone(),
            d.clone(),
            vec![p.clone(), q.clone()],
        )
        .expect("rsa accepts it");
        // rsa will not write this key (its CRT values do not exist), but a crafted file can carry any
        // numbers, and rsa rebuilds a key from n, e, d, p and q when it reads one. So the file is
        // written here by hand, through pkcs1's and pkcs8's own structures.
        use pkcs8::der::Encode;
        let bytes = |x: &rsa::BigUint| x.to_bytes_be();
        let (n, eb, db, pb, qb) = (
            bytes(&(&p * &q)),
            bytes(&e),
            bytes(&d),
            bytes(&p),
            bytes(&q),
        );
        fn uint(b: &[u8]) -> pkcs8::der::asn1::UintRef<'_> {
            pkcs8::der::asn1::UintRef::new(b).expect("uint")
        }
        let one_byte = [1u8];
        let pkcs1_key = rsa::pkcs1::RsaPrivateKey {
            modulus: uint(&n),
            public_exponent: uint(&eb),
            private_exponent: uint(&db),
            prime1: uint(&pb),
            prime2: uint(&qb),
            exponent1: uint(&one_byte),
            exponent2: uint(&one_byte),
            coefficient: uint(&one_byte),
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
        assert!(
            RsaPrivateKey::from_pkcs8_pem(&pem).is_ok(),
            "rsa reads the crafted file as a key"
        );
        let entry = KeyEntry {
            callsign: "QG0TEST".into(),
            public_key_pem: key
                .to_public_key()
                .to_public_key_pem(pkcs8::LineEnding::LF)
                .expect("PEM"),
            private_key_pem: Zeroizing::new(pem),
        };
        assert_eq!(entry.unlock(None).err(), Some(KeyError::NotLotwKey));
    }
}
