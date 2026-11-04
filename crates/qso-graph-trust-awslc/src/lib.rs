// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! LoTW's RSA signature from AWS-LC, the cryptographic library QSO Graph Desktop already ships.
//!
//! LoTW accepts only RSA PKCS#1 v1.5 over SHA-1 (`SIGN_LOTW_V2.0`). aws-lc-rs's safe API signs RSA
//! only with SHA-2, so this crate calls AWS-LC's C functions itself: the one place in QSO Graph Trust
//! with unsafe code (docs/decisions/0006). AWS-LC's RSA is constant-time and overwrites every block
//! it frees (`OPENSSL_free`, `crypto/mem.c`), so the key's numbers and their temporaries are wiped.
//!
//! The interface is safe: [`RsaKey`] owns its AWS-LC key, frees it when dropped, and can only be
//! checked and used to sign. Generation hands wiped PKCS#8 directly to the library for custody;
//! an imported key cannot be read back out or printed.

use std::ffi::c_int;
use std::fmt;
use std::ptr::NonNull;

use aws_lc_sys as sys;
use zeroize::Zeroizing;

mod encryption;
pub use encryption::{EncryptionError, aes256_gcm_open, aes256_gcm_seal, pbkdf2_sha256};

/// An RSA private key held by AWS-LC. It cannot be read back out.
pub struct RsaKey {
    rsa: NonNull<sys::RSA>,
}

impl fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RsaKey(..)")
    }
}

/// Why AWS-LC could not take or use a key. It never holds key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a PKCS#8 RSA private key, or a public key that is not RSA SubjectPublicKeyInfo.
    NotRsa,
    /// AWS-LC could not make the signature.
    Signing,
    /// AWS-LC could not generate or encode a key.
    Generation,
    /// The operating system could not supply random bytes.
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotRsa => "not an RSA key AWS-LC can read",
            Self::Signing => "AWS-LC could not sign",
            Self::Generation => "AWS-LC could not generate or encode a key",
            Self::Random => "AWS-LC could not supply random bytes",
        })
    }
}

impl std::error::Error for Error {}

/// Fill a buffer with cryptographically secure random bytes from AWS-LC's safe API.
pub fn random(bytes: &mut [u8]) -> Result<(), Error> {
    aws_lc_rs::rand::fill(bytes).map_err(|_| Error::Random)
}

/// An AWS-LC key read from DER, `parse` being EVP_parse_private_key or EVP_parse_public_key, as the
/// RSA it holds. The EVP wrapper is freed here; the RSA is the caller's to free.
fn parse_rsa(
    der: &[u8],
    parse: unsafe extern "C" fn(*mut sys::CBS) -> *mut sys::EVP_PKEY,
) -> Option<NonNull<sys::RSA>> {
    let mut cbs = sys::CBS {
        data: std::ptr::null(),
        len: 0,
    };
    #[allow(unsafe_code)]
    // SAFETY: `der` is a live slice for this whole function; CBS_init only records its pointer and length.
    unsafe {
        sys::CBS_init(&mut cbs, der.as_ptr(), der.len())
    };
    #[allow(unsafe_code)]
    // SAFETY: `cbs` was initialised above over `der`, which outlives the call; the result is owned or null.
    let pkey = NonNull::new(unsafe { parse(&mut cbs) })?;
    // A key with bytes after it is not one key (the same rule as the Rust parsers).
    if cbs.len != 0 {
        #[allow(unsafe_code)]
        // SAFETY: `pkey` is the owned, non-null result above, freed exactly once here.
        unsafe {
            sys::EVP_PKEY_free(pkey.as_ptr())
        };
        return None;
    }
    #[allow(unsafe_code)]
    // SAFETY: `pkey` is live; get1 returns a new reference to its RSA (or null if it is not RSA).
    let rsa = unsafe { sys::EVP_PKEY_get1_RSA(pkey.as_ptr()) };
    #[allow(unsafe_code)]
    // SAFETY: `pkey` is owned and freed exactly once; the RSA reference taken above outlives it.
    unsafe {
        sys::EVP_PKEY_free(pkey.as_ptr())
    };
    NonNull::new(rsa)
}

/// The digest an RSA signature is made over, as a certificate names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digest {
    /// SHA-1, which older certificates use.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512, which LoTW's root uses.
    Sha512,
}

/// Whether `signature` is a valid RSA PKCS#1 v1.5 signature over `message`, made with `digest`, by
/// `rsa_public_key`, an RSAPublicKey (RFC 8017) of 2048 bits or more: how a certificate's issuer is
/// checked. It is aws-lc-rs's own verification, with no unsafe code here: AWS-LC through its safe
/// API for every operation that API offers (AGENTS.md).
pub fn verify_rsa(rsa_public_key: &[u8], digest: Digest, message: &[u8], signature: &[u8]) -> bool {
    use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
    let algorithm: &'static dyn VerificationAlgorithm = match digest {
        Digest::Sha1 => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        Digest::Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        Digest::Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        Digest::Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
    };
    UnparsedPublicKey::new(algorithm, rsa_public_key)
        .verify(message, signature)
        .is_ok()
}

/// Free an RSA this crate owns.
fn free_rsa(rsa: NonNull<sys::RSA>) {
    #[allow(unsafe_code)]
    // SAFETY: every caller passes an RSA reference it owns and does not use again.
    unsafe {
        sys::RSA_free(rsa.as_ptr())
    };
}

impl RsaKey {
    /// Generate the key tqsllib 2.8.7 generates: RSA-1024 with exponent 65537.
    /// The private PKCS#8 DER is wiped on drop; the other result is public SPKI DER.
    /// This low-level custody handoff is for the library, not application key export.
    pub fn generate_lotw() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
        #[allow(unsafe_code)]
        // SAFETY: RSA_new takes no arguments and returns an owned RSA or null.
        let rsa = NonNull::new(unsafe { sys::RSA_new() }).ok_or(Error::Generation)?;
        let key = Self { rsa };
        #[allow(unsafe_code)]
        // SAFETY: BN_new takes no arguments and returns an owned BIGNUM or null.
        let e = NonNull::new(unsafe { sys::BN_new() }).ok_or(Error::Generation)?;
        #[allow(unsafe_code)]
        // SAFETY: e is owned and live; BN_set_word writes only to that BIGNUM.
        let set = unsafe { sys::BN_set_word(e.as_ptr(), 65_537) };
        let generated = if set == 1 {
            #[allow(unsafe_code)]
            // SAFETY: rsa and e are live and owned; no callback is supplied. The RSA owns
            // its generated components; e is only borrowed and freed below, also on failure.
            unsafe {
                sys::RSA_generate_key_ex(rsa.as_ptr(), 1024, e.as_ptr(), std::ptr::null_mut())
            }
        } else {
            0
        };
        #[allow(unsafe_code)]
        // SAFETY: e is owned, non-null and no longer borrowed; freed exactly once.
        unsafe {
            sys::BN_free(e.as_ptr())
        };
        if generated != 1 {
            return Err(Error::Generation);
        }
        #[allow(unsafe_code)]
        // SAFETY: EVP_PKEY_new returns an owned wrapper or null.
        let pkey = NonNull::new(unsafe { sys::EVP_PKEY_new() }).ok_or(Error::Generation)?;
        let pkey = OwnedPkey(pkey);
        #[allow(unsafe_code)]
        // SAFETY: both objects are live; set1 takes its own RSA reference, leaving key owned here.
        let assigned = unsafe { sys::EVP_PKEY_set1_RSA(pkey.0.as_ptr(), key.rsa.as_ptr()) };
        if assigned != 1 {
            return Err(Error::Generation);
        }
        let private = marshal(&pkey, sys::EVP_marshal_private_key)?;
        let public = marshal(&pkey, sys::EVP_marshal_public_key)?.to_vec();
        Ok((private, public))
    }

    /// RSA PKCS#1 v1.5 over SHA-256 for TQSL's PKCS#10 request.
    /// aws-lc-rs rejects RSA signing keys smaller than 2048 bits, so only the RSA operation
    /// uses the direct binding; hashing uses its safe API.
    pub fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
        self.sign_digest(sys::NID_sha256 as c_int, digest.as_ref())
    }

    /// Read a PKCS#8 RSA private key (DER). The caller keeps and wipes its own copy of `der`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<RsaKey, Error> {
        parse_rsa(der, sys::EVP_parse_private_key)
            .map(|rsa| RsaKey { rsa })
            .ok_or(Error::NotRsa)
    }

    /// Whether this is a key LoTW uses, as tqsllib makes them: a 1024-bit modulus, the exponent
    /// 65537, and two different 512-bit factors that each pass AWS-LC's primality test (64
    /// Miller-Rabin rounds with bases from AWS-LC's random generator, after trial division).
    pub fn is_lotw_shaped(&self) -> bool {
        let rsa = self.rsa.as_ptr();
        #[allow(unsafe_code)]
        // SAFETY: `rsa` is this key's live RSA; RSA_bits only reads it.
        let bits = unsafe { sys::RSA_bits(rsa) };
        #[allow(unsafe_code)]
        // SAFETY: `rsa` is live; the returned BIGNUM is borrowed from it and only read below.
        let e = unsafe { sys::RSA_get0_e(rsa) };
        if bits != 1024 || e.is_null() {
            return false;
        }
        #[allow(unsafe_code)]
        // SAFETY: `e` is non-null and borrowed from the live key.
        let e_ok = unsafe { sys::BN_is_word(e, 65_537) } == 1;
        let (mut p, mut q) = (std::ptr::null(), std::ptr::null());
        #[allow(unsafe_code)]
        // SAFETY: `rsa` is live; the out-pointers receive borrowed BIGNUMs (or null), only read below.
        unsafe {
            sys::RSA_get0_factors(rsa, &mut p, &mut q)
        };
        if !e_ok || p.is_null() || q.is_null() {
            return false;
        }
        #[allow(unsafe_code)]
        // SAFETY: `p` and `q` are non-null and borrowed from the live key.
        let distinct = unsafe { sys::BN_cmp(p, q) } != 0;
        let sized = |n: *const sys::BIGNUM| {
            #[allow(unsafe_code)]
            // SAFETY: called only with `p` or `q`, non-null and borrowed from the live key.
            let b = unsafe { sys::BN_num_bits(n) };
            b == 512
        };
        distinct && sized(p) && sized(q) && is_prime(p) && is_prime(q)
    }

    /// Whether `spki_der`, a SubjectPublicKeyInfo, is this key's own public key.
    pub fn matches_public_key(&self, spki_der: &[u8]) -> bool {
        let Some(public) = parse_rsa(spki_der, sys::EVP_parse_public_key) else {
            return false;
        };
        let same = |get: unsafe extern "C" fn(*const sys::RSA) -> *const sys::BIGNUM| {
            #[allow(unsafe_code)]
            // SAFETY: this key's RSA is live; the BIGNUM is borrowed from it and only compared.
            let a = unsafe { get(self.rsa.as_ptr()) };
            #[allow(unsafe_code)]
            // SAFETY: `public` is live until it is freed below; its BIGNUM is only compared.
            let b = unsafe { get(public.as_ptr()) };
            if a.is_null() || b.is_null() {
                return false;
            }
            #[allow(unsafe_code)]
            // SAFETY: `a` and `b` are non-null and borrowed from live keys; BN_cmp only reads them.
            let order = unsafe { sys::BN_cmp(a, b) };
            order == 0
        };
        let matches = same(sys::RSA_get0_n) && same(sys::RSA_get0_e);
        free_rsa(public);
        matches
    }

    /// LoTW's signature over `data`: SHA-1, then RSA PKCS#1 v1.5 (`RSA_sign` with `NID_sha1`), the
    /// bytes tqsllib's `tqsl_signDataBlock` returns.
    pub fn sign_sha1(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut digest = [0u8; 20];
        #[allow(unsafe_code)]
        // SAFETY: `data` is a live slice of its length; `digest` holds the 20 bytes SHA-1 writes.
        unsafe {
            sys::SHA1(data.as_ptr(), data.len(), digest.as_mut_ptr())
        };
        self.sign_digest(sys::NID_sha1 as c_int, &digest)
    }

    fn sign_digest(&self, nid: c_int, digest: &[u8]) -> Result<Vec<u8>, Error> {
        #[allow(unsafe_code)]
        // SAFETY: `rsa` is this key's live RSA; RSA_size only reads it.
        let size = unsafe { sys::RSA_size(self.rsa.as_ptr()) } as usize;
        let mut out = vec![0u8; size];
        let mut out_len: std::ffi::c_uint = 0;
        #[allow(unsafe_code)]
        // SAFETY: the private callers provide the digest length required by nid; `out` holds RSA_size bytes, the most
        // RSA_sign writes; `out_len` receives the length; `rsa` is live for the call.
        let ok = unsafe {
            sys::RSA_sign(
                nid,
                digest.as_ptr(),
                digest.len(),
                out.as_mut_ptr(),
                &mut out_len,
                self.rsa.as_ptr(),
            )
        };
        if ok != 1 || out_len as usize != size {
            return Err(Error::Signing);
        }
        Ok(out)
    }
}

// An owned EVP wrapper, including its RSA reference, freed on every error path.
struct OwnedPkey(NonNull<sys::EVP_PKEY>);

impl Drop for OwnedPkey {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        // SAFETY: this wrapper uniquely owns the non-null EVP_PKEY, freed exactly once.
        unsafe {
            sys::EVP_PKEY_free(self.0.as_ptr())
        };
    }
}

// A fixed wiped buffer avoids both copying private DER out of a C allocation and unbounded
// allocation. 2048 bytes is more than PKCS#8 or SPKI for RSA-1024 can need.
fn marshal(
    key: &OwnedPkey,
    encode: unsafe extern "C" fn(*mut sys::CBB, *const sys::EVP_PKEY) -> c_int,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Zeroizing::new(vec![0u8; 2048]);
    let mut cbb = sys::CBB::default();
    #[allow(unsafe_code)]
    // SAFETY: cbb is writable; out has the given capacity and remains live and unmoved until
    // cleanup. A fixed CBB never grows or takes ownership of this Rust buffer.
    unsafe {
        sys::CBB_init_fixed(&mut cbb, out.as_mut_ptr(), out.len())
    };
    #[allow(unsafe_code)]
    // SAFETY: cbb is initialised, key is live; only the two EVP marshal functions are passed.
    let ok = unsafe { encode(&mut cbb, key.0.as_ptr()) };
    let len = if ok == 1 {
        #[allow(unsafe_code)]
        // SAFETY: successful marshal flushed all children; cbb is live and initialised.
        unsafe {
            sys::CBB_len(&cbb)
        }
    } else {
        0
    };
    #[allow(unsafe_code)]
    // SAFETY: cbb was initialised exactly once and is no longer used; cleanup frees child state,
    // never the fixed buffer, which Rust owns and wipes on all paths.
    unsafe {
        sys::CBB_cleanup(&mut cbb)
    };
    if ok != 1 || len == 0 || len > out.len() {
        return Err(Error::Generation);
    }
    out.truncate(len);
    Ok(out)
}

impl Drop for RsaKey {
    fn drop(&mut self) {
        // AWS-LC clears the key's numbers as it frees them (BN_free and OPENSSL_free cleanse).
        free_rsa(self.rsa);
    }
}

/// AWS-LC's primality test on a factor borrowed from a live key.
fn is_prime(n: *const sys::BIGNUM) -> bool {
    #[allow(unsafe_code)]
    // SAFETY: BN_CTX_new takes no arguments; its result is owned, checked for null and freed below.
    let ctx = unsafe { sys::BN_CTX_new() };
    if ctx.is_null() {
        return false;
    }
    let mut prime: c_int = 0;
    #[allow(unsafe_code)]
    // SAFETY: `n` is borrowed from a live key, `ctx` is owned and live, `prime` receives the answer,
    // and no progress callback is given (null).
    let ok = unsafe { sys::BN_primality_test(&mut prime, n, 64, ctx, 1, std::ptr::null_mut()) };
    #[allow(unsafe_code)]
    // SAFETY: `ctx` is owned, non-null, and freed exactly once here.
    unsafe {
        sys::BN_CTX_free(ctx)
    };
    ok == 1 && prime == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rubbish_is_not_a_key() {
        assert_eq!(
            RsaKey::from_pkcs8_der(b"not a key").err(),
            Some(Error::NotRsa)
        );
        assert_eq!(RsaKey::from_pkcs8_der(&[]).err(), Some(Error::NotRsa));
    }

    #[test]
    fn a_key_prints_nothing_of_itself() {
        let pem = include_str!("../../../tests/corpus/pki/user-1024.key.pem");
        let der = pem_body(pem);
        let key = RsaKey::from_pkcs8_der(&der).expect("key");
        assert_eq!(format!("{key:?}"), "RsaKey(..)");
        assert!(key.is_lotw_shaped());
    }

    #[test]
    fn trailing_bytes_after_a_key_are_refused() {
        let mut der = pem_body(include_str!("../../../tests/corpus/pki/user-1024.key.pem"));
        der.push(0);
        assert_eq!(RsaKey::from_pkcs8_der(&der).err(), Some(Error::NotRsa));
    }

    /// A PEM's base64 body, decoded by hand so these tests need nothing outside this crate.
    fn pem_body(pem: &str) -> Vec<u8> {
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let val = |c: u8| match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            _ => 63,
        };
        let bytes: Vec<u8> = b64.bytes().filter(|&c| c != b'=').collect();
        let mut out = Vec::new();
        for chunk in bytes.chunks(4) {
            let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &c)| {
                acc | (u32::from(val(c)) << (18 - 6 * i))
            });
            let take = chunk.len() - 1;
            out.extend_from_slice(&n.to_be_bytes()[1..1 + take]);
        }
        out
    }
}
