// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! RFC 7292: password-integrity PFX, data/encryptedData, X.509 certBag and shroudedKeyBag.
//! Definite canonical DER only. Borrowed TLVs never allocate from an unchecked length. Outer
//! input, bag count, nesting, salts, iterations and total derivation work are bounded separately.
//! Every owned password, plaintext and derived-key buffer is wiped on success and error paths.

use qso_graph_trust_awslc::{ImportDigest, import_digest, import_hmac_verify};
use zeroize::Zeroizing;

use crate::certificate::{Certificate, MAX_CERTIFICATE_LEN, Trust};
use crate::import::{
    self, ImportError, MAX_IMPORT_ITEMS, MAX_IMPORT_LEN, MAX_ITERATIONS, MAX_PASSWORD_LEN,
};
use crate::protected_key::Parameters;
use crate::signing;
use crate::store::MAX_KEY_LEN;

// OID value octets, not encoded TLVs. No algorithm selected by a display string.
const DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 1];
const ENCRYPTED_DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 6];
const PBES2: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 5, 13];
const PBE_3DES: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 12, 1, 3];
const SHA1: &[u8] = &[43, 14, 3, 2, 26];
const SHA256: &[u8] = &[96, 134, 72, 1, 101, 3, 4, 2, 1];
const CERT_BAG: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 12, 10, 1, 3];
const KEY_BAG: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 12, 10, 1, 1];
const SHROUDED_BAG: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 12, 10, 1, 2];
const SAFE_BAG: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 12, 10, 1, 6];
const X509_BAG: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 22, 1];
const MAX_DEPTH: usize = 8;
const MAX_SALT: usize = 64;
const MAX_WORK: u64 = 4_000_000;

// The one private key never leaves this crate, even in Debug.
pub(crate) struct Loaded {
    pub certificate: Certificate,
    pub key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Copy)]
struct Der<'a>(&'a [u8]);
impl<'a> Der<'a> {
    fn value(&mut self, tag: u8) -> Result<&'a [u8], ImportError> {
        let (actual, value) = self.any()?;
        if actual != tag {
            return Err(ImportError::Malformed);
        }
        Ok(value)
    }
    fn any(&mut self) -> Result<(u8, &'a [u8]), ImportError> {
        let input = self.0;
        let (&tag, rest) = input.split_first().ok_or(ImportError::Malformed)?;
        // No high tags, indefinite lengths or nonminimal lengths in these formats.
        if tag & 31 == 31 || tag == 0 {
            return Err(ImportError::Malformed);
        }
        let (&first, rest) = rest.split_first().ok_or(ImportError::Malformed)?;
        let (len, rest) = if first < 128 {
            (usize::from(first), rest)
        } else {
            let n = usize::from(first & 127);
            if n == 0 || n > 4 || rest.len() < n || rest[0] == 0 {
                return Err(ImportError::Malformed);
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |a, b| (a << 8) | usize::from(*b));
            if len < 128 {
                return Err(ImportError::Malformed);
            }
            (len, &rest[n..])
        };
        let value = rest.get(..len).ok_or(ImportError::Malformed)?;
        self.0 = &rest[len..];
        Ok((tag, value))
    }
    fn sequence(&mut self) -> Result<Self, ImportError> {
        Ok(Self(self.value(0x30)?))
    }
    fn uint(&mut self) -> Result<u32, ImportError> {
        let b = self.value(2)?;
        if b.is_empty()
            || b.len() > 5
            || b[0] & 128 != 0
            || (b.len() > 1 && b[0] == 0 && b[1] & 128 == 0)
        {
            return Err(ImportError::Malformed);
        }
        b.iter().try_fold(0u32, |n, b| {
            n.checked_mul(256)
                .and_then(|n| n.checked_add(u32::from(*b)))
                .ok_or(ImportError::Malformed)
        })
    }
    fn end(self) -> Result<(), ImportError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ImportError::Malformed)
        }
    }
}
fn sequence(bytes: &[u8]) -> Result<Der<'_>, ImportError> {
    let mut outer = Der(bytes);
    let inner = outer.sequence()?;
    outer.end()?;
    Ok(inner)
}
fn one(bytes: &[u8], tag: u8) -> Result<&[u8], ImportError> {
    let mut r = Der(bytes);
    let out = r.value(tag)?;
    r.end()?;
    Ok(out)
}
fn work(iterations: u32, multiplier: u32, budget: &mut u64) -> Result<(), ImportError> {
    if !(1..=MAX_ITERATIONS).contains(&iterations) {
        return Err(ImportError::Limit);
    }
    let amount = u64::from(iterations) * u64::from(multiplier);
    *budget = budget.checked_sub(amount).ok_or(ImportError::Limit)?;
    Ok(())
}
fn salt(bytes: &[u8]) -> Result<(), ImportError> {
    if bytes.is_empty() || bytes.len() > MAX_SALT {
        Err(ImportError::Limit)
    } else {
        Ok(())
    }
}

// RFC 7292 B.1: BMP password, big endian, including the terminating zero character. PBES2
// separately takes the original UTF-8 bytes. Refuse invalid UTF-8 and non-BMP code points.
fn bmp(password: &[u8]) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ImportError::Limit);
    }
    let text = std::str::from_utf8(password).map_err(|_| ImportError::UnsupportedProtection)?;
    let mut out = Zeroizing::new(Vec::with_capacity(2 * (text.chars().count() + 1)));
    for c in text.chars() {
        let c = u16::try_from(u32::from(c)).map_err(|_| ImportError::UnsupportedProtection)?;
        out.extend_from_slice(&c.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    Ok(out)
}

// RFC 7292 B.2; both accepted digests have v=64. Hashes use the binding's safe provider API.
// The KDF's I, A, B, output and password all live in wiping heap buffers.
fn kdf(
    algorithm: ImportDigest,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    id: u8,
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let expanded = |n: usize| n.div_ceil(64) * 64;
    let mut input = Zeroizing::new(vec![0u8; expanded(salt.len()) + expanded(password.len())]);
    let split = expanded(salt.len());
    for (i, b) in input[..split].iter_mut().enumerate() {
        *b = salt[i % salt.len()];
    }
    for (i, b) in input[split..].iter_mut().enumerate() {
        *b = password[i % password.len()];
    }
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let d = [id; 64];
    while out.len() < len {
        let mut a = import_digest(algorithm, &[&d, &input]);
        for _ in 1..iterations {
            a = import_digest(algorithm, &[&a]);
        }
        let mut b = Zeroizing::new(vec![0u8; 64]);
        for (i, v) in b.iter_mut().enumerate() {
            *v = a[i % a.len()];
        }
        for block in input.as_chunks_mut::<64>().0 {
            let mut carry = 1u16;
            for i in (0..64).rev() {
                let n = u16::from(block[i]) + u16::from(b[i]) + carry;
                block[i] = n as u8;
                carry = n >> 8;
            }
        }
        let n = a.len().min(len - out.len());
        out.extend_from_slice(&a[..n]);
    }
    out
}

fn verify_mac(
    bytes: &[u8],
    data: &[u8],
    password: &[u8],
    budget: &mut u64,
) -> Result<(), ImportError> {
    let mut mac = Der(bytes);
    let mut info = mac.sequence()?;
    let mut algorithm = info.sequence()?;
    let oid = algorithm.value(6)?;
    if !algorithm.0.is_empty() {
        one(algorithm.0, 5)?
            .is_empty()
            .then_some(())
            .ok_or(ImportError::Malformed)?;
    }
    let expected = info.value(4)?;
    info.end()?;
    let salt_bytes = mac.value(4)?;
    salt(salt_bytes)?;
    let iterations = if mac.0.is_empty() { 1 } else { mac.uint()? };
    mac.end()?;
    work(iterations, 1, budget)?;
    let (algorithm, len) = match oid {
        SHA1 => (ImportDigest::Sha1, 20),
        SHA256 => (ImportDigest::Sha256, 32),
        _ => return Err(ImportError::UnsupportedProtection),
    };
    let key = kdf(algorithm, password, salt_bytes, iterations, 3, len);
    import_hmac_verify(algorithm, &key, data, expected).map_err(|_| ImportError::Authentication)
}

fn decrypt(
    algorithm: &[u8],
    ciphertext: &[u8],
    password: &[u8],
    bmp: &[u8],
    budget: &mut u64,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let mut alg = Der(algorithm);
    let oid = alg.value(6)?;
    match oid {
        PBES2 => {
            let params =
                Parameters::from_der(alg.0).map_err(|_| ImportError::UnsupportedProtection)?;
            salt(params.salt)?;
            work(params.iteration_count, 2, budget)?;
            if !params.accepted() {
                return Err(ImportError::UnsupportedProtection);
            }
            signing::decrypt(&params, password, ciphertext).map_err(ImportError::Key)
        }
        PBE_3DES => {
            let mut params = sequence(alg.0)?;
            let salt_bytes = params.value(4)?;
            salt(salt_bytes)?;
            let iterations = params.uint()?;
            params.end()?;
            work(iterations, 3, budget)?;
            let key = kdf(ImportDigest::Sha1, bmp, salt_bytes, iterations, 1, 24);
            let iv = kdf(ImportDigest::Sha1, bmp, salt_bytes, iterations, 2, 8);
            qso_graph_trust_awslc::import_cbc_decrypt(
                qso_graph_trust_awslc::ImportCipher::DesEde3,
                &key,
                &iv,
                ciphertext,
            )
            .map_err(|_| ImportError::Malformed)
        }
        _ => Err(ImportError::UnsupportedProtection),
    }
}

#[derive(Default)]
struct Contents {
    users: Vec<Vec<u8>>,
    authorities: Vec<Vec<u8>>,
    key: Option<Zeroizing<Vec<u8>>>,
    bags: usize,
}

// Attributes do not select a certificate or key: the actual SPKI must match. Still validate their
// DER with a bounded walk so crafted attribute nesting and large counts are refused too.
fn attributes(bytes: &[u8], depth: usize, count: &mut usize) -> Result<(), ImportError> {
    if depth > MAX_DEPTH {
        return Err(ImportError::Limit);
    }
    let mut r = Der(bytes);
    while !r.0.is_empty() {
        *count += 1;
        if *count > 4096 {
            return Err(ImportError::Limit);
        }
        let (tag, value) = r.any()?;
        if tag & 32 != 0 {
            attributes(value, depth + 1, count)?;
        }
    }
    Ok(())
}

impl Contents {
    fn bags(
        &mut self,
        bytes: &[u8],
        password: &[u8],
        bmp: &[u8],
        depth: usize,
        budget: &mut u64,
    ) -> Result<(), ImportError> {
        if depth > MAX_DEPTH {
            return Err(ImportError::Limit);
        }
        let mut contents = sequence(bytes)?;
        while !contents.0.is_empty() {
            self.bags += 1;
            if self.bags > MAX_IMPORT_ITEMS {
                return Err(ImportError::Limit);
            }
            let mut bag = contents.sequence()?;
            let oid = bag.value(6)?;
            let value = bag.value(0xa0)?;
            if !bag.0.is_empty() {
                let attrs = bag.value(0x31)?;
                attributes(attrs, 0, &mut 0)?;
            }
            bag.end()?;
            match oid {
                CERT_BAG => {
                    let mut cert = sequence(value)?;
                    if cert.value(6)? != X509_BAG {
                        return Err(ImportError::UnsupportedProtection);
                    }
                    let der = one(cert.value(0xa0)?, 4)?;
                    cert.end()?;
                    if der.len() > MAX_CERTIFICATE_LEN {
                        return Err(ImportError::Limit);
                    }
                    let list = if import::is_authority(der)? {
                        &mut self.authorities
                    } else {
                        &mut self.users
                    };
                    list.push(der.to_vec());
                }
                KEY_BAG | SHROUDED_BAG => {
                    if self.key.is_some() {
                        return Err(ImportError::Malformed);
                    }
                    let der = if oid == KEY_BAG {
                        if value.len() > MAX_KEY_LEN {
                            return Err(ImportError::Limit);
                        }
                        Zeroizing::new(value.to_vec())
                    } else {
                        let mut encrypted = sequence(value)?;
                        let algorithm = encrypted.value(0x30)?;
                        let ciphertext = encrypted.value(4)?;
                        encrypted.end()?;
                        if ciphertext.len() > MAX_KEY_LEN + 16 {
                            return Err(ImportError::Limit);
                        }
                        decrypt(algorithm, ciphertext, password, bmp, budget)?
                    };
                    if der.len() > MAX_KEY_LEN {
                        return Err(ImportError::Limit);
                    }
                    self.key = Some(der);
                }
                SAFE_BAG => self.bags(value, password, bmp, depth + 1, budget)?,
                _ => return Err(ImportError::UnsupportedProtection),
            }
        }
        Ok(())
    }
}

pub(crate) fn read(bytes: &[u8], password: &[u8], trust: &Trust) -> Result<Loaded, ImportError> {
    crate::memory::scrub_after(|| read_inner(bytes, password, trust))
}

#[inline(never)]
fn read_inner(bytes: &[u8], password: &[u8], trust: &Trust) -> Result<Loaded, ImportError> {
    if bytes.len() > MAX_IMPORT_LEN {
        return Err(ImportError::Limit);
    }
    let bmp = bmp(password)?;
    let mut pfx = sequence(bytes)?;
    if pfx.uint()? != 3 {
        return Err(ImportError::UnsupportedProtection);
    }
    let mut safe = pfx.sequence()?;
    if safe.value(6)? != DATA {
        return Err(ImportError::UnsupportedProtection);
    }
    let auth = one(safe.value(0xa0)?, 4)?;
    safe.end()?;
    if pfx.0.is_empty() {
        return Err(ImportError::Authentication);
    }
    let mac = pfx.value(0x30)?;
    pfx.end()?;
    let mut budget = MAX_WORK;
    // No decrypted bytes or bags are read until the authenticated safe is verified.
    verify_mac(mac, auth, &bmp, &mut budget)?;
    let mut auth = sequence(auth)?;
    let mut contents = Contents::default();
    let mut count = 0;
    while !auth.0.is_empty() {
        count += 1;
        if count > MAX_IMPORT_ITEMS {
            return Err(ImportError::Limit);
        }
        let mut info = auth.sequence()?;
        let oid = info.value(6)?;
        let value = info.value(0xa0)?;
        info.end()?;
        match oid {
            DATA => contents.bags(one(value, 4)?, password, &bmp, 0, &mut budget)?,
            ENCRYPTED_DATA => {
                let mut encrypted = sequence(value)?;
                if encrypted.uint()? != 0 {
                    return Err(ImportError::UnsupportedProtection);
                }
                let mut info = encrypted.sequence()?;
                encrypted.end()?;
                if info.value(6)? != DATA {
                    return Err(ImportError::UnsupportedProtection);
                }
                let algorithm = info.value(0x30)?;
                let ciphertext = info.value(0x80)?;
                info.end()?;
                let plain = decrypt(algorithm, ciphertext, password, &bmp, &mut budget)?;
                contents.bags(&plain, password, &bmp, 0, &mut budget)?;
            }
            _ => return Err(ImportError::UnsupportedProtection),
        }
    }
    let mut certificates =
        import::check_certificates(&contents.users, &contents.authorities, trust)?;
    if certificates.len() != 1 {
        return Err(ImportError::Malformed);
    }
    let certificate = certificates.remove(0);
    let key = contents.key.ok_or(ImportError::Malformed)?;
    // The enclosing import scrubs once, after validation and all KDF/CBC frames have returned.
    signing::TqslKey::from_pkcs8_der_inner(&key, certificate.public_key_der())?;
    Ok(Loaded { certificate, key })
}

#[cfg(test)]
mod tests;
