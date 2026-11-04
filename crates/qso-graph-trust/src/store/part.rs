// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The plaintext is library-private: versioned public store XML followed by length-prefixed
//! PKCS#8 DER in certificate order. Public XML includes the signed-QSO section unchanged.

use std::fmt;

use zeroize::Zeroizing;

use super::{Data, MAX_FILE_LEN, MAX_KEY_LEN, Store, StoreError, format, keys};
use crate::certificate::Trust;
use crate::export::{self, ExportError, LOTW_PART, Password};
use crate::signing::TqslKey;

const MAGIC: &[u8] = b"QGT-STORE\x01";

/// A restore result, containing counts only, never credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    /// Certificates installed, including public-only ones.
    pub certificates: usize,
    /// Private keys installed.
    pub keys: usize,
    /// Checked station locations installed.
    pub locations: usize,
}

/// An encrypted store operation failed. No variant contains plaintext, passwords or key data.
#[derive(Debug)]
pub enum PartError {
    /// Encryption, password validation or authentication failed.
    Export(ExportError),
    /// The authenticated plaintext failed format, certificate, key or location validation.
    Invalid,
    /// A store or credential backend operation failed.
    Store(StoreError),
}
impl fmt::Display for PartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Export(e) => e.fmt(f),
            Self::Invalid => f.write_str("the export part contents are invalid"),
            Self::Store(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for PartError {}
impl From<StoreError> for PartError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<super::KeyStoreError> for PartError {
    fn from(e: super::KeyStoreError) -> Self {
        Self::Store(e.into())
    }
}
impl From<ExportError> for PartError {
    fn from(e: ExportError) -> Self {
        Self::Export(e)
    }
}

impl Store {
    /// Export the complete LoTW store encrypted under a library-generated password. Only
    /// ciphertext leaves the library. Missing or mismatched credentials refuse the whole export.
    pub fn export_part(&self, password: &Password) -> Result<Vec<u8>, PartError> {
        password.require_generated()?;
        let plaintext = self.part_plaintext()?;
        Ok(export::seal(LOTW_PART, &plaintext, password)?)
    }

    /// Snapshot the public file and its secrets under the same lock. Never return this publicly.
    pub(crate) fn part_plaintext(&self) -> Result<Zeroizing<Vec<u8>>, PartError> {
        let _lock = self.lock()?;
        let data = self.read()?;
        let xml = Zeroizing::new(format::write(&data)?);
        let mut secrets = Vec::new();
        let mut size = MAGIC.len() + 4 + xml.len();
        for cert in &data.certificates {
            if let Some(name) = &cert.key_name {
                let der = self.keys.get(name)?.ok_or(StoreError::NotFound)?;
                if der.is_empty() || der.len() > MAX_KEY_LEN {
                    return Err(PartError::Invalid);
                }
                TqslKey::from_pkcs8_der(&der, cert.certificate.public_key_der())
                    .map_err(|_| PartError::Invalid)?;
                size += 4 + der.len();
                secrets.push(der);
            }
        }
        // Exact capacity avoids reallocating plaintext into freed, unwiped memory.
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(xml.len() as u32).to_be_bytes());
        out.extend_from_slice(xml.as_bytes());
        for der in secrets {
            out.extend_from_slice(&(der.len() as u32).to_be_bytes());
            out.extend_from_slice(&der);
        }
        Ok(out)
    }

    /// Authenticate and validate the complete part before touching this store. All certificates
    /// must chain to caller-supplied trust, keys must match, and locations must pass the store's
    /// `StationLocation::new` reader. Staged keys precede atomic file replacement; old keys are
    /// deleted afterwards. A failure before replacement rolls back staged keys. A durability
    /// failure after replacement keeps both sets of keys and reports uncertain crash durability.
    pub fn restore_part(
        &self,
        bytes: &[u8],
        password: &Password,
        trust: &Trust,
    ) -> Result<RestoreReport, PartError> {
        let opened = export::open(LOTW_PART, bytes, password)?;
        let (mut data, secrets) = decode(&opened, trust)?;
        let report = RestoreReport {
            certificates: data.certificates.len(),
            keys: secrets.len(),
            locations: data.locations.len(),
        };
        let _lock = self.lock()?;
        let old = self.read()?;
        let mut names = Vec::new();
        // Allocate fresh credential names so even a restore onto the source cannot overwrite a
        // key named by the current file. No backend mutation until all names and XML are checked.
        for cert in &mut data.certificates {
            if let Some(name) = &mut cert.key_name {
                *name = keys::new_name("key:")?;
                if names.contains(name) || self.keys.exists(name)? {
                    return Err(StoreError::AlreadyExists.into());
                }
                names.push(name.clone());
            }
        }
        let xml = format::write(&data)?;
        for (index, (name, der)) in names.iter().zip(&secrets).enumerate() {
            if let Err(e) = self.keys.put(name, der) {
                return Err(self.rollback_part(&names[..index], e.into()).into());
            }
        }
        if let Err(e) = self.replace(&xml) {
            if matches!(e, StoreError::Durability(_)) {
                return Err(e.into());
            }
            return Err(self.rollback_part(&names, e).into());
        }
        for cert in old.certificates {
            if let Some(name) = cert.key_name {
                self.keys.delete(&name)?;
            }
        }
        Ok(report)
    }

    fn rollback_part(&self, names: &[String], write: StoreError) -> StoreError {
        let mut failed = None;
        for name in names {
            if let Err(e) = self.keys.delete(name) {
                failed.get_or_insert(e);
            }
        }
        match failed {
            Some(cleanup) => StoreError::Rollback {
                write: Box::new(write),
                cleanup,
            },
            None => write,
        }
    }
}

// Length framing keeps raw key bytes out of XML parsing, strings, diagnostics and base64 copies.
fn take_record<'a>(input: &mut &'a [u8], max: usize) -> Result<&'a [u8], PartError> {
    let length = input.get(..4).ok_or(PartError::Invalid)?;
    let length = u32::from_be_bytes(length.try_into().map_err(|_| PartError::Invalid)?) as usize;
    if length > max {
        return Err(PartError::Invalid);
    }
    let record = input.get(4..4 + length).ok_or(PartError::Invalid)?;
    *input = &input[4 + length..];
    Ok(record)
}

type Secrets = Vec<Zeroizing<Vec<u8>>>;
fn decode(opened: &[u8], trust: &Trust) -> Result<(Data, Secrets), PartError> {
    let mut input = opened.strip_prefix(MAGIC).ok_or(PartError::Invalid)?;
    let xml = take_record(&mut input, MAX_FILE_LEN)?;
    let data = format::read(std::str::from_utf8(xml).map_err(|_| PartError::Invalid)?)
        .map_err(|_| PartError::Invalid)?;
    let mut secrets = Vec::new();
    for cert in &data.certificates {
        cert.certificate
            .verify(trust, &[])
            .map_err(|_| PartError::Invalid)?;
        if cert.key_name.is_some() {
            let der = take_record(&mut input, MAX_KEY_LEN)?;
            TqslKey::from_pkcs8_der(der, cert.certificate.public_key_der())
                .map_err(|_| PartError::Invalid)?;
            secrets.push(Zeroizing::new(der.to_vec()));
        }
    }
    if !input.is_empty() {
        return Err(PartError::Invalid);
    }
    Ok((data, secrets))
}

#[cfg(test)]
mod tests;
