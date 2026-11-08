// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Bounded certificate import. Inspect with `Store::inspect_tq6`, `Store::inspect_pkcs12` or
//! `Store::inspect_tbk`, review the public preview, then consume it with `Store::commit`. Decrypted
//! keys stay inside the pending value and are wiped on drop. The one-step convenience methods
//! use this same path. The whole file is validated before any store mutation. Errors contain
//! categories and public certificate details only.
//!
//! A root the file brings is trusted only by [`crate::certificate`]'s rules: it is in the file,
//! self-signed, a CA that may sign certificates with no critical extension unread, and a callsign
//! certificate in the file chains to it through the file's CAs. For a `.tq6` or `.p12` the operator
//! must also confirm it, by its SHA-256 fingerprint; until then the import is refused with
//! [`ImportError::UntrustedRoot`] naming it. A confirmed root is stored with the certificate, in
//! the same store write. LoTW's pinned roots, and those the store has accepted, need no confirming.

use crate::certificate::{
    Certificate, CertificateError, FoundRoot, MAX_CERTIFICATE_LEN, Trust, file_roots,
    verify_imported,
};
use crate::gzip::{self, GzipError};
use crate::signing::KeyError;
use crate::store::StoreError;
use crate::xml;
use std::fmt;
use x509_cert::der::{Decode, DecodePem, Encode};

/// Maximum input and decompressed certificate-file size (4 MiB).
pub const MAX_IMPORT_LEN: usize = 4 * 1024 * 1024;
/// Maximum certificates or bags in one file.
pub const MAX_IMPORT_ITEMS: usize = 128;
/// Maximum password size, before decoding or deriving anything.
pub const MAX_PASSWORD_LEN: usize = 1024;
/// Maximum iteration count for each PBKDF2 or PKCS#12 derivation.
pub const MAX_ITERATIONS: u32 = 1_000_000;

/// Why a certificate import failed. No variant contains passwords or key material.
#[derive(Debug)]
pub enum ImportError {
    /// Input, decompression, nesting, item count, password or KDF work exceeds a bound.
    Limit,
    /// Invalid XML, DER, bag structure, padding, or missing/ambiguous certificate or key.
    Malformed,
    /// Damaged gzip wrapper.
    Gzip(GzipError),
    /// A certificate is malformed or does not chain to caller trust.
    Certificate(CertificateError),
    /// The file's certificates chain to a root it brings, which may be accepted but is not
    /// trusted yet and was not confirmed. Nothing was imported; importing again confirming this
    /// fingerprint trusts the root and imports the file.
    UntrustedRoot {
        /// The root's subject common name, as the root gives it.
        subject: String,
        /// The root's SHA-256 fingerprint, uppercase hexadecimal pairs separated by colons.
        fingerprint: String,
    },
    /// The root fingerprint confirmed is not one this file's certificates chain to. Nothing was
    /// imported.
    RootMismatch {
        /// The fingerprint given, as [`crate::certificate::fingerprint`] writes one; empty if what
        /// was given is not a SHA-256 fingerprint.
        given: String,
    },
    /// The private key is invalid, not LoTW-shaped or does not match its certificate.
    Key(KeyError),
    /// Missing MAC, wrong password or modified authenticated content.
    Authentication,
    /// Unsupported encryption, MAC, KDF, content or bag type (RC2-40 included).
    UnsupportedProtection,
    /// The store or a referenced credential changed after inspection. Inspect again.
    Conflict,
    /// The backup could not be read.
    Backup(crate::tbk::TbkError),
    /// This key could not be checked. The index identifies its preview entry.
    KeyAt {
        /// Index in `ImportPreview::certificates`.
        index: usize,
        /// Fixed key error category.
        error: KeyError,
    },
    /// Publication or credential storage failed; see `StoreError` for durability semantics.
    Store(StoreError),
}
impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit => f.write_str("the certificate import exceeds a limit"),
            Self::Malformed => f.write_str("the certificate import is malformed"),
            Self::Gzip(e) => e.fmt(f),
            Self::Certificate(e) => e.fmt(f),
            Self::UntrustedRoot {
                subject,
                fingerprint,
            } => write!(
                f,
                "the certificates chain to a root that is not trusted yet: {subject}, SHA-256 \
                 {fingerprint}"
            ),
            Self::RootMismatch { given } if given.is_empty() => {
                f.write_str("the root to trust was not given as a SHA-256 fingerprint")
            }
            Self::RootMismatch { given } => write!(
                f,
                "the root to trust, SHA-256 {given}, is not one this file's certificates chain to"
            ),
            Self::Key(e) => e.fmt(f),
            Self::Authentication => f.write_str("the PKCS#12 MAC could not be authenticated"),
            Self::UnsupportedProtection => {
                f.write_str("unsupported certificate import protection or bag type")
            }
            Self::Conflict => {
                f.write_str("the store changed after inspection; inspect the import again")
            }
            Self::Backup(e) => e.fmt(f),
            Self::KeyAt { index, error } => write!(f, "import key {index}: {error}"),
            Self::Store(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for ImportError {}
impl From<CertificateError> for ImportError {
    fn from(e: CertificateError) -> Self {
        Self::Certificate(e)
    }
}
impl From<KeyError> for ImportError {
    fn from(e: KeyError) -> Self {
        Self::Key(e)
    }
}
impl From<StoreError> for ImportError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// One installed certificate, identified by its store ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedCertificate {
    /// The ID to use with the store's certificate operations.
    pub id: String,
    /// Whether this certificate has a matching private key in the store.
    pub has_key: bool,
    /// Whether import attached an existing pending request and removed that pending record.
    pub attached_request: bool,
    /// Whether the certificate was in the store already; nothing was added for it.
    pub already_here: bool,
}

type InspectedCertificates = (Vec<(Certificate, Option<CertificateError>)>, Vec<FoundRoot>);

/// Verification failures keep the parsed public identity available for a refusal preview.
pub(crate) fn inspect_certificates(
    users: &[Vec<u8>],
    authorities: &[Vec<u8>],
    trust: &Trust,
) -> Result<InspectedCertificates, ImportError> {
    if users.is_empty() {
        return Err(ImportError::Malformed);
    }
    let roots = file_roots(users, authorities, trust);
    let trust = trust.with_found(&roots);
    let authority_error = authorities
        .iter()
        .find_map(|a| verify_imported(a, &trust, authorities, true).err());
    let certificates = users
        .iter()
        .map(|der| {
            let certificate = Certificate::from_pem_or_der(der)?;
            let refusal = authority_error
                .clone()
                .or_else(|| certificate.verify(&trust, authorities).err());
            Ok((certificate, refusal))
        })
        .collect::<Result<_, ImportError>>()?;
    Ok((certificates, roots))
}

type CertificateContents = (Vec<Vec<u8>>, Vec<Vec<u8>>);

pub(crate) fn tq6_contents(bytes: &[u8]) -> Result<CertificateContents, ImportError> {
    if bytes.len() > MAX_IMPORT_LEN {
        return Err(ImportError::Limit);
    }
    let plain = if gzip::is_gzip(bytes) {
        gzip::decompress(bytes, MAX_IMPORT_LEN).map_err(|e| match e {
            GzipError::TooLarge => ImportError::Limit,
            e => ImportError::Gzip(e),
        })?
    } else {
        zeroize::Zeroizing::new(bytes.to_vec())
    };
    let root = xml::parse(std::str::from_utf8(&plain).map_err(|_| ImportError::Malformed)?)
        .map_err(|_| ImportError::Malformed)?;
    if root.name != "tqsldata"
        || root.children.len() != 1
        || root.children[0].name != "tqslcerts"
        || !root.text().trim().is_empty()
        || !root.children[0].text().trim().is_empty()
    {
        return Err(ImportError::Malformed);
    }
    let mut users = Vec::new();
    let mut authorities = Vec::new();
    for entry in &root.children[0].children {
        if users.len() + authorities.len() >= MAX_IMPORT_ITEMS {
            return Err(ImportError::Limit);
        }
        if !entry.children.is_empty() {
            return Err(ImportError::Malformed);
        }
        let pem = entry.text();
        if pem.len() > MAX_CERTIFICATE_LEN {
            return Err(ImportError::Limit);
        }
        let der = x509_cert::Certificate::from_pem(pem.trim().as_bytes())
            .and_then(|c| c.to_der())
            .map_err(|_| ImportError::Malformed)?;
        match entry.name {
            "usercert" => users.push(der),
            "rootcert" | "cacert" => authorities.push(der),
            _ => return Err(ImportError::Malformed),
        }
    }
    Ok((users, authorities))
}

pub(crate) fn is_authority(der: &[u8]) -> Result<bool, ImportError> {
    use x509_cert::ext::pkix::BasicConstraints;
    let cert = x509_cert::Certificate::from_der(der).map_err(|_| ImportError::Malformed)?;
    cert.tbs_certificate
        .get::<BasicConstraints>()
        .map(|v| v.is_some_and(|(_, bc)| bc.ca))
        .map_err(|_| ImportError::Malformed)
}
