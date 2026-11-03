// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A LoTW callsign certificate: what a signed log's tCERT record carries, and what decides which
//! QSOs it may sign. LoTW's own extensions name the DXCC entity and the first and last QSO date
//! the certificate covers; the callsign is an attribute of the subject.
//!
//! This reads the certificate's fields. Whether it was issued by LoTW's CA is checked when it is
//! imported (qso-graph-desktop#172), and by LoTW when it receives the log.

use std::fmt;
use std::time::SystemTime;

use x509_cert::Certificate as X509;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, DecodePem, Encode};

use crate::qso::Date;
use crate::signing::tqsl_base64;

/// LoTW's object identifiers, under ARRL's arc 1.3.6.1.4.1.12348.1.
const CALLSIGN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.12348.1.1");
const QSO_NOT_BEFORE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.12348.1.2");
const QSO_NOT_AFTER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.12348.1.3");
const DXCC_ENTITY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.12348.1.4");

/// A LoTW callsign certificate.
#[derive(Clone)]
pub struct Certificate {
    der: Vec<u8>,
    spki: Vec<u8>,
    callsign: String,
    dxcc: u32,
    qso_not_before: Date,
    qso_not_after: Date,
    not_before: SystemTime,
    not_after: SystemTime,
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("callsign", &self.callsign)
            .field("dxcc", &self.dxcc)
            .field("qso_not_before", &self.qso_not_before)
            .field("qso_not_after", &self.qso_not_after)
            .finish_non_exhaustive()
    }
}

/// Why a certificate cannot be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateError {
    /// Not a certificate in PEM or DER.
    NotACertificate,
    /// A certificate without LoTW's callsign, DXCC entity or QSO dates.
    NotLotw,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACertificate => write!(f, "this is not a certificate"),
            Self::NotLotw => write!(f, "this is not a LoTW callsign certificate"),
        }
    }
}

impl std::error::Error for CertificateError {}

impl Certificate {
    /// A certificate from PEM, as tqsllib stores it, or DER.
    pub fn from_pem_or_der(bytes: &[u8]) -> Result<Self, CertificateError> {
        let cert = X509::from_pem(bytes)
            .or_else(|_| X509::from_der(bytes))
            .map_err(|_| CertificateError::NotACertificate)?;
        let der = cert
            .to_der()
            .map_err(|_| CertificateError::NotACertificate)?;
        let tbs = &cert.tbs_certificate;
        let spki = tbs
            .subject_public_key_info
            .to_der()
            .map_err(|_| CertificateError::NotACertificate)?;

        let callsign = tbs
            .subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .find(|atv| atv.oid == CALLSIGN)
            .and_then(|atv| text_of(atv.value.value()))
            .filter(|c| crate::qso::is_callsign(c))
            .ok_or(CertificateError::NotLotw)?;
        let extension = |oid: ObjectIdentifier| {
            tbs.extensions
                .iter()
                .flatten()
                .find(|e| e.extn_id == oid)
                .and_then(|e| std::str::from_utf8(e.extn_value.as_bytes()).ok())
        };
        let date = |oid| {
            extension(oid)
                .and_then(Date::from_iso)
                .ok_or(CertificateError::NotLotw)
        };
        let dxcc = extension(DXCC_ENTITY)
            .and_then(|d| d.parse().ok())
            .ok_or(CertificateError::NotLotw)?;
        let validity = &tbs.validity;
        Ok(Self {
            der,
            spki,
            callsign,
            dxcc,
            qso_not_before: date(QSO_NOT_BEFORE)?,
            qso_not_after: date(QSO_NOT_AFTER)?,
            not_before: validity.not_before.to_system_time(),
            not_after: validity.not_after.to_system_time(),
        })
    }

    pub fn callsign(&self) -> &str {
        &self.callsign
    }

    pub fn dxcc(&self) -> u32 {
        self.dxcc
    }

    /// The first and last QSO date this certificate may sign.
    pub fn qso_dates(&self) -> (Date, Date) {
        (self.qso_not_before, self.qso_not_after)
    }

    /// Whether the certificate is in force at this time.
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// The certificate's SubjectPublicKeyInfo, DER.
    pub fn public_key_der(&self) -> &[u8] {
        &self.spki
    }

    /// The certificate as a tCERT record carries it: base64 of the DER, in lines of 64
    /// characters, each ended by a newline.
    pub fn tcert_base64(&self) -> String {
        tqsl_base64(&self.der)
    }
}

/// The text of a UTF8String, PrintableString or IA5String value, as a callsign is written.
fn text_of(value: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(value).ok()?;
    Some(s.trim().to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/corpus/tqsl/1024/tqsl/certs/user"
        ))
        .expect("the corpus certificate")
    }

    #[test]
    fn the_lotw_fields_are_read() {
        let cert = Certificate::from_pem_or_der(&corpus()).expect("certificate");
        assert_eq!(cert.callsign(), "QG0TEST");
        assert_eq!(cert.dxcc(), 291);
        let (first, last) = cert.qso_dates();
        assert_eq!(
            (first.to_string(), last.to_string()),
            ("2020-01-01".into(), "2099-12-31".into())
        );
        assert!(cert.is_valid_at(SystemTime::now()));
        assert!(!cert.is_valid_at(SystemTime::UNIX_EPOCH));
        assert!(!format!("{cert:?}").contains("spki"));
    }

    #[test]
    fn what_is_not_a_lotw_certificate_is_refused() {
        assert_eq!(
            Certificate::from_pem_or_der(b"not a certificate").err(),
            Some(CertificateError::NotACertificate)
        );
        // The test CA's own certificate has none of LoTW's fields.
        let ca = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/corpus/tqsl/pki/ca.pem"
        ))
        .expect("the test CA");
        assert_eq!(
            Certificate::from_pem_or_der(&ca).err(),
            Some(CertificateError::NotLotw)
        );
    }
}
