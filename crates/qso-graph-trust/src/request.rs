// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Callsign certificate requests compatible with TQSL 2.8.7 (`openssl_cert.cpp`,
//! `tqsl_createCertRequest` and `tqsl_sign_base64_data`). Nothing is sent to ARRL here.
//!
//! Desktop and CLI can collect a [`CertificateRequest`] and call [`CertificateRequest::generate`].
//! For additional requests or renewals, borrow the authorizing key through
//! [`crate::store::Store::with_key`]; return the generated request from the callback before
//! calling [`crate::store::Store::store_request`] (the callback must not reenter the store).
//! Store the opaque result before saving or submitting its public [`GeneratedRequest::tq5`].
//! The store owns the backend and records the pending call, DXCC, SPKI, creation time and key
//! name in `store.xml`; applications need not retain a credential handle or request metadata.
//! Use [`crate::store::Store::pending_requests`] to list requests and
//! [`crate::store::Store::abandon_request`] to discard one. Verify the response's issuer, then
//! pass it to [`crate::store::Store::add_requested_certificate`], which matches call, DXCC and
//! SPKI and checks the stored private key before attaching it and removing the pending record.
//!
//! Requests identify QG Trust with the same `TQSL_IDENT` value as signed logs. The other fields,
//! CSR subject, empty attributes and algorithms follow TQSL 2.8.7. [`CallKind`] captures wizard
//! intent; TQSL does not encode a kind-specific field. Generation uses AWS-LC through the binding
//! for RSA-1024 (exponent 65537) and SHA-256 CSR signing, which aws-lc-rs cannot perform at that
//! key size. Generated PKCS#8 remains in wiped memory and has no public byte accessor.
//!
//! These are library APIs; CLI commands and Desktop screens are not implemented yet. The only
//! backend currently selectable is volatile [`crate::store::KeyBackend::Memory`], for tests;
//! persistent OS backends await their dependency decision. Applications must install the wiping
//! allocator described in the crate README. No upload is performed here.

use std::fmt;

use qso_graph_trust_awslc::RsaKey;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::der::asn1::{
    Any, BitString, Ia5StringRef, ObjectIdentifier, SetOfVec, Utf8StringRef,
};
use x509_cert::der::{Decode, Encode, EncodePem, Tag, pem::LineEnding};
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
use x509_cert::request::{CertReq, CertReqInfo, Version};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use zeroize::Zeroizing;

use crate::certificate::Certificate;
use crate::qso::{Date, is_callsign};
use crate::signing::{TqslKey, tqsl_base64};

/// The operator's reason for requesting a call. TQSL's wizard uses this to guide signer
/// selection (`apps/crqwiz.cpp`, `signCode`); `TQSL_CERT_REQ` has no kind field and none is
/// encoded in the CSR or `.tq5`. The caller chooses the signer explicitly via [`Authorization`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CallKind {
    /// A personal callsign.
    #[default]
    Personal,
    /// A club callsign.
    Club,
    /// A DXpedition callsign.
    Dxpedition,
    /// A special event callsign.
    SpecialEvent,
    /// A previously held callsign.
    Former,
    /// A call replacing the operator's existing call.
    Replacing,
    /// A callsign for which the operator is QSL manager.
    QslManager,
}

/// Public request data. Text is bounded by TQSL's `TQSL_CRQ_*_MAX` byte limits, trimmed
/// as TQSL trims it (C-locale whitespace runs become one space), and cannot contain
/// framing delimiters or control characters.
#[derive(Clone, Debug)]
pub struct CertificateRequest {
    /// Uppercase station callsign, embedded in the CSR subject.
    pub callsign: String,
    /// ARRL DXCC entity number, checked against the generated LoTW tables.
    pub dxcc: u32,
    /// First QSO date. `Date` can only be constructed from a valid calendar date.
    pub qso_not_before: Date,
    /// Last QSO date; absent for a current call without an end date.
    pub qso_not_after: Option<Date>,
    /// Operator name (60 bytes).
    pub name: String,
    /// First address line (80 bytes).
    pub address1: String,
    /// Optional second address line (80 bytes).
    pub address2: String,
    /// City (80 bytes).
    pub city: String,
    /// Optional state or province (80 bytes).
    pub state: String,
    /// Optional postal code (20 bytes).
    pub postal_code: String,
    /// Country (80 bytes).
    pub country: String,
    /// ASCII email address (128 bytes, OpenSSL's CSR email bound; uses IA5String).
    pub email: String,
    /// Certificate provider organization (256 bytes); empty is allowed by tqsllib.
    pub provider: String,
    /// Certificate provider unit (256 bytes); empty is allowed by tqsllib.
    pub provider_unit: String,
    /// Operator's kind of call; see [`CallKind`] for its wire semantics.
    pub kind: CallKind,
}

/// Whether an existing certificate authorizes this request. The supplied key must belong
/// to the supplied certificate. Renewal additionally requires the same call and DXCC.
#[derive(Clone, Copy, Debug)]
pub enum Authorization<'a> {
    /// First or unsigned request (`TQSL_CRQ_NEW`).
    New,
    /// Request for another certificate (`TQSL_CRQ_ADDITIONAL`).
    Additional {
        /// Existing callsign certificate.
        certificate: &'a Certificate,
        /// Borrowed, unlocked key, for example from `Store::with_key`.
        key: &'a TqslKey,
    },
    /// Renew this call's certificate (`TQSL_CRQ_RENEWAL`), with a fresh key.
    Renewal {
        /// Certificate being renewed.
        certificate: &'a Certificate,
        /// Borrowed, unlocked key for that certificate.
        key: &'a TqslKey,
    },
}

/// A public request with a new private key held solely for a credential-store handoff.
/// Debug output never includes the key. Dropping this without storing loses the new key.
pub struct GeneratedRequest {
    tq5: String,
    pub(crate) private: Zeroizing<Vec<u8>>,
    pub(crate) public: Vec<u8>,
    pub(crate) callsign: String,
    pub(crate) dxcc: u32,
    pub(crate) created_at: u64,
}

impl fmt::Debug for GeneratedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GeneratedRequest(..)")
    }
}

impl GeneratedRequest {
    /// Public `.tq5` text. Save or submit only after successfully storing the new key.
    pub fn tq5(&self) -> &str {
        &self.tq5
    }

    /// Public SubjectPublicKeyInfo DER, for matching the response certificate.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public
    }
}

/// Fixed error categories; no key material, password or user-supplied text is included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// A missing, oversized or invalid public field, named here.
    Invalid(&'static str),
    /// Key generation, DER encoding or signing failed.
    Crypto,
    /// The signer does not match the certificate or renewal identity.
    SignerMismatch,
    /// The issuer name cannot be represented as TQSL's issuer field.
    Issuer,
    /// The system clock precedes the Unix epoch.
    Clock,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(f, "invalid certificate request field: {field}"),
            Self::Crypto => f.write_str("could not generate or sign the certificate request"),
            Self::SignerMismatch => f.write_str("request signer does not match the certificate"),
            Self::Issuer => f.write_str("certificate issuer cannot be written as a TQSL issuer"),
            Self::Clock => f.write_str("the system clock precedes the Unix epoch"),
        }
    }
}
impl std::error::Error for RequestError {}

impl CertificateRequest {
    /// Validate public inputs before generating a key or invoking a signer.
    pub fn validate(&self) -> Result<(), RequestError> {
        for (field, value, max, required) in self.text_fields() {
            if value.len() > max
                || value
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '<' | '>'))
                || (required && normalize_text(value).is_empty())
            {
                return Err(RequestError::Invalid(field));
            }
        }
        if !is_callsign(&normalize_text(&self.callsign)) {
            return Err(RequestError::Invalid("CALLSIGN"));
        }
        if crate::lotw::dxcc(self.dxcc).is_none() {
            return Err(RequestError::Invalid("DXCC_ENTITY"));
        }
        if self
            .qso_not_after
            .is_some_and(|last| last < self.qso_not_before)
        {
            return Err(RequestError::Invalid("QSO_NOT_AFTER"));
        }
        let email = normalize_text(&self.email);
        if !email.is_ascii()
            || !email
                .split_once('@')
                .is_some_and(|(_, domain)| domain.contains('.'))
        {
            return Err(RequestError::Invalid("EMAIL"));
        }
        Ok(())
    }

    /// Generate a fresh RSA-1024 key and TQSL-compatible PKCS#10 request. The private key has
    /// no public byte accessor: hand the result to [`crate::store::Store::store_request`].
    /// Framing follows TQSL 2.8.7; `TQSL_IDENT` names QG Trust.
    pub fn generate(
        &self,
        authorization: Authorization<'_>,
    ) -> Result<GeneratedRequest, RequestError> {
        crate::memory::scrub_after(|| self.generate_inner(authorization))
    }

    #[inline(never)]
    fn generate_inner(
        &self,
        authorization: Authorization<'_>,
    ) -> Result<GeneratedRequest, RequestError> {
        self.validate()?;
        let created_at = creation_time(std::time::SystemTime::now())?;
        let signer = self.signer(authorization)?;
        let (private, public) = RsaKey::generate_lotw().map_err(|_| RequestError::Crypto)?;
        // Exercise precisely the same shape and public/private match checks as imported keys.
        TqslKey::from_pkcs8_der_inner(&private, &public).map_err(|_| RequestError::Crypto)?;
        let csr = self.csr(&private, &public)?;
        let tq5 = self.frame(&csr, authorization, signer)?;
        Ok(GeneratedRequest {
            tq5,
            private,
            public,
            callsign: normalize_text(&self.callsign),
            dxcc: self.dxcc,
            created_at,
        })
    }

    fn text_fields(&self) -> [(&'static str, &str, usize, bool); 11] {
        [
            ("PROVIDER", &self.provider, 256, false),
            ("PROVIDER_UNIT", &self.provider_unit, 256, false),
            ("EMAIL", &self.email, 128, true),
            ("NAME", &self.name, 60, true),
            ("ADDRESS1", &self.address1, 80, true),
            ("ADDRESS2", &self.address2, 80, false),
            ("CITY", &self.city, 80, true),
            ("STATE", &self.state, 80, false),
            ("POSTAL", &self.postal_code, 20, false),
            ("COUNTRY", &self.country, 80, true),
            ("CALLSIGN", &self.callsign, 20, true),
        ]
    }

    fn signer<'a>(
        &self,
        auth: Authorization<'a>,
    ) -> Result<Option<(&'a Certificate, &'a TqslKey)>, RequestError> {
        let (certificate, key) = match auth {
            Authorization::New => return Ok(None),
            Authorization::Additional { certificate, key } => (certificate, key),
            Authorization::Renewal { certificate, key } => {
                if certificate.callsign() != normalize_text(&self.callsign)
                    || certificate.dxcc() != self.dxcc
                {
                    return Err(RequestError::SignerMismatch);
                }
                (certificate, key)
            }
        };
        if !key.matches_public_key(certificate.public_key_der()) {
            return Err(RequestError::SignerMismatch);
        }
        Ok(Some((certificate, key)))
    }

    fn csr(&self, private: &[u8], public: &[u8]) -> Result<CertReq, RequestError> {
        let build = || -> x509_cert::der::Result<CertReqInfo> {
            let mut subject = RdnSequence::default();
            for (oid, value) in [
                (
                    "1.3.6.1.4.1.12348.1.1",
                    Any::encode_from(&Utf8StringRef::new(&normalize_text(&self.callsign))?)?,
                ),
                (
                    "2.5.4.3",
                    Any::encode_from(&Utf8StringRef::new(&latin1_utf8(&normalize_text(
                        &self.name,
                    )))?)?,
                ),
                (
                    "1.2.840.113549.1.9.1",
                    Any::encode_from(&Ia5StringRef::new(&normalize_text(&self.email))?)?,
                ),
            ] {
                subject
                    .0
                    .push(RelativeDistinguishedName(SetOfVec::try_from(vec![
                        AttributeTypeAndValue {
                            oid: ObjectIdentifier::new_unwrap(oid),
                            value,
                        },
                    ])?));
            }
            Ok(CertReqInfo {
                version: Version::V1,
                subject,
                public_key: SubjectPublicKeyInfoOwned::from_der(public)?,
                attributes: Default::default(),
            })
        };
        let info = build().map_err(|_| RequestError::Crypto)?;
        let key = RsaKey::from_pkcs8_der(private).map_err(|_| RequestError::Crypto)?;
        let signature = key
            .sign_sha256(&info.to_der().map_err(|_| RequestError::Crypto)?)
            .map_err(|_| RequestError::Crypto)?;
        Ok(CertReq {
            info,
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
                parameters: Some(
                    Any::new(Tag::Null, Vec::<u8>::new()).map_err(|_| RequestError::Crypto)?,
                ),
            },
            signature: BitString::from_bytes(&signature).map_err(|_| RequestError::Crypto)?,
        })
    }

    fn frame(
        &self,
        csr: &CertReq,
        auth: Authorization<'_>,
        signer: Option<(&Certificate, &TqslKey)>,
    ) -> Result<String, RequestError> {
        let mut out = String::from("\ntQSL certificate request\n\n<eoh>\n\n");
        let (major, minor) = crate::lotw::CONFIG_VERSION;
        field(
            &mut out,
            "TQSL_IDENT",
            &format!(
                "QSO Graph Trust Lib: V{} Config: V{major}.{minor}",
                crate::VERSION
            ),
        );
        out.push_str(match auth {
            Authorization::New => "<TQSL_CRQ_NEW>\n\n",
            Authorization::Additional { .. } => "<TQSL_CRQ_ADDITIONAL>\n\n",
            Authorization::Renewal { .. } => "<TQSL_CRQ_RENEWAL>\n\n",
        });
        for (name, value, _, _) in self.text_fields().into_iter().take(10) {
            field(
                &mut out,
                &format!("TQSL_CRQ_{name}"),
                &normalize_text(value),
            );
        }
        field(&mut out, "TQSL_CRQ_DXCC_ENTITY", &self.dxcc.to_string());
        field(
            &mut out,
            "TQSL_CRQ_QSO_NOT_BEFORE",
            &self.qso_not_before.to_string(),
        );
        if let Some(last) = self.qso_not_after {
            field(&mut out, "TQSL_CRQ_QSO_NOT_AFTER", &last.to_string());
        }
        field(
            &mut out,
            "TQSL_CRQ_REQUEST",
            &csr.to_pem(LineEnding::LF)
                .map_err(|_| RequestError::Crypto)?,
        );
        if let Some((certificate, key)) = signer {
            // tqsl_sign_base64_data decodes PEM first: SHA-1 covers the *whole CSR DER*,
            // including its new-key signature, not the PEM text or just CertReqInfo.
            let der = csr.to_der().map_err(|_| RequestError::Crypto)?;
            let signature = key.sign(&der).map_err(|_| RequestError::Crypto)?;
            field(&mut out, "TQSL_CRQ_SIGNATURE", &tqsl_base64(&signature));
            field(
                &mut out,
                "TQSL_CRQ_SIGNATURE_CERT_ISSUER",
                &issuer(certificate)?,
            );
            field(
                &mut out,
                "TQSL_CRQ_SIGNATURE_CERT_SERIAL",
                &certificate.serial().unwrap_or(-1).to_string(),
            );
        }
        out.push_str("<eor>\n\n");
        Ok(out)
    }
}

// tqsl_trim (TQSL 2.8.7, openssl_cert.cpp): trim and fold C-locale isspace only.
// Validation still rejects controls in the original input before either encoding.
fn normalize_text(value: &str) -> String {
    value
        .split([' ', '\t', '\n', '\u{000b}', '\u{000c}', '\r'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn creation_time(now: std::time::SystemTime) -> Result<u64, RequestError> {
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RequestError::Clock)
}

fn field(out: &mut String, name: &str, value: &str) {
    use std::fmt::Write;
    // Writing into a String cannot fail. Empty values retain :0 as tqsl_write_adif_field does.
    let _ = write!(out, "<{name}:{}>{value}\n\n", value.len());
}

// TQSL passes MBSTRING_ASC, which OpenSSL interprets as Latin-1 bytes, not UTF-8.
fn latin1_utf8(value: &str) -> String {
    value.bytes().map(char::from).collect()
}

// X509_NAME_oneline order/short names/byte escaping; tqsllib provides a 256-byte buffer.
fn issuer(certificate: &Certificate) -> Result<String, RequestError> {
    use std::fmt::Write;
    let cert =
        x509_cert::Certificate::from_der(certificate.der()).map_err(|_| RequestError::Issuer)?;
    let mut out = String::new();
    'rdns: for rdn in &cert.tbs_certificate.issuer.0 {
        for (index, attr) in rdn.0.iter().enumerate() {
            let oid = attr.oid.to_string();
            let name = match oid.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "1.2.840.113549.1.9.1" => "emailAddress",
                "2.5.4.5" => "serialNumber",
                "2.5.4.4" => "SN",
                "2.5.4.42" => "GN",
                "2.5.4.9" => "street",
                "0.9.2342.19200300.100.1.25" => "DC",
                "0.9.2342.19200300.100.1.1" => "UID",
                _ => &oid,
            };
            let separator = if index == 0 { '/' } else { '+' };
            let mut entry = format!("{separator}{name}=");
            for &byte in attr.value.value() {
                if (b' '..=b'~').contains(&byte) {
                    if matches!(byte, b'/' | b'+') {
                        entry.push('\\');
                    }
                    entry.push(char::from(byte));
                } else {
                    let _ = write!(entry, "\\x{byte:02X}");
                }
            }
            if out.len() + entry.len() > 255 {
                break 'rdns;
            }
            out.push_str(&entry);
        }
    }
    if out.contains(['<', '>', '\n', '\r']) {
        return Err(RequestError::Issuer);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
