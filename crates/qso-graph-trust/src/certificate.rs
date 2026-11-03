// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A LoTW callsign certificate: what a signed log's tCERT record carries, and what decides which
//! QSOs it may sign. LoTW's own extensions name the DXCC entity and the first and last QSO date
//! the certificate covers; the callsign is an attribute of the subject.
//!
//! [`Certificate::from_pem_or_der`] reads the certificate's fields; [`Certificate::verify`] checks
//! that it was issued, signature by signature, under a root QG Trust trusts ([`Trust`]): LoTW's own,
//! pinned in [`crate::lotw::arrl`], never a root a file brings with it.

use std::fmt;
use std::time::SystemTime;

use qso_graph_trust_awslc::{Digest, verify_rsa};
use x509_cert::Certificate as X509;
use x509_cert::der::Tagged;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};

use crate::qso::Date;
use crate::signing::tqsl_base64;

/// LoTW's object identifiers, under ARRL's arc 1.3.6.1.4.1.12348.1.
const CALLSIGN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.12348.1.1");
const QSO_NOT_BEFORE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.12348.1.2");
const QSO_NOT_AFTER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.12348.1.3");
const DXCC_ENTITY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.12348.1.4");

/// The largest certificate accepted, PEM or DER: a LoTW certificate is about 1.2 KiB of DER, so
/// this leaves room for any real one and keeps its tCERT field well inside a record's limit.
pub const MAX_CERTIFICATE_LEN: usize = 16 * 1024;

/// A LoTW callsign certificate.
#[derive(Clone)]
pub struct Certificate {
    der: Vec<u8>,
    spki: Vec<u8>,
    serial: Vec<u8>,
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
            .field("serial", &self.serial())
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
    /// Larger than [`MAX_CERTIFICATE_LEN`], refused before it is read.
    TooLarge,
    /// A certificate without LoTW's callsign, DXCC entity or QSO dates.
    NotLotw,
    /// A certificate that does not chain, signature by signature, to a trusted root. Names the
    /// issuer it could not trust, as the certificate gives it.
    Untrusted { issuer: String },
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACertificate => write!(f, "this is not a certificate"),
            Self::TooLarge => write!(f, "this is too large to be a LoTW certificate"),
            Self::NotLotw => write!(f, "this is not a LoTW callsign certificate"),
            Self::Untrusted { issuer } => {
                write!(
                    f,
                    "this certificate is not issued under a trusted LoTW root (issuer: {issuer})"
                )
            }
        }
    }
}

impl std::error::Error for CertificateError {}

impl Certificate {
    /// A certificate from PEM, as tqsllib stores it, or DER.
    pub fn from_pem_or_der(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() > MAX_CERTIFICATE_LEN {
            return Err(CertificateError::TooLarge);
        }
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
        // The serial, big-endian, with no leading zeros: how ARRL numbers the certificates it issues,
        // and how TQSL tells one call's certificates apart. RFC 5280 makes it positive, and ARRL's
        // are; a negative one is refused (found by Codex review: its sign was dropped).
        let bytes = tbs.serial_number.as_bytes();
        if bytes.first().is_some_and(|&b| b & 0x80 != 0) {
            return Err(CertificateError::NotLotw);
        }
        let serial = bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..].to_vec();
        Ok(Self {
            der,
            spki,
            serial,
            callsign,
            dxcc,
            qso_not_before: date(QSO_NOT_BEFORE)?,
            qso_not_after: date(QSO_NOT_AFTER)?,
            not_before: validity.not_before.to_system_time(),
            not_after: validity.not_after.to_system_time(),
        })
    }

    /// The serial number, as its big-endian bytes.
    pub fn serial_number(&self) -> &[u8] {
        &self.serial
    }

    /// The serial number as a number, if it fits in a signed 64-bit one: ARRL's do. tqsllib reads
    /// it into a `long` and writes `-1` for one that does not fit (`ASN1_INTEGER_get`).
    pub fn serial(&self) -> Option<i64> {
        if self.serial.len() > 8 {
            return None;
        }
        let n = self
            .serial
            .iter()
            .fold(0u64, |n, &b| (n << 8) | u64::from(b));
        i64::try_from(n).ok()
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

    /// When the certificate comes into force and when it ends.
    pub fn validity(&self) -> (SystemTime, SystemTime) {
        (self.not_before, self.not_after)
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

/// The longest chain followed: a callsign certificate, its CA and LoTW's root, with room for one more.
const MAX_CHAIN: usize = 4;

/// The roots a callsign certificate must chain to, and CA certificates known to lie between.
pub struct Trust {
    roots: Vec<X509>,
    authorities: Vec<X509>,
}

impl fmt::Debug for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trust")
            .field("roots", &self.roots.len())
            .field("authorities", &self.authorities.len())
            .finish()
    }
}

impl Trust {
    /// LoTW's: ARRL's root, and its production CA, as TQSL embeds them ([`crate::lotw::arrl`]).
    pub fn lotw() -> Trust {
        let pem = |p: &str| X509::from_pem(p.as_bytes()).expect("LoTW's pinned certificates parse");
        Trust {
            roots: vec![pem(crate::lotw::arrl::ROOT)],
            authorities: vec![pem(crate::lotw::arrl::PRODUCTION_CA)],
        }
    }

    /// Other roots, PEM or DER, as tests use a test CA's: never LoTW's, and never from a file the
    /// certificate came in.
    pub fn with_roots(roots: &[&[u8]]) -> Result<Trust, CertificateError> {
        let roots = roots
            .iter()
            .map(|r| X509::from_pem(r).or_else(|_| X509::from_der(r)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CertificateError::NotACertificate)?;
        Ok(Trust {
            roots,
            authorities: Vec::new(),
        })
    }
}

/// The digest a certificate's signature algorithm names: RSA PKCS#1 v1.5 only, with its parameters
/// absent or NULL, as RFC 4055 section 5 requires (found by Codex review: parameters were not read).
fn digest_of(algorithm: &x509_cert::spki::AlgorithmIdentifierOwned) -> Option<Digest> {
    const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
    const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    let null = algorithm
        .parameters
        .as_ref()
        .is_none_or(|p| p.tag() == x509_cert::der::Tag::Null && p.value().is_empty());
    if !null {
        return None;
    }
    match algorithm.oid {
        SHA1 => Some(Digest::Sha1),
        SHA256 => Some(Digest::Sha256),
        SHA384 => Some(Digest::Sha384),
        SHA512 => Some(Digest::Sha512),
        _ => None,
    }
}

/// Whether `issuer` signed `cert`: its name is the certificate's issuer, and the signature checks
/// with its key.
fn signed_by(cert: &X509, issuer: &X509) -> bool {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject
        || cert.signature_algorithm != cert.tbs_certificate.signature
    {
        return false;
    }
    // The issuer's key must be RSA; its RSAPublicKey is the key info's bit string.
    const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != RSA {
        return false;
    }
    let (Some(digest), Ok(tbs), Some(key), Some(signature)) = (
        digest_of(&cert.signature_algorithm),
        cert.tbs_certificate.to_der(),
        spki.subject_public_key.as_bytes(),
        cert.signature.as_bytes(),
    ) else {
        return false;
    };
    verify_rsa(key, digest, &tbs, signature)
}

const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

fn extension(cert: &X509, oid: ObjectIdentifier) -> Option<&[u8]> {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

fn basic_constraints(cert: &X509) -> Option<BasicConstraints> {
    extension(cert, BASIC_CONSTRAINTS).and_then(|v| BasicConstraints::from_der(v).ok())
}

/// Whether a certificate may issue others: basic constraints say it is a CA.
fn is_ca(cert: &X509) -> bool {
    basic_constraints(cert).is_some_and(|b| b.ca)
}

/// Whether a key usage extension, if there is one, allows this use; unreadable allows nothing.
fn allows(cert: &X509, usage: KeyUsages) -> bool {
    match extension(cert, KEY_USAGE) {
        None => true,
        Some(v) => KeyUsage::from_der(v).is_ok_and(|k| k.0.contains(usage)),
    }
}

/// Whether the extensions this check reads can be read: none given twice, and basic constraints
/// and key usage, where present, decoded (found by Codex review: a second basic constraints went
/// unread, and an undecodable one counted as none).
fn extensions_well_formed(cert: &X509) -> bool {
    let extensions: Vec<_> = cert.tbs_certificate.extensions.iter().flatten().collect();
    let distinct = extensions
        .iter()
        .enumerate()
        .all(|(i, e)| extensions[..i].iter().all(|o| o.extn_id != e.extn_id));
    distinct
        && extension(cert, BASIC_CONSTRAINTS).is_none_or(|v| BasicConstraints::from_der(v).is_ok())
        && extension(cert, KEY_USAGE).is_none_or(|v| KeyUsage::from_der(v).is_ok())
}

/// Whether every extension marked critical is one this check reads (basic constraints and key
/// usage): an unknown critical one, name constraints among them, means the certificate's limits are
/// not known, so it is not trusted (RFC 5280 section 4.2; found by Codex review).
fn criticals_understood(cert: &X509) -> bool {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .all(|e| !e.critical || e.extn_id == BASIC_CONSTRAINTS || e.extn_id == KEY_USAGE)
}

impl Certificate {
    /// Checks that this certificate chains, signature by signature, to one of `trust`'s roots,
    /// through CA certificates from `trust` or from `intermediates` (those a file came with, which
    /// are trusted only as far as a root's signature reaches them). Each CA must say it is one. A
    /// root or CA past its dates still counts, as in TQSL; this certificate's own dates are checked
    /// when it signs.
    pub fn verify(&self, trust: &Trust, intermediates: &[Vec<u8>]) -> Result<(), CertificateError> {
        let cert = X509::from_der(&self.der).map_err(|_| CertificateError::NotACertificate)?;
        let others: Vec<X509> = intermediates
            .iter()
            .filter_map(|d| X509::from_der(d).ok())
            .collect();
        // A CA here is one that says it is, may sign certificates, and has no limit this check does
        // not read (found by Codex review: key usage and critical extensions were not read).
        let cas: Vec<&X509> = trust
            .authorities
            .iter()
            .chain(others.iter())
            .filter(|c| {
                extensions_well_formed(c)
                    && is_ca(c)
                    && allows(c, KeyUsages::KeyCertSign)
                    && criticals_understood(c)
            })
            .collect();
        let untrusted = |c: &X509| CertificateError::Untrusted {
            issuer: c.tbs_certificate.issuer.to_string(),
        };
        // The callsign certificate itself: not a CA, allowed to sign data, limits all read.
        if !extensions_well_formed(&cert)
            || is_ca(&cert)
            || !allows(&cert, KeyUsages::DigitalSignature)
            || !criticals_understood(&cert)
        {
            return Err(untrusted(&cert));
        }
        let mut current = cert;
        // The CA certificates passed so far lie below the one looked for next: a CA's path length is
        // the most it may have under it (RFC 5280 section 4.2.1.9; found by Codex review).
        for below in 0..MAX_CHAIN {
            if trust.roots.iter().any(|root| signed_by(&current, root)) {
                return Ok(());
            }
            let fits = |ca: &&&X509| {
                basic_constraints(ca)
                    .and_then(|b| b.path_len_constraint)
                    .is_none_or(|limit| usize::from(limit) >= below)
            };
            let Some(next) = cas.iter().filter(fits).find(|ca| signed_by(&current, ca)) else {
                return Err(untrusted(&current));
            };
            current = (*next).clone();
        }
        Err(untrusted(&current))
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

    fn file(rel: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/corpus/{rel}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("the corpus")
    }

    fn der_of(pem: &[u8]) -> Vec<u8> {
        X509::from_pem(pem).expect("PEM").to_der().expect("DER")
    }

    #[test]
    fn lotws_pinned_ca_is_signed_by_its_pinned_root() {
        // A real chain: ARRL's 4096-bit root's SHA-512 signature over its production CA.
        let trust = Trust::lotw();
        assert!(signed_by(&trust.authorities[0], &trust.roots[0]));
        assert!(is_ca(&trust.authorities[0]) && is_ca(&trust.roots[0]));
        // And it passes the limits a CA must keep, as a chain through it would need.
        let ca = &trust.authorities[0];
        assert!(allows(ca, KeyUsages::KeyCertSign) && criticals_understood(ca));
    }

    #[test]
    fn a_certificate_chains_to_a_trusted_root_through_its_ca() {
        let cert = Certificate::from_pem_or_der(&corpus()).expect("certificate");
        let root = file("tqsl/pki/root.pem");
        let ca = der_of(&file("tqsl/pki/ca.pem"));
        let test = Trust::with_roots(&[&root]).expect("the test root");
        assert_eq!(cert.verify(&test, std::slice::from_ref(&ca)), Ok(()));
        // Without its CA, or against LoTW's root, it does not.
        assert!(matches!(
            cert.verify(&test, &[]),
            Err(CertificateError::Untrusted { .. })
        ));
        assert!(matches!(
            cert.verify(&Trust::lotw(), std::slice::from_ref(&ca)),
            Err(CertificateError::Untrusted { .. })
        ));
        // The CA given as the root's stand-in is not trusted for being in the file: only a root is.
        let ca_pem = file("tqsl/pki/ca.pem");
        assert!(matches!(
            cert.verify(
                &Trust::with_roots(&[&file("standard/pki/root.pem")]).expect("another root"),
                &[der_of(&ca_pem)]
            ),
            Err(CertificateError::Untrusted { .. })
        ));
    }

    /// A certificate from tests/corpus/chains (scripts/make-chain-cases.sh).
    fn chain(name: &str) -> Vec<u8> {
        file(&format!("chains/{name}.pem"))
    }

    fn verify_chain(leaf: &str, cas: &[&str]) -> Result<(), CertificateError> {
        let cert = Certificate::from_pem_or_der(&chain(leaf)).expect("a test certificate");
        let root = chain("root");
        let trust = Trust::with_roots(&[&root]).expect("the chain test root");
        let cas: Vec<Vec<u8>> = cas.iter().map(|c| der_of(&chain(c))).collect();
        cert.verify(&trust, &cas)
    }

    #[test]
    fn a_chain_must_keep_its_cas_limits() {
        assert_eq!(verify_chain("leaf-good", &["ca-good"]), Ok(()));
        // Codex review: limits a CA states were not read, though every signature checked.
        let untrusted =
            |r: Result<(), CertificateError>| matches!(r, Err(CertificateError::Untrusted { .. }));
        // A CA allowed no CA under it, with one under it.
        assert!(untrusted(verify_chain(
            "leaf-pathlen",
            &["ca-under-pathlen0", "ca-pathlen0"]
        )));
        // A CA whose key may not sign certificates.
        assert!(untrusted(verify_chain("leaf-nosign", &["ca-nosign"])));
        // A CA, or the certificate itself, with a critical extension nothing here reads.
        assert!(untrusted(verify_chain(
            "leaf-critical-ca",
            &["ca-critical"]
        )));
        assert!(untrusted(verify_chain("leaf-critical", &["ca-good"])));
        // A callsign certificate that says it is a CA.
        assert!(untrusted(verify_chain("leaf-is-ca", &["ca-good"])));
        // Codex review round 3: a callsign certificate whose critical basic constraints cannot be
        // decoded, which counted as having none.
        assert!(untrusted(verify_chain(
            "leaf-bad-constraints",
            &["ca-good"]
        )));
    }

    #[test]
    fn an_extension_given_twice_is_not_read() {
        // Codex review round 3: a CA's basic constraints given twice, no limit then pathlen 0; only
        // the first was read. (openssl will not issue one, so it is made here: its signature no
        // longer checks, so the rule is tested on its own.)
        let ca = X509::from_pem(chain("ca-good")).expect("a CA");
        assert!(extensions_well_formed(&ca));
        let mut twice = ca.clone();
        let mut extensions = twice.tbs_certificate.extensions.take().expect("extensions");
        let limit = BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        };
        extensions.push(x509_cert::ext::Extension {
            extn_id: BASIC_CONSTRAINTS,
            critical: true,
            extn_value: x509_cert::der::asn1::OctetString::new(limit.to_der().expect("DER"))
                .expect("octets"),
        });
        twice.tbs_certificate.extensions = Some(extensions);
        assert!(!extensions_well_formed(&twice));
    }

    #[test]
    fn a_signature_algorithm_with_parameters_is_not_one() {
        // Codex review: RFC 4055 allows these algorithms no parameters but NULL.
        use x509_cert::der::Any;
        use x509_cert::spki::AlgorithmIdentifierOwned;
        let sha256 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let with = |parameters| AlgorithmIdentifierOwned {
            oid: sha256,
            parameters,
        };
        assert_eq!(digest_of(&with(None)), Some(Digest::Sha256));
        assert_eq!(
            digest_of(&with(Some(Any::from_der(&[0x05, 0x00]).expect("NULL")))),
            Some(Digest::Sha256)
        );
        assert_eq!(
            digest_of(&with(Some(
                Any::from_der(&[0x02, 0x01, 0x00]).expect("INTEGER 0")
            ))),
            None
        );
    }

    #[test]
    fn serials_are_read_whole_and_never_negative() {
        let cert = Certificate::from_pem_or_der(&chain("leaf-good")).expect("certificate");
        assert_eq!(cert.serial(), Some(1));
        let mut c = cert.clone();
        // 2^56: eight bytes, a signed 64-bit number (Codex review: refused at seven).
        c.serial = vec![1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(c.serial(), Some(1 << 56));
        c.serial = vec![0x80, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(c.serial(), None);
    }

    #[test]
    fn a_signature_changed_by_one_bit_does_not_verify() {
        let mut cert = Certificate::from_pem_or_der(&corpus()).expect("certificate");
        let n = cert.der.len();
        cert.der[n - 1] ^= 1;
        let root = file("tqsl/pki/root.pem");
        let test = Trust::with_roots(&[&root]).expect("the test root");
        assert!(matches!(
            cert.verify(&test, &[der_of(&file("tqsl/pki/ca.pem"))]),
            Err(CertificateError::Untrusted { .. })
        ));
    }

    #[test]
    fn a_certificate_too_large_to_be_lotws_is_refused_unread() {
        // Codex review: a 16 MiB extension was decoded, copied and re-encoded.
        let mut big = corpus();
        big.resize(MAX_CERTIFICATE_LEN + 1, b'\n');
        assert_eq!(
            Certificate::from_pem_or_der(&big).err(),
            Some(CertificateError::TooLarge)
        );
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
