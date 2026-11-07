// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! TQSL's backup, the `.tbk`: every certificate, key and station location a ham's TQSL holds, and the
//! QSOs it has signed, as TQSL's app writes them (apps/tqsl.cpp, MyFrame::BackupConfig): gzipped XML,
//! `<TQSL_Configuration>` holding `<Certificates>`, `<Locations>`, `<TQSLSettings>` and `<DupeDb>`.
//!
//! A backup is untrusted input that holds private keys. It is decompressed into one wiped buffer
//! within a limit, and read by QG Trust's own XML reader, bounded as it reads, with
//! no DTD and so no entity to expand. Every callsign certificate must chain, signature by signature,
//! to a root the caller trusts ([`Trust::lotw`], ARRL's, pinned, and the store's accepted roots).
//! [`read`] takes no root from the backup. [`read_trusting_roots`] reads it as the operator's own:
//! a root it carries is trusted when it is self-signed, a CA that may sign certificates with no
//! critical extension unread, and one of the backup's callsign certificates chains to it through
//! the backup's CAs ([`crate::certificate`]'s rules); a root none of them uses is never trusted.
//! Each certificate, key and location is checked as QG Trust
//! checks one on its own, and against the others it comes with: a key must be its certificate's, for
//! the same call and DXCC entity, and a key with no password must be a whole, LoTW-shaped key. A
//! protected key is checked the same way when it is first unlocked, which needs its password. A
//! backup that does not hang together is refused whole, saying what and where, never what a key
//! holds.
//!
//! TQSL's settings are read for the ones that change what LoTW receives ([`Preferences`]): custom
//! ADIF modes, Cabrillo contests, seconds, callsign checks and the log's own QTH details. Where logs
//! are uploaded, through which proxy, and whether TLS is checked are never taken from a file: a
//! backup that could set them could send a ham's logs anywhere.
//!
//! Reading is all this does: where the keys go (the OS credential store) is the caller's.

use std::fmt;

use base64ct::{Base64, Encoding};
use x509_cert::der::{DecodePem, Encode};
use zeroize::Zeroizing;

use crate::certificate::{
    Certificate, CertificateError, FoundRoot, MAX_CERTIFICATE_LEN, Trust, file_roots,
};
use crate::gzip::{self, GzipError};
use crate::lotw;
use crate::signing::{KeyEntry, KeyError};
use crate::station::{StationError, StationLocation};
use crate::xml::{self, Element};

/// The largest backup accepted, decompressed: room for many thousands of signed QSOs.
pub const MAX_TBK_LEN: usize = 256 * 1024 * 1024;
/// The most callsign certificates in one backup.
pub const MAX_CERTIFICATES: usize = 1024;
/// The most station locations in one backup.
pub const MAX_LOCATIONS: usize = 4096;
/// The longest station location name, in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// What a TQSL backup holds.
#[derive(Debug)]
pub struct Backup {
    /// The root certificates the backup carries, as DER. They are trusted only as
    /// [`read_trusting_roots`] says, and kept only by `Store::trust_backup_roots`.
    pub roots: Vec<Vec<u8>>,
    /// The certificate authorities' certificates, as DER.
    pub authorities: Vec<Vec<u8>>,
    /// Each callsign certificate with its key, in the order written.
    pub certificates: Vec<BackedUpCertificate>,
    /// Each station location, in the order written.
    pub locations: Vec<BackedUpLocation>,
    /// The QSOs TQSL has signed, from its duplicate database.
    pub signed_qsos: Vec<SignedQso>,
    /// TQSL's settings that change what LoTW receives.
    pub preferences: Preferences,
    /// TQSL's other settings, by group and name, not taken: its own interface, and anything that
    /// sets where logs go.
    pub settings_not_taken: Vec<String>,
    /// The sections of the backup not read: TQSL's own settings, and anything newer.
    pub not_read: Vec<String>,
}

/// One callsign certificate and its key, as a backup holds them. A key with no certificate is one
/// waiting for ARRL to answer its request; a certificate with no key cannot sign.
#[derive(Debug)]
pub struct BackedUpCertificate {
    /// The call, as the backup's entry names it.
    pub callsign: String,
    /// The DXCC entity, by ARRL's number.
    pub dxcc: u32,
    /// The certificate's serial number as TQSL wrote it: `-1` for one too large for tqsllib's `long`,
    /// `0` for a key still waiting for its certificate.
    pub serial: i64,
    /// The certificate, checked to LoTW's root; none for a key still waiting for one.
    pub certificate: Option<Certificate>,
    /// The key, as TQSL keeps it, locked if it has a password; none for a certificate without one.
    pub key: Option<KeyEntry>,
}

/// One station location, by its name.
#[derive(Debug)]
pub struct BackedUpLocation {
    /// The location's name in TQSL.
    pub name: String,
    /// The location, checked as LoTW checks one.
    pub station: StationLocation,
}

/// How a log's own QTH details (its `MY_` fields) are treated, as TQSL's "Log Handling" sets it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QthHandling {
    /// Not looked at (TQSL_LOC_IGNORE). When signing, STATION_CALLSIGN and MY_DXCC are not
    /// compared either, so another station's QSOs can be signed as the selected location's.
    Ignore,
    /// A QSO whose details disagree with the station location is refused: TQSL's default, and QG
    /// Trust's (TQSL_LOC_REPORT).
    #[default]
    Refuse,
    /// The log's details take the place of the station location's (TQSL_LOC_UPDATE).
    FromLog,
}

/// TQSL's settings that change what LoTW receives, as its preferences set them (apps/tqsl.cpp,
/// apps/tqsl_prefs.cpp). Each defaults to TQSL's own default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Preferences {
    /// Custom ADIF modes: an ADIF mode, and the LoTW mode it is signed as. One that names a mode
    /// LoTW already has is left out, as TQSL leaves it out.
    pub adif_modes: Vec<(String, String)>,
    /// Cabrillo contests: a contest's name, its type, and the field its call is in.
    pub cabrillo_contests: Vec<(String, i64, i64)>,
    /// QSO times signed without their seconds.
    pub ignore_seconds: bool,
    /// QSOs signed though their call does not look like one.
    pub allow_bad_calls: bool,
    /// A log's STATION_CALLSIGN and OPERATOR not checked against the certificate.
    pub ignore_log_callsigns: bool,
    /// What a log's own QTH details do.
    pub qth: QthHandling,
}

/// One QSO TQSL has signed: its duplicate-check key, and the station it was signed for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedQso {
    /// TQSL's duplicate-check key for the QSO.
    pub key: String,
    /// The station location it was signed for, as TQSL recorded it.
    pub station: String,
}

/// Why a backup cannot be read. Says what and where, never what a key holds.
#[derive(Debug, PartialEq, Eq)]
pub enum TbkError {
    /// The gzip around it is damaged.
    Gzip(GzipError),
    /// Larger than [`MAX_TBK_LEN`].
    TooLarge,
    /// Not UTF-8 text.
    NotText,
    /// Not XML this reader reads, at this line and column: malformed, or with a DTD.
    Xml {
        /// The line, from 1.
        line: usize,
        /// The column, from 1.
        column: usize,
        /// What is wrong there.
        problem: &'static str,
    },
    /// Well-formed XML, but not a TQSL backup.
    NotABackup,
    /// More of something than a backup holds.
    TooMany(&'static str),
    /// An element or attribute a backup's entry needs is missing, given twice, or not one a backup has.
    Malformed {
        /// What is missing, repeated or unknown.
        what: String,
    },
    /// A root or CA certificate, by its place among them from 0, that is not a certificate.
    Authority {
        /// Its place among the backup's root and CA certificates, from 0.
        index: usize,
    },
    /// A callsign certificate that cannot be read.
    Certificate {
        /// The call its entry names.
        callsign: String,
        /// Why it cannot be read.
        error: CertificateError,
    },
    /// A key that cannot be read, or, with no password, does not unlock.
    Key {
        /// The call its entry names.
        callsign: String,
        /// Why it cannot be read or unlocked.
        error: KeyError,
    },
    /// A key or certificate that is not for the call or entity its entry names, or a key that is
    /// not its certificate's.
    Mismatch {
        /// The call its entry names.
        callsign: String,
        /// What does not match.
        what: &'static str,
    },
    /// A station location LoTW would not accept.
    Location {
        /// The location's name.
        name: String,
        /// Why LoTW would not accept it.
        error: StationError,
    },
    /// Two station locations with one name.
    RepeatedLocation {
        /// The name given twice.
        name: String,
    },
}

impl fmt::Display for TbkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gzip(e) => write!(f, "the backup: {e}"),
            Self::TooLarge => write!(f, "the backup is too large"),
            Self::NotText => write!(f, "the backup is not text"),
            Self::Xml {
                line,
                column,
                problem,
            } => {
                write!(
                    f,
                    "the backup's XML: {problem}, at line {line}, column {column}"
                )
            }
            Self::NotABackup => write!(f, "this is not a TQSL backup"),
            Self::TooMany(what) => write!(f, "the backup holds too many {what}"),
            Self::Malformed { what } => write!(f, "the backup's {what} is malformed"),
            Self::Authority { index } => {
                write!(
                    f,
                    "the backup's root or CA certificate {} is not a certificate",
                    index + 1
                )
            }
            Self::Certificate { callsign, error } => write!(f, "{callsign}'s certificate: {error}"),
            Self::Key { callsign, error } => write!(f, "{callsign}'s key: {error}"),
            Self::Mismatch { callsign, what } => write!(f, "{callsign}: {what}"),
            Self::Location { name, error } => write!(f, "station location {name:?}: {error}"),
            Self::RepeatedLocation { name } => {
                write!(f, "two station locations are named {name:?}")
            }
        }
    }
}

impl std::error::Error for TbkError {}

impl From<GzipError> for TbkError {
    fn from(e: GzipError) -> Self {
        match e {
            GzipError::TooLarge => Self::TooLarge,
            e => Self::Gzip(e),
        }
    }
}

/// A TQSL backup read whole, gzipped as TQSL writes it or the XML itself, each callsign
/// certificate checked against `trust`: [`Trust::lotw`], or the store's trust
/// (`Store::trust_with`). The roots the backup carries establish nothing here.
pub fn read(bytes: &[u8], trust: &Trust) -> Result<Backup, TbkError> {
    read_with(bytes, trust, false)
}

/// A TQSL backup read as [`read`] reads one, but as the operator's own: a root it carries is
/// trusted for its certificates when it may be accepted, by [`crate::certificate`]'s rules
/// (self-signed, a CA that may sign certificates, and a callsign certificate in the backup chains
/// to it through the backup's CAs). `Store::trust_backup_roots` then keeps those roots, and says
/// which are new.
pub fn read_trusting_roots(bytes: &[u8], trust: &Trust) -> Result<Backup, TbkError> {
    read_with(bytes, trust, true)
}

fn read_with(bytes: &[u8], trust: &Trust, own_roots: bool) -> Result<Backup, TbkError> {
    let plain;
    let text: &[u8] = if gzip::is_gzip(bytes) {
        plain = gzip::decompress(bytes, MAX_TBK_LEN)?;
        &plain
    } else if bytes.len() > MAX_TBK_LEN {
        return Err(TbkError::TooLarge);
    } else {
        bytes
    };
    let text = std::str::from_utf8(text).map_err(|_| TbkError::NotText)?;
    let root = xml::parse(text).map_err(|e| TbkError::Xml {
        line: e.line,
        column: e.column,
        problem: e.problem,
    })?;
    if root.name != "TQSL_Configuration" {
        return Err(TbkError::NotABackup);
    }
    let mut backup = Backup {
        roots: Vec::new(),
        authorities: Vec::new(),
        certificates: Vec::new(),
        locations: Vec::new(),
        signed_qsos: Vec::new(),
        preferences: Preferences::default(),
        settings_not_taken: Vec::new(),
        not_read: Vec::new(),
    };
    for section in &root.children {
        match section.name {
            "Certificates" => read_certificates(section, &mut backup)?,
            "Locations" => read_locations(section, &mut backup)?,
            "DupeDb" => read_signed_qsos(section, &mut backup)?,
            "TQSLSettings" => read_settings(section, &mut backup)?,
            other => backup.not_read.push(other.to_string()),
        }
    }
    // Every certificate issued under a trusted root, through the CAs the backup carries if need be:
    // checked once all of them are read, whatever order they came in.
    let trust = if own_roots {
        let found = backup.found_roots(trust);
        trust.with_found(&found)
    } else {
        trust.clone()
    };
    for entry in &backup.certificates {
        if let Some(cert) = &entry.certificate {
            cert.verify(&trust, &backup.authorities)
                .map_err(|error| TbkError::Certificate {
                    callsign: entry.callsign.clone(),
                    error,
                })?;
        }
    }
    Ok(backup)
}

impl Backup {
    /// The roots this backup carries that its own certificates chain to and `trust` does not hold,
    /// by [`crate::certificate`]'s rules.
    pub(crate) fn found_roots(&self, trust: &Trust) -> Vec<FoundRoot> {
        let users: Vec<Vec<u8>> = self
            .certificates
            .iter()
            .filter_map(|c| c.certificate.as_ref().map(|c| c.der().to_vec()))
            .collect();
        let supplied: Vec<Vec<u8>> = self
            .roots
            .iter()
            .chain(&self.authorities)
            .cloned()
            .collect();
        file_roots(&users, &supplied, trust)
    }
}

fn malformed(what: impl Into<String>) -> TbkError {
    TbkError::Malformed { what: what.into() }
}

/// The one child element with this name, if there is one; two is malformed.
fn only_child<'e, 'a>(
    node: &'e Element<'a>,
    name: &'e str,
    of: &str,
) -> Result<Option<&'e Element<'a>>, TbkError> {
    let mut found = node.children_named(name);
    let first = found.next();
    if found.next().is_some() {
        return Err(malformed(format!("{of} {name}")));
    }
    Ok(first)
}

fn read_certificates(section: &Element, backup: &mut Backup) -> Result<(), TbkError> {
    for entry in &section.children {
        match entry.name {
            kind @ ("RootCert" | "CACert") => {
                let index = backup.roots.len() + backup.authorities.len();
                let pem = entry.text();
                let pem = pem.trim();
                if pem.len() > MAX_CERTIFICATE_LEN {
                    return Err(TbkError::Authority { index });
                }
                let der = x509_cert::Certificate::from_pem(pem.as_bytes())
                    .and_then(|c| c.to_der())
                    .map_err(|_| TbkError::Authority { index })?;
                let list = if kind == "RootCert" {
                    &mut backup.roots
                } else {
                    &mut backup.authorities
                };
                if list.len() == MAX_CERTIFICATES {
                    return Err(TbkError::TooMany("root and CA certificates"));
                }
                if !list.contains(&der) {
                    list.push(der);
                }
            }
            "UserCert" => {
                if backup.certificates.len() == MAX_CERTIFICATES {
                    return Err(TbkError::TooMany("callsign certificates"));
                }
                backup.certificates.push(read_user_certificate(entry)?);
            }
            _ => return Err(malformed("certificate list")),
        }
    }
    Ok(())
}

fn read_user_certificate(entry: &Element) -> Result<BackedUpCertificate, TbkError> {
    let callsign = entry
        .attribute("CallSign")
        .filter(|c| crate::qso::is_callsign(c))
        .ok_or_else(|| malformed("callsign certificate's CallSign"))?
        .to_string();
    let dxcc = entry
        .attribute("dxcc")
        .and_then(|d| d.parse::<u32>().ok())
        .filter(|&d| d != 0 && lotw::dxcc(d).is_some())
        .ok_or_else(|| malformed(format!("{callsign}'s dxcc")))?;
    let serial = entry
        .attribute("serial")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .ok_or_else(|| malformed(format!("{callsign}'s serial")))?;
    if let Some(other) = entry
        .children
        .iter()
        .find(|c| !matches!(c.name, "SignedCert" | "PrivateKey"))
    {
        return Err(malformed(format!("{callsign}'s {}", other.name)));
    }
    let certificate = only_child(entry, "SignedCert", &callsign)?
        .map(|node| {
            Certificate::from_pem_or_der(node.text().trim().as_bytes()).map_err(|error| {
                TbkError::Certificate {
                    callsign: callsign.clone(),
                    error,
                }
            })
        })
        .transpose()?;
    let key = only_child(entry, "PrivateKey", &callsign)?
        .map(|node| read_key(&node.text(), &callsign))
        .transpose()?;
    // A key waiting for its certificate has none, and TQSL writes 0.
    if certificate.is_none() && serial != 0 {
        return Err(malformed(format!("{callsign}'s serial")));
    }
    if certificate.is_none() && key.is_none() {
        return Err(malformed(format!(
            "{callsign}'s entry, with neither certificate nor key,"
        )));
    }
    let mismatch = |what| TbkError::Mismatch {
        callsign: callsign.clone(),
        what,
    };
    if let Some(cert) = &certificate {
        if cert.callsign() != callsign {
            return Err(mismatch("the certificate is for another call"));
        }
        if cert.dxcc() != dxcc {
            return Err(mismatch("the certificate is for another DXCC entity"));
        }
        // The serial TQSL wrote is the certificate's, as tqsllib reads one: the serial is how one
        // call's certificates are told apart.
        // TQSL on Windows reads it into a 32-bit `long`, so writes -1 for one past 2^31 - 1.
        let written = cert.serial();
        let windows = written.is_some_and(|n| n > i64::from(i32::MAX)) && serial == -1;
        if written.unwrap_or(-1) != serial && !windows {
            return Err(mismatch(
                "the certificate's serial number is not its entry's",
            ));
        }
    }
    if let Some(key) = &key {
        if key.callsign() != callsign {
            return Err(mismatch("the key was made for another call"));
        }
        // A key is known by its request: its DXCC entity, where the key file records it, must be
        // its entry's; a key waiting for its certificate must record one, as tqsllib always does
        // (found in review: a pending key was reported for any entity).
        match key.request_dxcc() {
            Some(d) if d != dxcc => {
                return Err(mismatch("the key was requested for another DXCC entity"));
            }
            None if certificate.is_none() => {
                return Err(mismatch(
                    "the key waiting for its certificate names no DXCC entity",
                ));
            }
            _ => {}
        }
        if let Some(cert) = &certificate
            && key.public_key_der().as_deref() != Some(cert.public_key_der())
        {
            return Err(mismatch("the key is not the certificate's"));
        }
        // A key with no password is unlocked now, which proves its private key is the public key's
        // and LoTW-shaped, and dropped at once; a protected one is checked as far as it can be
        // without its password (found in review, twice).
        key.check().map_err(|error| TbkError::Key {
            callsign: callsign.clone(),
            error,
        })?;
    }
    Ok(BackedUpCertificate {
        callsign,
        dxcc,
        serial,
        certificate,
        key,
    })
}

/// A key as a backup holds it: base64 of one tqsllib key record, in lines. Every copy is wiped.
fn read_key(text: &str, callsign: &str) -> Result<KeyEntry, TbkError> {
    let error = |error| TbkError::Key {
        callsign: callsign.to_string(),
        error,
    };
    let mut joined = Zeroizing::new(String::with_capacity(text.len()));
    joined.extend(text.chars().filter(|c| !c.is_ascii_whitespace()));
    let mut decoded = Zeroizing::new(vec![0u8; joined.len() / 4 * 3 + 3]);
    let len = Base64::decode(joined.as_bytes(), &mut decoded)
        .map_err(|_| error(KeyError::NotAKey))?
        .len();
    let mut keys = KeyEntry::read_key_file(&decoded[..len]).map_err(error)?;
    if keys.len() != 1 {
        return Err(error(KeyError::NotAKey));
    }
    Ok(keys.remove(0))
}

fn read_locations(section: &Element, backup: &mut Backup) -> Result<(), TbkError> {
    for entry in &section.children {
        if entry.name != "Location" {
            return Err(malformed("station location list"));
        }
        if backup.locations.len() == MAX_LOCATIONS {
            return Err(TbkError::TooMany("station locations"));
        }
        let name = entry
            .attribute("name")
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty() && n.len() <= MAX_NAME_LEN)
            .ok_or_else(|| malformed("station location's name"))?;
        if backup.locations.iter().any(|l| l.name == name) {
            return Err(TbkError::RepeatedLocation { name });
        }
        let values: Vec<(&str, Zeroizing<String>)> =
            entry.attributes().filter(|(n, _)| *n != "name").collect();
        let fields: Vec<(&str, &str)> = values.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let station = StationLocation::new(&fields).map_err(|error| TbkError::Location {
            name: name.clone(),
            error,
        })?;
        backup.locations.push(BackedUpLocation { name, station });
    }
    Ok(())
}

/// The most settings read: TQSL has some sixty, and custom modes and contests besides.
const MAX_SETTINGS: usize = 10_000;

fn read_settings(section: &Element, backup: &mut Backup) -> Result<(), TbkError> {
    if section.children.len() > MAX_SETTINGS {
        return Err(TbkError::TooMany("settings"));
    }
    let prefs = &mut backup.preferences;
    for entry in &section.children {
        let (Some(name), Some(value)) = (entry.attribute("name"), entry.attribute("Value")) else {
            return Err(malformed("setting"));
        };
        if entry.name != "Setting" {
            return Err(malformed("setting"));
        }
        let group = entry
            .attribute("group")
            .map(|g| g.to_string())
            .unwrap_or_else(|| "/".into());
        let flag = |v: &str| v.trim().parse::<i64>().is_ok_and(|n| n != 0);
        match (group.as_str(), name.as_str()) {
            // A mode with `/` in it is stored with !SLASH! (apps/tqsl_prefs.cpp).
            ("/modeMap", adif) => {
                let adif = adif.replace("!SLASH!", "/").to_ascii_uppercase();
                let lotw = value.trim().to_ascii_uppercase();
                let standard = lotw::lotw_mode(&adif, None).is_some_and(|m| m == adif);
                match lotw::lotw_mode(&lotw, None).filter(|m| *m == lotw) {
                    Some(_) if !standard => prefs.adif_modes.push((adif, lotw)),
                    _ => backup.settings_not_taken.push(format!("/modeMap/{adif}")),
                }
            }
            // `type;field`, as tqsllib takes one (tqsl_setCabrilloMapEntry): type 0 for HF or 1 for
            // VHF, and the call worked in a field after the fifth (found in review).
            ("/cabrilloMap", contest) => {
                let (kind, field) = value.split_once(';').unwrap_or((&value, ""));
                match (kind.trim().parse::<i64>(), field.trim().parse::<i64>()) {
                    (Ok(k @ (0 | 1)), Ok(f @ 6..=64)) => {
                        prefs
                            .cabrillo_contests
                            .push((contest.to_ascii_uppercase(), k, f));
                    }
                    _ => backup
                        .settings_not_taken
                        .push(format!("/cabrilloMap/{contest}")),
                }
            }
            ("/", "IgnoreSeconds") => prefs.ignore_seconds = flag(&value),
            ("/", "BadCalls") => prefs.allow_bad_calls = flag(&value),
            ("/", "IgnoreADIFCallsign") => prefs.ignore_log_callsigns = flag(&value),
            ("/", "LogVerify") => {
                prefs.qth = match value.trim() {
                    "0" => QthHandling::Ignore,
                    "2" => QthHandling::FromLog,
                    _ => QthHandling::Refuse,
                }
            }
            (group, name) => backup
                .settings_not_taken
                .push(format!("{}/{name}", group.trim_end_matches('/'))),
        }
    }
    Ok(())
}

fn read_signed_qsos(section: &Element, backup: &mut Backup) -> Result<(), TbkError> {
    for entry in &section.children {
        let key = entry.attribute("key").filter(|_| entry.name == "Dupe");
        let Some(key) = key else {
            return Err(malformed("signed QSO list"));
        };
        backup.signed_qsos.push(SignedQso {
            key: key.to_string(),
            station: entry
                .attribute("data")
                .map(|d| d.to_string())
                .unwrap_or_default(),
        });
    }
    Ok(())
}
