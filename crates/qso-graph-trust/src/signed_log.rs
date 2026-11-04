// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A signed log, as LoTW receives it: an identification field, then a tCERT record with the
//! certificate, a tSTATION record with the station location, and a tCONTACT record for each QSO,
//! each carrying what was signed and its signature. This is the `.tq7`; a `.tq8` is the same,
//! gzipped.
//!
//! Before anything is signed, the key must be the certificate's, the station location the
//! certificate's call and DXCC entity, the certificate in force, and every QSO dated within the
//! certificate's QSO dates; and every QSO whose record names its station (`STATION_CALLSIGN`, or
//! `OPERATOR` without it, `MY_DXCC`, `MY_GRIDSQUARE` and the rest) must name this one. One that
//! is not stops the whole log, so a log is signed whole or not at all.

use std::fmt;
use std::time::SystemTime;

use crate::certificate::Certificate;
use crate::lotw;
use crate::options::SigningOptions;
use crate::qso::Qso;
use crate::signing::{TqslKey, tqsl_base64};
use crate::station::StationLocation;

/// Why a log cannot be signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogError {
    /// The key is not the certificate's.
    KeyNotCertificates,
    /// The certificate is not in force now.
    CertificateNotInForce,
    /// The station location's call is not the certificate's.
    CallNotCertificates {
        /// The station location's call.
        station: String,
        /// The certificate's call.
        certificate: String,
    },
    /// The station location's DXCC entity is not the certificate's.
    DxccNotCertificates {
        /// The station location's entity.
        station: u32,
        /// The certificate's entity.
        certificate: u32,
    },
    /// A QSO, by its place in the log from 0, dated outside the certificate's QSO dates.
    QsoOutsideCertificate {
        /// The QSO's place in the log, from 0.
        index: usize,
    },
    /// A QSO, by its place in the log from 0, whose record names another station: the ADIF field
    /// and the value it gives.
    QsoFromAnotherStation {
        /// The QSO's place in the log, from 0.
        index: usize,
        /// The ADIF field that disagrees.
        field: &'static str,
        /// The value the log gives it.
        value: String,
    },
    /// A log with no QSOs.
    Empty,
    /// The signing itself failed.
    Signing,
    /// A location resulting from the log is invalid.
    Location {
        /// QSO's zero-based input index.
        index: usize,
        /// The invalid location field.
        error: crate::station::StationError,
    },
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotCertificates => write!(f, "the key is not this certificate's"),
            Self::CertificateNotInForce => write!(f, "the certificate is not in force"),
            Self::CallNotCertificates {
                station,
                certificate,
            } => write!(
                f,
                "the station location is for {station}, the certificate for {certificate}"
            ),
            Self::DxccNotCertificates {
                station,
                certificate,
            } => write!(
                f,
                "the station location is in DXCC entity {station}, the certificate in {certificate}"
            ),
            Self::QsoOutsideCertificate { index } => write!(
                f,
                "QSO {} is dated outside the certificate's QSO dates",
                index + 1
            ),
            Self::QsoFromAnotherStation {
                index,
                field,
                value,
            } => write!(
                f,
                "QSO {} gives {field} {value:?}, which is not this station location's",
                index + 1
            ),
            Self::Empty => write!(f, "the log has no QSOs"),
            Self::Signing => write!(f, "signing failed"),
            Self::Location { index, error } => write!(f, "QSO {}: {error}", index + 1),
        }
    }
}

impl std::error::Error for LogError {}

/// The log, signed, as the bytes of a `.tq7`.
pub fn sign_log(
    cert: &Certificate,
    key: &TqslKey,
    station: &StationLocation,
    qsos: &[Qso],
    now: SystemTime,
) -> Result<Vec<u8>, LogError> {
    let locations = vec![station.clone(); qsos.len().max(1)];
    validate_log(cert, key, qsos, &locations, now)?;
    for (index, q) in qsos.iter().enumerate() {
        if let Some((field, value)) = q.station().find(|(f, v)| station.contradicts(f, v)) {
            return Err(LogError::QsoFromAnotherStation {
                index,
                field,
                value: value.to_owned(),
            });
        }
    }
    write_log(cert, key, qsos, &locations)
}

/// Sign with explicit log handling settings. Construct QSOs with these options too, so custom
/// modes and relaxed calls are accepted at input. Locations are resolved in input order before
/// any signature is made. Report mode fills empty fields; update mode carries changes forward.
/// A log requiring a different certificate is refused; the caller selects certificates explicitly.
pub fn sign_log_with_options(
    cert: &Certificate,
    key: &TqslKey,
    station: &StationLocation,
    qsos: &[Qso],
    now: SystemTime,
    options: &SigningOptions,
) -> Result<Vec<u8>, LogError> {
    let locations = options.locations(qsos, station)?;
    let qsos = options.qsos(qsos, &locations)?;
    sign_resolved(cert, key, &qsos, &locations, now)
}

pub(crate) fn sign_resolved(
    cert: &Certificate,
    key: &TqslKey,
    qsos: &[Qso],
    locations: &[StationLocation],
    now: SystemTime,
) -> Result<Vec<u8>, LogError> {
    validate_log(cert, key, qsos, locations, now)?;
    write_log(cert, key, qsos, locations)
}

fn validate_log(
    cert: &Certificate,
    key: &TqslKey,
    qsos: &[Qso],
    locations: &[StationLocation],
    now: SystemTime,
) -> Result<(), LogError> {
    if !key.matches_public_key(cert.public_key_der()) {
        return Err(LogError::KeyNotCertificates);
    }
    if !cert.is_valid_at(now) {
        return Err(LogError::CertificateNotInForce);
    }
    for station in locations {
        if station.call() != cert.callsign() {
            return Err(LogError::CallNotCertificates {
                station: station.call().to_string(),
                certificate: cert.callsign().to_string(),
            });
        }
        if station.dxcc() != cert.dxcc() {
            return Err(LogError::DxccNotCertificates {
                station: station.dxcc(),
                certificate: cert.dxcc(),
            });
        }
    }
    if qsos.is_empty() {
        return Err(LogError::Empty);
    }
    let (first, last) = cert.qso_dates();
    if let Some(index) = qsos
        .iter()
        .position(|q| q.date() < first || q.date() > last)
    {
        return Err(LogError::QsoOutsideCertificate { index });
    }

    Ok(())
}

fn write_log(
    cert: &Certificate,
    key: &TqslKey,
    qsos: &[Qso],
    locations: &[StationLocation],
) -> Result<Vec<u8>, LogError> {
    let (major, minor) = lotw::CONFIG_VERSION;
    let mut out = String::new();
    field(
        &mut out,
        "TQSL_IDENT",
        &format!(
            "QSO Graph Trust Lib: V{} Config: V{major}.{minor}",
            crate::VERSION
        ),
    );
    out.push_str("<Rec_Type:5>tCERT\n<CERT_UID:1>1\n");
    let cert_text = cert.tcert_base64();
    out.push_str(&format!(
        "<CERTIFICATE:{}>{cert_text}<eor>\n",
        cert_text.len()
    ));

    let mut previous = None;
    let mut station_uid = 0;
    for (q, station) in qsos.iter().zip(locations) {
        if previous != Some(station) {
            station_uid += 1;
            out.push_str("<Rec_Type:8>tSTATION\n");
            field(&mut out, "STATION_UID", &station_uid.to_string());
            out.push_str("<CERT_UID:1>1\n");
            for (name, value) in station.fields() {
                field(&mut out, name, value);
            }
            out.push_str("<eor>\n");
            previous = Some(station);
        }
        let station_data = station.sign_data();
        let sign_data = (station_data.clone() + &q.sign_data()).to_ascii_uppercase();
        let signature = key
            .sign(sign_data.as_bytes())
            .map_err(|_| LogError::Signing)?;
        let signature = tqsl_base64(&signature);
        out.push_str("<Rec_Type:8>tCONTACT\n");
        field(&mut out, "STATION_UID", &station_uid.to_string());
        let date = q.date().to_string();
        let time = q.time().to_string();
        let fields = [
            ("CALL", Some(q.call())),
            ("BAND", Some(q.band())),
            ("MODE", Some(q.mode())),
            ("FREQ", q.freq()),
            ("FREQ_RX", q.freq_rx()),
            ("PROP_MODE", q.prop_mode()),
            ("SAT_NAME", q.sat_name()),
            ("BAND_RX", q.band_rx()),
            ("QSO_DATE", Some(date.as_str())),
            ("QSO_TIME", Some(time.as_str())),
        ];
        for (name, value) in fields {
            if let Some(v) = value {
                field(&mut out, name, v);
            }
        }
        // The signature's base64 ends in a newline already.
        out.push_str(&format!(
            "<{}:{}:6>{signature}",
            lotw::SIGNATURE_FIELD,
            signature.len()
        ));
        field(&mut out, "SIGNDATA", &sign_data);
        out.push_str("<eor>\n");
    }
    Ok(out.into_bytes())
}

/// A signed log gzipped, as a `.tq8`: one gzip member with no name and no time in its header, so
/// the same log always gives the same bytes.
pub fn tq8(tq7: &[u8]) -> Vec<u8> {
    crate::gzip::compress(tq7)
}

/// One field and its newline, `<NAME:LENGTH>VALUE`, the length in bytes.
fn field(out: &mut String, name: &str, value: &str) {
    out.push_str(&format!("<{name}:{}>{value}\n", value.len()));
}
