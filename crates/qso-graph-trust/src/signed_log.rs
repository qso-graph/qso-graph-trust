// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A signed log, as LoTW receives it: an identification field, then a tCERT record with the
//! certificate, a tSTATION record with the station location, and a tCONTACT record for each QSO,
//! each carrying what was signed and its signature. This is the `.tq7`; a `.tq8` is the same,
//! gzipped.
//!
//! Before anything is signed, the key must be the certificate's, the station location the
//! certificate's call and DXCC entity, the certificate in force, and every QSO dated within the
//! certificate's QSO dates. One that is not stops the whole log, so a log is signed whole or not
//! at all.

use std::fmt;
use std::time::SystemTime;

use crate::certificate::Certificate;
use crate::lotw;
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
        station: String,
        certificate: String,
    },
    /// The station location's DXCC entity is not the certificate's.
    DxccNotCertificates { station: u32, certificate: u32 },
    /// A QSO, by its place in the log from 0, dated outside the certificate's QSO dates.
    QsoOutsideCertificate { index: usize },
    /// A log with no QSOs.
    Empty,
    /// The signing itself failed.
    Signing,
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
            Self::Empty => write!(f, "the log has no QSOs"),
            Self::Signing => write!(f, "signing failed"),
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
    if !key.matches_public_key(cert.public_key_der()) {
        return Err(LogError::KeyNotCertificates);
    }
    if !cert.is_valid_at(now) {
        return Err(LogError::CertificateNotInForce);
    }
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
    if qsos.is_empty() {
        return Err(LogError::Empty);
    }
    let (first, last) = cert.qso_dates();
    if let Some(index) = qsos.iter().position(|q| q.date < first || q.date > last) {
        return Err(LogError::QsoOutsideCertificate { index });
    }

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

    out.push_str("<Rec_Type:8>tSTATION\n<STATION_UID:1>1\n<CERT_UID:1>1\n");
    for (name, value) in station.fields() {
        field(&mut out, name, value);
    }
    out.push_str("<eor>\n");

    let station_data = station.sign_data();
    for q in qsos {
        let sign_data = (station_data.clone() + &q.sign_data()).to_ascii_uppercase();
        let signature = key
            .sign(sign_data.as_bytes())
            .map_err(|_| LogError::Signing)?;
        let signature = tqsl_base64(&signature);
        out.push_str("<Rec_Type:8>tCONTACT\n<STATION_UID:1>1\n");
        let date = q.date.to_string();
        let time = q.time.to_string();
        let fields = [
            ("CALL", Some(q.call.as_str())),
            ("BAND", Some(q.band)),
            ("MODE", Some(q.mode)),
            ("FREQ", q.freq.as_deref()),
            ("FREQ_RX", q.freq_rx.as_deref()),
            ("PROP_MODE", q.prop_mode.as_deref()),
            ("SAT_NAME", q.sat_name.as_deref()),
            ("BAND_RX", q.band_rx),
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

/// A signed log gzipped, as a `.tq8`: one gzip member (RFC 1952) with no name and no time in its
/// header, so the same log always gives the same bytes.
pub fn tq8(tq7: &[u8]) -> Vec<u8> {
    // ID1 ID2, deflate, no flags, no modification time, no extra flags, OS unknown.
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    out.extend(miniz_oxide::deflate::compress_to_vec(tq7, 9));
    out.extend(crc32(tq7).to_le_bytes());
    // ISIZE is the length modulo 2^32, as RFC 1952 defines it.
    out.extend((tq7.len() as u32).to_le_bytes());
    out
}

/// The CRC-32 gzip carries (RFC 1952 section 8: polynomial 0xEDB88320, reflected).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One field and its newline, `<NAME:LENGTH>VALUE`, the length in bytes.
fn field(out: &mut String, name: &str, value: &str) {
    out.push_str(&format!("<{name}:{}>{value}\n", value.len()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_is_gzips() {
        // RFC 1952's CRC-32 of "123456789", the standard check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_tq8_is_the_log_gzipped() {
        let log = b"<TQSL_IDENT:4>test\n<Rec_Type:5>tCERT\n<eor>\n".repeat(50);
        let gz = tq8(&log);
        assert_eq!(gz[..4], [0x1f, 0x8b, 8, 0]);
        let body = &gz[10..gz.len() - 8];
        let inflated =
            miniz_oxide::inflate::decompress_to_vec_with_limit(body, log.len()).expect("inflates");
        assert_eq!(inflated, log);
        assert_eq!(gz[gz.len() - 8..gz.len() - 4], crc32(&log).to_le_bytes());
        assert_eq!(gz[gz.len() - 4..], (log.len() as u32).to_le_bytes());
        assert_eq!(tq8(&log), gz, "the same log, the same bytes");
    }
}
