// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A QSO as LoTW receives it, from an ADIF record: the call in capitals, LoTW's band and mode,
//! the frequency only if it is in that band, and the date and time in LoTW's form. A QSO LoTW
//! would refuse is refused here, saying which field and why.
//!
//! A QSO's record may also say which station made it (`STATION_CALLSIGN`, `MY_DXCC`,
//! `MY_GRIDSQUARE` and the rest). Those are kept, and a log is signed only if they agree with the
//! station location it is signed for (`signed_log`), under the caller's chosen log handling
//! settings. A [`Qso`] is made through [`Qso::from_adif`] or [`Qso::from_adif_with_options`], so
//! every one has been checked.

use std::fmt;

use crate::lotw;
use crate::options::{QthHandling, SigningOptions};
use crate::records::Record;

/// The longest frequency accepted, in characters: far more than any real one's digits.
pub const MAX_FREQ_LEN: usize = 16;
/// The longest value of any field read, in bytes, checked before the value is copied: longer than
/// every real callsign, mode, satellite, grid list or county.
pub const MAX_VALUE_LEN: usize = 64;

/// A calendar date, a real one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// A date written `YYYYMMDD`, as ADIF writes it, if it is a real one.
    pub fn from_adif(s: &str) -> Option<Self> {
        Self::from_digits(s.get(0..4)?, s.get(4..6)?, s.get(6..8)?).filter(|_| s.len() == 8)
    }

    /// A date written `YYYY-MM-DD`, as LoTW's certificates write it, if it is a real one.
    pub fn from_iso(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return None;
        }
        Self::from_digits(&s[0..4], &s[5..7], &s[8..10])
    }

    fn from_digits(y: &str, m: &str, d: &str) -> Option<Self> {
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !(digits(y) && digits(m) && digits(d)) {
            return None;
        }
        let (year, month, day): (u16, u8, u8) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return None,
        };
        (year >= 1900 && (1..=days).contains(&day)).then_some(Self { year, month, day })
    }

    /// The year, from 1900.
    pub fn year(&self) -> u16 {
        self.year
    }

    /// The month, 1 to 12.
    pub fn month(&self) -> u8 {
        self.month
    }

    /// The day of the month, from 1.
    pub fn day(&self) -> u8 {
        self.day
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// A time of day, UTC, a real one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time {
    hour: u8,
    minute: u8,
    second: u8,
}

impl Time {
    /// A time written `HHMM` or `HHMMSS`, as ADIF writes it, if it is a real one.
    pub fn from_adif(s: &str) -> Option<Self> {
        if !(s.len() == 4 || s.len() == 6) || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let two = |i: usize| s[i..i + 2].parse::<u8>().ok();
        let second = if s.len() == 6 { two(4)? } else { 0 };
        let t = Self {
            hour: two(0)?,
            minute: two(2)?,
            second,
        };
        (t.hour < 24 && t.minute < 60 && t.second < 60).then_some(t)
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}:{:02}Z", self.hour, self.minute, self.second)
    }
}

/// One QSO, every field as LoTW receives it, checked. Its fields are read through its methods
/// and never changed, so what is signed is what was checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qso {
    call: String,
    band: &'static str,
    mode: &'static str,
    adif_submode: Option<String>,
    freq: Option<String>,
    band_rx: Option<&'static str>,
    freq_rx: Option<String>,
    prop_mode: Option<String>,
    sat_name: Option<String>,
    date: Date,
    time: Time,
    station: Vec<(&'static str, String)>,
}

/// The ADIF fields that say which station made a QSO, each checked against the station location
/// before the QSO is signed.
/// `OPERATOR` names the station too when `STATION_CALLSIGN` is absent, as ADIF defines it; it is
/// then kept under its own name.
pub const STATION_FIELDS: [&str; 9] = [
    "STATION_CALLSIGN",
    "MY_VUCC_GRIDS",
    "MY_DXCC",
    "MY_GRIDSQUARE",
    "MY_STATE",
    "MY_CNTY",
    "MY_CQ_ZONE",
    "MY_ITU_ZONE",
    "MY_IOTA",
];

/// Why a QSO cannot be signed. QSO fields are log data, not secrets, so the value is named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QsoError {
    /// A field LoTW requires is missing.
    Missing(&'static str),
    /// A field appears more than once, so which one counts is not clear.
    Repeated(&'static str),
    /// A record with more fields than any record read from a file may have.
    TooManyFields,
    /// A field's value is not one LoTW accepts.
    Invalid {
        /// The ADIF field.
        field: &'static str,
        /// The value the log gives it.
        value: String,
    },
    /// PROP_MODE is SAT with no SAT_NAME.
    SatelliteNotNamed,
    /// SAT_NAME is given and PROP_MODE is not SAT.
    SatelliteWithoutSat,
}

impl fmt::Display for QsoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(f, "the QSO has no {field}"),
            Self::Repeated(field) => write!(f, "the QSO has more than one {field}"),
            Self::TooManyFields => write!(f, "the QSO record has too many fields"),
            Self::Invalid { field, value } => {
                write!(f, "{field} {value:?} is not one LoTW accepts")
            }
            Self::SatelliteNotNamed => write!(f, "PROP_MODE is SAT but there is no SAT_NAME"),
            Self::SatelliteWithoutSat => write!(f, "SAT_NAME is set but PROP_MODE is not SAT"),
        }
    }
}

impl std::error::Error for QsoError {}

/// The ADIF fields read, so a repeat of any of them is refused.
const READ: [&str; 21] = [
    "STATION_CALLSIGN",
    "OPERATOR",
    "MY_VUCC_GRIDS",
    "MY_DXCC",
    "MY_GRIDSQUARE",
    "MY_STATE",
    "MY_CNTY",
    "MY_CQ_ZONE",
    "MY_ITU_ZONE",
    "MY_IOTA",
    "CALL",
    "QSO_DATE",
    "TIME_ON",
    "BAND",
    "FREQ",
    "MODE",
    "SUBMODE",
    "BAND_RX",
    "FREQ_RX",
    "PROP_MODE",
    "SAT_NAME",
];

impl Qso {
    /// The QSO in an ADIF record.
    pub fn from_adif(record: &Record) -> Result<Self, QsoError> {
        Self::from_adif_with_options(record, &SigningOptions::default())
    }

    /// Read and normalize a QSO using caller-selected log handling settings. Use these same
    /// options with `sign_log_with_options` or `Store::prepare_signing_with_options`.
    pub fn from_adif_with_options(
        record: &Record,
        options: &SigningOptions,
    ) -> Result<Self, QsoError> {
        // A Record can be built by hand, so the reader's limit is checked here too.
        if record.fields.len() > crate::records::MAX_FIELDS {
            return Err(QsoError::TooManyFields);
        }
        for name in READ {
            if record
                .fields
                .iter()
                .filter(|f| f.name.eq_ignore_ascii_case(name))
                .count()
                > 1
            {
                return Err(QsoError::Repeated(name));
            }
        }
        // A field present but empty or not UTF-8 counts as given, so it is refused, not ignored.
        let text = |name: &'static str| -> Result<Option<String>, QsoError> {
            match record.get(name) {
                None => Ok(None),
                // Refused before it is copied, decoded or put in capitals.
                Some(v) if v.len() > MAX_VALUE_LEN => {
                    Err(invalid(name, &String::from_utf8_lossy(&v[..MAX_VALUE_LEN])))
                }
                Some(v) => match std::str::from_utf8(v) {
                    // Non-amateur calls bypass plausibility, never character safety. Check
                    // before trimming so leading/trailing controls cannot disappear.
                    Ok(s)
                        if name == "CALL"
                            && s.chars().any(|c| {
                                c.is_control() || matches!(c, '\u{fffe}' | '\u{ffff}')
                            }) =>
                    {
                        Err(invalid(name, s))
                    }
                    Ok(s) => match s.trim() {
                        "" => Ok(None),
                        s => Ok(Some(s.to_ascii_uppercase())),
                    },
                    Err(_) => Err(invalid(name, &String::from_utf8_lossy(v))),
                },
            }
        };
        let required = |name: &'static str| text(name)?.ok_or(QsoError::Missing(name));

        let call = required("CALL")?;
        if call.len() > 20 || (!options.allow_bad_calls && !is_contacted_callsign(&call)) {
            return Err(invalid("CALL", &call));
        }
        let date = required("QSO_DATE")?;
        let date = Date::from_adif(&date).ok_or_else(|| invalid("QSO_DATE", &date))?;
        let time = required("TIME_ON")?;
        let mut time = Time::from_adif(&time).ok_or_else(|| invalid("TIME_ON", &time))?;
        if options.ignore_seconds {
            time.second = 0;
        }

        let (band, freq) = band_and_freq(text("BAND")?, text("FREQ")?, ("BAND", "FREQ"))?
            .ok_or(QsoError::Missing("BAND"))?;
        let rx = band_and_freq(text("BAND_RX")?, text("FREQ_RX")?, ("BAND_RX", "FREQ_RX"))?;
        let (band_rx, freq_rx) = rx.map_or((None, None), |(b, f)| (Some(b), f));

        let mode = required("MODE")?;
        let submode = text("SUBMODE")?;
        let mode = options.mode(&mode, submode.as_deref()).ok_or_else(|| {
            let shown = submode
                .as_deref()
                .map_or(mode.clone(), |s| format!("{mode}/{s}"));
            invalid("MODE", &shown)
        })?;

        let prop_mode = text("PROP_MODE")?;
        if let Some(p) = &prop_mode
            && !lotw::is_prop_mode(p)
        {
            return Err(invalid("PROP_MODE", p));
        }
        // Two-line element sets name AMSAT-OSCAR 7 "AO-07"; LoTW names it "AO-7".
        let sat_name = text("SAT_NAME")?.map(|s| if s == "AO-07" { "AO-7".into() } else { s });
        if let Some(s) = &sat_name
            && !lotw::is_satellite(s)
        {
            return Err(invalid("SAT_NAME", s));
        }
        match (prop_mode.as_deref() == Some("SAT"), sat_name.is_some()) {
            (true, false) => return Err(QsoError::SatelliteNotNamed),
            (false, true) => return Err(QsoError::SatelliteWithoutSat),
            _ => {}
        }

        let mut station = Vec::new();
        for name in STATION_FIELDS {
            if (name == "STATION_CALLSIGN" && options.ignore_log_callsigns)
                || (name != "STATION_CALLSIGN" && options.qth == QthHandling::Ignore)
            {
                continue;
            }
            let Some(v) = text(name)? else { continue };
            let ok = match name {
                "STATION_CALLSIGN" => is_callsign(&v),
                "MY_DXCC" | "MY_CQ_ZONE" | "MY_ITU_ZONE" => {
                    v.len() <= 4 && v.parse::<u32>().is_ok()
                }
                "MY_GRIDSQUARE" => crate::station::is_adif_grid(&v),
                "MY_VUCC_GRIDS" => crate::station::is_adif_vucc_grids(&v),
                // Text compared with the location's own.
                _ => true,
            };
            if !ok {
                return Err(invalid(name, &v));
            }
            station.push((name, v));
        }
        // OPERATOR is a person's call; only when it looks like one, and STATION_CALLSIGN is
        // absent, does it name the station.
        if !options.ignore_log_callsigns
            && !station.iter().any(|(n, _)| *n == "STATION_CALLSIGN")
            && let Some(op) = text("OPERATOR")?.filter(|op| is_callsign(op))
        {
            station.push(("OPERATOR", op));
        }

        Ok(Self {
            call,
            band,
            mode,
            adif_submode: submode,
            freq,
            band_rx,
            freq_rx,
            prop_mode,
            sat_name,
            date,
            time,
            station,
        })
    }

    /// The call worked, uppercased.
    pub fn call(&self) -> &str {
        &self.call
    }

    /// The band, as LoTW names it (`20M`, `2M`, `70CM`).
    pub fn band(&self) -> &'static str {
        self.band
    }

    /// The mode, as LoTW names it, from the log's MODE and SUBMODE through ARRL's mode map.
    pub fn mode(&self) -> &'static str {
        self.mode
    }

    /// The frequency in MHz, as the log gives it, if it does.
    pub fn freq(&self) -> Option<&str> {
        self.freq.as_deref()
    }

    /// The receive band, for a split or satellite QSO, if the log gives one.
    pub fn band_rx(&self) -> Option<&'static str> {
        self.band_rx
    }

    /// The receive frequency in MHz, if the log gives one.
    pub fn freq_rx(&self) -> Option<&str> {
        self.freq_rx.as_deref()
    }

    /// The propagation mode, as LoTW names it (`SAT`, `EME`), if the log gives one.
    pub fn prop_mode(&self) -> Option<&str> {
        self.prop_mode.as_deref()
    }

    /// The satellite, as LoTW names it, for a satellite QSO.
    pub fn sat_name(&self) -> Option<&str> {
        self.sat_name.as_deref()
    }

    /// The QSO's date, UTC.
    pub fn date(&self) -> Date {
        self.date
    }

    /// The QSO's time, UTC.
    pub fn time(&self) -> Time {
        self.time
    }

    pub(crate) fn with_options(&self, options: &SigningOptions) -> Self {
        let mut qso = self.clone();
        if options.ignore_seconds {
            qso.time.second = 0;
        }
        qso
    }

    pub(crate) fn remap_mode(&mut self, options: &SigningOptions) -> bool {
        let Some(mode) = options.mode(self.mode, self.adif_submode.as_deref()) else {
            return false;
        };
        self.mode = mode;
        true
    }

    /// What the QSO's record says about the station that made it: ADIF field names, from
    /// [`STATION_FIELDS`], and their values in capitals.
    pub fn station(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.station.iter().map(|(n, v)| (*n, v.as_str()))
    }

    /// The fields the signature covers, in the signature specification's order, as one string in
    /// capitals: the QSO's part of what is signed.
    pub fn sign_data(&self) -> String {
        let date = self.date.to_string();
        let time = self.time.to_string();
        let mut out = String::new();
        for (name, _) in lotw::SIGN_CONTACT {
            let value = match *name {
                "BAND" => Some(self.band),
                "BAND_RX" => self.band_rx,
                "CALL" => Some(self.call.as_str()),
                "FREQ" => self.freq.as_deref(),
                "FREQ_RX" => self.freq_rx.as_deref(),
                "MODE" => Some(self.mode),
                "PROP_MODE" => self.prop_mode.as_deref(),
                "QSO_DATE" => Some(date.as_str()),
                "QSO_TIME" => Some(time.as_str()),
                "SAT_NAME" => self.sat_name.as_deref(),
                // The specification is generated and checked by the tests; a field this code does
                // not know would be a new specification, and it signs nothing until it is read.
                other => unreachable!("signature field {other} is not known"),
            };
            out.push_str(value.unwrap_or(""));
        }
        out.to_ascii_uppercase()
    }
}

/// The error for a value, shown cut to [`MAX_VALUE_LEN`] characters, so an error is never large.
fn invalid(field: &'static str, value: &str) -> QsoError {
    QsoError::Invalid {
        field,
        value: value.chars().take(MAX_VALUE_LEN).collect(),
    }
}

/// The band, from BAND or else from the frequency, and the frequency only if it is in that band:
/// LoTW receives no frequency rather than one that disagrees with the band. `None` if neither is
/// given.
fn band_and_freq(
    band: Option<String>,
    freq: Option<String>,
    (field, freq_field): (&'static str, &'static str),
) -> Result<Option<(&'static str, Option<String>)>, QsoError> {
    if let Some(f) = freq.as_deref().filter(|f| f.len() > MAX_FREQ_LEN) {
        return Err(invalid(freq_field, f));
    }
    let mhz = freq
        .as_deref()
        .and_then(adif_number)
        .filter(|&f| f.is_finite() && f > 0.0);
    let freq = freq.filter(|_| mhz.is_some());
    let band = match (band, mhz) {
        (Some(b), _) => lotw::band(&b).ok_or_else(|| invalid(field, &b))?,
        (None, Some(f)) => match lotw::band_of(f) {
            Some(b) => b,
            None => return Err(invalid(field, freq.as_deref().unwrap_or(""))),
        },
        (None, None) => return Ok(None),
    };
    // SUBMM spans everything above 300 GHz, so no frequency is checked against it.
    let keep = band.name == "SUBMM" || mhz.is_some_and(|f| lotw::freq_in_band(band, f));
    Ok(Some((band.name, freq.filter(|_| keep))))
}

/// An ADIF Number: digits, at most one point, an optional leading minus.
fn adif_number(s: &str) -> Option<f64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    let ok = !digits.is_empty()
        && digits.bytes().filter(|&b| b == b'.').count() <= 1
        && digits.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && digits.bytes().any(|b| b.is_ascii_digit());
    ok.then(|| s.parse().ok()).flatten()
}

/// A callsign LoTW accepts as the station worked: a plausible callsign ([`is_callsign`]) that
/// does not begin with `0` or `Q`, or with `1` other than `1A`, `1M` or `1S`, as no amateur
/// callsign does (ARRL's rules for submitted QSOs).
pub fn is_contacted_callsign(call: &str) -> bool {
    let b = call.as_bytes();
    is_callsign(call)
        && b[0] != b'0'
        && b[0] != b'Q'
        && (b[0] != b'1' || matches!(b[1], b'A' | b'M' | b'S'))
}

/// A plausible amateur callsign: capitals, digits and `/`, with at least one of each of the first
/// two, and no `/` at either end.
pub fn is_callsign(call: &str) -> bool {
    (3..=20).contains(&call.len())
        && call
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'/')
        && call.bytes().any(|b| b.is_ascii_uppercase())
        && call.bytes().any(|b| b.is_ascii_digit())
        && !call.starts_with('/')
        && !call.ends_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records;

    fn qso(adif: &str) -> Result<Qso, QsoError> {
        let records = records::parse(adif.as_bytes()).expect("records");
        Qso::from_adif(&records[0])
    }

    const BASE: &str = "<CALL:6>KC4QPQ<QSO_DATE:8>20261101<TIME_ON:4>1830";

    #[test]
    fn a_qso_is_written_as_lotw_receives_it() {
        let q = qso(&format!(
            "{BASE}<BAND:3>20m<FREQ:9>14.074000<MODE:4>MFSK<SUBMODE:3>FT8<EOR>"
        ))
        .expect("qso");
        assert_eq!(q.band, "20M");
        assert_eq!(q.mode, "FT8");
        assert_eq!(q.freq.as_deref(), Some("14.074000"));
        assert_eq!(q.date.to_string(), "2026-11-01");
        assert_eq!(q.time.to_string(), "18:30:00Z");
        assert_eq!(q.sign_data(), "20MKC4QPQ14.074000FT82026-11-0118:30:00Z");
    }

    #[test]
    fn a_frequency_outside_its_band_is_left_out() {
        let q = qso(&format!("{BASE}<BAND:3>20m<FREQ:5>7.074<MODE:2>CW<EOR>")).expect("qso");
        assert_eq!((q.band, q.freq), ("20M", None));
    }

    #[test]
    fn the_band_comes_from_the_frequency_when_it_is_missing() {
        let q = qso(&format!("{BASE}<FREQ:5>7.030<MODE:2>CW<EOR>")).expect("qso");
        assert_eq!((q.band, q.freq.as_deref()), ("40M", Some("7.030")));
        assert_eq!(
            qso(&format!("{BASE}<MODE:2>CW<EOR>")),
            Err(QsoError::Missing("BAND"))
        );
        assert!(matches!(
            qso(&format!("{BASE}<FREQ:3>9.0<MODE:2>CW<EOR>")),
            Err(QsoError::Invalid { field: "BAND", .. })
        ));
    }

    #[test]
    fn what_lotw_would_refuse_is_refused() {
        let bad = [
            (
                "<CALL:6>KC4QPQ<QSO_DATE:8>20261131<TIME_ON:4>1830<BAND:3>20m<MODE:2>CW<EOR>",
                "QSO_DATE",
            ),
            (
                "<CALL:6>KC4QPQ<QSO_DATE:8>20261101<TIME_ON:4>2460<BAND:3>20m<MODE:2>CW<EOR>",
                "TIME_ON",
            ),
            (
                "<CALL:5>KC4Q*<QSO_DATE:8>20261101<TIME_ON:4>1830<BAND:3>20m<MODE:2>CW<EOR>",
                "CALL",
            ),
            (
                "<CALL:6>KC4QPQ<QSO_DATE:8>20261101<TIME_ON:4>1830<BAND:3>21m<MODE:2>CW<EOR>",
                "BAND",
            ),
            (
                "<CALL:6>KC4QPQ<QSO_DATE:8>20261101<TIME_ON:4>1830<BAND:3>20m<MODE:4>NOPE<EOR>",
                "MODE",
            ),
        ];
        for (adif, field) in bad {
            assert!(
                matches!(qso(adif), Err(QsoError::Invalid { field: f, .. }) if f == field),
                "{adif}"
            );
        }
        assert_eq!(
            qso(&format!("{BASE}<CALL:5>KN4YU<BAND:3>20m<MODE:2>CW<EOR>")),
            Err(QsoError::Repeated("CALL"))
        );
        assert_eq!(
            qso(&format!("{BASE}<BAND:2>2m<MODE:2>FM<PROP_MODE:3>SAT<EOR>")),
            Err(QsoError::SatelliteNotNamed)
        );
        assert_eq!(
            qso(&format!("{BASE}<BAND:2>2m<MODE:2>FM<SAT_NAME:5>SO-50<EOR>")),
            Err(QsoError::SatelliteWithoutSat)
        );
    }

    #[test]
    fn a_frequency_too_long_to_be_one_is_refused() {
        let long = format!("14.{}", "0".repeat(MAX_FREQ_LEN));
        let adif = format!(
            "{BASE}<BAND:5>SUBMM<FREQ:{}>{long}<MODE:2>CW<EOR>",
            long.len()
        );
        assert!(matches!(
            qso(&adif),
            Err(QsoError::Invalid { field: "FREQ", .. })
        ));
        // A number too large for a float is not a frequency, so it is left out, never kept.
        let q = qso(&format!("{BASE}<BAND:5>SUBMM<FREQ:6>1e9999<MODE:2>CW<EOR>")).expect("qso");
        assert_eq!(q.freq(), None);
    }

    #[test]
    fn what_the_record_says_about_its_station_is_kept_and_checked() {
        let q = qso(&format!(
            "{BASE}<BAND:3>20m<MODE:2>CW<STATION_CALLSIGN:7>qg0test<MY_DXCC:3>291<MY_GRIDSQUARE:6>EM17ab<EOR>"
        ))
        .expect("qso");
        let station: Vec<_> = q.station().collect();
        assert_eq!(
            station,
            [
                ("STATION_CALLSIGN", "QG0TEST"),
                ("MY_DXCC", "291"),
                ("MY_GRIDSQUARE", "EM17AB")
            ]
        );
        for bad in [
            "<MY_DXCC:3>abc",
            "<MY_GRIDSQUARE:4>ZZ99",
            "<STATION_CALLSIGN:3>Q*Q",
        ] {
            assert!(
                matches!(
                    qso(&format!("{BASE}<BAND:3>20m<MODE:2>CW{bad}<EOR>")),
                    Err(QsoError::Invalid { .. })
                ),
                "{bad}"
            );
        }
        assert_eq!(
            qso(&format!(
                "{BASE}<BAND:3>20m<MODE:2>CW<MY_DXCC:3>291<MY_DXCC:1>1<EOR>"
            )),
            Err(QsoError::Repeated("MY_DXCC"))
        );
    }

    #[test]
    fn calls_no_amateur_has_are_refused() {
        for call in ["0A1", "1B1", "Q1ABC"] {
            assert!(!is_contacted_callsign(call), "{call}");
        }
        for call in ["1A0KM", "1S1A", "KC4QPQ", "M0EHA"] {
            assert!(is_contacted_callsign(call), "{call}");
        }
    }

    #[test]
    fn an_oversized_value_is_refused_before_it_is_copied() {
        let long = "1".repeat(MAX_VALUE_LEN + 1);
        let adif = format!(
            "{BASE}<BAND:3>20m<FREQ:{}>{long}<MODE:2>CW<EOR>",
            long.len()
        );
        match qso(&adif) {
            Err(QsoError::Invalid {
                field: "FREQ",
                value,
            }) => assert_eq!(value.len(), MAX_VALUE_LEN),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn operator_names_the_station_only_without_station_callsign() {
        let station = |extra: &str| {
            let q = qso(&format!("{BASE}<BAND:3>20m<MODE:2>CW{extra}<EOR>")).expect("qso");
            q.station()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
        };
        assert_eq!(station("<OPERATOR:7>QG1TEST"), ["OPERATOR=QG1TEST"]);
        assert_eq!(
            station("<OPERATOR:7>QG1TEST<STATION_CALLSIGN:5>KN4YU"),
            ["STATION_CALLSIGN=KN4YU"]
        );
        assert!(station("<OPERATOR:3>Bob").is_empty());
    }

    #[test]
    fn dates_and_times_are_checked() {
        assert!(Date::from_adif("20240229").is_some());
        assert!(Date::from_adif("20230229").is_none());
        assert!(Date::from_adif("2026110").is_none());
        assert!(Date::from_adif("2026-11-01").is_none());
        assert_eq!(
            Date::from_iso("2099-12-31")
                .map(|d| d.to_string())
                .as_deref(),
            Some("2099-12-31")
        );
        assert_eq!(
            Time::from_adif("183415").map(|t| t.to_string()).as_deref(),
            Some("18:34:15Z")
        );
        assert!(Time::from_adif("18341").is_none());
        assert!(Time::from_adif("1860").is_none());
    }
}
