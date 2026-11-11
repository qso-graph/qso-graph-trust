// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Read TQSL's station locations on request, without changing its files.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::station::{StationError, StationLocation};
use crate::store::StoredLocation;
use crate::{gzip, lotw, tbk, xml};

/// Largest station data file, whether compressed or expanded.
pub const MAX_FILE_LEN: usize = 16 * 1024 * 1024;

/// A location TQSL recorded and its validation result.
#[derive(Debug)]
pub struct Location {
    /// Name in TQSL.
    pub name: String,
    /// A validated location, or a reason it cannot be imported.
    pub station: Result<StationLocation, String>,
}

/// Why a station data file could not be read.
#[derive(Debug)]
pub struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

/// TQSL's library default folder, respecting a nonempty TQSLDIR.
pub fn default_folder() -> PathBuf {
    if let Some(dir) = std::env::var_os("TQSLDIR").filter(|v| !v.is_empty()) {
        return dir.into();
    }
    if cfg!(windows) {
        std::env::var_os("APPDATA").map_or_else(
            || PathBuf::from(r"C:\TrustedQSL"),
            |p| PathBuf::from(p).join("TrustedQSL"),
        )
    } else {
        std::env::var_os("HOME").map_or_else(
            || PathBuf::from(".tqsl"),
            |p| PathBuf::from(p).join(".tqsl"),
        )
    }
}

/// Open only `station_data` in the supplied folder. A missing file is an empty list.
/// Refuse special files without waiting for a FIFO writer. Both the opened file and the actual
/// read are bounded by [`MAX_FILE_LEN`], including when the file grows during reading.
pub fn read(folder: &Path) -> Result<Vec<Location>, Error> {
    let bytes = match crate::files::read_regular_file(&folder.join("station_data"), MAX_FILE_LEN) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error(format!("cannot open station_data: {e}"))),
    };
    parse(&bytes)
}

/// Parse a plain or gzipped TQSL station data file.
pub fn parse(bytes: &[u8]) -> Result<Vec<Location>, Error> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(Error("station_data is too large".into()));
    }
    let expanded;
    let plain = if gzip::is_gzip(bytes) {
        expanded = gzip::decompress(bytes, MAX_FILE_LEN)
            .map_err(|e| Error(format!("invalid gzip: {e}")))?;
        &expanded[..]
    } else {
        bytes
    };
    let text = std::str::from_utf8(plain).map_err(|_| Error("station_data is not UTF-8".into()))?;
    let root = xml::parse(text).map_err(|e| Error(format!("invalid XML: {e}")))?;
    if root.name != "StationDataFile"
        || root.attribute_names().next().is_some()
        || !root.text().trim().is_empty()
    {
        return Err(Error("expected a StationDataFile root".into()));
    }
    if root.children.len() > tbk::MAX_LOCATIONS {
        return Err(Error("too many station locations".into()));
    }
    let mut names = HashSet::new();
    let mut result = Vec::new();
    for entry in &root.children {
        if entry.name != "StationData" {
            return Err(Error("unknown element in station location list".into()));
        }
        let name = tbk::location_name(
            entry.attribute("name").as_deref().map(String::as_str),
            false,
        )
        .ok_or_else(|| {
            Error("station location needs a nonempty name of at most 255 bytes".into())
        })?;
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(Error(format!(
                "station location {name:?} has a repeated name"
            )));
        }
        if entry.attribute_names().any(|a| a != "name") || !entry.text().trim().is_empty() {
            return Err(Error(format!(
                "station location {name:?} has unexpected content"
            )));
        }
        let mut values = Vec::new();
        for field in &entry.children {
            if lotw::loc_field(field.name).is_none()
                || field.attribute_names().next().is_some()
                || !field.children.is_empty()
            {
                return Err(Error(format!(
                    "station location {name:?} has an unknown or malformed field"
                )));
            }
            if values.iter().any(|(n, _)| *n == field.name) {
                return Err(Error(format!("station location {name:?} repeats a field")));
            }
            values.push((field.name, field.text()));
        }
        let fields: Vec<_> = values.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let station = StationLocation::new(&fields).map_err(|e| match e {
            StationError::Missing(field) => format!("add {field} in TQSL"),
            StationError::Invalid { field, .. } => format!("correct {field} in TQSL"),
            StationError::NotAField(_) => {
                "remove the field that does not apply to this DXCC entity in TQSL".into()
            }
            StationError::Repeated(_) | StationError::TooManyFields => {
                "correct the station fields in TQSL".into()
            }
        });
        result.push(Location { name, station });
    }
    Ok(result)
}

/// A field whose values differ between TQSL and the store.
#[derive(Debug, PartialEq, Eq)]
pub struct Difference {
    /// Field name.
    pub field: String,
    /// TQSL value, if present.
    pub tqsl: Option<String>,
    /// Store value, if present.
    pub stored: Option<String>,
}
/// Comparison with the store; comparisons never change it.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// This name is not stored.
    New,
    /// Its fields match.
    Same,
    /// Its fields differ.
    Differs(Vec<Difference>),
    /// LoTW would refuse this location.
    Refused(String),
}
/// Compare one TQSL location by its exact name.
pub fn compare(location: &Location, stored: &[StoredLocation]) -> Status {
    let station = match &location.station {
        Ok(s) => s,
        Err(e) => return Status::Refused(e.clone()),
    };
    let Some(existing) = stored.iter().find(|s| s.name == location.name) else {
        return Status::New;
    };
    if &existing.station == station {
        return Status::Same;
    }
    let mut fields: Vec<_> = station
        .fields()
        .map(|(n, _)| n)
        .chain(existing.station.fields().map(|(n, _)| n))
        .collect();
    fields.sort_unstable();
    fields.dedup();
    Status::Differs(
        fields
            .into_iter()
            .filter_map(|field| {
                let tqsl = station
                    .fields()
                    .find(|(n, _)| *n == field)
                    .map(|(_, v)| v.to_string());
                let stored = existing
                    .station
                    .fields()
                    .find(|(n, _)| *n == field)
                    .map(|(_, v)| v.to_string());
                (tqsl != stored).then(|| Difference {
                    field: field.into(),
                    tqsl,
                    stored,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const STANDARD: &[u8] = include_bytes!("../../../tests/corpus/standard/tqsl/station_data");
    const SMALL: &[u8] = include_bytes!("../../../tests/corpus/tqsl/1024/tqsl/station_data");
    const SMALL_PASSWORD: &[u8] =
        include_bytes!("../../../tests/corpus/tqsl/1024-password/tqsl/station_data");

    #[test]
    fn corpus_and_gzip() {
        for bytes in [STANDARD, SMALL, SMALL_PASSWORD] {
            let plain = parse(bytes).expect("TQSL file");
            assert!(!plain.is_empty());
            assert!(plain.iter().all(|l| l.station.is_ok()));
            let compressed = parse(&gzip::compress(bytes)).expect("gzip");
            assert_eq!(format!("{plain:?}"), format!("{compressed:?}"));
        }
        let backup = tbk::read_trusting_roots(
            include_bytes!("../../../tests/corpus/standard/standard.tbk"),
            &crate::certificate::Trust::lotw(),
        )
        .expect("backup");
        let parsed = parse(STANDARD).expect("station data");
        assert_eq!(parsed.len(), backup.locations.len());
        for (a, b) in parsed.iter().zip(&backup.locations) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.station.as_ref().expect("valid"), &b.station);
        }
    }

    #[test]
    fn malformed_is_refused_and_invalid_is_named() {
        for (bad, reason) in [
            ("<wrong/>", "root"),
            ("<StationDataFile><UNKNOWN/></StationDataFile>", "unknown"),
            ("<StationDataFile><StationData/></StationDataFile>", "name"),
            (
                "<StationDataFile><StationData name=''/></StationDataFile>",
                "name",
            ),
            (
                "<StationDataFile><StationData name='a'/><StationData name='a'/></StationDataFile>",
                "repeated name",
            ),
            (
                "<StationDataFile><StationData name='a'/><StationData name='A'/></StationDataFile>",
                "repeated name",
            ),
            (
                "<StationDataFile><StationData name='a'><UNKNOWN>secret</UNKNOWN></StationData></StationDataFile>",
                "unknown",
            ),
        ] {
            let error = parse(bad.as_bytes()).expect_err("malformed").to_string();
            assert!(error.contains(reason), "{error}");
            assert!(!error.contains("secret"));
        }
        let data = b"<StationDataFile><StationData name='bad'><CALL>NOT A CALL</CALL><DXCC>291</DXCC></StationData><StationData name='good'><CALL>QG0TEST</CALL><DXCC>291</DXCC></StationData></StationDataFile>";
        let got = parse(data).expect("file");
        assert!(got[0].station.is_err());
        assert!(!got[0].station.as_ref().unwrap_err().contains("NOT A CALL"));
        assert!(got[1].station.is_ok());
    }

    #[test]
    fn names_keep_their_spaces() {
        let data = b"<StationDataFile><StationData name=' home '><CALL>QG0TEST</CALL><DXCC>291</DXCC></StationData></StationDataFile>";
        assert_eq!(parse(data).unwrap()[0].name, " home ");
    }

    #[test]
    fn limits_refuse_without_truncation() {
        let many = format!(
            "<StationDataFile>{}</StationDataFile>",
            "<StationData name='x'/>".repeat(tbk::MAX_LOCATIONS + 1)
        );
        assert!(
            parse(many.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("too many")
        );
        let long_name = format!(
            "<StationDataFile><StationData name='{}'/></StationDataFile>",
            "x".repeat(tbk::MAX_NAME_LEN + 1)
        );
        assert!(
            parse(long_name.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("name")
        );
        assert!(
            parse(&vec![b' '; MAX_FILE_LEN + 1])
                .unwrap_err()
                .to_string()
                .contains("large")
        );
    }

    #[test]
    fn compares_without_changing_stored() {
        let data = b"<StationDataFile><StationData name='home'><CALL>QG0TEST</CALL><DXCC>291</DXCC><GRIDSQUARE>EM17</GRIDSQUARE></StationData></StationDataFile>";
        let locations = parse(data).expect("file");
        let loc = &locations[0];
        assert_eq!(compare(loc, &[]), Status::New);
        let mut stored = vec![StoredLocation {
            name: loc.name.clone(),
            station: loc.station.as_ref().unwrap().clone(),
        }];
        assert_eq!(compare(loc, &stored), Status::Same);
        stored[0].station =
            StationLocation::new(&[("CALL", "QG0TEST"), ("DXCC", "291"), ("GRIDSQUARE", "EM18")])
                .unwrap();
        let before = stored.clone();
        assert_eq!(
            compare(loc, &stored),
            Status::Differs(vec![Difference {
                field: "GRIDSQUARE".into(),
                tqsl: Some("EM17".into()),
                stored: Some("EM18".into())
            }])
        );
        assert_eq!(stored, before);
    }
    #[test]
    fn default_folder_respects_tqsldir() {
        if let Ok(expected) = std::env::var("QGT_EXPECT_FOLDER") {
            assert_eq!(default_folder(), std::path::PathBuf::from(expected));
            return;
        }
        let exe = std::env::current_exe().expect("test binary");
        let fallback = if cfg!(windows) {
            std::path::PathBuf::from("test-appdata").join("TrustedQSL")
        } else {
            std::path::PathBuf::from("test-home").join(".tqsl")
        };
        for (dir, expected) in [
            ("custom-tqsl", std::path::PathBuf::from("custom-tqsl")),
            ("", fallback),
        ] {
            let status = std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "tqsl_locations::tests::default_folder_respects_tqsldir",
                ])
                .env("TQSLDIR", dir)
                .env("HOME", "test-home")
                .env("APPDATA", "test-appdata")
                .env("QGT_EXPECT_FOLDER", expected)
                .status()
                .expect("run child");
            assert!(status.success());
        }
    }
}
