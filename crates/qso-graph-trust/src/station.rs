// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A station location: where the QSOs were made from, as LoTW receives it in a signed log's
//! tSTATION record, and the station's part of every signature. Every field is checked against
//! the configuration's fields for the location's DXCC entity, and a list field's value must be
//! one of its list's.

use std::fmt;

use crate::lotw::{self, FieldKind};

/// The most fields a location is given: more than any DXCC entity's pages hold, all together.
pub const MAX_FIELDS: usize = 32;
/// The longest name or value given, in bytes, checked before anything is copied: longer than any
/// field the configuration defines.
pub const MAX_LEN: usize = 64;

/// A station location, its fields in the order LoTW's configuration lists them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StationLocation {
    fields: Vec<(&'static str, String)>,
    dxcc: u32,
}

/// Why a station location is not one LoTW accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StationError {
    /// CALL or DXCC is missing.
    Missing(&'static str),
    /// A field given twice.
    Repeated(String),
    /// More than [`MAX_FIELDS`] fields.
    TooManyFields,
    /// A field that is not a location field for this DXCC entity.
    NotAField(String),
    /// A field whose value is not one LoTW accepts.
    Invalid { field: &'static str, value: String },
}

impl fmt::Display for StationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(f, "the station location has no {field}"),
            Self::Repeated(field) => write!(f, "the station location gives {field} twice"),
            Self::TooManyFields => write!(f, "the station location has too many fields"),
            Self::NotAField(field) => {
                write!(
                    f,
                    "{field} is not a station-location field for this DXCC entity"
                )
            }
            Self::Invalid { field, value } => {
                write!(f, "{field} {value:?} is not one LoTW accepts")
            }
        }
    }
}

impl std::error::Error for StationError {}

impl StationLocation {
    /// A station location from its fields, named as LoTW names them (`CALL`, `DXCC`,
    /// `GRIDSQUARE`, `US_STATE`, …). Empty values are left out.
    pub fn new(given: &[(&str, &str)]) -> Result<Self, StationError> {
        if given.len() > MAX_FIELDS {
            return Err(StationError::TooManyFields);
        }
        if let Some((name, v)) = given
            .iter()
            .find(|(n, v)| n.len() > MAX_LEN || v.len() > MAX_LEN)
        {
            return Err(match lotw::loc_field(name) {
                Some(f) => invalid(f.id, v),
                None => StationError::NotAField(name.chars().take(MAX_LEN).collect()),
            });
        }
        let value = |name: &str| {
            given
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.trim())
                .filter(|v| !v.is_empty())
        };
        let dxcc_text = value("DXCC").ok_or(StationError::Missing("DXCC"))?;
        let dxcc = dxcc_text
            .parse::<u32>()
            .ok()
            .filter(|&id| id != 0 && lotw::dxcc(id).is_some())
            .ok_or_else(|| invalid("DXCC", dxcc_text))?;
        value("CALL").ok_or(StationError::Missing("CALL"))?;

        let allowed: Vec<&'static str> = lotw::loc_fields_for(dxcc)
            .filter(|f| lotw::loc_field(f).is_some_and(|f| f.shown))
            .collect();
        if let Some((name, _)) = given.iter().find(|(n, _)| !allowed.contains(n)) {
            return Err(StationError::NotAField(name.to_string()));
        }
        for (i, (name, _)) in given.iter().enumerate() {
            if given[..i].iter().any(|(n, _)| n == name) {
                return Err(StationError::Repeated(name.to_string()));
            }
        }

        let mut fields: Vec<(&'static str, String)> = Vec::new();
        for id in allowed {
            let Some(v) = value(id) else { continue };
            let field = lotw::loc_field(id).ok_or(StationError::NotAField(id.to_string()))?;
            let v = match field.kind {
                FieldKind::Int => {
                    let n: i64 = v.parse().map_err(|_| invalid(id, v))?;
                    if field.range.is_some_and(|(lo, hi)| !(lo..=hi).contains(&n)) {
                        return Err(invalid(id, v));
                    }
                    n.to_string()
                }
                FieldKind::Text if v.chars().count() > field.len => return Err(invalid(id, v)),
                FieldKind::Text if lotw::is_list(id) => {
                    let dependency = match field.depends_on {
                        None => String::new(),
                        Some("DXCC") => dxcc.to_string(),
                        Some(other) => fields
                            .iter()
                            .find(|(n, _)| *n == other)
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default(),
                    };
                    lotw::loc_values(id, &dependency)
                        .find(|known| known.eq_ignore_ascii_case(v))
                        .ok_or_else(|| invalid(id, v))?
                        .to_string()
                }
                FieldKind::Text => {
                    let v = v.to_ascii_uppercase();
                    let ok = match id {
                        "CALL" => crate::qso::is_callsign(&v),
                        "GRIDSQUARE" => is_grid_list(&v),
                        "IOTA" => is_iota(&v),
                        _ => true,
                    };
                    if !ok {
                        return Err(invalid(id, &v));
                    }
                    v
                }
            };
            fields.push((id, v));
        }
        Ok(Self { fields, dxcc })
    }

    /// Whether this grid is one of the location's, compared as precisely as both are given: a
    /// subsquare against a subsquare, else the square.
    fn has_grid(&self, grid: &str) -> bool {
        self.get("GRIDSQUARE").is_some_and(|grids| {
            grids.split(',').map(str::trim).any(|ours| {
                let n = ours.len().min(grid.len());
                n >= 4
                    && ours
                        .get(..n)
                        .zip(grid.get(..n))
                        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            })
        })
    }

    /// Whether a QSO record's own word about its station, an ADIF field from
    /// [`crate::qso::STATION_FIELDS`] in capitals, disagrees with this location. A field the
    /// location has nothing to compare with disagrees too: the QSO says more than the location can
    /// confirm, so it is not signed for it.
    pub fn contradicts(&self, adif: &str, value: &str) -> bool {
        let same = |field: &str| {
            self.get(field)
                .is_some_and(|v| v.eq_ignore_ascii_case(value))
        };
        let number = |field: &str| {
            let ours = self.get(field).and_then(|v| v.parse::<u32>().ok());
            ours.is_some() && ours == value.parse().ok()
        };
        let agrees = match adif {
            "STATION_CALLSIGN" | "OPERATOR" => same("CALL"),
            "MY_DXCC" => value.parse() == Ok(self.dxcc),
            "MY_CQ_ZONE" => number("CQZ"),
            "MY_ITU_ZONE" => number("ITUZ"),
            "MY_IOTA" => same("IOTA"),
            "MY_GRIDSQUARE" => self.has_grid(value),
            // Every grid of a VUCC QSO must be one of the location's.
            "MY_VUCC_GRIDS" => value.split(',').all(|g| self.has_grid(g.trim())),
            "MY_STATE" => SUBDIVISIONS.iter().any(|f| same(f)),
            // ADIF writes a US county as "KS,Sedgwick": the state, if given, must agree too.
            "MY_CNTY" => {
                let (state, county) = match value.split_once(',') {
                    Some((st, c)) => (Some(st.trim()), c.trim()),
                    None => (None, value.trim()),
                };
                let county_ok = ["US_COUNTY", "JA_CITY_GUN_KU"]
                    .iter()
                    .any(|f| self.get(f).is_some_and(|v| v.eq_ignore_ascii_case(county)));
                let state_ok = state.is_none_or(|st| {
                    SUBDIVISIONS
                        .iter()
                        .any(|f| self.get(f).is_some_and(|v| v.eq_ignore_ascii_case(st)))
                });
                county_ok && state_ok
            }
            _ => false,
        };
        !agrees
    }

    /// The location's fields, in the order its tSTATION record lists them.
    pub fn fields(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.fields.iter().map(|(n, v)| (*n, v.as_str()))
    }

    /// One field's value.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The station's callsign.
    pub fn call(&self) -> &str {
        self.get("CALL").unwrap_or_default()
    }

    /// The station's DXCC entity.
    pub fn dxcc(&self) -> u32 {
        self.dxcc
    }

    /// The fields the signature covers, in the signature specification's order: the station's
    /// part of what is signed, before each QSO's. Not yet in capitals; the whole string is.
    pub fn sign_data(&self) -> String {
        lotw::SIGN_STATION
            .iter()
            .filter_map(|name| self.get(name))
            .collect()
    }
}

/// The error for a value, shown cut to [`MAX_LEN`] characters, so an error is never large.
fn invalid(field: &'static str, value: &str) -> StationError {
    StationError::Invalid {
        field,
        value: value.chars().take(MAX_LEN).collect(),
    }
}

/// One to four Maidenhead locators, comma-separated: a field and square (`EM17`), with an
/// optional subsquare (`EM17ab`).
pub(crate) fn is_grid_list(s: &str) -> bool {
    let grids: Vec<&str> = s.split(',').collect();
    grids.len() <= 4 && grids.iter().all(|g| is_grid(g.trim()))
}

/// One Maidenhead locator in capitals, `EM17` or `EM17AB`. Read as bytes, so any input is safe.
pub(crate) fn is_grid(g: &str) -> bool {
    let b = g.as_bytes();
    let field = |c: u8| (b'A'..=b'R').contains(&c);
    let sub = |c: u8| (b'A'..=b'X').contains(&c);
    let square = b.len() >= 4
        && field(b[0])
        && field(b[1])
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit();
    match b.len() {
        4 => square,
        6 => square && sub(b[4]) && sub(b[5]),
        _ => false,
    }
}

/// The location fields that are a DXCC entity's first subdivision, which ADIF's MY_STATE names.
const SUBDIVISIONS: [&str; 7] = [
    "US_STATE",
    "CA_PROVINCE",
    "AU_STATE",
    "CN_PROVINCE",
    "RU_OBLAST",
    "JA_PREFECTURE",
    "FI_KUNTA",
];

/// An IOTA reference: a continent and three digits, as `NA-001`.
fn is_iota(s: &str) -> bool {
    let (cont, num) = s.split_once('-').unwrap_or(("", ""));
    ["AF", "AN", "AS", "EU", "NA", "OC", "SA"].contains(&cont)
        && num.len() == 3
        && num.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_qsos_word_about_its_station_must_agree_with_the_location() {
        let loc = StationLocation::new(KANSAS).expect("location");
        for (adif, value) in [
            ("STATION_CALLSIGN", "QG0TEST"),
            ("MY_DXCC", "291"),
            ("MY_GRIDSQUARE", "EM17AB"),
            ("MY_STATE", "KS"),
            ("MY_CNTY", "KS,SEDGWICK"),
            ("MY_CNTY", "SEDGWICK"),
            ("MY_CQ_ZONE", "04"),
            ("MY_ITU_ZONE", "7"),
            ("MY_VUCC_GRIDS", "EM17"),
            ("OPERATOR", "QG0TEST"),
        ] {
            assert!(!loc.contradicts(adif, value), "{adif} {value}");
        }
        // Codex review: subsquares that differ were compared only as squares.
        let mut fine = KANSAS.to_vec();
        fine[4] = ("GRIDSQUARE", "EM17AB");
        let fine = StationLocation::new(&fine).expect("location");
        assert!(!fine.contradicts("MY_GRIDSQUARE", "EM17AB"));
        assert!(!fine.contradicts("MY_GRIDSQUARE", "EM17"));
        assert!(fine.contradicts("MY_GRIDSQUARE", "EM17CD"));
        let huge = "A".repeat(MAX_LEN + 1);
        let mut given = KANSAS.to_vec();
        given[4] = ("GRIDSQUARE", &huge);
        assert!(matches!(
            StationLocation::new(&given),
            Err(StationError::Invalid { field: "GRIDSQUARE", value }) if value.len() == MAX_LEN
        ));
        for (adif, value) in [
            ("STATION_CALLSIGN", "QG1TEST"),
            ("MY_DXCC", "1"),
            ("MY_GRIDSQUARE", "FN03"),
            ("MY_STATE", "SC"),
            ("MY_CNTY", "SC,SEDGWICK"),
            ("MY_CNTY", "CHARLESTON"),
            ("MY_CQ_ZONE", "5"),
            ("MY_ITU_ZONE", "8"),
            // The location has no IOTA, so a QSO naming one is not signed for it.
            ("MY_IOTA", "NA-110"),
            ("MY_VUCC_GRIDS", "EM17,EM18"),
            ("OPERATOR", "QG1TEST"),
            ("NOT_A_FIELD", "x"),
        ] {
            assert!(loc.contradicts(adif, value), "{adif} {value}");
        }
    }

    const KANSAS: &[(&str, &str)] = &[
        ("CALL", "QG0TEST"),
        ("DXCC", "291"),
        ("US_STATE", "KS"),
        ("US_COUNTY", "Sedgwick"),
        ("GRIDSQUARE", "EM17"),
        ("CQZ", "4"),
        ("ITUZ", "7"),
    ];

    #[test]
    fn fields_are_listed_in_the_configurations_order() {
        let loc = StationLocation::new(KANSAS).expect("location");
        let names: Vec<&str> = loc.fields().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [
                "CALL",
                "DXCC",
                "GRIDSQUARE",
                "ITUZ",
                "CQZ",
                "US_STATE",
                "US_COUNTY"
            ]
        );
        assert_eq!(loc.sign_data(), "4EM177SedgwickKS");
        assert_eq!((loc.call(), loc.dxcc()), ("QG0TEST", 291));
    }

    #[test]
    fn list_values_are_matched_and_written_as_the_list_writes_them() {
        let mut given = KANSAS.to_vec();
        given[3] = ("US_COUNTY", "SEDGWICK");
        let loc = StationLocation::new(&given).expect("location");
        assert_eq!(loc.get("US_COUNTY"), Some("Sedgwick"));
        // A county of another state is not one of Kansas's.
        given[3] = ("US_COUNTY", "Charleston");
        assert!(matches!(
            StationLocation::new(&given),
            Err(StationError::Invalid {
                field: "US_COUNTY",
                ..
            })
        ));
    }

    #[test]
    fn what_lotw_would_refuse_is_refused() {
        let with = |name: &'static str, value: &'static str| {
            let mut given: Vec<(&str, &str)> =
                KANSAS.iter().filter(|(n, _)| *n != name).copied().collect();
            given.push((name, value));
            StationLocation::new(&given)
        };
        assert!(matches!(
            with("CQZ", "41"),
            Err(StationError::Invalid { field: "CQZ", .. })
        ));
        assert!(matches!(
            with("ITUZ", "x"),
            Err(StationError::Invalid { field: "ITUZ", .. })
        ));
        assert!(matches!(
            with("GRIDSQUARE", "ZZ17"),
            Err(StationError::Invalid { .. })
        ));
        assert!(matches!(
            with("US_STATE", "XX"),
            Err(StationError::Invalid { .. })
        ));
        assert!(matches!(
            with("DXCC", "9999"),
            Err(StationError::Invalid { field: "DXCC", .. })
        ));
        assert_eq!(
            with("CA_PROVINCE", "ON"),
            Err(StationError::NotAField("CA_PROVINCE".into()))
        );
        assert_eq!(
            with("ZERR", "x"),
            Err(StationError::NotAField("ZERR".into()))
        );
        assert_eq!(
            StationLocation::new(&[("DXCC", "291")]),
            Err(StationError::Missing("CALL"))
        );
        assert_eq!(
            StationLocation::new(&[("CALL", "QG0TEST"), ("CALL", "QG0TEST"), ("DXCC", "291")]),
            Err(StationError::Repeated("CALL".into()))
        );
        assert!(with("GRIDSQUARE", "EM17ab,EM18").is_ok());
        // Codex review: a six-byte grid with a two-byte character inside panicked on slicing.
        assert!(matches!(
            with("GRIDSQUARE", "AAA\u{e9}A"),
            Err(StationError::Invalid { .. })
        ));
        let many: Vec<(String, &str)> = (0..=MAX_FIELDS).map(|i| (format!("X{i}"), "")).collect();
        let many: Vec<(&str, &str)> = many.iter().map(|(n, v)| (n.as_str(), *v)).collect();
        assert_eq!(
            StationLocation::new(&many),
            Err(StationError::TooManyFields)
        );
        assert!(with("IOTA", "NA-110").is_ok());
        assert!(with("IOTA", "NA-1").is_err());
    }
}
