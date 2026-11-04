// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Caller-selected settings that affect signing. These are local to one conversion; importing a
//! backup never changes process-wide settings. Construct QSOs with the same options used to sign.

use crate::{lotw, qso::Qso, signed_log::LogError, station::StationLocation, tbk};

pub use crate::tbk::QthHandling;

/// TQSL's log handling settings. Defaults preserve the existing signing output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigningOptions {
    /// Custom ADIF mode (or `MODE%SUBMODE`) to LoTW mode mappings. Compared without case.
    /// Later entries win. Entries redefining a native LoTW mode are ignored, as in TQSL's app.
    pub adif_modes: Vec<(String, String)>,
    /// Set seconds to zero before signing and duplicate detection.
    pub ignore_seconds: bool,
    /// Bypass the contacted call's amateur callsign check. Other QSO validation still applies.
    pub allow_bad_calls: bool,
    /// Disregard the log's STATION_CALLSIGN and OPERATOR, without changing the selected certificate.
    pub ignore_log_callsigns: bool,
    /// Ignore, report differences in, or update location details from the log.
    pub qth: QthHandling,
}

impl From<&tbk::Preferences> for SigningOptions {
    fn from(prefs: &tbk::Preferences) -> Self {
        Self {
            adif_modes: prefs.adif_modes.clone(),
            ignore_seconds: prefs.ignore_seconds,
            allow_bad_calls: prefs.allow_bad_calls,
            ignore_log_callsigns: prefs.ignore_log_callsigns,
            qth: prefs.qth,
        }
    }
}

impl SigningOptions {
    pub(crate) fn qsos(
        &self,
        qsos: &[Qso],
        locations: &[StationLocation],
    ) -> Result<Vec<Qso>, LogError> {
        qsos.iter()
            .enumerate()
            .map(|(index, qso)| {
                let mut qso = qso.with_options(self);
                // TQSL revisits the mode lookup after emitting certificate/location records and
                // unlocking the key. SUBMODE remains present even after MODE has been mapped.
                // The first QSO traverses all three; later QTH changes emit one location record.
                let repeats = if index == 0 {
                    3
                } else {
                    usize::from(locations[index] != locations[index - 1])
                };
                for _ in 0..repeats {
                    if !qso.remap_mode(self) {
                        return Err(LogError::Signing);
                    }
                }
                Ok(qso)
            })
            .collect()
    }

    pub(crate) fn locations(
        &self,
        qsos: &[Qso],
        station: &StationLocation,
    ) -> Result<Vec<StationLocation>, LogError> {
        let mut current = station.clone();
        let mut locations = Vec::with_capacity(qsos.len());
        for (index, qso) in qsos.iter().enumerate() {
            current = self.location(qso, &current, index)?;
            locations.push(current.clone());
        }
        Ok(locations)
    }

    fn location(
        &self,
        qso: &Qso,
        station: &StationLocation,
        index: usize,
    ) -> Result<StationLocation, LogError> {
        if self.qth == QthHandling::Ignore {
            return Ok(station.clone());
        }
        let mut fields: Vec<_> = station.fields().map(|(n, v)| (n, v.to_owned())).collect();
        let failure = |field, value: &str| LogError::QsoFromAnotherStation {
            index,
            field,
            value: value.to_owned(),
        };
        for (adif, value) in qso.station() {
            if matches!(adif, "STATION_CALLSIGN" | "OPERATOR") {
                if !self.ignore_log_callsigns && station.contradicts(adif, value) {
                    // This API signs with one selected certificate. UPDATE cannot select another
                    // certificate on the caller's behalf.
                    return Err(failure(adif, value));
                }
            } else if adif == "MY_DXCC"
                && value
                    .parse::<u32>()
                    .is_ok_and(|n| n != 0 && n != station.dxcc())
            {
                return Err(failure(adif, value));
            }
        }
        // Converter order matters: grid, primary subdivision (refreshing dependent fields),
        // secondary subdivision, ITU zone, CQ zone, IOTA. MY_VUCC_GRIDS takes precedence.
        let get = |name| qso.station().find(|(n, _)| *n == name).map(|(_, v)| v);
        let primary = lotw::loc_fields_for(station.dxcc()).find(|id| {
            matches!(
                *id,
                "US_STATE"
                    | "CA_PROVINCE"
                    | "RU_OBLAST"
                    | "CN_PROVINCE"
                    | "AU_STATE"
                    | "JA_PREFECTURE"
                    | "FI_KUNTA"
            )
        });
        let secondary = lotw::loc_fields_for(station.dxcc())
            .find(|id| matches!(*id, "US_COUNTY" | "JA_CITY_GUN_KU"));
        let vucc = (index != 0).then(|| get("MY_VUCC_GRIDS")).flatten();
        let grid = vucc.or_else(|| get("MY_GRIDSQUARE"));
        let changes = [
            (
                "GRIDSQUARE",
                if vucc.is_some() {
                    "MY_VUCC_GRIDS"
                } else {
                    "MY_GRIDSQUARE"
                },
                grid,
            ),
            (primary.unwrap_or(""), "MY_STATE", get("MY_STATE")),
            (secondary.unwrap_or(""), "MY_CNTY", get("MY_CNTY")),
            ("ITUZ", "MY_ITU_ZONE", get("MY_ITU_ZONE")),
            ("CQZ", "MY_CQ_ZONE", get("MY_CQ_ZONE")),
            ("IOTA", "MY_IOTA", get("MY_IOTA")),
        ];
        for (field, adif, value) in changes {
            let Some(value) = value else { continue };
            if field.is_empty() {
                continue;
            }
            let value = if adif == "MY_CNTY" {
                value.split_once(',').map_or(value, |(_, c)| c.trim())
            } else {
                value
            };
            let value = match (field, value) {
                ("CA_PROVINCE", "QC") => "PQ",
                ("CA_PROVINCE", "NL") => "NF",
                ("RU_OBLAST", "YR") => "JA",
                ("RU_OBLAST", "YN") => "JN",
                _ => value,
            };
            let number = matches!(field, "ITUZ" | "CQZ")
                .then(|| value.parse::<u32>().ok().map(|v| v.to_string()))
                .flatten();
            let value = number.as_deref().unwrap_or(value);
            let previous = fields
                .iter()
                .find(|(n, _)| *n == field)
                .map(|(_, v)| v.as_str());
            let dependency = lotw::loc_field(field)
                .and_then(|f| f.depends_on)
                .and_then(|name| {
                    fields
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, v)| v.as_str())
                })
                .unwrap_or("");
            let listed = Some(field) == primary || Some(field) == secondary;
            let value = if listed
                && previous.is_some_and(|previous| {
                    lotw::loc_value_label(field, dependency, previous)
                        .is_some_and(|label| label.eq_ignore_ascii_case(value))
                }) {
                previous.unwrap_or(value)
            } else if listed && (self.qth == QthHandling::FromLog || previous.is_none()) {
                lotw::loc_values(field, dependency)
                    .find(|v| v.eq_ignore_ascii_case(value))
                    .or_else(|| lotw::loc_value_from_label(field, dependency, value))
                    .unwrap_or(value)
            } else {
                value
            };
            let value = value.to_owned();
            let value = value.as_str();
            let matches = previous.is_some_and(|v| {
                if field == "GRIDSQUARE" && (v.contains(',') || value.contains(',')) {
                    // tqslconvert.cpp:1651–1694 treats equal-size VUCC lists as matching.
                    v.split(',').count() == value.split(',').count()
                } else if field == "GRIDSQUARE" && value.len() == 4 && !v.contains(',') {
                    v.get(..4).is_some_and(|v| v.eq_ignore_ascii_case(value))
                } else {
                    v.eq_ignore_ascii_case(value)
                }
            });
            if matches {
                continue;
            }
            if self.qth == QthHandling::Refuse && previous.is_some_and(|v| !v.is_empty()) {
                return Err(failure(adif, value));
            }
            fields.retain(|(n, _)| *n != field);
            fields.push((field, value.to_owned()));
            if Some(field) == primary {
                // Refreshing the primary subdivision retains only selections that remain in
                // the new county/zone lists. Later MY_ fields can supply cleared values again.
                let zones = lotw::loc_value_zones(field, &station.dxcc().to_string(), value);
                fields.retain(|(name, selected)| {
                    if Some(*name) == secondary {
                        lotw::loc_values(name, value).any(|v| v.eq_ignore_ascii_case(selected))
                    } else if matches!(*name, "ITUZ" | "CQZ") && !zones.is_empty() {
                        lotw::zone_pairs(zones).any(|(itu, cq)| {
                            selected.parse() == Ok(if *name == "ITUZ" { itu } else { cq })
                        })
                    } else {
                        true
                    }
                });
            }
        }
        let location = StationLocation::new(
            &fields
                .iter()
                .map(|(n, v)| (*n, v.as_str()))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| LogError::Location { index, error })?;
        if let Some(county) = get("MY_CNTY")
            && let Some((state, _)) = county.split_once(',')
            && !location
                .get("US_STATE")
                .is_some_and(|v| v.eq_ignore_ascii_case(state.trim()))
        {
            return Err(failure("MY_CNTY", county));
        }
        Ok(location)
    }

    pub(crate) fn mode(&self, mode: &str, submode: Option<&str>) -> Option<&'static str> {
        // tqslconvert.cpp:1410–1435: each lookup consults the user-overlaid ARRL map,
        // in order: mode%submode, bare submode, bare mode, then the original mode.
        let lookup = |key: &str| {
            self.adif_modes
                .iter()
                .rev()
                .find(|(from, _)| from.eq_ignore_ascii_case(key) && !lotw::is_native_mode(from))
                .map(|(_, to)| to.to_ascii_uppercase())
                .or_else(|| lotw::mapped_mode(key).map(str::to_owned))
        };
        let found = submode
            .and_then(|sub| lookup(&format!("{mode}%{sub}")).or_else(|| lookup(sub)))
            .or_else(|| lookup(mode));
        lotw::native_mode(found.as_deref().unwrap_or(mode))
    }
}
