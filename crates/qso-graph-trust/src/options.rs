// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Caller-selected settings that affect signing. These are local to one conversion; importing a
//! backup never changes process-wide settings. Construct QSOs with the same options used to sign.

use crate::{lotw, qso::Qso, signed_log::LogError, station::StationLocation, tbk};

pub use crate::tbk::QthHandling;

/// Log handling settings. Defaults preserve TQSL-compatible signing output.
/// Construct QSOs with these same options before signing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigningOptions {
    /// Custom ADIF mode (or `MODE%SUBMODE`) to LoTW mode mappings. Compared without case.
    /// Later entries win. Entries redefining a native LoTW mode are ignored, as in TQSL's app.
    pub adif_modes: Vec<(String, String)>,
    /// Set seconds to zero before signing and duplicate detection.
    pub ignore_seconds: bool,
    /// Bypass the contacted call's amateur callsign check. Controls and characters forbidden by
    /// XML remain refused, as does other invalid QSO data.
    pub allow_bad_calls: bool,
    /// Disregard the log's STATION_CALLSIGN and OPERATOR, without changing the selected certificate.
    pub ignore_log_callsigns: bool,
    /// Ignore, report differences in, or update location details from the log.
    /// `Ignore`, like TQSL's, does not compare STATION_CALLSIGN or MY_DXCC, so another station's
    /// QSOs can be signed as the selected location's.
    pub qth: QthHandling,
    /// Require every station field named by each QSO to agree with the supplied location,
    /// without filling or changing it. Overrides `qth` and `ignore_log_callsigns`.
    /// Use [`Self::with_exact_station`] to select this mode.
    pub exact_station: bool,
}

impl From<&tbk::Preferences> for SigningOptions {
    fn from(prefs: &tbk::Preferences) -> Self {
        Self {
            adif_modes: prefs.adif_modes.clone(),
            ignore_seconds: prefs.ignore_seconds,
            allow_bad_calls: prefs.allow_bad_calls,
            ignore_log_callsigns: prefs.ignore_log_callsigns,
            qth: prefs.qth,
            exact_station: false,
        }
    }
}

impl SigningOptions {
    /// Select exact station checking. Every named station field must agree with the input
    /// location, including fields it leaves empty, on every QSO. Both callsign fields are checked
    /// even when `ignore_log_callsigns` is set. A four-character grid may abbreviate the station's
    /// six-character grid; VUCC lists compare as sets, and never match a single grid.
    /// The supplied station is used unchanged for every signature. Defaults to `false`.
    #[must_use]
    pub fn with_exact_station(mut self, exact: bool) -> Self {
        self.exact_station = exact;
        self
    }

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

    /// The QSOs signing would refuse as another station's, each by its place in the log from 0 with
    /// the reason, so a caller can leave them out and sign the rest. Each QSO is checked against the
    /// station as `sign_log_with_options` checks it, in order, carrying forward what earlier QSOs
    /// filled in, except that a refused QSO changes nothing: signing the QSOs left gives the same
    /// stations, and so the same signed log, as though the refused ones had never been in it.
    /// The first-QSO VUCC exception counts accepted QSOs. In exact mode each check is independent
    /// against the input station. Every returned error identifies its ADIF field through
    /// [`LogError::adif_field`], including invalid location values.
    pub fn station_refusals(
        &self,
        qsos: &[Qso],
        station: &StationLocation,
    ) -> Vec<(usize, LogError)> {
        let mut current = station.clone();
        let mut refused = Vec::new();
        let mut accepted = 0;
        for (index, qso) in qsos.iter().enumerate() {
            match self.location_at(qso, &current, index, accepted == 0) {
                Ok(next) => {
                    current = next;
                    accepted += 1;
                }
                Err(error) => refused.push((index, error)),
            }
        }
        refused
    }

    fn location(
        &self,
        qso: &Qso,
        station: &StationLocation,
        index: usize,
    ) -> Result<StationLocation, LogError> {
        self.location_at(qso, station, index, index == 0)
    }

    fn location_at(
        &self,
        qso: &Qso,
        station: &StationLocation,
        index: usize,
        first: bool,
    ) -> Result<StationLocation, LogError> {
        if self.exact_station {
            return self.exact_location(qso, station, index);
        }
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
        let primary = crate::station::primary_subdivision(station.dxcc());
        let secondary = crate::station::secondary_subdivision(station.dxcc());
        let vucc = (!first).then(|| get("MY_VUCC_GRIDS")).flatten();
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
            let value = crate::station::lotw_value(field, value);
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
        .map_err(|error| {
            // Validation's coupled zone error names the last explicitly supplied zone.
            // Keep the existing variant while giving callers an unambiguous ADIF field.
            let error = match error {
                crate::station::StationError::Invalid {
                    field: "GRIDSQUARE",
                    value,
                } if vucc.is_some() => crate::station::StationError::Invalid {
                    field: "MY_VUCC_GRIDS",
                    value,
                },
                crate::station::StationError::Invalid {
                    field: "ZONES",
                    value,
                } => crate::station::StationError::Invalid {
                    field: if get("MY_CQ_ZONE").is_some() {
                        "MY_CQ_ZONE"
                    } else if get("MY_ITU_ZONE").is_some() {
                        "MY_ITU_ZONE"
                    } else {
                        "MY_STATE"
                    },
                    value,
                },
                error => error,
            };
            LogError::Location { index, error }
        })?;
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

    fn exact_location(
        &self,
        qso: &Qso,
        station: &StationLocation,
        index: usize,
    ) -> Result<StationLocation, LogError> {
        for (adif, given) in qso.station() {
            let field = match adif {
                "STATION_CALLSIGN" | "OPERATOR" => Some("CALL"),
                "MY_DXCC" => Some("DXCC"),
                "MY_GRIDSQUARE" | "MY_VUCC_GRIDS" => Some("GRIDSQUARE"),
                // A subdivision LoTW has no field for in this entity can never be signed, so it
                // can't disagree with the station; tqsllib and `from_adif` leave it out too.
                "MY_STATE" => match crate::station::primary_subdivision(station.dxcc()) {
                    Some(field) => Some(field),
                    None => continue,
                },
                "MY_CNTY" => match crate::station::secondary_subdivision(station.dxcc()) {
                    Some(field) => Some(field),
                    None => continue,
                },
                "MY_ITU_ZONE" => Some("ITUZ"),
                "MY_CQ_ZONE" => Some("CQZ"),
                "MY_IOTA" => Some("IOTA"),
                _ => None,
            };
            let failure = || LogError::QsoFromAnotherStation {
                index,
                field: adif,
                value: given.to_owned(),
            };
            let field = field.ok_or_else(failure)?;
            let ours = station.get(field).ok_or_else(failure)?;
            let mut value = given;
            if adif == "MY_CNTY"
                && let Some((state, county)) = given.split_once(',')
            {
                if !station
                    .get("US_STATE")
                    .is_some_and(|v| v.eq_ignore_ascii_case(state.trim()))
                {
                    return Err(failure());
                }
                value = county.trim();
            }
            value = crate::station::lotw_value(field, value);
            let dependency = lotw::loc_field(field)
                .and_then(|f| f.depends_on)
                .and_then(|f| station.get(f))
                .unwrap_or("");
            // Resolve the same list codes and labels as conversion, without changing the station.
            value = lotw::loc_values(field, dependency)
                .find(|v| v.eq_ignore_ascii_case(value))
                .or_else(|| lotw::loc_value_from_label(field, dependency, value))
                .unwrap_or(value);
            let agrees = match adif {
                "MY_DXCC" | "MY_ITU_ZONE" | "MY_CQ_ZONE" => value
                    .parse::<u32>()
                    .ok()
                    .is_some_and(|n| ours.parse() == Ok(n)),
                "MY_VUCC_GRIDS" => {
                    let grids = |s: &str| {
                        s.split(',')
                            .map(|g| g.trim().to_ascii_uppercase())
                            .collect::<std::collections::BTreeSet<_>>()
                    };
                    ours.contains(',') && value.contains(',') && grids(ours) == grids(value)
                }
                "MY_GRIDSQUARE" => {
                    !ours.contains(',')
                        && !value.contains(',')
                        && (ours.eq_ignore_ascii_case(value)
                            || (value.len() == 4
                                && ours.len() == 6
                                && ours[..4].eq_ignore_ascii_case(value)))
                }
                _ => ours.eq_ignore_ascii_case(value),
            };
            if !agrees {
                return Err(failure());
            }
        }
        Ok(station.clone())
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
