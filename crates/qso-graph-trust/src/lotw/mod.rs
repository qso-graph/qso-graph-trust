// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! What LoTW checks a signed log against: ARRL's TQSL configuration, as data. The tables are
//! generated from `data/tqsl-config/config.xml` by `scripts/gen-lotw-tables.py`, so a new
//! configuration from ARRL is a regenerated file, never new code.

pub mod arrl;
#[rustfmt::skip]
mod tables;

pub use tables::{CONFIG_VERSION, SIGN_CONTACT, SIGN_STATION, SIGNATURE_FIELD};

/// Which part of the spectrum a band is in, and so the unit of its edges: kHz for HF, MHz above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spectrum {
    Hf,
    Vhf,
    Uhf,
}

/// A band LoTW accepts, with its edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Band {
    pub name: &'static str,
    pub spectrum: Spectrum,
    pub low: u64,
    pub high: u64,
}

/// One entry of the map from ADIF's MODE and SUBMODE to the mode LoTW records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdifMode {
    pub mode: &'static str,
    pub submode: Option<&'static str>,
    pub lotw: &'static str,
}

/// A DXCC entity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DxccEntity {
    pub id: u32,
    pub name: &'static str,
    pub deleted: bool,
    /// The ITU and CQ zones it lies in, as config.xml writes them: `ITU:CQ` pairs, comma-separated.
    pub zones: &'static str,
}

/// Whether a station-location field holds text or a whole number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Int,
}

/// A station-location field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocField {
    pub id: &'static str,
    pub kind: FieldKind,
    /// The longest value, in characters.
    pub len: usize,
    /// The lowest and highest value of a number.
    pub range: Option<(i64, i64)>,
    /// The field whose value chooses this one's list of values.
    pub depends_on: Option<&'static str>,
    /// False for a field that is only a message to the operator, never part of a location.
    pub shown: bool,
}

/// A page of station-location fields: the first page, or the page for one DXCC entity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocPage {
    pub id: u32,
    pub follows: u32,
    pub dxcc: Option<u32>,
    pub fields: &'static [&'static str],
}

/// The band with this name, compared without regard to case.
pub fn band(name: &str) -> Option<&'static Band> {
    tables::BANDS
        .iter()
        .find(|b| b.name.eq_ignore_ascii_case(name))
}

/// The band a frequency in MHz falls in. A logger may round the lower edge of 30, 17 and 12
/// metres down to the whole MHz, so 10.000, 18.000 and 24.000 are in those bands.
pub fn band_of(mhz: f64) -> Option<&'static Band> {
    tables::BANDS.iter().find(|b| freq_in_band(b, mhz))
}

/// Whether a frequency in MHz is in this band.
pub fn freq_in_band(b: &Band, mhz: f64) -> bool {
    match b.spectrum {
        Spectrum::Hf => {
            let khz = mhz * 1000.0;
            let low = match b.low {
                10100 => 10000,
                18068 => 18000,
                24890 => 24000,
                low => low,
            };
            khz >= low as f64 && khz <= b.high as f64
        }
        Spectrum::Vhf | Spectrum::Uhf => mhz >= b.low as f64 && mhz <= b.high as f64,
    }
}

/// The mode LoTW records for an ADIF MODE and SUBMODE, both already in capitals: the entry for
/// both, else one naming the submode alone, else the entry for the mode alone, else the mode
/// itself. `None` if what that gives is not a mode LoTW accepts.
pub fn lotw_mode(mode: &str, submode: Option<&str>) -> Option<&'static str> {
    let map = tables::ADIF_MODES;
    let found = submode
        .and_then(|sub| {
            map.iter()
                .find(|m| m.mode == mode && m.submode == Some(sub))
                .or_else(|| map.iter().find(|m| m.submode.is_none() && m.mode == sub))
                .or_else(|| map.iter().find(|m| m.submode == Some(sub)))
        })
        .or_else(|| map.iter().find(|m| m.submode.is_none() && m.mode == mode))
        .map_or(mode, |m| m.lotw);
    tables::MODES.iter().copied().find(|&m| m == found)
}

pub(crate) fn native_mode(mode: &str) -> Option<&'static str> {
    tables::MODES.iter().copied().find(|m| *m == mode)
}

pub(crate) fn is_native_mode(mode: &str) -> bool {
    tables::MODES.iter().any(|m| m.eq_ignore_ascii_case(mode))
}

pub(crate) fn mapped_mode(key: &str) -> Option<&'static str> {
    let (mode, submode) = key
        .split_once('%')
        .map_or((key, None), |(m, s)| (m, Some(s)));
    tables::ADIF_MODES
        .iter()
        .find(|m| m.mode == mode && m.submode == submode)
        .or_else(|| {
            submode
                .is_none()
                .then(|| tables::ADIF_MODES.iter().find(|m| m.submode == Some(mode)))
                .flatten()
        })
        .map(|m| m.lotw)
}

/// Whether LoTW accepts this propagation mode, in capitals.
pub fn is_prop_mode(name: &str) -> bool {
    tables::PROP_MODES.contains(&name)
}

/// Whether LoTW knows this satellite, in capitals.
pub fn is_satellite(name: &str) -> bool {
    tables::SATELLITES.contains(&name)
}

/// The DXCC entity with this number.
pub fn dxcc(id: u32) -> Option<&'static DxccEntity> {
    tables::DXCC.iter().find(|e| e.id == id)
}

/// The station-location field with this name, exactly as the configuration writes it.
pub fn loc_field(id: &str) -> Option<&'static LocField> {
    tables::LOC_FIELDS.iter().find(|f| f.id == id)
}

/// A list field's values, given the value of the field it depends on ("" if it depends on none).
/// Empty for a field that is not a list.
pub fn loc_values<'a>(
    field: &'a str,
    dependency: &'a str,
) -> impl Iterator<Item = &'static str> + 'a {
    tables::LOC_ENUMS
        .iter()
        .filter(move |(f, d, _, _)| *f == field && *d == dependency)
        .map(|(_, _, v, _)| *v)
}

/// Whether this field is a list in any case, so its value must be one of the list's.
pub fn is_list(field: &str) -> bool {
    tables::LOC_ENUMS.iter().any(|(f, _, _, _)| *f == field)
}

/// The ITU and CQ zones a list value lies in, as config.xml writes them, or "" if it says none.
pub fn loc_value_zones(field: &str, dependency: &str, value: &str) -> &'static str {
    tables::LOC_ENUMS
        .iter()
        .find(|(f, d, v, _)| *f == field && *d == dependency && *v == value)
        .map_or("", |(_, _, _, z)| *z)
}

pub(crate) fn loc_value_label(field: &str, dependency: &str, value: &str) -> Option<&'static str> {
    tables::LOC_LABELS
        .iter()
        .find(|(f, d, v, _)| *f == field && *d == dependency && *v == value)
        .map(|(_, _, _, label)| *label)
}

pub(crate) fn loc_value_from_label(
    field: &str,
    dependency: &str,
    label: &str,
) -> Option<&'static str> {
    // location.cpp:4076–4110: the setter accepts labels without spaces, punctuation or the
    // administrative suffixes listed here. These are normalization rules, not ARRL tables.
    let normalize = |value: &str| {
        let mut value = value.to_ascii_uppercase().replace([' ', '\'', '-'], "");
        for (from, to) in [
            ("CITYANDBOROUGH", ""),
            ("BOROUGH", ""),
            ("CENSUSAREA", ""),
            ("MUNICIPALITY", ""),
            ("ST.", "SAINT"),
            ("STE.", "SAINTE"),
            ("DOÑAANA", "DONAANA"),
            ("BRISTOLCITY", "BRISTOL"),
            ("SALEMCITY", "SALEM"),
        ] {
            value = value.replace(from, to);
        }
        value
    };
    let label = normalize(label);
    tables::LOC_LABELS
        .iter()
        .find(|(f, d, _, v)| *f == field && *d == dependency && normalize(v) == label)
        .map(|(_, _, value, _)| *value)
        .or_else(|| {
            loc_values(field, dependency)
                .find(|v| loc_value_label(field, dependency, v).is_none() && normalize(v) == label)
        })
}

/// The (ITU, CQ) zone pairs in a zone map as config.xml writes it, `07:04,08:05`.
pub fn zone_pairs(map: &str) -> impl Iterator<Item = (u32, u32)> + '_ {
    map.split(',').filter_map(|pair| {
        let (itu, cq) = pair.split_once(':')?;
        Some((itu.trim().parse().ok()?, cq.trim().parse().ok()?))
    })
}

/// The station-location fields for a DXCC entity, in the order a location lists them: the first
/// page's, then those of the page for this entity, if there is one.
pub fn loc_fields_for(dxcc: u32) -> impl Iterator<Item = &'static str> {
    let first = tables::LOC_PAGES.iter().filter(|p| p.follows == 0);
    let entity = tables::LOC_PAGES
        .iter()
        .filter(move |p| p.follows != 0 && p.dxcc == Some(dxcc));
    first.chain(entity).flat_map(|p| p.fields.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configuration_is_the_one_checked_in() {
        assert_eq!(CONFIG_VERSION, (11, 35));
        assert_eq!(SIGNATURE_FIELD, "SIGN_LOTW_V2.0");
        assert_eq!(SIGN_CONTACT.len(), 10);
    }

    #[test]
    fn modes_map_from_adif_as_the_configuration_says() {
        assert_eq!(lotw_mode("MFSK", Some("FT8")), Some("FT8"));
        assert_eq!(lotw_mode("MFSK", Some("FT4")), Some("FT4"));
        assert_eq!(lotw_mode("MFSK", Some("JS8")), Some("DATA"));
        // ADIF 3.1.8 added SUBMODE=JTTY under MFSK. TQSL's configuration 11.35 has no JTTY row,
        // so it takes the MFSK row, as TQSL itself does. A configuration that maps JTTY to
        // anything else must fail here, so the change is a decision rather than a surprise.
        assert_eq!(lotw_mode("MFSK", Some("JTTY")), Some("DATA"));
        assert_eq!(lotw_mode("MFSK", None), Some("DATA"));
        assert_eq!(lotw_mode("SSB", Some("USB")), Some("SSB"));
        assert_eq!(lotw_mode("CW", None), Some("CW"));
        // An old log's MODE=FT8, before ADIF made it a submode.
        assert_eq!(lotw_mode("FT8", None), Some("FT8"));
        assert_eq!(lotw_mode("NOTAMODE", None), None);
    }

    #[test]
    fn frequencies_fall_in_their_bands() {
        assert_eq!(band_of(14.074).map(|b| b.name), Some("20M"));
        assert_eq!(band_of(7.074).map(|b| b.name), Some("40M"));
        assert_eq!(band_of(145.99).map(|b| b.name), Some("2M"));
        assert_eq!(band_of(435.8).map(|b| b.name), Some("70CM"));
        assert_eq!(band_of(10.0).map(|b| b.name), Some("30M"));
        assert_eq!(band_of(9.0), None);
        assert!(!freq_in_band(band("20m").expect("20M"), 7.074));
    }

    #[test]
    fn a_us_location_lists_its_fields_in_page_order() {
        let fields: Vec<&str> = loc_fields_for(291).collect();
        assert_eq!(
            fields,
            [
                "CALL",
                "DXCC",
                "GRIDSQUARE",
                "ITUZ",
                "CQZ",
                "IOTA",
                "ZERR",
                "US_STATE",
                "US_COUNTY",
                "US_PARK",
                "ZERR"
            ]
        );
        assert!(loc_values("US_STATE", "291").any(|v| v == "KS"));
        assert!(loc_values("US_COUNTY", "KS").any(|v| v == "Sedgwick"));
        assert!(loc_values("US_COUNTY", "SC").any(|v| v == "Charleston"));
        assert_eq!(loc_value_zones("US_STATE", "291", "KS"), "07:04");
        let us: Vec<_> = zone_pairs(dxcc(291).expect("USA").zones).collect();
        assert!(us.contains(&(7, 4)) && !us.contains(&(45, 25)));
    }
}

#[cfg(test)]
mod release_edges;
