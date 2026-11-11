// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! ADIF's XML representation, converted to the same records as ADI.

use zeroize::Zeroizing;

use crate::records::{
    Field, MAX_FIELDS, MAX_RECORDS, MAX_TOTAL_FIELDS, MAX_VALUE_LEN, Record, RecordError,
};
use crate::xml::{self, Element, Limits};

// ADIF 3.1.7 section III.C: QSO field names, not the LoTW station or mode tables.
const QSO_FIELDS: &[&str] = &[
    "ADDRESS",
    "ADDRESS_INTL",
    "AGE",
    "ALTITUDE",
    "ANT_AZ",
    "ANT_EL",
    "ANT_PATH",
    "ARRL_SECT",
    "AWARD_GRANTED",
    "AWARD_SUBMITTED",
    "A_INDEX",
    "BAND",
    "BAND_RX",
    "CALL",
    "CHECK",
    "CLASS",
    "CLUBLOG_QSO_UPLOAD_DATE",
    "CLUBLOG_QSO_UPLOAD_STATUS",
    "CNTY",
    "CNTY_ALT",
    "COMMENT",
    "COMMENT_INTL",
    "CONT",
    "CONTACTED_OP",
    "CONTEST_ID",
    "COUNTRY",
    "COUNTRY_INTL",
    "CQZ",
    "CREDIT_GRANTED",
    "CREDIT_SUBMITTED",
    "DARC_DOK",
    "DCL_QSLRDATE",
    "DCL_QSLSDATE",
    "DCL_QSL_RCVD",
    "DCL_QSL_SENT",
    "DISTANCE",
    "DXCC",
    "EMAIL",
    "EQSL_AG",
    "EQSL_QSLRDATE",
    "EQSL_QSLSDATE",
    "EQSL_QSL_RCVD",
    "EQSL_QSL_SENT",
    "EQ_CALL",
    "FISTS",
    "FISTS_CC",
    "FORCE_INIT",
    "FREQ",
    "FREQ_RX",
    "GRIDSQUARE",
    "GRIDSQUARE_EXT",
    "GUEST_OP",
    "HAMLOGEU_QSO_UPLOAD_DATE",
    "HAMLOGEU_QSO_UPLOAD_STATUS",
    "HAMQTH_QSO_UPLOAD_DATE",
    "HAMQTH_QSO_UPLOAD_STATUS",
    "HRDLOG_QSO_UPLOAD_DATE",
    "HRDLOG_QSO_UPLOAD_STATUS",
    "IOTA",
    "IOTA_ISLAND_ID",
    "ITUZ",
    "K_INDEX",
    "LAT",
    "LON",
    "LOTW_QSLRDATE",
    "LOTW_QSLSDATE",
    "LOTW_QSL_RCVD",
    "LOTW_QSL_SENT",
    "MAX_BURSTS",
    "MODE",
    "MORSE_KEY_INFO",
    "MORSE_KEY_TYPE",
    "MS_SHOWER",
    "MY_ALTITUDE",
    "MY_ANTENNA",
    "MY_ANTENNA_INTL",
    "MY_ARRL_SECT",
    "MY_CITY",
    "MY_CITY_INTL",
    "MY_CNTY",
    "MY_CNTY_ALT",
    "MY_COUNTRY",
    "MY_COUNTRY_INTL",
    "MY_CQ_ZONE",
    "MY_DARC_DOK",
    "MY_DXCC",
    "MY_FISTS",
    "MY_GRIDSQUARE",
    "MY_GRIDSQUARE_EXT",
    "MY_IOTA",
    "MY_IOTA_ISLAND_ID",
    "MY_ITU_ZONE",
    "MY_LAT",
    "MY_LON",
    "MY_MORSE_KEY_INFO",
    "MY_MORSE_KEY_TYPE",
    "MY_NAME",
    "MY_NAME_INTL",
    "MY_POSTAL_CODE",
    "MY_POSTAL_CODE_INTL",
    "MY_POTA_REF",
    "MY_RIG",
    "MY_RIG_INTL",
    "MY_SIG",
    "MY_SIG_INFO",
    "MY_SIG_INFO_INTL",
    "MY_SIG_INTL",
    "MY_SOTA_REF",
    "MY_STATE",
    "MY_STREET",
    "MY_STREET_INTL",
    "MY_USACA_COUNTIES",
    "MY_VUCC_GRIDS",
    "MY_WWFF_REF",
    "NAME",
    "NAME_INTL",
    "NOTES",
    "NOTES_INTL",
    "NR_BURSTS",
    "NR_PINGS",
    "OPERATOR",
    "OWNER_CALLSIGN",
    "PFX",
    "POTA_REF",
    "PRECEDENCE",
    "PROP_MODE",
    "PUBLIC_KEY",
    "QRZCOM_QSO_DOWNLOAD_DATE",
    "QRZCOM_QSO_DOWNLOAD_STATUS",
    "QRZCOM_QSO_UPLOAD_DATE",
    "QRZCOM_QSO_UPLOAD_STATUS",
    "QSLMSG",
    "QSLMSG_INTL",
    "QSLMSG_RCVD",
    "QSLRDATE",
    "QSLSDATE",
    "QSL_RCVD",
    "QSL_RCVD_VIA",
    "QSL_SENT",
    "QSL_SENT_VIA",
    "QSL_VIA",
    "QSO_COMPLETE",
    "QSO_DATE",
    "QSO_DATE_OFF",
    "QSO_RANDOM",
    "QTH",
    "QTH_INTL",
    "REGION",
    "RIG",
    "RIG_INTL",
    "RST_RCVD",
    "RST_SENT",
    "RX_PWR",
    "SAT_MODE",
    "SAT_NAME",
    "SFI",
    "SIG",
    "SIG_INFO",
    "SIG_INFO_INTL",
    "SIG_INTL",
    "SILENT_KEY",
    "SKCC",
    "SOTA_REF",
    "SRX",
    "SRX_STRING",
    "STATE",
    "STATION_CALLSIGN",
    "STX",
    "STX_STRING",
    "SUBMODE",
    "SWL",
    "TEN_TEN",
    "TIME_OFF",
    "TIME_ON",
    "TX_PWR",
    "UKSMG",
    "USACA_COUNTIES",
    "VE_PROV",
    "VUCC_GRIDS",
    "WEB",
    "WWFF_REF",
];

fn bad(problem: &'static str) -> RecordError {
    RecordError::Adx(problem)
}

fn attributes(element: &Element<'_>, allowed: &[&str]) -> Result<(), RecordError> {
    if element
        .attribute_names()
        .any(|n| n != "xmlns" && !n.starts_with("xmlns:") && !allowed.contains(&n))
    {
        return Err(bad("an unexpected attribute"));
    }
    Ok(())
}

fn container(element: &Element<'_>) -> Result<(), RecordError> {
    attributes(element, &[])?;
    if !element
        .text()
        .trim_matches([' ', '\t', '\r', '\n'])
        .is_empty()
    {
        return Err(bad("text outside a field"));
    }
    Ok(())
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.')
}

pub(crate) fn parse(input: &[u8]) -> Result<Vec<Record>, RecordError> {
    let input = std::str::from_utf8(input).map_err(|_| bad("invalid UTF-8"))?;
    let limits = Limits {
        elements: xml::MAX_ELEMENTS,
        elements_named: &[("RECORD", MAX_RECORDS)],
        attribute_len: |_, _| MAX_VALUE_LEN,
        text_len: |_| MAX_VALUE_LEN,
    };
    let root = xml::parse_with_processing_instructions(input, &limits, true).map_err(|e| {
        if e.problem == "an attribute with no value" {
            bad("invalid XML attribute name or missing value; names must be ASCII")
        } else if e.problem == "too many named elements" {
            bad("too many records")
        } else {
            bad(e.problem)
        }
    })?;
    if root.name != "ADX" {
        return Err(bad("expected ADX"));
    }
    container(&root)?;
    let mut header = false;
    let mut records = None;
    for child in &root.children {
        match child.name {
            "HEADER" if !header && records.is_none() => {
                header = true;
                container(child)?;
                for field in &child.children {
                    if !field.children.is_empty()
                        || !identifier(field.name)
                        || field.name.bytes().any(|c| c.is_ascii_lowercase())
                    {
                        return Err(bad("invalid header field"));
                    }
                    attributes(
                        field,
                        match field.name {
                            "USERDEF" => &["FIELDID", "TYPE", "ENUM", "RANGE"],
                            "APP" => &["PROGRAMID", "FIELDNAME", "TYPE"],
                            _ => &[],
                        },
                    )?;
                }
            }
            "RECORDS" if records.is_none() => {
                records = Some(child);
            }
            _ => return Err(bad("unexpected ADX element")),
        }
    }
    let records = records.ok_or_else(|| bad("missing RECORDS"))?;
    if !header {
        return Err(bad("missing HEADER"));
    }
    container(records)?;
    let mut result = Vec::new();
    let mut total = 0;
    for item in &records.children {
        if item.name != "RECORD" {
            return Err(bad("expected RECORD"));
        }
        container(item)?;
        if item.children.len() > MAX_FIELDS {
            return Err(bad("too many fields in a record"));
        }
        total += item.children.len();
        if total > MAX_TOTAL_FIELDS {
            return Err(bad("too many fields"));
        }
        let mut record = Record::default();
        for field in &item.children {
            if !field.children.is_empty()
                || !identifier(field.name)
                || matches!(field.name, "ADX" | "HEADER" | "RECORDS" | "RECORD")
                || field.name.bytes().any(|c| c.is_ascii_lowercase())
            {
                return Err(bad("invalid record field"));
            }
            let (name, kind) = match field.name {
                "APP" => {
                    attributes(field, &["PROGRAMID", "FIELDNAME", "TYPE"])?;
                    let program = field
                        .attribute("PROGRAMID")
                        .ok_or_else(|| bad("APP missing PROGRAMID"))?;
                    let name = field
                        .attribute("FIELDNAME")
                        .ok_or_else(|| bad("APP missing FIELDNAME"))?;
                    let kind = field
                        .attribute("TYPE")
                        .ok_or_else(|| bad("APP missing TYPE"))?;
                    if !identifier(&program)
                        || !identifier(&name)
                        || kind.len() != 1
                        || !kind.as_bytes()[0].is_ascii_alphanumeric()
                    {
                        return Err(bad("invalid APP attributes"));
                    }
                    (
                        format!("APP_{}_{}", program.as_str(), name.as_str()),
                        Some(kind.to_string()),
                    )
                }
                "USERDEF" => {
                    attributes(field, &["FIELDNAME", "TYPE"])?;
                    let name = field
                        .attribute("FIELDNAME")
                        .ok_or_else(|| bad("USERDEF missing FIELDNAME"))?;
                    if !identifier(&name) {
                        return Err(bad("invalid USERDEF name"));
                    }
                    (name.to_string(), None)
                }
                name => {
                    attributes(field, &[])?;
                    if QSO_FIELDS.binary_search(&name).is_err() {
                        return Err(bad("unknown ADIF record field"));
                    }
                    (name.to_string(), None)
                }
            };
            let value = field.text();
            record.fields.push(Field {
                name,
                kind,
                value: Zeroizing::new(value.as_bytes().to_vec()),
            });
        }
        result.push(record);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::records;

    #[test]
    fn published_adi_and_adx_samples() {
        let Some(path) = std::env::var_os("QGT_ADIF_TEST_DIR") else {
            eprintln!(
                "skipped: QGT_ADIF_TEST_DIR is unset; ADIF test file redistribution terms are unclear"
            );
            return;
        };
        let read = |ext| {
            let path =
                std::path::Path::new(&path).join(format!("ADIF_317_test_QSOs_2026_03_22.{ext}"));
            records::parse(&std::fs::read(path).expect("ADIF test file is missing or unreadable"))
                .expect("ADIF test file must parse")
        };
        let adi = read("adi");
        let adx = read("adx");
        assert_eq!(adi.len(), 6197);
        assert_eq!(adx.len(), 6197);
        // ADIF's own equivalence: field names are case-insensitive (the ADI file mixes case on
        // purpose), values are compared byte for byte, and a type indicator is compared only
        // on application-defined fields: ADI may repeat a standard field's own type (`CALL:..:S`),
        // and ADX carries type indicators on application- and user-defined fields alone.
        let same = |a: &records::Field, x: &records::Field| {
            a.name.eq_ignore_ascii_case(&x.name)
                && *a.value == *x.value
                && (!x.name.starts_with("APP_")
                    || a.kind.as_deref().map(str::to_ascii_uppercase)
                        == x.kind.as_deref().map(str::to_ascii_uppercase))
        };
        let mut differences = Vec::new();
        let mut intl = 0;
        for (index, (a, x)) in adi.iter().zip(&adx).enumerate() {
            let mut used = vec![false; x.fields.len()];
            for field in &a.fields {
                if let Some(i) = x
                    .fields
                    .iter()
                    .enumerate()
                    .position(|(i, f)| !used[i] && same(field, f))
                {
                    used[i] = true;
                } else if let Some(i) = x.fields.iter().enumerate().position(|(i, f)| {
                    !used[i]
                        && f.name
                            .strip_suffix("_INTL")
                            .is_some_and(|n| n.eq_ignore_ascii_case(&field.name))
                }) {
                    used[i] = true;
                    intl += 1;
                } else {
                    differences.push(format!(
                        "record {}: ADI field {} has no matching ADX field",
                        index + 1,
                        field.name
                    ));
                }
            }
            for (i, field) in x.fields.iter().enumerate() {
                if !used[i] {
                    if field.name.ends_with("_INTL") {
                        intl += 1;
                    } else {
                        differences.push(format!(
                            "record {}: unmatched ADX field {}",
                            index + 1,
                            field.name
                        ));
                    }
                }
            }
        }
        println!("ADIF published files: {intl} _INTL pairs");
        assert!(
            differences.is_empty(),
            "unexpected differences:\n{}",
            differences.join("\n")
        );
    }
}

#[cfg(test)]
mod validation_tests {
    use crate::records::{self, MAX_FIELDS, MAX_RECORDS, MAX_TOTAL_FIELDS, MAX_VALUE_LEN};

    #[test]
    fn equivalent_fields_and_detection() {
        let adi = b"<EOH><CALL:6>QG0ABC<APP_FOO_BAR:1:N>2<USER_FIELD:1>X<EOR>";
        let adx = b"\xef\xbb\xbf<?xml version=\"1.0\"?><ADX xmlns=\"urn:test\"><HEADER/><RECORDS><RECORD><CALL>QG0ABC</CALL><APP PROGRAMID=\"FOO\" FIELDNAME=\"BAR\" TYPE=\"N\">2</APP><USERDEF FIELDNAME=\"USER_FIELD\">X</USERDEF></RECORD></RECORDS></ADX>";
        assert_eq!(records::parse(adi).unwrap(), records::parse(adx).unwrap());
        assert!(records::parse(b"<ADX><!--good-comment--><HEADER/><RECORDS/></ADX>").is_ok());
        assert!(records::parse(br#"<ADX xmlns="urn:]]>"><HEADER/><RECORDS/></ADX>"#).is_ok());
        assert!(records::parse(b"<ADX><?p <!--bad--comment--><HEADER/><RECORDS/></ADX>").is_err());
        assert!(records::parse(b"<ADX><?p <!--ok--> ?><HEADER/><RECORDS/></ADX>").is_ok());
        assert!(records::parse(b"free <CALL:1>X<EOR>").is_ok());
        assert!(records::parse(b"<ADX broken").is_err());
        assert!(records::parse(b" \n<ADX><HEADER/><RECORDS/></ADX>").is_ok());
    }

    #[test]
    fn processing_instructions_and_namespaces() {
        assert!(records::parse(b"<?xml-stylesheet x?><ADX xmlns:x=\"u\"><?p x?><HEADER/><RECORDS><RECORD><CALL xmlns=\"u\">X</CALL></RECORD></RECORDS></ADX>").is_ok());
        for bad in ["<?XML x?>", "<?xml x?>", "<?p", "<?p!?>"] {
            assert!(
                records::parse(format!("<ADX>{bad}<HEADER/><RECORDS/></ADX>").as_bytes()).is_err()
            );
        }
        let long = format!("<ADX><?pi {}?><HEADER/><RECORDS/></ADX>", "x".repeat(65537));
        assert!(records::parse(long.as_bytes()).is_err());
        let long_target = format!("<ADX><?{}?><HEADER/><RECORDS/></ADX>", "p".repeat(65537));
        assert!(records::parse(long_target.as_bytes()).is_err());
        assert!(
            records::parse(
                b"<ADX><HEADER/><RECORDS><RECORD><x:CALL>X</x:CALL></RECORD></RECORDS></ADX>"
            )
            .is_err()
        );
        let error = records::parse(r#"<ADX xmlns:é="u"><RECORDS/></ADX>"#.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("names must be ASCII"));
    }

    #[test]
    fn processing_instructions_count_toward_the_xml_limit() {
        let limits = crate::xml::Limits {
            elements: 2,
            elements_named: &[],
            attribute_len: |_, _| 100,
            text_len: |_| 100,
        };
        assert!(
            crate::xml::parse_with_processing_instructions("<ADX><?p?></ADX>", &limits, true)
                .is_ok()
        );
        assert_eq!(
            crate::xml::parse_with_processing_instructions("<ADX><?p?><?p?></ADX>", &limits, true)
                .unwrap_err()
                .problem,
            "too many elements"
        );
        assert!(
            crate::xml::parse_with_processing_instructions("<ADX><?p?></ADX>", &limits, false)
                .is_err()
        );
    }

    #[test]
    fn other_xml_formats_still_reject_processing_instructions() {
        use crate::{certificate::Trust, import, tbk};
        let trust = Trust::with_roots(&[]).expect("empty trust");
        assert!(tbk::read(b"<TQSL_Configuration/>", &trust).is_ok());
        assert!(matches!(
            tbk::read(b"<TQSL_Configuration><?p x?></TQSL_Configuration>", &trust),
            Err(tbk::TbkError::Xml { .. })
        ));
        // The XML failure is checked before certificate validation.
        assert!(matches!(
            import::tq6_contents(b"<tqsldata><?p x?><tqslcerts/></tqsldata>"),
            Err(import::ImportError::Malformed)
        ));
        assert!(crate::xml::parse("<tqsldata><tqslcerts/></tqsldata>").is_ok());
    }

    #[test]
    fn total_field_limit_is_not_cut() {
        let one = format!("<RECORD>{}</RECORD>", "<CALL/>".repeat(MAX_FIELDS));
        let input = format!(
            "<ADX><HEADER/><RECORDS>{}</RECORDS></ADX>",
            one.repeat(MAX_TOTAL_FIELDS / MAX_FIELDS + 1)
        );
        let error = records::parse(input.as_bytes()).expect_err("total limit");
        assert!(error.to_string().contains("too many"));
    }

    #[test]
    fn malformed_and_oversized_inputs_are_refused() {
        for bad in [
            "<ADX><HEADER/><RECORDS>",
            "<!DOCTYPE ADX><ADX><HEADER/><RECORDS/></ADX>",
            "<ADX><HEADER/><RECORDS>&unknown;</RECORDS></ADX>",
            "<ADX/>",
            "<ADX><RECORDS/></ADX>",
            "<ADX>text<RECORDS/></ADX>",
            "<ADX><!--bad--comment--><HEADER/><RECORDS/></ADX>",
            "<ADX><HEADER/><RECORDS><RECORD><CALL>]]></CALL></RECORD></RECORDS></ADX>",
            "<ADX>\u{a0}<RECORDS/></ADX>",
            "<ADX><HEADER/><RECORDS><RECORD><CALL><NESTED/></CALL></RECORD></RECORDS></ADX>",
            "<ADX><HEADER/><RECORDS><RECORD><call>X</call></RECORD></RECORDS></ADX>",
            "<ADX><HEADER/><RECORDS><RECORD><RECORD/></RECORD></RECORDS></ADX>",
            "<ADX><HEADER/><RECORDS><RECORD><NOT_A_FIELD/></RECORD></RECORDS></ADX>",
            "<ADX><HEADER/><RECORDS><RECORD><CALL><![CDATA[X]]></CALL></RECORD></RECORDS></ADX>",
        ] {
            let input = format!("<?xml version=\"1.0\"?>{bad}");
            let error = records::parse(input.as_bytes())
                .expect_err("refused")
                .to_string();
            assert!(error.starts_with("ADX:"));
        }
        for declaration in [
            "<?xml?>",
            "<?xml version='2.0'?>",
            "<?xml encoding='UTF-8' version='1.0'?>",
            "<?xml version='1.0' encoding='UTF-16'?>",
            "<?xml version='1.0' standalone='maybe'?>",
        ] {
            let input = format!("{declaration}<ADX><HEADER/><RECORDS/></ADX>");
            assert!(
                records::parse(input.as_bytes())
                    .unwrap_err()
                    .to_string()
                    .contains("declaration")
            );
        }
        assert!(records::parse(b"<?xml version='1.0' encoding='utf-8' standalone='yes'?><ADX><HEADER/><RECORDS/></ADX>").is_ok());
        let secret = "DO_NOT_ECHO_THIS_VALUE";
        let planted = format!(
            "<ADX><HEADER/><RECORDS><RECORD><CALL>{secret}</WRONG></RECORD></RECORDS></ADX>"
        );
        assert!(
            !records::parse(planted.as_bytes())
                .unwrap_err()
                .to_string()
                .contains(secret)
        );
        for (input, problem) in [
            (
                format!(
                    "<ADX><HEADER/><RECORDS>{}</RECORDS></ADX>",
                    "<RECORD/>".repeat(MAX_RECORDS + 1)
                ),
                "too many records",
            ),
            (
                format!(
                    "<ADX><HEADER/><RECORDS><RECORD>{}</RECORD></RECORDS></ADX>",
                    "<CALL/>".repeat(MAX_FIELDS + 1)
                ),
                "too many fields in a record",
            ),
            (
                format!(
                    "<ADX><HEADER/><RECORDS><RECORD><CALL>{}</CALL></RECORD></RECORDS></ADX>",
                    "x".repeat(MAX_VALUE_LEN + 1)
                ),
                "text too long",
            ),
        ] {
            assert!(
                records::parse(input.as_bytes())
                    .unwrap_err()
                    .to_string()
                    .contains(problem)
            );
        }
    }
}
