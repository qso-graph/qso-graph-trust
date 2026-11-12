// SPDX-License-Identifier: GPL-3.0-or-later
//! Permanent synthetic regressions from the 0.2.1 pre-release review.

#![forbid(unsafe_code)]

use crate::{lotw, options::SigningOptions, qso::Qso, records, station::StationLocation};

// Read the generated configuration directly without a test-only public API.
use super::tables;

fn qso(fields: &[(&str, &str)], exact: bool) -> Result<Qso, crate::qso::QsoError> {
    let mut s =
        "<CALL:6>Z0TEST<QSO_DATE:8>20261101<TIME_ON:6>120000<BAND:3>20m<MODE:2>CW".to_owned();
    for (n, v) in fields {
        s.push_str(&format!("<{n}:{}>{v}", v.len()));
    }
    s.push_str("<eor>");
    Qso::from_adif_with_options(
        &records::parse(s.as_bytes()).unwrap()[0],
        &SigningOptions::default().with_exact_station(exact),
    )
}
#[test]
fn valid_adx_prolog_comments_and_processing_instructions() {
    let body = "<ADX><HEADER/><RECORDS><RECORD><CALL>Z0TEST</CALL><QSO_DATE>20261101</QSO_DATE><TIME_ON>120000</TIME_ON><BAND>20m</BAND><MODE>CW</MODE></RECORD></RECORDS></ADX>";
    let expected = records::parse(body.as_bytes()).unwrap();
    let mut failed = Vec::new();
    for prefix in [
        "<!-- exported log -->",
        "<?logger synthetic?>",
        " \n<!-- first -->\n<?logger synthetic?>",
        "\u{feff}<!-- exported log -->",
    ] {
        let with_decl = format!(
            "<?xml version=\"1.0\"?>{}{body}",
            prefix.trim_start_matches('\u{feff}')
        );
        assert!(
            records::parse(with_decl.as_bytes()).is_ok(),
            "same prolog after a declaration is accepted"
        );
        let actual = records::parse(format!("{prefix}{body}").as_bytes());
        eprintln!("prefix={prefix:?}: {actual:?}");
        if actual.as_ref().ok() != Some(&expected) {
            failed.push(prefix);
        }
    }
    assert!(
        failed.is_empty(),
        "valid XML prologs must reach the ADX reader: {failed:?}"
    );
}
#[test]
fn all_subdivision_codes_and_labels_match_signing() {
    let primary = [
        "US_STATE",
        "CA_PROVINCE",
        "RU_OBLAST",
        "CN_PROVINCE",
        "AU_STATE",
        "JA_PREFECTURE",
        "FI_KUNTA",
    ];
    let secondary = ["US_COUNTY", "JA_CITY_GUN_KU"];
    let mut total = 0;
    let mut failures = Vec::new();
    let mut entities = Vec::new();
    for e in tables::DXCC {
        let dxcc = e.id.to_string();
        let Some(p) = lotw::loc_fields_for(e.id).find(|f| primary.contains(f)) else {
            continue;
        };
        entities.push(e.id);
        let dep = if lotw::loc_field(p).unwrap().depends_on == Some("DXCC") {
            dxcc.as_str()
        } else {
            ""
        };
        for code in lotw::loc_values(p, dep) {
            let mut checks = vec![(
                p,
                code,
                vec![("CALL", "QG0TEST"), ("DXCC", dxcc.as_str()), (p, code)],
                vec![("MY_STATE", code)],
            )];
            if let Some(s) = lotw::loc_fields_for(e.id).find(|f| secondary.contains(f)) {
                for value in lotw::loc_values(s, code) {
                    checks.push((
                        s,
                        value,
                        vec![
                            ("CALL", "QG0TEST"),
                            ("DXCC", dxcc.as_str()),
                            (p, code),
                            (s, value),
                        ],
                        vec![("MY_STATE", code), ("MY_CNTY", value)],
                    ));
                }
            }
            for (field, value, station_fields, log_fields) in checks {
                let station = StationLocation::new(&station_fields).unwrap();
                let dependency = if field == p { dep } else { code };
                let label = tables::LOC_LABELS
                    .iter()
                    .find(|(f, d, v, _)| *f == field && *d == dependency && *v == value)
                    .map(|(_, _, _, l)| *l);
                for input in std::iter::once(value).chain(label) {
                    let mut fields = log_fields.clone();
                    fields.last_mut().unwrap().1 = input;
                    let cq = qso(&fields, false);
                    let eq = qso(&fields, true);
                    if cq.is_err() && eq.is_err() {
                        continue;
                    }
                    let compatible =
                        SigningOptions::default().station_refusals(&[cq.unwrap()], &station);
                    let exact = SigningOptions::default()
                        .with_exact_station(true)
                        .station_refusals(&[eq.unwrap()], &station);
                    total += 1;
                    if !compatible.is_empty() || !exact.is_empty() {
                        failures.push(format!("DXCC={} {field}={input:?} code={value:?} compat={compatible:?} exact={exact:?}",e.id));
                    }
                }
            }
        }
    }
    eprintln!(
        "checked {total} code/label cases across entities {entities:?}; mismatches={}",
        failures.len()
    );
    for f in failures.iter().take(20) {
        eprintln!("{f}");
    }
    assert_eq!(total, 8132);
    assert_eq!(entities.len(), 15);
    assert!(
        failures.is_empty(),
        "signing-compatible codes and labels must remain valid"
    );
}

#[test]
fn japanese_county_prefix_agrees_with_its_prefecture() {
    let fields = [
        ("MY_DXCC", "339"),
        ("MY_STATE", "01"),
        ("MY_CNTY", "01,0101"),
    ];
    let station = StationLocation::from_adif("QG0TEST", &fields, None).unwrap();
    let opts = SigningOptions::default().with_exact_station(true);
    let plain = opts.station_refusals(
        &[qso(&[("MY_STATE", "01"), ("MY_CNTY", "0101")], true).unwrap()],
        &station,
    );
    let prefixed = opts.station_refusals(&[qso(&fields, true).unwrap()], &station);
    eprintln!(
        "station prefecture={:?}, city={:?}; plain={plain:?}; prefixed={prefixed:?}",
        station.get("JA_PREFECTURE"),
        station.get("JA_CITY_GUN_KU")
    );
    assert!(plain.is_empty());
    assert!(
        prefixed.is_empty(),
        "a county prefix identical to its prefecture must agree"
    );
}
#[test]
fn exact_validation_preserves_signing_alias_before_comparing() {
    // A code and another entry's human label can collide. Signing preserves the selected label.
    let station =
        StationLocation::new(&[("CALL", "QG0TEST"), ("DXCC", "224"), ("FI_KUNTA", "339")]).unwrap();
    let input = [("MY_STATE", "Somero")];
    let compat =
        SigningOptions::default().station_refusals(&[qso(&input, false).unwrap()], &station);
    let exact = SigningOptions::default()
        .with_exact_station(true)
        .station_refusals(&[qso(&input, true).unwrap()], &station);
    eprintln!("FI_KUNTA=339, MY_STATE=Somero: signing-compatible={compat:?}; exact={exact:?}");
    assert!(compat.is_empty());
    assert!(
        exact.is_empty(),
        "the selected subdivision's own label must agree"
    );
}

#[test]
fn adx_detection_is_bounded_and_preserves_xml_validation() {
    let body = "<ADX><HEADER/><RECORDS/></ADX>";
    // Legal Misc can repeat and can contain misleading root/field text.
    let misc = "<!-- <ADX> <CALL:6>Z0TEST --><?logger synthetic?>\n";
    assert!(records::parse(format!("{}{body}", misc.repeat(1000)).as_bytes()).is_ok());
    for prefix in [
        "<!-- bad -- comment -->",
        "<!-- comment --->",
        "<!-- comment --><?xml version=\"1.0\"?>",
        "<?logger synthetic?>\u{feff}",
        "<!-- comment -->\u{000b}",
    ] {
        assert!(
            records::parse(format!("{prefix}{body}").as_bytes()).is_err(),
            "{prefix:?}"
        );
    }
    // The root and an ADIF field in the value cannot claim XML for an ADI log.
    let adi = b"<COMMENT:25><!-- exported log --><ADX<eor>";
    assert_eq!(
        records::parse(adi).unwrap()[0].text("COMMENT"),
        Some("<!-- exported log --><ADX")
    );
    // Detecting a prolog never examines more than the fixed lookahead, even if
    // the root is hidden beyond it in whitespace, a comment, or a PI.
    for prefix in [
        " ".repeat(65536),
        format!("<!--{}-->", "x".repeat(65536)),
        format!("<?logger {}?>", "x".repeat(65536)),
    ] {
        assert!(matches!(
            records::parse(format!("{prefix}{body}").as_bytes()),
            Err(records::RecordError::TooLong { .. })
        ));
    }
}

#[test]
fn exact_county_prefix_works_without_an_explicit_primary() {
    for (dxcc, primary, state, secondary, county) in [
        ("291", "US_STATE", "ID", "US_COUNTY", "Ada"),
        ("339", "JA_PREFECTURE", "01", "JA_CITY_GUN_KU", "0101"),
    ] {
        let station = StationLocation::new(&[
            ("CALL", "QG0TEST"),
            ("DXCC", dxcc),
            (primary, state),
            (secondary, county),
        ])
        .unwrap();
        let value = format!("{state},{county}");
        let options = SigningOptions::default().with_exact_station(true);
        assert!(
            options
                .station_refusals(&[qso(&[("MY_CNTY", &value)], true).unwrap()], &station)
                .is_empty()
        );
    }
}
