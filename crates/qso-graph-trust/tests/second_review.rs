// SPDX-License-Identifier: GPL-3.0-or-later
//! Permanent synthetic demonstrations from the second verification review.

#![forbid(unsafe_code)]

use qso_graph_trust::{
    certificate::Certificate,
    options::SigningOptions,
    qso::Qso,
    records,
    signed_log::{LogError, sign_log_with_options},
    signing::KeyEntry,
    station::{StationError, StationLocation},
    store::{KeyBackend, Store, StoreError},
    tqsl_locations,
};

#[test]
fn from_adif_refuses_contradictory_county_prefix() {
    let good = [
        ("MY_DXCC", "291"),
        ("MY_STATE", "ID"),
        ("MY_CNTY", "ID,Ada"),
    ];
    assert!(StationLocation::from_adif("QG0TEST", &good, None).is_ok());
    let bad = [
        ("MY_DXCC", "291"),
        ("MY_STATE", "ID"),
        ("MY_CNTY", "WA,Ada"),
    ];
    let error = StationLocation::from_adif("QG0TEST", &bad, None).unwrap_err();
    assert!(matches!(error, StationError::Invalid { .. }));
    assert_eq!(
        LogError::Location { index: 0, error }.adif_field(),
        Some("MY_CNTY")
    );
}

#[test]
fn from_adif_refuses_conflicting_repetitions_and_accepts_identical_values() {
    for (name, value, other) in [
        ("MY_DXCC", "291", "1"),
        ("MY_STATE", "ID", "WA"),
        ("MY_CNTY", "ID,Ada", "ID,Adams"),
        ("MY_GRIDSQUARE", "DN13", "DN14"),
        ("MY_VUCC_GRIDS", "DN13,DN14", "DN13,DN23"),
        ("MY_CQ_ZONE", "3", "4"),
        ("MY_ITU_ZONE", "6", "7"),
        ("MY_IOTA", "NA-110", "NA-111"),
    ] {
        let mut fields = vec![("MY_DXCC", "291"), ("MY_STATE", "ID")];
        fields.retain(|(n, _)| *n != name);
        fields.extend([(name, value), (name, value)]);
        assert!(
            StationLocation::from_adif("QG0TEST", &fields, None).is_ok(),
            "{name}"
        );
        fields.pop();
        let lower = name.to_ascii_lowercase();
        fields.push((&lower, other));
        let error = StationLocation::from_adif("QG0TEST", &fields, None).unwrap_err();
        assert!(
            matches!(error, StationError::Repeated(_)),
            "{name}: {error:?}"
        );
        assert_eq!(
            LogError::Location { index: 0, error }.adif_field(),
            Some(name)
        );
    }
}

const ADX: &str = "<?xml version=\"1.0\"?><ADX><HEADER/><RECORDS/></ADX>";

#[test]
fn adx_declaration_cannot_follow_whitespace() {
    assert!(records::parse(ADX.as_bytes()).is_ok());
    assert!(records::parse(format!("\u{feff}{ADX}").as_bytes()).is_ok());
    assert!(records::parse(format!(" \n{ADX}").as_bytes()).is_err());
    // XML whitespace is legal before a root when there is no declaration.
    assert!(records::parse(b" \n<ADX><HEADER/><RECORDS/></ADX>").is_ok());
}

#[test]
fn adx_bom_after_whitespace_is_refused() {
    assert!(records::parse(format!(" \u{feff}{ADX}").as_bytes()).is_err());
    assert!(records::parse(format!("\u{feff}\u{feff}{ADX}").as_bytes()).is_err());
}

#[test]
fn adx_forbidden_prolog_characters_are_refused() {
    for prefix in ["\u{000b}", "\u{000c}"] {
        assert!(records::parse(format!("{prefix}{ADX}").as_bytes()).is_err());
        assert!(records::parse(format!("\u{feff}{prefix}{ADX}").as_bytes()).is_err());
    }
}

#[test]
fn station_xml_prolog_controls() {
    for prefix in [" ", "\n"] {
        assert!(
            tqsl_locations::parse(
                format!("{prefix}<?xml version=\"1.0\"?><StationDataFile/>").as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn exact_invalid_values_precede_missing_location_fields() {
    let options = SigningOptions::default().with_exact_station(true);
    let empty = StationLocation::new(&[("CALL", "QG0TEST"), ("DXCC", "291")]).unwrap();
    let corpus =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/tqsl/1024/tqsl");
    let cert =
        Certificate::from_pem_or_der(&std::fs::read(corpus.join("certs/user")).unwrap()).unwrap();
    let key = KeyEntry::read_key_file(&std::fs::read(corpus.join("keys/QG0TEST")).unwrap())
        .unwrap()
        .remove(0)
        .unlock(None)
        .unwrap();
    let folder = std::env::temp_dir().join(format!("qgt-second-review-{}", std::process::id()));
    let store = Store::open(&folder, KeyBackend::Memory).unwrap().0;
    assert!(
        StationLocation::from_adif("QG0TEST", &[("MY_DXCC", "291"), ("MY_STATE", "ZZ")], None)
            .is_err()
    );
    for (extra, field) in [
        ("<MY_STATE:2>ZZ", "MY_STATE"),
        ("<MY_IOTA:3>bad", "MY_IOTA"),
        ("<MY_ITU_ZONE:2>91", "MY_ITU_ZONE"),
        ("<MY_CQ_ZONE:2>99", "MY_CQ_ZONE"),
        ("<MY_DXCC:1>0", "MY_DXCC"),
        ("<MY_CNTY:7>ID,Fake", "MY_CNTY"),
        ("<MY_GRIDSQUARE:4>DN13<MY_STATE:2>ZZ", "MY_STATE"),
        ("<MY_STATE:2>ID<MY_ITU_ZONE:1>8", "MY_ITU_ZONE"),
        ("<MY_STATE:2>ID<MY_CNTY:6>WA,Ada", "MY_CNTY"),
        ("<OPERATOR:3>Bob", "OPERATOR"),
    ] {
        let input = format!(
            "<CALL:6>Z0TEST<QSO_DATE:8>20261101<TIME_ON:6>120000<BAND:3>20m<MODE:2>CW{extra}<eor>"
        );
        let qso =
            Qso::from_adif_with_options(&records::parse(input.as_bytes()).unwrap()[0], &options)
                .unwrap();
        let qsos = [qso];
        let refused = options.station_refusals(&qsos, &empty);
        assert_eq!(refused.len(), 1, "{extra}");
        assert!(
            matches!(
                refused[0].1,
                LogError::Location {
                    error: StationError::Invalid { .. },
                    ..
                }
            ),
            "{extra}: {refused:?}"
        );
        assert_eq!(refused[0].1.adif_field(), Some(field), "{extra}");
        assert_eq!(
            sign_log_with_options(&cert, &key, &empty, &qsos, cert.validity().0, &options)
                .unwrap_err(),
            refused[0].1,
            "signing must agree: {extra}"
        );
        assert!(
            matches!(
                store.prepare_signing_with_options(&qsos, &empty, &options),
                Err(StoreError::Log(error)) if error == refused[0].1
            ),
            "preparation must agree: {extra}"
        );
    }
    for extra in ["<MY_STATE:2>ID", "<MY_CNTY:6>ID,Ada", "<MY_STATE:5>Idaho"] {
        let input = format!(
            "<CALL:6>Z0TEST<QSO_DATE:8>20261101<TIME_ON:6>120000<BAND:3>20m<MODE:2>CW{extra}<eor>"
        );
        let qso =
            Qso::from_adif_with_options(&records::parse(input.as_bytes()).unwrap()[0], &options)
                .unwrap();
        assert!(matches!(
            options.station_refusals(&[qso], &empty)[0].1,
            LogError::QsoFromAnotherStation { .. }
        ));
    }
    std::fs::remove_dir_all(folder).unwrap();
}

// A log naming only `MY_CNTY` gives its state through the county's prefix. In exact mode that state
// must equal the selected Location's: Adams County exists in both Idaho and Washington, so the
// county name alone would agree with the wrong state.
#[test]
fn exact_county_prefix_state_must_match_the_location() {
    let corpus =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/tqsl/1024/tqsl");
    let cert =
        Certificate::from_pem_or_der(&std::fs::read(corpus.join("certs/user")).unwrap()).unwrap();
    let key = KeyEntry::read_key_file(&std::fs::read(corpus.join("keys/QG0TEST")).unwrap())
        .unwrap()
        .remove(0)
        .unlock(None)
        .unwrap();
    let options = SigningOptions::default().with_exact_station(true);
    let station = StationLocation::new(&[
        ("CALL", "QG0TEST"),
        ("DXCC", "291"),
        ("US_STATE", "ID"),
        ("US_COUNTY", "Adams"),
    ])
    .unwrap();
    let qso = |extra: &str| {
        let input = format!(
            "<CALL:6>Z0TEST<QSO_DATE:8>20261101<TIME_ON:6>120000<BAND:3>20m<MODE:2>CW{extra}<eor>"
        );
        Qso::from_adif_with_options(&records::parse(input.as_bytes()).unwrap()[0], &options)
            .unwrap()
    };
    for agrees in ["<MY_CNTY:8>ID,Adams", "<MY_STATE:2>ID<MY_CNTY:8>ID,Adams"] {
        let qsos = [qso(agrees)];
        assert!(
            options.station_refusals(&qsos, &station).is_empty(),
            "{agrees}"
        );
        assert!(
            sign_log_with_options(&cert, &key, &station, &qsos, cert.validity().0, &options)
                .is_ok(),
            "{agrees}"
        );
    }
    for (other, field) in [
        ("<MY_CNTY:8>WA,Adams", "MY_CNTY"),
        ("<MY_STATE:2>WA<MY_CNTY:8>WA,Adams", "MY_STATE"),
    ] {
        let qsos = [qso(other)];
        let refused = options.station_refusals(&qsos, &station);
        assert_eq!(refused.len(), 1, "{other}");
        assert!(
            matches!(refused[0].1, LogError::QsoFromAnotherStation { .. }),
            "{other}: {refused:?}"
        );
        assert_eq!(refused[0].1.adif_field(), Some(field), "{other}");
        assert_eq!(
            sign_log_with_options(&cert, &key, &station, &qsos, cert.validity().0, &options)
                .unwrap_err(),
            refused[0].1,
            "signing must agree: {other}"
        );
    }
}
