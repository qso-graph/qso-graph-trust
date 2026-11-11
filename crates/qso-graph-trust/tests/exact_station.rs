// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

#![forbid(unsafe_code)]

use qso_graph_trust::{
    certificate::Trust,
    options::{QthHandling, SigningOptions},
    qso::Qso,
    records,
    signed_log::{LogError, sign_log_with_options},
    signing::KeyEntry,
    station::StationLocation,
    store::{DuplicateChoice, KeyBackend, Store},
    tbk,
};

fn qso(fields: &[(&str, &str)], options: &SigningOptions) -> Qso {
    let mut adif =
        "<CALL:6>Z0TEST<QSO_DATE:8>20261103<TIME_ON:6>120000<BAND:3>20m<MODE:2>CW".to_owned();
    for (name, value) in fields {
        adif.push_str(&format!("<{name}:{}>{value}", value.len()));
    }
    adif.push_str("<eor>");
    Qso::from_adif_with_options(&records::parse(adif.as_bytes()).unwrap()[0], options).unwrap()
}

fn station(fields: &[(&str, &str)]) -> StationLocation {
    let mut given = vec![("CALL", "QG0TEST"), ("DXCC", "291")];
    given.extend_from_slice(fields);
    StationLocation::new(&given).unwrap()
}

fn refusal(
    options: &SigningOptions,
    station: &StationLocation,
    fields: &[(&str, &str)],
    expected: &str,
) {
    let refused = options.station_refusals(&[qso(fields, options)], station);
    assert_eq!(refused.len(), 1, "{fields:?}");
    assert_eq!(refused[0].0, 0);
    assert_eq!(
        refused[0].1.adif_field(),
        Some(expected),
        "{:?}",
        refused[0].1
    );
}

#[test]
fn exact_mode_refuses_every_named_field_the_station_cannot_confirm() {
    let options = SigningOptions::default().with_exact_station(true);
    let empty = station(&[]);
    for (name, value) in [
        ("MY_GRIDSQUARE", "DN13"),
        ("MY_VUCC_GRIDS", "DN13,DN14"),
        ("MY_STATE", "ID"),
        ("MY_CNTY", "ID,Ada"),
        ("MY_ITU_ZONE", "6"),
        ("MY_CQ_ZONE", "3"),
        ("MY_IOTA", "NA-110"),
        ("STATION_CALLSIGN", "QG1TEST"),
        ("OPERATOR", "QG1TEST"),
        ("MY_DXCC", "1"),
        ("MY_DXCC", "0"),
    ] {
        refusal(&options, &empty, &[(name, value)], name);
    }
    // The earlier TQSL-compatible behavior fills an empty station field.
    assert!(
        SigningOptions::default()
            .station_refusals(&[qso(&[("MY_STATE", "ID")], &options)], &empty)
            .is_empty()
    );
}

#[test]
fn exact_mode_converts_aliases_labels_and_number_forms_as_signing_does() {
    let options = SigningOptions::default().with_exact_station(true);
    let ours = station(&[
        ("US_STATE", "KS"),
        ("US_COUNTY", "Sedgwick"),
        ("ITUZ", "7"),
        ("CQZ", "4"),
        ("IOTA", "NA-110"),
    ]);
    let fields = [
        ("STATION_CALLSIGN", "qg0test"),
        ("OPERATOR", "qg0test"),
        ("MY_DXCC", "0291"),
        ("MY_STATE", "Kansas"),
        ("MY_CNTY", "KS, Sedgwick"),
        ("MY_ITU_ZONE", "007"),
        ("MY_CQ_ZONE", "+4"),
        ("MY_IOTA", "na-110"),
    ];
    assert!(
        options
            .station_refusals(&[qso(&fields, &options)], &ours)
            .is_empty()
    );
    for (dxcc, field, code, alias) in [
        (1, "CA_PROVINCE", "PQ", "QC"),
        (1, "CA_PROVINCE", "NF", "NL"),
        (54, "RU_OBLAST", "JA", "YR"),
        (15, "RU_OBLAST", "JN", "YN"),
    ] {
        let loc = StationLocation::new(&[
            ("CALL", "QG0TEST"),
            ("DXCC", &dxcc.to_string()),
            (field, code),
        ])
        .unwrap();
        assert!(
            options
                .station_refusals(&[qso(&[("MY_STATE", alias)], &options)], &loc)
                .is_empty(),
            "{alias}"
        );
    }
    refusal(&options, &ours, &[("MY_CNTY", "ID,Sedgwick")], "MY_CNTY");
}

#[test]
fn exact_grids_compare_precision_and_sets_on_every_qso() {
    let options = SigningOptions::default().with_exact_station(true);
    let fine = station(&[("GRIDSQUARE", "DN13ab")]);
    for grid in ["dn13", "DN13AB"] {
        assert!(
            options
                .station_refusals(&[qso(&[("MY_GRIDSQUARE", grid)], &options)], &fine)
                .is_empty()
        );
    }
    refusal(
        &options,
        &fine,
        &[("MY_GRIDSQUARE", "DN13CD")],
        "MY_GRIDSQUARE",
    );
    refusal(
        &options,
        &station(&[("GRIDSQUARE", "DN13")]),
        &[("MY_GRIDSQUARE", "DN13AB")],
        "MY_GRIDSQUARE",
    );
    refusal(
        &options,
        &fine,
        &[("MY_GRIDSQUARE", "DN13AB12")],
        "MY_GRIDSQUARE",
    );
    let list = station(&[("GRIDSQUARE", "DN13, DN14")]);
    let same = qso(&[("MY_VUCC_GRIDS", "dn14, dn13")], &options);
    assert!(
        options
            .station_refusals(&[same.clone(), same.clone()], &list)
            .is_empty()
    );
    // Equal-length lists are insufficient; both the first and later QSO must be compared.
    let different = qso(&[("MY_VUCC_GRIDS", "EM17,EM18")], &options);
    let refused = options.station_refusals(&[different.clone(), same, different], &list);
    assert_eq!(
        refused
            .iter()
            .map(|(i, e)| (*i, e.adif_field()))
            .collect::<Vec<_>>(),
        [(0, Some("MY_VUCC_GRIDS")), (2, Some("MY_VUCC_GRIDS"))]
    );
    refusal(
        &options,
        &list,
        &[("MY_GRIDSQUARE", "DN13")],
        "MY_GRIDSQUARE",
    );
    refusal(
        &options,
        &fine,
        &[("MY_VUCC_GRIDS", "DN13,DN14")],
        "MY_VUCC_GRIDS",
    );
    // Both named fields must agree; VUCC cannot hide a contradictory single grid.
    refusal(
        &options,
        &list,
        &[("MY_VUCC_GRIDS", "DN13,DN14"), ("MY_GRIDSQUARE", "DN13")],
        "MY_GRIDSQUARE",
    );
}

#[test]
fn exact_mode_overrides_ignore_and_checks_both_callsigns() {
    for qth in [
        QthHandling::Ignore,
        QthHandling::Refuse,
        QthHandling::FromLog,
    ] {
        let options = SigningOptions {
            qth,
            ignore_log_callsigns: true,
            ..Default::default()
        }
        .with_exact_station(true);
        refusal(
            &options,
            &station(&[]),
            &[("STATION_CALLSIGN", "QG1TEST")],
            "STATION_CALLSIGN",
        );
        refusal(
            &options,
            &station(&[]),
            &[("STATION_CALLSIGN", "QG0TEST"), ("OPERATOR", "QG1TEST")],
            "OPERATOR",
        );
        refusal(&options, &station(&[]), &[("OPERATOR", "Bob")], "OPERATOR");
        refusal(&options, &station(&[]), &[("MY_STATE", "ID")], "MY_STATE");
    }
    assert!(!SigningOptions::default().exact_station);
    assert!(
        !SigningOptions::default()
            .with_exact_station(true)
            .with_exact_station(false)
            .exact_station
    );
    assert!(!SigningOptions::from(&tbk::Preferences::default()).exact_station);
}

#[test]
fn every_station_refusal_names_its_adif_field_including_invalid_values() {
    for exact in [false, true] {
        for qth in [QthHandling::Refuse, QthHandling::FromLog] {
            let options = SigningOptions {
                qth,
                ..Default::default()
            }
            .with_exact_station(exact);
            for (name, value) in [
                ("MY_STATE", "ZZ"),
                ("MY_CNTY", "ZZ"),
                ("MY_IOTA", "ZZ"),
                ("MY_ITU_ZONE", "99"),
                ("MY_CQ_ZONE", "99"),
            ] {
                refusal(&options, &station(&[]), &[(name, value)], name);
            }
            for (name, value) in [("MY_ITU_ZONE", "8"), ("MY_CQ_ZONE", "5")] {
                refusal(
                    &options,
                    &station(&[("US_STATE", "KS")]),
                    &[(name, value)],
                    name,
                );
            }
        }
    }
}

fn corpus(path: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus")
            .join(path),
    )
    .unwrap()
}

#[test]
fn a_whole_exact_log_signs_with_the_input_station_and_matches_reference_bytes() {
    let trust = Trust::with_roots(&[&corpus("standard/pki/root.pem")]).unwrap();
    let backup = tbk::read(&corpus("standard/standard.tbk"), &trust).unwrap();
    let cert = backup
        .certificates
        .iter()
        .find(|c| c.callsign == "KC4QPQ")
        .unwrap()
        .certificate
        .as_ref()
        .unwrap();
    let key = KeyEntry::read_key_file(&corpus("standard/tqsl/keys/KC4QPQ"))
        .unwrap()
        .remove(0)
        .unlock(Some(&corpus("standard/keys/KC4QPQ.password")))
        .unwrap();
    let station = &backup
        .locations
        .iter()
        .find(|l| l.name == "KC4QPQ-HOME")
        .unwrap()
        .station;
    let original = station.clone();
    let options = SigningOptions::default().with_exact_station(true);
    let log = [
        qso(&[], &options),
        qso(
            &[
                ("MY_STATE", "South Carolina"),
                ("MY_CQ_ZONE", "05"),
                ("MY_GRIDSQUARE", "FM02"),
            ],
            &options,
        ),
        qso(&[("MY_CNTY", "SC,Charleston")], &options),
    ];
    let at = cert.validity().0 + std::time::Duration::from_secs(3600);
    let actual = sign_log_with_options(cert, &key, station, &log, at, &options).unwrap();
    let compatible =
        sign_log_with_options(cert, &key, station, &log, at, &SigningOptions::default()).unwrap();
    assert_eq!(actual, compatible);
    let decoded = records::parse(&actual).unwrap();
    let mut contacts = 0;
    let mut signed_stations = 0;
    for record in &decoded {
        if record.text("Rec_Type") == Some("tSTATION") {
            signed_stations += 1;
            let fields = qso_graph_trust::station::fields_for(station.dxcc())
                .into_iter()
                .filter_map(|n| record.text(n).map(|v| (n, v)))
                .collect::<Vec<_>>();
            assert_eq!(StationLocation::new(&fields).unwrap(), original);
        }
        if record.text("Rec_Type") == Some("tCONTACT") {
            contacts += 1;
        }
    }
    assert_eq!(contacts, log.len());
    assert_eq!(signed_stations, 1);
    assert_eq!(station, &original);
    let folder = std::env::temp_dir().join(format!("qgt-exact-{}", std::process::id()));
    let store = Store::open(&folder, KeyBackend::Memory).unwrap().0;
    let plan = store
        .prepare_signing_with_options(&log, station, &options)
        .unwrap();
    let signed = plan
        .choose(DuplicateChoice::SignAgain)
        .unwrap()
        .sign(cert, &key, at)
        .unwrap();
    assert_eq!(
        qso_graph_trust::gzip::decompress(signed.tq8(), 1024 * 1024)
            .unwrap()
            .as_slice(),
        actual
    );
    std::fs::remove_dir_all(folder).unwrap();
    // Exact checking is independent per QSO, including across a refused prefix.
    let rejected = qso(&[("MY_IOTA", "NA-110")], &options);
    let mut prefixed = vec![rejected];
    prefixed.extend_from_slice(&log);
    assert!(matches!(
        options.station_refusals(&prefixed, station).as_slice(),
        [(
            0,
            LogError::QsoFromAnotherStation {
                field: "MY_IOTA",
                ..
            }
        )]
    ));
    assert!(options.station_refusals(&log, station).is_empty());
}

#[test]
fn exact_mode_leaves_out_subdivisions_the_entity_has_no_field_for() {
    let options = SigningOptions::default().with_exact_station(true);
    // Germany (DXCC 230): LoTW has no primary or secondary subdivision field.
    let germany = StationLocation::new(&[("CALL", "QG0TEST"), ("DXCC", "230")]).unwrap();
    let qsos = [qso(
        &[("MY_STATE", "BY"), ("MY_CNTY", "BY,Munich")],
        &options,
    )];
    assert!(options.station_refusals(&qsos, &germany).is_empty());
    // The United States has both, so an empty one is still refused.
    refusal(&options, &station(&[]), &[("MY_STATE", "ID")], "MY_STATE");
}
