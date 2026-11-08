// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Full signed records, signatures and duplicate metadata against tqsllib 2.8.7. Reproduce with
//! tests/tqsllib/make-options.py and the harness driver; all keys are the existing test corpus's.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use qso_graph_trust::certificate::Trust;
use qso_graph_trust::options::{QthHandling, SigningOptions};
use qso_graph_trust::qso::{Qso, QsoError};
use qso_graph_trust::records;
use qso_graph_trust::signed_log::{sign_log, sign_log_with_options};
use qso_graph_trust::signing::KeyEntry;
use qso_graph_trust::store::{DuplicateChoice, KeyBackend, Store, duplicate_key};
use qso_graph_trust::tbk;

fn corpus(path: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus")
            .join(path),
    )
    .expect("test corpus")
}

fn fixture(case: &str, suffix: &str) -> Vec<u8> {
    let file = corpus(&format!("signing-options/{case}.{suffix}"));
    assert!(file.starts_with(b"SPDX-License-Identifier: GPL-3.0-or-later\n"));
    let start = file
        .windows(2)
        .position(|w| w == b"\n\n")
        .expect("license preamble")
        + 2;
    file[start..].to_vec()
}

fn options(case: &str) -> SigningOptions {
    let mut options = SigningOptions::default();
    match case {
        "custom" => options.adif_modes.push(("legacy".into(), "ft8".into())),
        "custom-pair" => options
            .adif_modes
            .push(("MFSK%SPECIAL".into(), "CW".into())),
        "custom-remap" => options.adif_modes.push(("MFSK%FT8".into(), "CW".into())),
        "custom-submode" => options.adif_modes.push(("SPECIAL".into(), "RTTY".into())),
        "seconds" | "seconds-dupe" => options.ignore_seconds = true,
        "callsign" | "operator" => options.ignore_log_callsigns = true,
        "bad-call" | "bad-prefix" | "bad-punctuation" | "bad-unicode" | "bad-long" => {
            options.allow_bad_calls = true
        }
        "ignore" => options.qth = QthHandling::Ignore,
        c if c.starts_with("update") => options.qth = QthHandling::FromLog,
        _ => {}
    }
    options
}

fn qsos(case: &str, options: &SigningOptions) -> Vec<Qso> {
    records::parse(&fixture(case, "adi"))
        .expect("ADIF")
        .iter()
        .map(|r| Qso::from_adif_with_options(r, options).expect("QSO"))
        .collect()
}

fn without_ident(log: &[u8]) -> &[u8] {
    &log[log.iter().position(|&b| b == b'\n').expect("ident line") + 1..]
}

struct Folder(PathBuf);
impl Folder {
    fn new(case: &str) -> Self {
        let path = std::env::temp_dir().join(format!("qgt-options-{}-{case}", std::process::id()));
        std::fs::create_dir(&path).expect("test directory");
        Self(path)
    }
}
impl Drop for Folder {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove test directory");
    }
}

#[test]
fn settings_sign_and_record_exactly_as_tqsllib() {
    let trust = Trust::with_roots(&[&corpus("standard/pki/root.pem")]).expect("test root");
    let backup = tbk::read(&corpus("standard/standard.tbk"), &trust).expect("test backup");
    let cert = backup
        .certificates
        .iter()
        .find(|c| c.callsign == "KC4QPQ")
        .and_then(|c| c.certificate.as_ref())
        .expect("certificate");
    let station = &backup
        .locations
        .iter()
        .find(|l| l.name == "KC4QPQ-HOME")
        .expect("home")
        .station;
    let key = KeyEntry::read_key_file(&corpus("standard/tqsl/keys/KC4QPQ"))
        .expect("key")
        .remove(0)
        .unlock(Some(&corpus("standard/keys/KC4QPQ.password")))
        .expect("unlock test key");
    let at = cert.validity().0 + Duration::from_secs(3600);
    for case in [
        "default",
        "custom",
        "custom-pair",
        "custom-submode",
        "custom-remap",
        "seconds",
        "seconds-dupe",
        "callsign",
        "operator",
        "bad-call",
        "bad-prefix",
        "bad-punctuation",
        "bad-unicode",
        "ignore",
        "report-fill",
        "report-label",
        "report-zone",
        "update",
        "update-state",
        "update-neighbor",
        "update-label",
        "update-vucc",
    ] {
        let options = options(case);
        let defaults = SigningOptions::default();
        let qsos = qsos(
            case,
            if case == "seconds" {
                &defaults
            } else {
                &options
            },
        );
        let expected = fixture(case, "tq7");
        if case != "seconds-dupe" {
            let actual =
                sign_log_with_options(cert, &key, station, &qsos, at, &options).expect(case);
            assert_eq!(
                String::from_utf8_lossy(without_ident(&actual)),
                String::from_utf8_lossy(without_ident(&expected)),
                "{case}"
            );
            if case == "default" {
                assert_eq!(
                    actual,
                    sign_log(cert, &key, station, &qsos, at).expect("legacy defaults")
                );
            }
        }
        let folder = Folder::new(case);
        let store = Store::open(folder.0.join("store"), KeyBackend::Memory)
            .expect("store")
            .0;
        let plan = store
            .prepare_signing_with_options(&qsos, station, &options)
            .expect(case);
        if case == "seconds-dupe" {
            assert_eq!(plan.new_indices(), &[0]);
            assert_eq!(plan.signed_before()[0].index, 1);
            assert_eq!(
                duplicate_key(&qsos[0], station),
                duplicate_key(&qsos[1], station)
            );
            assert!(duplicate_key(&qsos[0], station).ends_with("18:30:00Z"));
        }
        let selection = plan.choose(DuplicateChoice::NewOnly).expect("select");
        let signed = selection.sign(cert, &key, at).expect(case);
        let gz = signed.tq8();
        let actual = miniz_oxide::inflate::decompress_to_vec(&gz[10..gz.len() - 8]).expect("gzip");
        assert_eq!(
            without_ident(&actual),
            without_ident(&expected),
            "selection {case}"
        );
        signed
            .write_to(&store, &folder.0.join("log.tq8"))
            .expect("write and record");
        let actual = store
            .signed_qsos()
            .expect("records")
            .into_iter()
            .map(|r| format!("{}\t{}\n", r.key, r.station))
            .collect::<String>();
        assert_eq!(actual.as_bytes(), fixture(case, "keys"), "record {case}");
        if case == "update-state" {
            // The first QSO supplied KS, the second inherited it. Even if the first is already
            // signed, selecting only the second must keep KS and its exact signature.
            let first = store.signed_qsos().expect("records").remove(0);
            store.wipe_signed_qsos().expect("wipe");
            store
                .add_signed_qsos(&[first])
                .expect("plant first duplicate");
            let plan = store
                .prepare_signing_with_options(&qsos, station, &options)
                .expect("plan");
            assert_eq!(plan.new_indices(), &[1]);
            let selection = plan
                .choose(DuplicateChoice::NewOnly)
                .expect("select second");
            let signed = selection
                .sign(cert, &key, at)
                .expect("sign inherited location");
            let gz = signed.tq8();
            let actual =
                miniz_oxide::inflate::decompress_to_vec(&gz[10..gz.len() - 8]).expect("gzip");
            let actual = records::parse(&actual).expect("signed records");
            let expected = records::parse(&expected).expect("reference");
            let contact = |r: &records::Record| r.text("Rec_Type") == Some("tCONTACT");
            let actual = actual.iter().find(|r| contact(r)).expect("contact");
            let expected = expected
                .iter()
                .filter(|r| contact(r))
                .nth(1)
                .expect("second contact");
            assert_eq!(actual.get("SIGNDATA"), expected.get("SIGNDATA"));
            assert_eq!(actual.get("SIGN_LOTW_V2.0"), expected.get("SIGN_LOTW_V2.0"));
            signed
                .write_to(&store, &folder.0.join("second.tq8"))
                .expect("record inherited location");
            let actual = store
                .signed_qsos()
                .expect("records")
                .into_iter()
                .map(|r| format!("{}\t{}\n", r.key, r.station))
                .collect::<String>();
            assert_eq!(actual.as_bytes(), fixture(case, "keys"));
        }
    }
    for case in [
        "callsign-refused",
        "operator-refused",
        "report",
        "update-county-state",
        "update-dxcc",
    ] {
        let options = options(case);
        let qsos = qsos(case, &options);
        assert!(
            sign_log_with_options(cert, &key, station, &qsos, at, &options).is_err(),
            "{case}"
        );
    }
    for case in ["bad-call-refused", "bad-long"] {
        assert!(
            records::parse(&fixture(case, "adi"))
                .expect("ADIF")
                .iter()
                .any(|r| Qso::from_adif_with_options(r, &options(case)).is_err())
        );
    }
}

#[test]
fn calls_refuse_controls_and_xml_forbidden_characters_with_any_options() {
    let forbidden = (0..=0x1f)
        .chain(0x7f..=0x9f)
        .chain([0xfffe, 0xffff])
        .map(|c| char::from_u32(c).expect("Unicode scalar"));
    for c in forbidden {
        for call in [
            format!("TEST{c}X"),
            format!("{c}KC4QPQ"),
            format!("KC4QPQ{c}"),
        ] {
            let adif = format!(
                "<CALL:{}>{call}<QSO_DATE:8>20261103<TIME_ON:6>183055<BAND:3>20m<MODE:2>CW<EOR>",
                call.len()
            );
            let record = records::parse(adif.as_bytes()).expect("ADIF").remove(0);
            for allow_bad_calls in [false, true] {
                let options = SigningOptions {
                    allow_bad_calls,
                    ..SigningOptions::default()
                };
                assert_eq!(
                    Qso::from_adif_with_options(&record, &options),
                    Err(QsoError::Invalid {
                        field: "CALL",
                        value: call.clone(),
                    }),
                    "CALL {call:?}, allow_bad_calls={allow_bad_calls}"
                );
            }
        }
    }
    // Removing the planted character leaves a permitted non-amateur call.
    let adif = b"<CALL:5>TESTX<QSO_DATE:8>20261103<TIME_ON:6>183055<BAND:3>20m<MODE:2>CW<EOR>";
    let record = records::parse(adif).expect("ADIF").remove(0);
    let options = SigningOptions {
        allow_bad_calls: true,
        ..SigningOptions::default()
    };
    assert_eq!(
        Qso::from_adif_with_options(&record, &options)
            .expect("printable non-amateur call")
            .call(),
        "TESTX"
    );
}

#[test]
fn preferences_are_explicit_and_do_not_change_other_conversions() {
    let preferences = tbk::Preferences {
        adif_modes: vec![("legacy".into(), "FT8".into())],
        ignore_seconds: true,
        allow_bad_calls: true,
        ignore_log_callsigns: true,
        qth: QthHandling::FromLog,
        ..tbk::Preferences::default()
    };
    let options = SigningOptions::from(&preferences);
    assert_eq!(options.qth, QthHandling::FromLog);
    assert!(options.ignore_log_callsigns && options.allow_bad_calls);
    assert_eq!(qsos("custom", &options)[0].mode(), "FT8");
    assert_eq!(qsos("custom", &options)[0].time().to_string(), "18:30:00Z");
    assert!(Qso::from_adif(&records::parse(&fixture("custom", "adi")).expect("ADIF")[0]).is_err());
    let native = SigningOptions {
        adif_modes: vec![("CW".into(), "FT8".into())],
        ..SigningOptions::default()
    };
    assert_eq!(qsos("default", &native)[0].mode(), "CW");
}

#[test]
fn equivalent_adi_and_adx_sign_to_the_same_tq8() {
    let trust = Trust::with_roots(&[&corpus("standard/pki/root.pem")]).expect("test root");
    let backup = tbk::read(&corpus("standard/standard.tbk"), &trust).expect("test backup");
    let cert = backup
        .certificates
        .iter()
        .find(|c| c.callsign == "KC4QPQ")
        .and_then(|c| c.certificate.as_ref())
        .expect("certificate");
    let station = &backup
        .locations
        .iter()
        .find(|l| l.name == "KC4QPQ-HOME")
        .expect("home")
        .station;
    let key = KeyEntry::read_key_file(&corpus("standard/tqsl/keys/KC4QPQ"))
        .expect("key")
        .remove(0)
        .unlock(Some(&corpus("standard/keys/KC4QPQ.password")))
        .expect("unlock test key");
    let at = cert.validity().0 + Duration::from_secs(3600);
    let logs: [&[u8]; 2] = [b"<CALL:5>KN4YU<QSO_DATE:8>20261103<TIME_ON:6>183055<BAND:3>20m<MODE:2>CW<EOR>", b"<ADX><HEADER/><RECORDS><RECORD><CALL>KN4YU</CALL><QSO_DATE>20261103</QSO_DATE><TIME_ON>183055</TIME_ON><BAND>20m</BAND><MODE>CW</MODE></RECORD></RECORDS></ADX>"];
    let mut results = Vec::new();
    for (i, log) in logs.iter().enumerate() {
        let qsos: Vec<Qso> = records::parse(log)
            .expect("records")
            .iter()
            .map(|r| Qso::from_adif(r).expect("qso"))
            .collect();
        let folder = Folder::new(if i == 0 { "adx-adi" } else { "adx-xml" });
        let store = Store::open(folder.0.join("store"), KeyBackend::Memory)
            .expect("store")
            .0;
        let plan = store
            .prepare_signing_with_options(&qsos, station, &SigningOptions::default())
            .expect("plan");
        let signed = plan
            .choose(DuplicateChoice::NewOnly)
            .expect("select")
            .sign(cert, &key, at)
            .expect("sign");
        results.push(signed.tq8().to_vec());
    }
    assert_eq!(results[0], results[1]);
}
