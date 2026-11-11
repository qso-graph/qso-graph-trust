// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
#[global_allocator]
static ALLOCATOR: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
    zeroizing_alloc::ZeroAlloc(std::alloc::System);
mod tests {
    struct TestFolder(std::path::PathBuf);
    impl TestFolder {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "qgt-review-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestFolder {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    use qso_graph_trust::{
        gzip,
        options::{QthHandling, SigningOptions},
        qso::Qso,
        records,
        station::StationLocation,
        tqsl_locations, upload,
    };
    fn corpus(p: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus")
                .join(p),
        )
        .unwrap()
    }
    fn qso(extra: &str) -> Qso {
        Qso::from_adif(&records::parse(format!("<CALL:6>Z0TEST<QSO_DATE:8>20261101<TIME_ON:6>120000<BAND:3>20m<MODE:2>CW{extra}<eor>").as_bytes()).unwrap()[0]).unwrap()
    }
    #[test]
    fn review_rejected_qso_changes_no_state() {
        let station = StationLocation::new(&[
            ("CALL", "QG0TEST"),
            ("DXCC", "291"),
            ("US_STATE", "ID"),
            ("GRIDSQUARE", "DN13,DN14"),
        ])
        .unwrap();
        let opts = SigningOptions {
            qth: QthHandling::Refuse,
            ..Default::default()
        };
        let rejected = qso("<MY_STATE:2>WA");
        let retained = qso("<MY_VUCC_GRIDS:19>EM17,EM18,EM27,EM28");
        let alone = opts.station_refusals(std::slice::from_ref(&retained), &station);
        let together = opts.station_refusals(&[rejected, retained], &station);
        eprintln!(
            "refusals with rejected prefix: {:?}; without prefix: {:?}",
            together, alone
        );
        assert_eq!(
            together.len(),
            alone.len() + 1,
            "a rejected QSO must have no effect on later refusals"
        );
    }
    #[test]
    fn review_signed_log_rejects_empty_signature() {
        let tq7 = String::from_utf8(corpus("tqsl/1024/qg0test-small.tq7")).unwrap();
        assert!(
            upload::check_signed_log(&gzip::compress(tq7.as_bytes())).is_ok(),
            "valid control"
        );
        let mut modified = tq7.clone();
        while let Some(start) = modified.find("<SIGN_LOTW_V2.0:175:6>") {
            let value = start + "<SIGN_LOTW_V2.0:175:6>".len();
            modified.replace_range(start..value + 175, "<SIGN_LOTW_V2.0:0:6>");
        }
        assert_ne!(modified, tq7);
        let result = upload::check_signed_log(&gzip::compress(modified.as_bytes()));
        eprintln!(
            "all six signatures removed; check_signed_log accepted={}",
            result.is_ok()
        );
        assert!(result.is_err(), "a signed log requires RSA-1024 signatures");
    }
    #[test]
    fn review_adx_rejects_malformed_xml() {
        let valid = "<ADX><HEADER/><RECORDS><RECORD><CALL>Z0TEST</CALL><QSO_DATE>20261101</QSO_DATE><TIME_ON>120000</TIME_ON><BAND>20m</BAND><MODE>CW</MODE></RECORD></RECORDS></ADX>";
        assert!(records::parse(valid.as_bytes()).is_ok());
        let mut accepted = vec![];
        for (name, xml) in [
            ("invalid declaration", format!("<?xml nonsense?>{valid}")),
            (
                "double hyphen in comment",
                valid.replace("<HEADER/>", "<HEADER/><!-- forbidden -- comment -->"),
            ),
            (
                "forbidden text delimiter",
                valid.replace("</CALL>", "]]></CALL>"),
            ),
        ] {
            if records::parse(xml.as_bytes()).is_ok() {
                accepted.push(name);
            }
        }
        eprintln!("malformed XML accepted: {accepted:?}");
        assert!(accepted.is_empty(), "malformed XML must be rejected");
    }
    #[test]
    fn review_gzip_data_checksum_control() {
        let mut data = gzip::compress(b"<StationDataFile/>");
        assert!(tqsl_locations::parse(&data).is_ok());
        let end = data.len();
        data[end - 8] ^= 1;
        assert!(tqsl_locations::parse(&data).is_err());
        // RFC 1952 2.3.1.2 permits skipping FHCRC. Do not treat that as a defect.
    }
    #[test]
    fn review_non_adx_readers_reject_malformed_xml() {
        use qso_graph_trust::{
            certificate::Trust,
            store::{KeyBackend, Store},
            tbk,
        };
        let mut accepted = vec![];
        let station = b"<?xml nonsense?><StationDataFile><!-- bad -- comment --></StationDataFile>";
        if tqsl_locations::parse(station).is_ok() {
            accepted.push("station_data");
        }
        let break_xml = |bytes: Vec<u8>| {
            let bytes = if gzip::is_gzip(&bytes) {
                gzip::decompress(&bytes, 32 * 1024 * 1024).unwrap().to_vec()
            } else {
                bytes
            };
            let s = String::from_utf8(bytes).unwrap();
            let s = if s.starts_with("<?xml") {
                &s[s.find("?>").unwrap() + 2..]
            } else {
                &s
            };
            format!("<?xml nonsense?>{s}").into_bytes()
        };
        let dir = TestFolder::new();
        let (store, _) = Store::open(dir.path(), KeyBackend::Memory).unwrap();
        let trust = Trust::with_roots(&[&corpus("tqsl/pki/root.pem")]).unwrap();
        let tq6 = corpus("tqsl/1024/QG0TEST.tq6");
        assert!(store.inspect_tq6(&tq6, &trust).is_ok(), "tq6 control");
        if store.inspect_tq6(&break_xml(tq6), &trust).is_ok() {
            accepted.push("tq6");
        }
        let trust = Trust::with_roots(&[&corpus("standard/pki/root.pem")]).unwrap();
        let backup = corpus("standard/standard.tbk");
        assert!(tbk::read(&backup, &trust).is_ok(), "tbk control");
        if tbk::read(&break_xml(backup), &trust).is_ok() {
            accepted.push("tbk");
        }
        eprintln!("malformed XML accepted by {accepted:?}");
        assert!(
            accepted.is_empty(),
            "all XML readers must reject malformed XML"
        );
    }
    #[test]
    fn review_malformed_formats_and_limits_controls() {
        use qso_graph_trust::{
            certificate::{Certificate, Trust},
            store::{KeyBackend, Store},
            tbk,
        };
        let dir = TestFolder::new();
        let (store, _) = Store::open(dir.path(), KeyBackend::Memory).unwrap();
        let trust = Trust::with_roots(&[&corpus("tqsl/pki/root.pem")]).unwrap();
        assert!(Certificate::from_pem_or_der(b"bad DER").is_err());
        assert!(Certificate::from_pem_or_der(&vec![0; 16385]).is_err());
        assert!(store.inspect_tq6(b"<bad>", &trust).is_err());
        assert!(
            store
                .inspect_pkcs12(b"bad p12", &corpus("pki/p12-password"), &trust)
                .is_err()
        );
        assert!(tbk::read(b"<bad>", &trust).is_err());
        assert!(tqsl_locations::parse(b"<bad>").is_err());
        assert!(records::parse(b"<CALL:99999999999999>x<eor>").is_err());
        assert!(records::parse(b"<ADX><HEADER/></ADX>").is_err());
        assert!(records::parse(b"START-OF-LOG: 3.0\nQSO: junk\nEND-OF-LOG:\n").is_err());
        assert_eq!(
            upload::parse_response(200, b"bad reply"),
            upload::UploadOutcome::Unknown
        );
        assert_eq!(
            upload::parse_response(200, &vec![b'x'; upload::MAX_RESPONSE_BYTES + 1]),
            upload::UploadOutcome::Unknown
        );
    }
}

#[test]
fn malformed_declarations_and_comments_are_refused_by_each_shared_xml_reader() {
    use qso_graph_trust::{
        certificate::Trust,
        gzip,
        store::{KeyBackend, Listing, Store},
        tbk, tqsl_locations,
    };
    let corpus = |p: &str| {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus")
                .join(p),
        )
        .unwrap()
    };
    let folder = std::env::temp_dir().join(format!("qgt-review-xml-{}", std::process::id()));
    let store = Store::open(&folder, KeyBackend::Memory).unwrap().0;
    let tq6_trust = Trust::with_roots(&[&corpus("tqsl/pki/root.pem")]).unwrap();
    let tbk_trust = Trust::with_roots(&[&corpus("standard/pki/root.pem")]).unwrap();
    for (kind, bytes) in [
        ("station", b"<StationDataFile/>".to_vec()),
        ("tq6", corpus("tqsl/1024/QG0TEST.tq6")),
        ("tbk", corpus("standard/standard.tbk")),
        ("store", b"<qgt-store version='1'><certificates/><locations/><signed-qsos version='1'/></qgt-store>".to_vec()),
    ] {
        let bytes = if gzip::is_gzip(&bytes) { gzip::decompress(&bytes, 32 * 1024 * 1024).unwrap().to_vec() } else { bytes };
        let text = String::from_utf8(bytes).unwrap();
        let text = text.trim_start_matches('\u{feff}');
        let body = if text.starts_with("<?xml") { &text[text.find("?>").unwrap() + 2..] } else { text };
        let accepts = |data: &[u8]| match kind {
            "station" => tqsl_locations::parse(data).is_ok(),
            "tq6" => store.inspect_tq6(data, &tq6_trust).is_ok(),
            "tbk" => tbk::read(data, &tbk_trust).is_ok(),
            "store" => {
                std::fs::write(folder.join("store.xml"), data).unwrap();
                Listing::read(&folder).is_ok()
            }
            _ => unreachable!(),
        };
        assert!(accepts(format!("<?xml version='1.0' encoding='utf-8' standalone='yes'?><!-- valid-comment -->{body}").as_bytes()), "{kind} control");
        for prefix in ["<?xml nonsense?>", "<?xml version='1.0' version='1.0'?>", "<?xml version='1.&#48;'?>", "<!-- forbidden -- comment -->", "<!-- bad --->"] {
            assert!(!accepts(format!("{prefix}{body}").as_bytes()), "{kind}: {prefix}");
        }
        std::fs::remove_file(folder.join("store.xml")).ok();
    }
    std::fs::remove_dir_all(folder).unwrap();
}
