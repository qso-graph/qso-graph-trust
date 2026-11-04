// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;

fn store(folder: &Folder) -> Store {
    Store::open(&folder.0, KeyBackend::Memory).expect("open").0
}

fn qsos() -> Vec<Qso> {
    records::parse(&corpus("adif/KC4QPQ-HOME.adi"))
        .expect("ADIF")
        .iter()
        .map(|r| Qso::from_adif(r).expect("QSO"))
        .collect()
}

fn home() -> StationLocation {
    backup()
        .locations
        .into_iter()
        .find(|l| l.name == "KC4QPQ-HOME")
        .expect("home")
        .station
}

fn entry(key: &str) -> SignedQso {
    SignedQso {
        key: key.into(),
        station: "GRIDSQUARE: FM02".into(),
        signed_at: Some(123),
    }
}

fn signed(store: &Store, qsos: &[Qso], choice: DuplicateChoice) -> SignedLog {
    let backup = backup();
    let cert = backup
        .certificates
        .iter()
        .find(|c| c.callsign == "KC4QPQ")
        .expect("cert");
    let id = store
        .add_certificate_with_key(cert, Some(&corpus("keys/KC4QPQ.password")))
        .expect("import key");
    let selection = store
        .prepare_signing(qsos, &home())
        .expect("plan")
        .choose(choice)
        .expect("selection");
    let at =
        cert.certificate.as_ref().expect("certificate").validity().0 + Duration::from_secs(3600);
    store
        .with_key(&id, |key| {
            selection.sign(cert.certificate.as_ref().expect("certificate"), key, at)
        })
        .expect("key")
        .expect("sign")
}

#[test]
fn standard_backup_keys_and_station_descriptions_match_every_qso() {
    let folder = Folder::new();
    let store = store(&folder);
    let backup = backup();
    assert_eq!(store.import_signed_qsos(&backup).expect("merge"), 21);
    assert_eq!(store.import_signed_qsos(&backup).expect("idempotent"), 0);
    let mut computed = std::collections::BTreeSet::new();
    for location in &backup.locations {
        let qsos: Vec<Qso> = records::parse(&corpus(&format!("adif/{}.adi", location.name)))
            .expect("log")
            .iter()
            .map(|r| Qso::from_adif(r).expect("QSO"))
            .collect();
        let plan = store
            .prepare_signing(&qsos, &location.station)
            .expect("partition");
        assert!(
            plan.new_indices().is_empty(),
            "{}: station metadata must also match TQSL",
            location.name
        );
        assert_eq!(plan.signed_before().len(), 3);
        for qso in qsos {
            let key = duplicate_key(&qso, &location.station);
            let expected = backup
                .signed_qsos
                .iter()
                .find(|q| q.key == key)
                .expect("exact TQSL key");
            let record = store.signed_qso(&key).expect("lookup").expect("record");
            assert_eq!(record.station, expected.station);
            assert_eq!(record.signed_at, None);
            computed.insert(key);
        }
    }
    assert_eq!(
        computed,
        backup.signed_qsos.iter().map(|q| q.key.clone()).collect()
    );
    let reopened = Store::open(&folder.0, KeyBackend::Memory)
        .expect("reopen")
        .0;
    assert_eq!(
        reopened.signed_qsos().expect("roundtrip"),
        store.signed_qsos().expect("records")
    );
    assert_eq!(store.wipe_signed_qsos().expect("wipe"), 21);
    assert!(reopened.signed_qsos().expect("reload").is_empty());
}

#[test]
fn choices_write_only_the_selected_qsos_and_record_only_after_success() {
    let folder = Folder::new();
    let store = store(&folder);
    let qsos = qsos();
    let key = duplicate_key(&qsos[0], &home());
    // A conflicting old grid still identifies the contact as signed before, as TQSL does.
    store
        .add_signed_qsos(&[SignedQso {
            station: "GRIDSQUARE: EM17".into(),
            ..entry(&key)
        }])
        .expect("seed");
    let before = store.signed_qsos().expect("before");
    let plan = store.prepare_signing(&qsos, &home()).expect("plan");
    assert_eq!(plan.new_indices(), &[1, 2]);
    assert_eq!(plan.signed_before()[0].index, 0);
    assert_eq!(plan.signed_before()[0].previous.signed_at, Some(123));
    assert!(plan.choose(DuplicateChoice::Cancel).is_none());
    assert_eq!(
        plan.choose(DuplicateChoice::SignAgain).expect("all").qsos(),
        qsos
    );
    assert_eq!(
        plan.choose(DuplicateChoice::NewOnly).expect("new").qsos(),
        &qsos[1..]
    );
    let log = signed(&store, &qsos, DuplicateChoice::NewOnly);
    assert_eq!(store.signed_qsos().expect("signing is read-only"), before);
    let bad_path = folder.0.join("missing").join("out.tq8");
    assert!(log.write_to(&store, &bad_path).is_err());
    assert_eq!(store.signed_qsos().expect("failed write"), before);
    let output_folder = Folder::new();
    let path = output_folder.0.join("out.tq8");
    log.write_to(&store, &path).expect("write and record");
    assert_eq!(fs::read(&path).expect("output"), log.tq8());
    let tq7 = crate::gzip::decompress(log.tq8(), 1024 * 1024).expect("tq8");
    assert_eq!(
        records::parse(&tq7)
            .expect("records")
            .iter()
            .filter(|r| r.get("REC_TYPE") == Some(b"tCONTACT"))
            .count(),
        2
    );
    let after = store.signed_qsos().expect("after");
    assert_eq!(after.len(), 3);
    assert_eq!(
        store.signed_qso(&key).expect("old retained"),
        Some(before[0].clone())
    );
    assert!(
        after
            .iter()
            .filter(|r| r.key != key)
            .all(|r| r.signed_at.is_some())
    );
    assert!(log.write_to(&store, &path).is_err());
    assert_eq!(store.signed_qsos().expect("existing output"), after);
    // The fresh inspection now sees no new contacts.
    assert!(
        store
            .prepare_signing(&qsos, &home())
            .expect("plan")
            .new_indices()
            .is_empty()
    );
}

#[test]
fn sign_again_preserves_sign_log_bytes_and_replaces_previous_metadata() {
    let folder = Folder::new();
    let store = store(&folder);
    store.import_signed_qsos(&backup()).expect("import");
    let qsos = qsos();
    let log = signed(&store, &qsos, DuplicateChoice::SignAgain);
    let cert = backup()
        .certificates
        .into_iter()
        .find(|c| c.callsign == "KC4QPQ")
        .expect("cert");
    let id = store.certificates().expect("certs")[0].id.clone();
    let at =
        cert.certificate.as_ref().expect("certificate").validity().0 + Duration::from_secs(3600);
    let expected = store
        .with_key(&id, |key| {
            sign_log(
                cert.certificate.as_ref().expect("certificate"),
                key,
                &home(),
                &qsos,
                at,
            )
        })
        .expect("key")
        .expect("sign");
    assert_eq!(log.tq8(), crate::signed_log::tq8(&expected));
    let output_folder = Folder::new();
    log.write_to(&store, &output_folder.0.join("all.tq8"))
        .expect("write");
    assert_eq!(store.signed_qsos().expect("records").len(), 21);
    assert_eq!(
        store
            .import_signed_qsos(&backup())
            .expect("retain QGT metadata"),
        0
    );
    for qso in &qsos {
        assert_eq!(
            store
                .signed_qso(&duplicate_key(qso, &home()))
                .expect("lookup")
                .expect("record")
                .signed_at,
            Some(
                at.duration_since(std::time::UNIX_EPOCH)
                    .expect("unix")
                    .as_secs()
            )
        );
    }
}

#[test]
fn station_conflicts_are_duplicates_but_enrichment_is_new_and_calls_are_distinct() {
    let folder = Folder::new();
    let store = store(&folder);
    let qsos = qsos();
    let minimal = StationLocation::new(&[("CALL", "KC4QPQ"), ("DXCC", "291")]).expect("minimal");
    let key = duplicate_key(&qsos[0], &minimal);
    store
        .add_signed_qsos(&[SignedQso {
            key: key.clone(),
            station: String::new(),
            signed_at: None,
        }])
        .expect("old minimal");
    assert_eq!(
        store
            .prepare_signing(&qsos[..1], &minimal)
            .expect("same")
            .signed_before()
            .len(),
        1
    );
    assert_eq!(
        store
            .prepare_signing(&qsos[..1], &home())
            .expect("enrich")
            .new_indices(),
        &[0]
    );
    store.wipe_signed_qsos().expect("wipe");
    store.import_signed_qsos(&backup()).expect("import");
    let changed =
        StationLocation::new(&[("CALL", "KC4QPQ"), ("DXCC", "291"), ("GRIDSQUARE", "EM17")])
            .expect("changed");
    assert_eq!(duplicate_key(&qsos[0], &changed), key);
    assert_eq!(
        store
            .prepare_signing(&qsos[..1], &changed)
            .expect("conflict")
            .signed_before()
            .len(),
        1
    );
    let other_call = StationLocation::new(&[("CALL", "KN4YU"), ("DXCC", "291")]).expect("other");
    assert_ne!(duplicate_key(&qsos[0], &other_call), key);
    assert_eq!(
        store
            .prepare_signing(&qsos[..1], &other_call)
            .expect("other call")
            .new_indices(),
        &[0]
    );
    store.wipe_signed_qsos().expect("wipe");
    let repeats = vec![qsos[0].clone(), qsos[0].clone()];
    let plan = store
        .prepare_signing(&repeats, &home())
        .expect("input duplicates");
    assert_eq!(plan.new_indices(), &[0]);
    assert_eq!(plan.signed_before()[0].index, 1);
    assert_eq!(plan.signed_before()[0].previous.signed_at, None);
}

#[test]
fn key_fields_are_exact_and_mode_mapping_precedes_key_creation() {
    let make = |fields: &[(&str, &str)]| {
        let text = fields
            .iter()
            .map(|(n, v)| format!("<{n}:{}>{v}", v.len()))
            .collect::<String>()
            + "<eor>";
        Qso::from_adif(&records::parse(text.as_bytes()).expect("ADIF")[0]).expect("QSO")
    };
    let fields = [
        ("CALL", "m0eha"),
        ("BAND", "2m"),
        ("BAND_RX", "70cm"),
        ("FREQ", "145.900"),
        ("FREQ_RX", "435.100"),
        ("MODE", "MFSK"),
        ("SUBMODE", "FT8"),
        ("PROP_MODE", "SAT"),
        ("SAT_NAME", "AO-07"),
        ("QSO_DATE", "20261103"),
        ("TIME_ON", "123459"),
    ];
    let qso = make(&fields);
    assert_eq!(
        duplicate_key(&qso, &home()),
        "KC4QPQ2M70CMM0EHA145.900435.100FT8SAT2026-11-0312:34:59ZAO-7"
    );
    let mut changed = fields;
    changed[10].1 = "1234";
    assert_ne!(
        duplicate_key(&qso, &home()),
        duplicate_key(&make(&changed), &home())
    );
    changed = fields;
    changed[3].1 = "145.9000";
    assert_ne!(
        duplicate_key(&qso, &home()),
        duplicate_key(&make(&changed), &home())
    );
}

#[test]
fn large_record_is_compact_bounded_and_roundtrips() {
    let folder = Folder::new();
    let store = store(&folder);
    let entries: Vec<_> = (0..MAX_SIGNED_QSOS)
        .map(|i| entry(&format!("test{i}")))
        .collect();
    assert_eq!(
        store.add_signed_qsos(&entries).expect("capacity"),
        MAX_SIGNED_QSOS
    );
    let before = fs::read(folder.0.join("store.xml")).expect("snapshot");
    assert!(
        before.len() < 6 * 1024 * 1024,
        "dictionary keeps repeated descriptions compact"
    );
    assert_eq!(
        store.signed_qsos().expect("roundtrip"),
        entries
            .into_iter()
            .map(|q| (q.key.clone(), q))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_values()
            .collect::<Vec<_>>()
    );
    assert!(matches!(
        store.add_signed_qsos(&[entry("overflow")]),
        Err(StoreError::Limit(_))
    ));
    assert_eq!(
        fs::read(folder.0.join("store.xml")).expect("unchanged"),
        before
    );
    assert_eq!(
        store
            .wipe_signed_qsos()
            .expect("remove planted overflow condition"),
        MAX_SIGNED_QSOS
    );
    assert_eq!(
        store
            .add_signed_qsos(&[entry("overflow")])
            .expect("now fits"),
        1
    );
}

#[test]
fn invalid_entries_and_station_bounds_leave_the_store_unchanged() {
    let folder = Folder::new();
    let store = store(&folder);
    store.add_signed_qsos(&[entry("existing")]).expect("seed");
    let before = fs::read(folder.0.join("store.xml")).expect("before");
    for record in [
        entry(""),
        entry("nul\0"),
        entry(&"k".repeat(MAX_SIGNED_KEY_LEN + 1)),
        SignedQso {
            station: "s".repeat(MAX_SIGNED_STATION_LEN + 1),
            ..entry("new")
        },
        SignedQso {
            station: "nul\0".into(),
            ..entry("new")
        },
    ] {
        assert!(store.add_signed_qsos(&[record]).is_err());
        assert_eq!(
            fs::read(folder.0.join("store.xml")).expect("unchanged"),
            before
        );
    }
    let stations: Vec<_> = (0..MAX_SIGNED_STATIONS)
        .map(|i| SignedQso {
            station: format!("place{i}"),
            ..entry(&format!("key{i}"))
        })
        .collect();
    assert!(matches!(
        store.add_signed_qsos(&stations),
        Err(StoreError::Limit(_))
    ));
    assert_eq!(
        fs::read(folder.0.join("store.xml")).expect("unchanged"),
        before
    );
    store.wipe_signed_qsos().expect("remove extra station");
    assert_eq!(
        store.add_signed_qsos(&stations).expect("fits"),
        MAX_SIGNED_STATIONS
    );
}

#[test]
fn old_version_stays_readable_but_never_accepts_nonempty_records() {
    let folder = Folder::new();
    let store = store(&folder);
    let path = folder.0.join("store.xml");
    let legacy = empty_xml().replace("qgt-store version=\"2\"", "qgt-store version=\"1\"");
    fs::write(&path, &legacy).expect("old version");
    assert!(store.signed_qsos().expect("v1 reader").is_empty());
    store
        .add_signed_qsos(&[entry("new")])
        .expect("upgrade on mutation");
    let current = fs::read_to_string(&path).expect("v2");
    assert!(current.contains("qgt-store version=\"2\""));
    fs::write(
        &path,
        current.replace("qgt-store version=\"2\"", "qgt-store version=\"1\""),
    )
    .expect("plant nonempty v1");
    assert!(store.signed_qsos().is_err());
    fs::write(&path, current).expect("remove plant");
    assert_eq!(store.signed_qsos().expect("v2 restored").len(), 1);
}

#[test]
fn malformed_xml_records_are_refused_on_open_and_on_mutation() {
    let folder = Folder::new();
    let store = store(&folder);
    let path = folder.0.join("store.xml");
    let valid = empty_xml();
    let s = "<s id=\"0\">GRIDSQUARE: FM02</s>";
    let q = "<q k=\"contact\" s=\"0\" t=\"123\"/>";
    let cases = [
        q.to_string(),
        format!("{s}{s}{q}"),
        format!("{s}{q}{q}"),
        format!("{s}{}", q.replace("123", "-1")),
        format!("{s}{}", q.replace("123", "18446744073709551616")),
        format!("{s}{}", q.replace("contact", "")),
        format!(
            "{s}{}",
            q.replace("contact", &"k".repeat(MAX_SIGNED_KEY_LEN + 1))
        ),
        format!(
            "{}{}",
            s.replace("FM02", &"s".repeat(MAX_SIGNED_STATION_LEN + 1)),
            q
        ),
        format!("{}{}", s.replace("id=\"0\"", "id=\"4096\""), q),
        format!("{s}{}", q.replace("/>", ">text</q>")),
        format!("{s}{}", q.replace("/>", "><q/></q>")),
        format!("{s}{}", q.replace("/>", " extra=\"1\"/>")),
        format!("{s}{q}<unknown/>"),
        format!("{s}{}", q.repeat(MAX_SIGNED_QSOS + 1)),
    ];
    for contents in cases {
        let planted = valid.replace(
            "<signed-qsos version=\"1\"/>",
            &format!("<signed-qsos version=\"1\">{contents}</signed-qsos>"),
        );
        fs::write(&path, &planted).expect("plant");
        assert!(Store::open(&folder.0, KeyBackend::Memory).is_err());
        assert!(store.add_signed_qsos(&[entry("new")]).is_err());
        assert_eq!(fs::read_to_string(&path).expect("unchanged"), planted);
        fs::write(&path, &valid).expect("remove plant");
        assert!(store.signed_qsos().expect("valid again").is_empty());
    }
}

#[test]
fn output_cannot_use_store_directory_and_store_failures_keep_successful_output() {
    let folder = Folder::new();
    let store = store(&folder);
    let log = signed(&store, &qsos(), DuplicateChoice::SignAgain);
    let before = fs::read(folder.0.join("store.xml")).expect("before");
    for name in [
        "store.xml",
        "store.xml.partial",
        "store.lock",
        "STORE.XML.PARTIAL",
        "Store.Lock",
        "plain.tq8",
    ] {
        let existed = folder.0.join(name).exists();
        assert!(matches!(
            log.write_to(&store, &folder.0.join(name)),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(
            fs::read(folder.0.join("store.xml")).expect("unchanged"),
            before
        );
        assert!(store.signed_qsos().expect("nothing recorded").is_empty());
        assert_eq!(folder.0.join(name).exists(), existed);
    }
    fs::create_dir(folder.0.join("child")).expect("child for parent alias");
    let alias = folder.0.join("child/../alias.tq8");
    assert!(matches!(
        log.write_to(&store, &alias),
        Err(StoreError::Invalid(_))
    ));
    assert!(!alias.exists());
    assert!(store.signed_qsos().expect("nothing recorded").is_empty());
    let output_folder = Folder::new();
    let output = output_folder.0.join("log.tq8");
    fs::create_dir(folder.0.join("store.xml.partial")).expect("plant replacement failure");
    assert!(log.write_to(&store, &output).is_err());
    assert_eq!(
        fs::read(&output).expect("successful output survives"),
        log.tq8()
    );
    assert!(store.signed_qsos().expect("not recorded").is_empty());
    fs::remove_dir(folder.0.join("store.xml.partial")).expect("remove plant");
    log.write_to(&store, &output_folder.0.join("retry.tq8"))
        .expect("retry");
    assert_eq!(store.signed_qsos().expect("recorded").len(), 3);
}

#[test]
fn signing_write_preflights_record_capacity_before_creating_output() {
    let folder = Folder::new();
    let store = store(&folder);
    let log = signed(&store, &qsos(), DuplicateChoice::SignAgain);
    let entries: Vec<_> = (0..MAX_SIGNED_QSOS)
        .map(|i| entry(&format!("test{i}")))
        .collect();
    store.add_signed_qsos(&entries).expect("fill record");
    let output_folder = Folder::new();
    let output = output_folder.0.join("log.tq8");
    assert!(matches!(
        log.write_to(&store, &output),
        Err(StoreError::Limit(_))
    ));
    assert!(!output.exists());
    store.wipe_signed_qsos().expect("remove plant");
    log.write_to(&store, &output).expect("now fits");
}

#[test]
fn signed_record_mutations_wait_for_lock_and_merge_other_writers() {
    let folder = Folder::new();
    let store = store(&folder);
    let other = Store::open(&folder.0, KeyBackend::Memory)
        .expect("other handle")
        .0;
    let lock = store.lock().expect("hold lock");
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).expect("started");
        other.add_signed_qsos(&[entry("second")]).expect("merge");
        done_tx.send(()).expect("done");
    });
    started_rx.recv().expect("started");
    assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
    let mut data = store.read().expect("locked read");
    data.signed_qsos.insert("first".into(), entry("first"));
    store
        .replace(&format::write(&data).expect("XML"))
        .expect("first write");
    drop(lock);
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("writer released");
    worker.join().expect("join");
    assert_eq!(store.signed_qsos().expect("both writers").len(), 2);
}

#[test]
fn encoded_record_must_fit_the_whole_file_limit() {
    let folder = Folder::new();
    let store = store(&folder);
    store.add_signed_qsos(&[entry("existing")]).expect("seed");
    let before = fs::read(folder.0.join("store.xml")).expect("before");
    let suffix = "x".repeat(MAX_SIGNED_KEY_LEN - 6);
    let entries: Vec<_> = (0..33_000)
        .map(|i| entry(&format!("{i:06}{suffix}")))
        .collect();
    assert!(matches!(
        store.add_signed_qsos(&entries),
        Err(StoreError::Limit("file bytes"))
    ));
    assert_eq!(
        fs::read(folder.0.join("store.xml")).expect("unchanged"),
        before
    );
    assert_eq!(
        store
            .add_signed_qsos(&entries[..10])
            .expect("remove excess entries"),
        10
    );
}

#[cfg(unix)]
#[test]
fn output_parent_symlink_to_store_is_refused_before_creation() {
    let folder = Folder::new();
    let store = store(&folder);
    let log = signed(&store, &qsos(), DuplicateChoice::SignAgain);
    let output_folder = Folder::new();
    let alias = output_folder.0.join("store-alias");
    std::os::unix::fs::symlink(&folder.0, &alias).expect("directory alias");
    let output = alias.join("STORE.XML.PARTIAL");
    assert!(matches!(
        log.write_to(&store, &output),
        Err(StoreError::Invalid(_))
    ));
    assert!(!output.exists());
    assert!(store.signed_qsos().expect("nothing recorded").is_empty());
    fs::remove_file(alias).expect("remove alias");
    log.write_to(&store, &output_folder.0.join("STORE.XML.PARTIAL"))
        .expect("same name outside store is safe");
    assert_eq!(store.signed_qsos().expect("recorded").len(), 3);
}
