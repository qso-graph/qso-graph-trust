// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The commands, run as a ham runs them, on a store in memory, against the standard test set
//! (tests/corpus/standard): its TQSL backup and test root (never LoTW's), its logs, and tqsllib's
//! signed logs of them. Uploads go to a stand-in for LoTW: nothing here connects anywhere.

use std::cell::RefCell;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use qso_graph_trust::certificate::Trust;
use qso_graph_trust::store::{KeyBackend, Store, StoreError};
use qso_graph_trust::upload::UploadRequest;
use qso_graph_trust::{gzip, tbk};
use zeroize::Zeroizing;

use crate::cli::{Env, UploadFailure, run};

fn set(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/standard")
        .join(file)
}

fn read(file: &str) -> Vec<u8> {
    std::fs::read(set(file)).unwrap_or_else(|e| panic!("{file}: {e}"))
}

fn scratch() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "qg-trust-commands-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch folder");
    dir
}

fn path(p: &Path) -> &str {
    p.to_str().expect("a UTF-8 path")
}

/// What LoTW's stand-in answers.
#[derive(Clone)]
enum Lotw {
    Accepts,
    Refuses,
    Unreachable,
    Garbled,
    /// The connection fails after the log has gone.
    Silent,
}

/// A ham's computer: a store in memory that lasts across commands, the test root, a time when
/// every test certificate is in force, and a stand-in for LoTW that records what it was sent.
struct Ham {
    store: Store,
    dir: PathBuf,
    trust: Trust,
    now: SystemTime,
    lotw: Lotw,
    sent: RefCell<Vec<Vec<u8>>>,
}

struct Ran {
    code: u8,
    out: String,
    err: String,
    prompts: Vec<String>,
}

impl Ham {
    fn new() -> Self {
        let dir = scratch().join("store");
        let (store, _) = Store::open(&dir, KeyBackend::Memory).expect("a store");
        let trust = Trust::with_roots(&[&read("pki/root.pem")]).expect("the test root");
        let backup = tbk::read(&read("standard.tbk"), &trust).expect("the backup");
        let w4w = backup
            .certificates
            .iter()
            .find(|c| c.callsign == "W4W")
            .expect("W4W");
        let now = w4w.certificate.as_ref().expect("W4W's").validity().0 + Duration::from_secs(3600);
        Self {
            store,
            dir,
            trust,
            now,
            lotw: Lotw::Accepts,
            sent: RefCell::new(Vec::new()),
        }
    }

    /// Runs `qg-trust args`, answering each password prompt with the test password of the call
    /// it names.
    fn run(&self, args: &[&str]) -> Ran {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut prompts = Vec::new();
        let mut ask = |prompt: &str| -> io::Result<Zeroizing<Vec<u8>>> {
            prompts.push(prompt.to_string());
            for call in ["KC4QPQ", "KN4YU", "W4W"] {
                if prompt.contains(call) {
                    return Ok(Zeroizing::new(read(&format!("keys/{call}.password"))));
                }
            }
            Err(io::Error::other("no password was expected"))
        };
        let store = || -> Result<&Store, StoreError> { Ok(&self.store) };
        let mut upload = |request: &UploadRequest| -> Result<(u16, Vec<u8>), UploadFailure> {
            assert_eq!(request.url(), "https://lotw.arrl.org/lotw/upload");
            self.sent.borrow_mut().push(request.body().to_vec());
            match self.lotw {
                Lotw::Accepts => Ok((
                    200,
                    b"<!-- .UPL.  accepted -->\n<!-- .UPLMESSAGE. 3 QSOs -->".to_vec(),
                )),
                Lotw::Refuses => Ok((
                    200,
                    b"<!-- .UPL.  rejected -->\n<!-- .UPLMESSAGE. bad signature -->".to_vec(),
                )),
                Lotw::Garbled => Ok((502, b"<html>Bad Gateway</html>".to_vec())),
                Lotw::Unreachable => Err(UploadFailure {
                    message: "the connection timed out".into(),
                    maybe_sent: false,
                }),
                Lotw::Silent => Err(UploadFailure {
                    message: "the connection was reset".into(),
                    maybe_sent: true,
                }),
            }
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(
            &args,
            &mut Env {
                trust: &self.trust,
                now: self.now,
                color_out: false,
                color_err: false,
                ask_password: &mut ask,
                out: &mut out,
                err: &mut err,
                store: &store,
                upload: &mut upload,
            },
        );
        Ran {
            code,
            out: String::from_utf8(out).expect("text"),
            err: String::from_utf8(err).expect("text"),
            prompts,
        }
    }

    fn imported() -> Self {
        let ham = Self::new();
        let ran = ham.run(&["import", path(&set("standard.tbk"))]);
        assert_eq!(ran.code, 0, "{}{}", ran.out, ran.err);
        ham
    }

    /// The backup's certificates and locations, without TQSL's record of what it signed, so a
    /// test sees qg-trust's own record.
    fn unsigned() -> Self {
        let ham = Self::new();
        let backup = tbk::read(&read("standard.tbk"), &ham.trust).expect("the backup");
        for entry in &backup.certificates {
            let pw = read(&format!("keys/{}.password", entry.callsign));
            ham.store
                .add_certificate_with_key(entry, (!pw.is_empty()).then_some(pw.as_slice()))
                .expect("the certificate");
        }
        for loc in &backup.locations {
            ham.store
                .add_location(&loc.name, &loc.station)
                .expect("the location");
        }
        ham
    }
}

/// A signed log's lines after the first, the identification line naming the program that made it.
fn body(tq7: &[u8]) -> String {
    let text = String::from_utf8_lossy(tq7);
    text.split_once('\n').expect("a line").1.to_string()
}

fn signed(tq8: &Path) -> Vec<u8> {
    let bytes = std::fs::read(tq8).expect("the .tq8");
    gzip::decompress(&bytes, 64 * 1024 * 1024)
        .expect("gzip")
        .to_vec()
}

const LOCATIONS: &[&str] = &[
    "KC4QPQ-HOME",
    "KC4QPQ-MN35",
    "KC4QPQ-NP12",
    "KC4QPQ-NS09",
    "KC4QPQ-TR10-MP06",
    "KN4YU-CLUB",
    "W4W-EVENT",
];

#[test]
fn a_tqsl_backup_imports_certificates_keys_locations_and_the_signed_record() {
    let ham = Ham::new();
    let ran = ham.run(&["import", path(&set("standard.tbk"))]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(
        ran.out.contains("certificate and key imported"),
        "{}",
        ran.out
    );
    for name in LOCATIONS {
        assert!(
            ran.out.contains(&format!("location {name}: imported")),
            "{name}: {}",
            ran.out
        );
    }
    // A password is asked only for the keys that have one, each naming whose key it is.
    for prompt in &ran.prompts {
        assert!(prompt.contains("as set in TQSL"), "{prompt}");
    }
    let certs = ham.store.certificates().expect("certificates");
    assert_eq!(certs.len(), 3);
    assert!(certs.iter().all(|c| c.key_name.is_some()));
    assert_eq!(
        ham.store.locations().expect("locations").len(),
        LOCATIONS.len()
    );
    assert!(!ham.store.signed_qsos().expect("record").is_empty());

    // Importing it again changes nothing and says so.
    let again = ham.run(&["import", path(&set("standard.tbk"))]);
    assert_eq!(again.code, 0, "{}", again.err);
    assert!(again.out.contains("already here"), "{}", again.out);
    assert_eq!(ham.store.certificates().expect("certificates").len(), 3);
}

#[test]
fn every_location_signs_from_the_store_as_tqsllib_signs_it() {
    let ham = Ham::imported();
    let dir = scratch();
    for name in LOCATIONS {
        let out = dir.join(format!("{name}.tq8"));
        let ran = ham.run(&[
            "sign",
            path(&set(&format!("adif/{name}.adi"))),
            "-l",
            name,
            "-o",
            path(&out),
            "--again",
        ]);
        assert_eq!(ran.code, 0, "{name}: {}", ran.err);
        assert!(ran.out.starts_with("Signed "), "{}", ran.out);
        // Keys come from the credential store: no password is asked for.
        assert!(ran.prompts.is_empty(), "{name}: {:?}", ran.prompts);
        assert_eq!(
            body(&signed(&out)),
            body(&read(&format!("signed/{name}.tq7"))),
            "{name}"
        );
    }
}

#[test]
fn qsos_signed_before_are_skipped_unless_asked_again() {
    let ham = Ham::unsigned();
    let dir = scratch();
    let adi = dir.join("club.adi");
    std::fs::copy(set("adif/KN4YU-CLUB.adi"), &adi).expect("copy");

    let first = ham.run(&["sign", path(&adi), "-l", "KN4YU-CLUB"]);
    assert_eq!(first.code, 0, "{}", first.err);
    assert!(
        first.out.contains("for KN4YU at KN4YU-CLUB"),
        "{}",
        first.out
    );
    assert!(dir.join("club.tq8").exists());

    // The signed log is there: it is never replaced without --force.
    let refused = ham.run(&["sign", path(&adi), "-l", "KN4YU-CLUB", "--again"]);
    assert_eq!(refused.code, 7, "{}", refused.err);
    assert!(
        refused.err.contains("--force replaces it"),
        "{}",
        refused.err
    );

    let second = ham.run(&["sign", path(&adi), "-l", "KN4YU-CLUB", "--force"]);
    assert_eq!(second.code, 8, "{}{}", second.out, second.err);
    assert!(
        second
            .err
            .contains("signed before; --again signs them again"),
        "{}",
        second.err
    );

    let again = ham.run(&["sign", path(&adi), "-l", "KN4YU-CLUB", "--again", "--force"]);
    assert_eq!(again.code, 0, "{}", again.err);
}

#[test]
fn send_signs_and_uploads_and_reports_lotws_answer_with_tqsls_codes() {
    let mut ham = Ham::imported();
    let dir = scratch();
    let adi = dir.join("event.adi");
    std::fs::copy(set("adif/W4W-EVENT.adi"), &adi).expect("copy");

    let ran = ham.run(&["send", path(&adi), "-l", "W4W-EVENT", "--again"]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(
        ran.out.contains("LoTW accepted the log for processing."),
        "{}",
        ran.out
    );
    assert!(ran.out.contains("LoTW says: 3 QSOs"), "{}", ran.out);
    // What was sent is the signed log kept on disk, unchanged, in TQSL's form field.
    let sent = ham.sent.borrow()[0].clone();
    let tq8 = std::fs::read(dir.join("event.tq8")).expect("the signed log is kept");
    assert!(sent.windows(tq8.len()).any(|w| w == tq8.as_slice()));
    assert!(String::from_utf8_lossy(&sent).contains("name=\"upfile\""));

    for (lotw, code, says) in [
        (Lotw::Refuses, 2, "LoTW refused the log: bad signature"),
        (
            Lotw::Garbled,
            3,
            "check your LoTW account before uploading it again",
        ),
        (
            Lotw::Unreachable,
            11,
            "LoTW could not be reached: the connection timed out",
        ),
    ] {
        ham.lotw = lotw;
        let ran = ham.run(&["upload", path(&dir.join("event.tq8"))]);
        assert_eq!(ran.code, code, "{}", ran.err);
        assert!(ran.err.contains(says), "{}", ran.err);
    }
}

#[test]
fn upload_refuses_a_file_that_is_not_a_signed_log() {
    let ham = Ham::new();
    let ran = ham.run(&["upload", path(&set("adif/W4W-EVENT.adi"))]);
    assert_eq!(ran.code, 6, "{}", ran.err);
    assert!(
        ran.err.contains("is not a signed log (.tq8)"),
        "{}",
        ran.err
    );
    assert!(ham.sent.borrow().is_empty());
}

#[test]
fn signing_names_whats_missing_and_what_to_do() {
    let ham = Ham::new();
    let ran = ham.run(&["sign", path(&set("adif/W4W-EVENT.adi")), "-l", "Home"]);
    assert_eq!(ran.code, 10);
    assert!(
        ran.err
            .contains("you have none yet: qg-trust import your TQSL backup"),
        "{}",
        ran.err
    );

    let ham = Ham::imported();
    let ran = ham.run(&["sign", path(&set("adif/W4W-EVENT.adi")), "-l", "Home"]);
    assert_eq!(ran.code, 10);
    assert!(ran.err.contains("you have: KC4QPQ-HOME"), "{}", ran.err);
}

#[test]
fn certificates_list_with_their_dates_and_as_json() {
    let ham = Ham::imported();
    let ran = ham.run(&["cert", "list"]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    for call in ["KC4QPQ", "KN4YU", "W4W"] {
        assert!(ran.out.contains(call), "{}", ran.out);
    }
    assert!(ran.out.contains("QSOs "), "{}", ran.out);
    let json = ham.run(&["cert", "list", "--json"]);
    assert!(
        json.out.starts_with("{\"certificates\":[{\"id\":\"cert:"),
        "{}",
        json.out
    );
    assert!(json.out.contains("\"call\":\"W4W\""), "{}", json.out);
    assert!(json.out.contains("\"has_key\":true"), "{}", json.out);
}

#[test]
fn a_certificate_is_deleted_only_with_force() {
    let ham = Ham::imported();
    let certs = ham.store.certificates().expect("certificates");
    let w4w = certs
        .iter()
        .find(|c| c.certificate.callsign() == "W4W")
        .expect("W4W");
    let id = &w4w.id.split_once(':').expect("kind").1[..8];
    let ran = ham.run(&["cert", "delete", id]);
    assert_eq!(ran.code, 10);
    assert!(
        ran.err.contains("cannot be undone; give --force"),
        "{}",
        ran.err
    );
    assert_eq!(ham.store.certificates().expect("certificates").len(), 3);
    let ran = ham.run(&["cert", "delete", id, "--force"]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(ran.out.contains("Deleted W4W"), "{}", ran.out);
    assert_eq!(ham.store.certificates().expect("certificates").len(), 2);
}

const REQUEST: &[&str] = &[
    "cert",
    "request",
    "--call",
    "n0call",
    "--dxcc",
    "291",
    "--from",
    "2020-01-01",
    "--name",
    "Test Operator",
    "--address",
    "1 Main St",
    "--city",
    "Boise",
    "--state",
    "ID",
    "--postcode",
    "83702",
    "--country",
    "USA",
    "--email",
    "test@example.org",
    "-o",
];

#[test]
fn a_request_keeps_its_key_in_the_store_and_writes_the_tq5() {
    let ham = Ham::new();
    let dir = scratch();
    let tq5 = dir.join("N0CALL.tq5");
    let mut args = REQUEST.to_vec();
    args.push(path(&tq5));
    let ran = ham.run(&args);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(
        ran.out.contains("Request for N0CALL written to"),
        "{}",
        ran.out
    );
    assert!(
        ran.out.contains("https://lotw.arrl.org/lotw/load-cert"),
        "{}",
        ran.out
    );
    let text = std::fs::read_to_string(&tq5).expect("the .tq5");
    assert!(text.contains("TQSL_CRQ"), "{text}");
    let pending = ham.store.pending_requests().expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].callsign, "N0CALL");

    // The .tq5 is there: it is not replaced without --force, and no second key is made.
    let ran = ham.run(&args);
    assert_eq!(ran.code, 7);
    assert_eq!(ham.store.pending_requests().expect("pending").len(), 1);

    let list = ham.run(&["cert", "list"]);
    assert!(list.out.contains("waiting for ARRL's .tq6"), "{}", list.out);

    let id = &pending[0].id.split_once(':').expect("kind").1[..8];
    let ran = ham.run(&["cert", "abandon", id]);
    assert_eq!(ran.code, 10);
    let ran = ham.run(&["cert", "abandon", id, "--force"]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(ham.store.pending_requests().expect("pending").is_empty());
}

#[test]
fn a_renewal_is_signed_by_the_certificate_it_renews() {
    let ham = Ham::imported();
    let dir = scratch();
    let tq5 = dir.join("W4W.tq5");
    let ran = ham.run(&[
        "cert",
        "renew",
        "W4W",
        "--name",
        "Test Operator",
        "--address",
        "1 Main St",
        "--city",
        "Boise",
        "--country",
        "USA",
        "--email",
        "test@example.org",
        "-o",
        path(&tq5),
    ]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(tq5.exists());
    assert_eq!(
        ham.store.pending_requests().expect("pending")[0].callsign,
        "W4W"
    );
}

#[test]
fn arrls_answer_imports_and_a_certificate_alone_cannot_sign() {
    let ham = Ham::new();
    let ran = ham.run(&["import", path(&set("certs/W4W.tq6"))]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(
        ran.out.contains("without a key: it cannot sign"),
        "{}",
        ran.out
    );
    let list = ham.run(&["cert", "list"]);
    assert!(list.out.contains("(no key: cannot sign)"), "{}", list.out);
}

#[test]
fn station_locations_are_added_shown_changed_and_deleted() {
    let ham = Ham::new();
    let ran = ham.run(&[
        "location",
        "add",
        "Home",
        "--call",
        "n0call",
        "--dxcc",
        "291",
        "--grid",
        "DN13",
        "US_STATE=ID",
    ]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(ran.out.contains("Added Home: N0CALL"), "{}", ran.out);

    let show = ham.run(&["location", "show", "Home"]);
    assert!(show.out.contains("GRIDSQUARE=DN13"), "{}", show.out);
    assert!(show.out.contains("US_STATE=ID"), "{}", show.out);

    let edit = ham.run(&["location", "edit", "Home", "--grid", "DN14", "US_STATE="]);
    assert_eq!(edit.code, 0, "{}", edit.err);
    let show = ham.run(&["location", "show", "Home", "--json"]);
    assert!(show.out.contains("\"GRIDSQUARE\":\"DN14\""), "{}", show.out);
    assert!(!show.out.contains("US_STATE"), "{}", show.out);

    // A field this entity's locations do not take is refused, and the fields it takes are named.
    let bad = ham.run(&[
        "location",
        "add",
        "Away",
        "--call",
        "N0CALL",
        "--dxcc",
        "291",
        "CA_PROVINCE=ON",
    ]);
    assert_eq!(bad.code, 10);
    assert!(
        bad.err.contains("qg-trust location fields 291"),
        "{}",
        bad.err
    );
    let fields = ham.run(&["location", "fields", "291"]);
    assert!(fields.out.contains("US_STATE"), "{}", fields.out);
    assert!(!fields.out.contains("CA_PROVINCE"), "{}", fields.out);

    let del = ham.run(&["location", "delete", "Home"]);
    assert_eq!(del.code, 10);
    let del = ham.run(&["location", "delete", "Home", "--force"]);
    assert_eq!(del.code, 0, "{}", del.err);
    assert!(ham.store.locations().expect("locations").is_empty());
}

#[test]
fn every_command_has_help_with_an_example() {
    let ham = Ham::new();
    for command in [
        &["sign"][..],
        &["send"],
        &["upload"],
        &["import"],
        &["cert", "list"],
        &["cert", "request"],
        &["cert", "renew"],
        &["cert", "delete"],
        &["cert", "abandon"],
        &["location", "list"],
        &["location", "show"],
        &["location", "add"],
        &["location", "edit"],
        &["location", "delete"],
        &["location", "fields"],
    ] {
        let mut args = command.to_vec();
        args.push("--help");
        let ran = ham.run(&args);
        assert_eq!(ran.code, 0, "{command:?}: {}", ran.err);
        assert!(ran.out.contains("Example"), "{command:?}: {}", ran.out);
    }
    // The TQSL-style help names the commands.
    let ran = ham.run(&["--help"]);
    assert!(ran.out.contains("qg-trust import FILE"), "{}", ran.out);
}

#[test]
fn a_command_never_writes_the_loggers_final_status_line() {
    let ham = Ham::new();
    let ran = ham.run(&["cert", "list"]);
    assert!(!ran.err.contains("Final Status"), "{}", ran.err);
    let ran = ham.run(&["sign"]);
    assert_eq!(ran.code, 10);
    assert!(!ran.err.contains("Final Status"), "{}", ran.err);
}

/// A logger's call, as it calls TQSL: no -i, so the keys and locations come from the store.
fn final_status(ran: &Ran) -> &str {
    ran.err.lines().last().expect("a final line")
}

#[test]
fn a_logger_signs_from_the_store_with_tqsls_options_and_codes() {
    let ham = Ham::unsigned();
    let dir = scratch();
    let adi = dir.join("event.adi");
    std::fs::copy(set("adif/W4W-EVENT.adi"), &adi).expect("copy");
    let tq8 = dir.join("event.tq8");

    let ran = ham.run(&["-x", "-d", "-l", "W4W-EVENT", path(&adi)]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(final_status(&ran), "Final Status: Success(0)");
    assert_eq!(body(&signed(&tq8)), body(&read("signed/W4W-EVENT.tq7")));

    // Signed before, and no -a: TQSL would ask; qg-trust cannot, and says how to choose.
    let ran = ham.run(&["-x", "-l", "W4W-EVENT", path(&adi)]);
    assert_eq!(ran.code, 14, "{}", ran.err);
    assert_eq!(
        final_status(&ran),
        "Final Status: Previously signed QSOs were detected(14)"
    );
    assert!(ran.err.contains("-a compliant"), "{}", ran.err);

    for (action, code, status) in [
        // TQSL's batch mode aborts at the first QSO signed before (apps/tqsl.cpp, SignLogFile).
        (
            "abort",
            14,
            "Final Status: Previously signed QSOs were detected(14)",
        ),
        ("compliant", 8, "Final Status: No QSOs to upload(8)"),
        ("ALL", 0, "Final Status: Success(0)"),
    ] {
        let ran = ham.run(&["-x", "-a", action, "-l", "W4W-EVENT", path(&adi)]);
        assert_eq!(ran.code, code, "{action}: {}", ran.err);
        assert_eq!(final_status(&ran), status, "{action}");
    }
}

#[test]
fn a_logger_uploads_with_u_and_gets_lotws_answer_as_tqsls_code() {
    let mut ham = Ham::unsigned();
    let dir = scratch();
    let adi = dir.join("club.adi");
    std::fs::copy(set("adif/KN4YU-CLUB.adi"), &adi).expect("copy");
    let ran = ham.run(&["-x", "-u", "-a", "all", "-l", "KN4YU-CLUB", path(&adi)]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(final_status(&ran), "Final Status: Success(0)");
    assert_eq!(ham.sent.borrow().len(), 1);

    ham.lotw = Lotw::Refuses;
    let ran = ham.run(&["-x", "-u", "-a", "all", "-l", "KN4YU-CLUB", path(&adi)]);
    assert_eq!(ran.code, 2, "{}", ran.err);
    assert_eq!(final_status(&ran), "Final Status: Upload Rejected(2)");

    ham.lotw = Lotw::Unreachable;
    let ran = ham.run(&["-x", "-u", "-a", "all", "-l", "KN4YU-CLUB", path(&adi)]);
    assert_eq!(ran.code, 11, "{}", ran.err);
    assert_eq!(
        final_status(&ran),
        "Final Status: LoTW Connection Failed(11)"
    );

    // With -i, the backup signs and -u uploads it the same way.
    ham.lotw = Lotw::Accepts;
    let ran = ham.run(&[
        "-x",
        "-u",
        "-i",
        path(&set("standard.tbk")),
        "-l",
        "KN4YU-CLUB",
        path(&adi),
    ]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(ham.sent.borrow().len(), 4);
}

#[test]
fn a_logger_chooses_what_the_logs_own_location_details_do_with_f() {
    let ham = Ham::unsigned();
    let dir = scratch();
    // A QSO whose MY_GRIDSQUARE disagrees with the location's.
    let adi = dir.join("moved.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    let moved = log.replacen("<EOR>", "<MY_GRIDSQUARE:4>AA00 <EOR>", 1);
    assert_ne!(moved, log, "the log has a record to change");
    std::fs::write(&adi, moved).expect("write");

    let report = ham.run(&[
        "-x",
        "-a",
        "all",
        "-f",
        "report",
        "-l",
        "W4W-EVENT",
        path(&adi),
    ]);
    assert_eq!(report.code, 9, "{}", report.err);
    assert!(report.err.contains("MY_GRIDSQUARE"), "{}", report.err);

    let ignore = ham.run(&[
        "-x",
        "-a",
        "all",
        "-f",
        "IGNORE",
        "-l",
        "W4W-EVENT",
        path(&adi),
    ]);
    assert_eq!(ignore.code, 0, "{}", ignore.err);

    let bad = ham.run(&["-x", "-f", "sometimes", "-l", "W4W-EVENT", path(&adi)]);
    assert_eq!(bad.code, 10);
    assert!(
        bad.err.contains("-f takes ignore, report or update"),
        "{}",
        bad.err
    );
}

#[test]
fn force_never_touches_the_stores_own_files() {
    let ham = Ham::imported();
    let store_xml = ham.dir.join("store.xml");
    let before = std::fs::read(&store_xml).expect("the store file");
    for args in [
        vec![
            "sign",
            path(&set("adif/W4W-EVENT.adi")),
            "-l",
            "W4W-EVENT",
            "--again",
            "--force",
            "-o",
            path(&store_xml),
        ],
        vec![
            "-x",
            "-a",
            "all",
            "-l",
            "W4W-EVENT",
            "-o",
            path(&store_xml),
            path(&set("adif/W4W-EVENT.adi")),
        ],
    ] {
        let ran = ham.run(&args);
        assert_eq!(ran.code, 7, "{args:?}: {}", ran.err);
        assert_eq!(
            std::fs::read(&store_xml).expect("still there"),
            before,
            "{args:?}"
        );
        assert_eq!(ham.store.certificates().expect("certificates").len(), 3);
    }
}

#[test]
fn abort_signs_nothing_when_any_qso_cannot_be_signed() {
    let ham = Ham::unsigned();
    let dir = scratch();
    let adi = dir.join("bad.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    // One QSO with no mode: the rest are fine.
    let bad = log.replacen("<MODE:2>CW ", "", 1);
    assert_ne!(bad, log);
    std::fs::write(&adi, bad).expect("write");
    let ran = ham.run(&["-x", "-u", "-a", "abort", "-l", "W4W-EVENT", path(&adi)]);
    assert_eq!(ran.code, 8, "{}", ran.err);
    assert!(ran.err.contains("aborted, nothing signed"), "{}", ran.err);
    assert!(!dir.join("bad.tq8").exists());
    assert!(ham.sent.borrow().is_empty());
    assert!(ham.store.signed_qsos().expect("record").is_empty());
    // compliant signs the others and says some were left out.
    let ran = ham.run(&["-x", "-a", "compliant", "-l", "W4W-EVENT", path(&adi)]);
    assert_eq!(ran.code, 9, "{}", ran.err);
}

#[test]
fn an_action_that_needs_the_signed_record_is_refused_with_i() {
    let ham = Ham::new();
    for action in ["abort", "compliant", "ask"] {
        let ran = ham.run(&[
            "-x",
            "-a",
            action,
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "W4W-EVENT",
            path(&set("adif/W4W-EVENT.adi")),
        ]);
        assert_eq!(ran.code, 10, "{action}: {}", ran.err);
        assert!(ran.err.contains("leave out -i"), "{}", ran.err);
        assert!(ham.sent.borrow().is_empty());
    }
}

#[test]
fn a_failure_after_the_log_was_sent_is_not_a_safe_retry() {
    let mut ham = Ham::imported();
    let dir = scratch();
    let adi = dir.join("event.adi");
    std::fs::copy(set("adif/W4W-EVENT.adi"), &adi).expect("copy");
    ham.lotw = Lotw::Silent;
    let ran = ham.run(&["send", path(&adi), "-l", "W4W-EVENT", "--again"]);
    assert_eq!(ran.code, 3, "{}", ran.err);
    assert!(
        ran.err.contains("whether LoTW has it is not known"),
        "{}",
        ran.err
    );
    assert!(!ran.err.contains("tries again"), "{}", ran.err);
}

#[test]
fn report_lets_the_log_fill_a_field_the_location_leaves_empty() {
    let ham = Ham::unsigned();
    let event = ham
        .store
        .locations()
        .expect("locations")
        .into_iter()
        .find(|l| l.name == "W4W-EVENT")
        .expect("W4W-EVENT");
    let (field, adif) = [("CQZ", "MY_CQ_ZONE"), ("ITUZ", "MY_ITU_ZONE")]
        .into_iter()
        .find(|(f, _)| event.station.get(f).is_some())
        .expect("the location gives a zone");
    let value = event.station.get(field).expect("zone").to_string();
    let fields: Vec<(&str, &str)> = event
        .station
        .fields()
        .filter(|(k, _)| *k != field)
        .collect();
    let without = qso_graph_trust::station::StationLocation::new(&fields).expect("a location");
    ham.store.add_location("NO-ZONE", &without).expect("added");

    let dir = scratch();
    let adi = dir.join("zone.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    std::fs::write(
        &adi,
        log.replace("<EOR>", &format!("<{adif}:{}>{value} <EOR>", value.len())),
    )
    .expect("write");
    for args in [
        vec![
            "-x",
            "-a",
            "all",
            "-f",
            "report",
            "-l",
            "NO-ZONE",
            path(&adi),
        ],
        vec!["-x", "-a", "all", "-l", "NO-ZONE", path(&adi)],
    ] {
        let ran = ham.run(&args);
        assert_eq!(ran.code, 0, "{args:?}: {}", ran.err);
    }
}

#[test]
fn a_qso_from_another_station_is_left_out_whatever_the_options() {
    let ham = Ham::unsigned();
    let dir = scratch();
    let adi = dir.join("other.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    let other = log.replacen("<EOR>", "<STATION_CALLSIGN:6>N0CALL <EOR>", 1);
    std::fs::write(&adi, other).expect("write");
    for verify in ["update", "report", "ignore"] {
        let ran = ham.run(&[
            "-x",
            "-a",
            "all",
            "-f",
            verify,
            "-l",
            "W4W-EVENT",
            path(&adi),
        ]);
        if verify == "ignore" {
            // TQSL's ignore does not compare STATION_CALLSIGN.
            assert_eq!(ran.code, 0, "{verify}: {}", ran.err);
        } else {
            assert_eq!(ran.code, 9, "{verify}: {}", ran.err);
            assert!(
                ran.err.contains("STATION_CALLSIGN"),
                "{verify}: {}",
                ran.err
            );
        }
    }
}

#[test]
fn a_request_never_writes_through_another_file() {
    let ham = Ham::new();
    let dir = scratch();
    let tq5 = dir.join("N0CALL.tq5");
    let bystander = dir.join("N0CALL.tq5.partial");
    std::fs::write(&bystander, b"someone else's file").expect("write");
    let mut args = REQUEST.to_vec();
    args.push(path(&tq5));
    let ran = ham.run(&args);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(
        std::fs::read(&bystander).expect("kept"),
        b"someone else's file"
    );
    #[cfg(unix)]
    {
        // A link where the request goes is refused, not followed.
        let link = dir.join("link.tq5");
        std::os::unix::fs::symlink(&bystander, &link).expect("link");
        let mut args = REQUEST.to_vec();
        args.push(path(&link));
        let ran = ham.run(&args);
        assert_eq!(ran.code, 7, "{}", ran.err);
        assert_eq!(
            std::fs::read(&bystander).expect("kept"),
            b"someone else's file"
        );
    }
}

#[test]
fn a_tqsl_backup_is_never_uploaded() {
    let ham = Ham::new();
    let ran = ham.run(&["upload", path(&set("standard.tbk"))]);
    assert_eq!(ran.code, 6, "{}", ran.err);
    assert!(
        ran.err.contains("is not a signed log (.tq8)"),
        "{}",
        ran.err
    );
    assert!(ham.sent.borrow().is_empty());
}

#[test]
fn no_output_may_take_a_store_files_name_in_any_folder() {
    let ham = Ham::imported();
    let other = scratch();
    let elsewhere = other.join("STORE.XML");
    std::fs::write(&elsewhere, b"another store's index").expect("write");
    let mut request = REQUEST.to_vec();
    let own = ham.dir.join("store.xml");
    for out in [&own, &elsewhere] {
        let before = std::fs::read(out).expect("there");
        for args in [
            vec![
                "sign",
                path(&set("adif/W4W-EVENT.adi")),
                "-l",
                "W4W-EVENT",
                "--again",
                "--force",
                "-o",
                path(out),
            ],
            vec![
                "-x",
                "-a",
                "all",
                "-l",
                "W4W-EVENT",
                "-o",
                path(out),
                path(&set("adif/W4W-EVENT.adi")),
            ],
            vec![
                "-x",
                "-i",
                path(&set("standard.tbk")),
                "-l",
                "W4W-EVENT",
                "-o",
                path(out),
                path(&set("adif/W4W-EVENT.adi")),
            ],
            {
                request.truncate(REQUEST.len());
                request.push(path(out));
                request.push("--force");
                request.clone()
            },
        ] {
            let ran = ham.run(&args);
            assert_eq!(ran.code, 7, "{args:?}: {}", ran.err);
            assert_eq!(std::fs::read(out).expect("still there"), before, "{args:?}");
        }
    }
    assert!(ham.store.pending_requests().expect("pending").is_empty());
}

#[test]
fn a_logger_that_cannot_be_asked_signs_nothing_when_a_qso_cannot_be_signed() {
    let ham = Ham::unsigned();
    let dir = scratch();
    let adi = dir.join("bad.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    std::fs::write(&adi, log.replacen("<MODE:2>CW ", "", 1)).expect("write");
    for args in [
        vec!["-x", "-u", "-l", "W4W-EVENT", path(&adi)],
        vec!["-x", "-u", "-a", "ask", "-l", "W4W-EVENT", path(&adi)],
    ] {
        let ran = ham.run(&args);
        assert_eq!(ran.code, 8, "{args:?}: {}", ran.err);
        assert!(
            ran.err.contains("-a compliant signs the rest"),
            "{}",
            ran.err
        );
    }
    assert!(ham.sent.borrow().is_empty());
    assert!(!dir.join("bad.tq8").exists());
}

#[test]
fn sign_says_when_some_qsos_were_left_out() {
    let ham = Ham::unsigned();
    let dir = scratch();
    let adi = dir.join("bad.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    std::fs::write(&adi, log.replacen("<MODE:2>CW ", "", 1)).expect("write");
    let ran = ham.run(&["sign", path(&adi), "-l", "W4W-EVENT"]);
    assert_eq!(ran.code, 9, "{}", ran.err);
    assert!(ran.out.contains("1 not signed, named above"), "{}", ran.out);
}

#[test]
fn f_works_with_i_on_the_same_path_as_the_store() {
    let ham = Ham::new();
    let dir = scratch();
    let adi = dir.join("moved.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    std::fs::write(
        &adi,
        log.replacen("<EOR>", "<MY_GRIDSQUARE:4>AA00 <EOR>", 1),
    )
    .expect("write");
    let i = path(&set("standard.tbk")).to_string();
    let report = ham.run(&["-x", "-i", &i, "-l", "W4W-EVENT", path(&adi)]);
    assert_eq!(report.code, 9, "{}", report.err);
    let _ = std::fs::remove_file(dir.join("moved.tq8"));
    let ignore = ham.run(&[
        "-x",
        "-f",
        "ignore",
        "-i",
        &i,
        "-l",
        "W4W-EVENT",
        path(&adi),
    ]);
    assert_eq!(ignore.code, 0, "{}", ignore.err);
}

#[test]
fn an_invalid_location_from_the_log_leaves_out_that_qso_only_with_i() {
    let ham = Ham::new();
    let dir = scratch();
    let adi = dir.join("state.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    std::fs::write(&adi, log.replacen("<EOR>", "<MY_STATE:2>XX <EOR>", 1)).expect("write");
    let ran = ham.run(&[
        "-x",
        "-a",
        "all",
        "-f",
        "update",
        "-i",
        path(&set("standard.tbk")),
        "-l",
        "W4W-EVENT",
        path(&adi),
    ]);
    assert_eq!(ran.code, 9, "{}", ran.err);
    assert!(dir.join("state.tq8").exists());
}

#[test]
fn a_call_that_is_not_ascii_signs_and_uploads_with_allow_bad_calls() {
    let ham = Ham::unsigned();
    let dir = scratch();
    let adi = dir.join("unicode.adi");
    let log = String::from_utf8(read("adif/W4W-EVENT.adi")).expect("text");
    let call = "TESTÉ";
    let changed = log.replacen("<CALL:6>KC4QPQ", &format!("<CALL:{}>{call}", call.len()), 1);
    assert_ne!(changed, log);
    std::fs::write(&adi, changed).expect("write");
    let ran = ham.run(&["send", path(&adi), "-l", "W4W-EVENT", "--allow-bad-calls"]);
    assert_eq!(ran.code, 0, "{}{}", ran.out, ran.err);
    assert_eq!(ham.sent.borrow().len(), 1);
}
