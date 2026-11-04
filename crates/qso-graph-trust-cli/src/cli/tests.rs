// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `qg-trust` run as a logger runs it, against the standard test set (tests/corpus/standard): its
//! TQSL backup, its test root (never LoTW's), its logs and tqsllib's signed logs of them.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use qso_graph_trust::certificate::Trust;
use qso_graph_trust::{gzip, tbk};
use zeroize::Zeroizing;

use super::{Env, Exit, run};

fn set(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/standard")
        .join(file)
}

fn read(file: &str) -> Vec<u8> {
    std::fs::read(set(file)).unwrap_or_else(|e| panic!("{file}: {e}"))
}

/// A folder of its own for each test's output.
fn scratch() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "qg-trust-cli-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("a scratch folder");
    dir
}

/// One run of `qg-trust`: its exit code, standard output and standard error, and the prompts it
/// asked a password with.
struct Ran {
    code: u8,
    out: String,
    err: String,
    prompts: Vec<String>,
}

/// Runs `qg-trust` at a time KC4QPQ's and W4W's certificates are both in force, answering a
/// password prompt with `password` (None: a prompt is a failure).
fn qg_trust(args: &[&str], password: Option<&[u8]>) -> Ran {
    let trust = Trust::with_roots(&[&read("pki/root.pem")]).expect("the test root");
    let backup = tbk::read(&read("standard.tbk"), &trust).expect("the backup");
    let w4w = backup
        .certificates
        .iter()
        .find(|c| c.callsign == "W4W")
        .expect("W4W");
    let now = w4w.certificate.as_ref().expect("W4W's").validity().0 + Duration::from_secs(3600);
    run_at(args, password, &trust, now)
}

fn run_at(args: &[&str], password: Option<&[u8]>, trust: &Trust, now: SystemTime) -> Ran {
    let mut prompts = Vec::new();
    let mut ask = |prompt: &str| -> io::Result<Zeroizing<Vec<u8>>> {
        prompts.push(prompt.to_string());
        password
            .map(|p| Zeroizing::new(p.to_vec()))
            .ok_or_else(|| io::Error::other("no password was expected"))
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let code = run(
        &args,
        &mut Env {
            trust,
            now,
            ask_password: &mut ask,
            out: &mut out,
            err: &mut err,
        },
    );
    Ran {
        code,
        out: String::from_utf8(out).expect("text"),
        err: String::from_utf8(err).expect("text"),
        prompts,
    }
}

fn password(call: &str) -> Vec<u8> {
    read(&format!("keys/{call}.password"))
}

fn path(p: &Path) -> &str {
    p.to_str().expect("a UTF-8 path")
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

fn final_status(ran: &Ran) -> &str {
    ran.err.lines().last().expect("a final line")
}

#[test]
fn every_location_signs_as_tqsllib_signs_it() {
    let dir = scratch();
    let trust = Trust::with_roots(&[&read("pki/root.pem")]).expect("the test root");
    let backup = tbk::read(&read("standard.tbk"), &trust).expect("the backup");
    for location in &backup.locations {
        let call = location.station.call();
        let out = dir.join(format!("{}.tq8", location.name));
        let adi = set(&format!("adif/{}.adi", location.name));
        let pw = password(call);
        let ran = qg_trust(
            &[
                "-x",
                "-i",
                path(&set("standard.tbk")),
                "-l",
                &location.name,
                "-o",
                path(&out),
                path(&adi),
            ],
            (!pw.is_empty()).then_some(pw.as_slice()),
        );
        assert_eq!(ran.code, 0, "{}: {}", location.name, ran.err);
        assert_eq!(final_status(&ran), "Final Status: Success(0)");
        assert_eq!(
            body(&signed(&out)),
            body(&read(&format!("signed/{}.tq7", location.name))),
            "{}",
            location.name
        );
        // A key with a password asks once, naming whose key; one without asks nothing.
        assert_eq!(
            ran.prompts.len(),
            usize::from(!pw.is_empty()),
            "{}",
            location.name
        );
    }
}

#[test]
fn the_output_defaults_to_the_log_with_tq8() {
    let dir = scratch();
    let adi = dir.join("club.adi");
    std::fs::copy(set("adif/KN4YU-CLUB.adi"), &adi).expect("copy");
    let ran = qg_trust(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            path(&adi),
        ],
        None,
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(dir.join("club.tq8").is_file());
    assert!(ran.prompts.is_empty(), "KN4YU's key has no password");
}

#[test]
fn a_wrong_password_writes_nothing_and_says_so_with_tqsls_code() {
    let dir = scratch();
    let out = dir.join("home.tq8");
    let ran = qg_trust(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KC4QPQ-HOME",
            "-o",
            path(&out),
            path(&set("adif/KC4QPQ-HOME.adi")),
        ],
        Some(b"not the password"),
    );
    assert_eq!(ran.code, Exit::BadPassphrase as u8, "{}", ran.err);
    assert_eq!(ran.prompts, ["Password for KC4QPQ's key: "]);
    assert!(!out.exists() && !dir.join("home.tq8.partial").exists());
    assert!(
        !ran.err.contains("not the password"),
        "the password is never printed"
    );
}

#[test]
fn a_date_range_leaves_out_the_qsos_outside_it() {
    let dir = scratch();
    let args = |b: &str, e: &str, out: &Path| {
        vec![
            "-i".to_string(),
            path(&set("standard.tbk")).to_string(),
            "-l".to_string(),
            "KN4YU-CLUB".to_string(),
            "-b".to_string(),
            b.to_string(),
            "-e".to_string(),
            e.to_string(),
            "-o".to_string(),
            path(out).to_string(),
            path(&set("adif/KN4YU-CLUB.adi")).to_string(),
        ]
    };
    // The set's QSOs are dated 2026-11-03: inside the range, in either of TQSL's forms.
    let inside = dir.join("inside.tq8");
    let ran = qg_trust(&strs(&args("2026-11-01", "20261130", &inside)), None);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(inside.is_file());
    // Every QSO outside it: nothing to sign, nothing written, as TQSL says it.
    let outside = dir.join("outside.tq8");
    let ran = qg_trust(&strs(&args("2026-12-01", "2026-12-31", &outside)), None);
    assert_eq!(ran.code, Exit::NoQsos as u8, "{}", ran.err);
    assert!(
        ran.err
            .contains("QSOs were outside the selected date range"),
        "{}",
        ran.err
    );
    assert_eq!(final_status(&ran), "Final Status: No QSOs to upload(8)");
    assert!(!outside.exists());
}

#[test]
fn a_qso_lotw_would_refuse_is_left_out_and_the_rest_signed() {
    let dir = scratch();
    let adi = dir.join("mixed.adi");
    let mut log = read("adif/KN4YU-CLUB.adi");
    log.extend_from_slice(
        b"<CALL:5>M0EHA <QSO_DATE:8>20261103 <TIME_ON:4>0100 <BAND:4>99mm <MODE:2>CW <EOR>\n",
    );
    std::fs::write(&adi, &log).expect("write");
    let out = dir.join("mixed.tq8");
    let ran = qg_trust(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            "-o",
            path(&out),
            path(&adi),
        ],
        None,
    );
    assert_eq!(ran.code, Exit::QsosSuppressed as u8, "{}", ran.err);
    assert!(ran.err.contains("QSO 4: not signed"), "{}", ran.err);
    assert_eq!(
        final_status(&ran),
        "Final Status: Some QSOs not processed(9)"
    );
    let contacts = body(&signed(&out)).matches("tCONTACT").count();
    assert_eq!(contacts, 3, "the three good QSOs are signed");
}

#[test]
fn a_backup_not_under_the_trusted_root_signs_nothing() {
    // LoTW's root, as the real program has it: the set's test certificates are not under it.
    let ran = run_at(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        None,
        &Trust::lotw(),
        SystemTime::now(),
    );
    assert_eq!(ran.code, Exit::InputError as u8, "{}", ran.err);
}

#[test]
fn a_location_not_in_the_backup_names_those_that_are() {
    let ran = qg_trust(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "NOWHERE",
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        None,
    );
    assert_eq!(ran.code, Exit::CommandError as u8);
    assert!(
        ran.err.contains("KC4QPQ-HOME") && ran.err.contains("W4W-EVENT"),
        "{}",
        ran.err
    );
}

#[test]
fn files_that_cannot_be_read_are_tqsls_input_error() {
    let missing = scratch().join("missing");
    for args in [
        vec![
            "-i",
            path(&missing),
            "-l",
            "KN4YU-CLUB",
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        vec![
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            path(&missing),
        ],
    ] {
        assert_eq!(
            qg_trust(&args, None).code,
            Exit::InputError as u8,
            "{args:?}"
        );
    }
}

#[test]
fn an_output_that_cannot_be_written_is_tqsls_output_error() {
    let out = scratch().join("no such folder").join("x.tq8");
    let ran = qg_trust(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            "-o",
            path(&out),
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        None,
    );
    assert_eq!(ran.code, Exit::OutputError as u8, "{}", ran.err);
}

#[test]
fn the_command_line_is_refused_with_tqsls_syntax_code() {
    let tbk = path(&set("standard.tbk")).to_string();
    let log = path(&set("adif/KN4YU-CLUB.adi")).to_string();
    for args in [
        vec![],
        vec![log.as_str()],
        vec!["-i", &tbk, log.as_str()],
        vec!["-l", "KN4YU-CLUB", log.as_str()],
        vec!["-i", &tbk, "-l", "KN4YU-CLUB"],
        vec!["-i", &tbk, "-l", "KN4YU-CLUB", log.as_str(), log.as_str()],
        vec![
            "-i",
            &tbk,
            "-l",
            "KN4YU-CLUB",
            "-b",
            "2026-13-01",
            log.as_str(),
        ],
        vec![
            "-i",
            &tbk,
            "-l",
            "KN4YU-CLUB",
            "-b",
            "2026-12-01",
            "-e",
            "2026-11-01",
            log.as_str(),
        ],
        vec!["-i", &tbk, "-l", "KN4YU-CLUB", "-u", log.as_str()],
        vec!["-i", &tbk, "-l", "KN4YU-CLUB", "--bogus", log.as_str()],
        vec!["-i", &tbk, "-l"],
    ] {
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, Exit::CommandError as u8, "{args:?}: {}", ran.err);
        assert_eq!(
            final_status(&ran),
            "Final Status: Command Syntax Error(10)",
            "{args:?}"
        );
    }
}

#[test]
fn a_password_on_the_command_line_is_refused_and_never_echoed() {
    let ran = qg_trust(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KC4QPQ-HOME",
            "-p",
            "hunter2",
            path(&set("adif/KC4QPQ-HOME.adi")),
        ],
        None,
    );
    assert_eq!(ran.code, Exit::CommandError as u8);
    assert!(
        ran.err.contains("never given on the command line"),
        "{}",
        ran.err
    );
    assert!(!ran.err.contains("hunter2"));
    assert!(ran.prompts.is_empty());
}

#[test]
fn long_options_take_tqsls_names_with_a_space_or_an_equals_sign() {
    let dir = scratch();
    let out = dir.join("long.tq8");
    let tbk = format!("--import={}", path(&set("standard.tbk")));
    let ran = qg_trust(
        &[
            &tbk,
            "--location",
            "KN4YU-CLUB",
            "--output",
            path(&out),
            "--batch",
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        None,
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(out.is_file());
}

#[test]
fn help_and_version_print_and_exit_zero() {
    let ran = qg_trust(&["--version"], None);
    assert_eq!(
        (ran.code, ran.out.trim()),
        (0, format!("qg-trust {}", qso_graph_trust::VERSION).as_str())
    );
    let ran = qg_trust(&["-h"], None);
    assert_eq!(ran.code, 0);
    assert!(
        ran.out
            .contains("Usage: qg-trust -i BACKUP.tbk -l LOCATION")
    );
    assert!(ran.err.is_empty());
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}
