// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `qg-trust` run as a logger runs it, against the standard test set (tests/corpus/standard): its
//! TQSL backup, its test root (never LoTW's), its logs and tqsllib's signed logs of them.

use std::ffi::OsString;
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
    std::fs::read(set(file)).expect("a file of the standard test set")
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
    run_with_color(args, password, trust, now, false)
}

fn run_with_color(
    args: &[&str],
    password: Option<&[u8]>,
    trust: &Trust,
    now: SystemTime,
    color: bool,
) -> Ran {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    run_os_with_colors(&args, password, trust, now, color, color)
}

fn run_os_with_colors(
    args: &[OsString],
    password: Option<&[u8]>,
    trust: &Trust,
    now: SystemTime,
    color_out: bool,
    color_err: bool,
) -> Ran {
    let mut prompts = Vec::new();
    let mut ask = |prompt: &str| -> io::Result<Zeroizing<Vec<u8>>> {
        prompts.push(prompt.to_string());
        password
            .map(|p| Zeroizing::new(p.to_vec()))
            .ok_or_else(|| io::Error::other("no password was expected"))
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let no_store =
        || -> Result<&qso_graph_trust::store::Store, qso_graph_trust::store::StoreError> {
            panic!("the TQSL-style command line does not open the store")
        };
    let mut no_upload =
        |_: &qso_graph_trust::upload::UploadRequest| -> Result<(u16, Vec<u8>), super::UploadFailure> {
            panic!("the TQSL-style command line does not upload")
        };
    let code = run(
        args,
        &mut Env {
            trust,
            now,
            color_out,
            color_err,
            ask_password: &mut ask,
            out: &mut out,
            err: &mut err,
            store: &no_store,
            upload: &mut no_upload,
            trace: super::Trace::off(),
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
    // LoTW's root, as the real program has it: the set's test certificates are not under it. The
    // backup brings their root, one that `qg-trust import` would trust from a backup, but -i has
    // no way to confirm or keep a root: it refuses, with TQSL's input error.
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
        vec!["-i", &tbk, log.as_str()],
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
        vec!["-i", &tbk, "-l", "KN4YU-CLUB", "-a", "maybe", log.as_str()],
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
fn backup_without_location_names_the_files_locations() {
    let ran = qg_trust(
        &[
            "-i",
            path(&set("standard.tbk")),
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        None,
    );
    assert_eq!(ran.code, 10, "{}", ran.err);
    assert!(
        ran.err.contains("KN4YU-CLUB") && ran.err.contains("W4W-EVENT"),
        "{}",
        ran.err
    );
}

#[test]
fn a_passphrase_with_p_unlocks_a_protected_key_says_it_is_not_needed_and_is_never_echoed() {
    let dir = scratch();
    let right = String::from_utf8(password("KC4QPQ")).expect("the test passphrase is text");
    assert!(!right.is_empty(), "KC4QPQ's test key has a passphrase");
    for (given, code) in [(right.as_str(), 0), ("hunter2", Exit::BadPassphrase as u8)] {
        let out = dir.join(format!("{code}.tq8"));
        let ran = qg_trust(
            &[
                "-x",
                "-i",
                path(&set("standard.tbk")),
                "-l",
                "KC4QPQ-HOME",
                "-p",
                given,
                "-o",
                path(&out),
                path(&set("adif/KC4QPQ-HOME.adi")),
            ],
            None,
        );
        assert_eq!(ran.code, code, "{}", ran.err);
        // -p takes the place of asking, as in TQSL.
        assert!(ran.prompts.is_empty());
        assert!(
            ran.err.contains("-p is TQSL's key passphrase"),
            "{}",
            ran.err
        );
        assert!(!ran.out.contains(given) && !ran.err.contains(given));
    }
}

#[test]
fn a_passphrase_with_p_is_accepted_and_ignored_for_a_key_with_none() {
    let dir = scratch();
    let out = dir.join("club.tq8");
    let ran = qg_trust(
        &[
            "-x",
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            "-p",
            "",
            "-o",
            path(&out),
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        Some(&password("KN4YU")),
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(final_status(&ran), "Final Status: Success(0)");
    assert!(
        ran.err.contains("-p is TQSL's key passphrase"),
        "{}",
        ran.err
    );
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
    let short = qg_trust(&["-v"], None);
    assert_eq!(short.out, ran.out);
    let ran = qg_trust(&["-h"], None);
    assert_eq!(ran.code, 0);
    assert!(ran.out.contains("Usage: qg-trust"), "{}", ran.out);
    assert!(ran.out.contains("--import <FILE>"), "{}", ran.out);
    assert!(ran.out.contains("--location <NAME>"), "{}", ran.out);
    assert!(ran.err.is_empty());
}

#[test]
fn clap_errors_keep_the_syntax_code_and_final_status() {
    for args in [
        vec!["--bogus"],
        vec!["-i"],
        vec!["--location="],
        vec!["--import="],
        vec!["--completions", "unknown-shell"],
        vec!["-V"],
    ] {
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, Exit::CommandError as u8, "{args:?}: {}", ran.err);
        assert!(ran.err.starts_with("qg-trust:"), "{}", ran.err);
        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
        assert!(ran.out.is_empty());
        assert!(ran.prompts.is_empty());
    }
}

#[test]
fn completions_name_the_program_and_never_use_color_or_a_status_line() {
    let trust = Trust::lotw();
    for color in [false, true] {
        for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
            let ran = run_with_color(
                &["--completions", shell],
                None,
                &trust,
                SystemTime::now(),
                color,
            );
            assert_eq!(ran.code, 0, "{shell}: {}", ran.err);
            assert!(ran.out.contains("qg-trust"), "{shell}: {}", ran.out);
            assert!(!ran.out.contains("Final Status:"));
            assert!(!ran.out.contains('\x1b'), "{shell}: {}", ran.out);
            assert!(ran.err.is_empty(), "{shell}: {}", ran.err);
            assert!(ran.prompts.is_empty());
        }
    }
}

#[test]
fn help_version_and_parse_errors_follow_the_color_choice() {
    let trust = Trust::lotw();
    for color in [false, true] {
        for flag in ["-h", "--help", "-v", "--version", "--bogus"] {
            let ran = run_with_color(&[flag], None, &trust, SystemTime::now(), color);
            if flag == "--bogus" {
                assert_eq!(ran.code, Exit::CommandError as u8);
                assert_eq!(ran.err.contains('\x1b'), color, "{}", ran.err);
                assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
            } else {
                assert_eq!(ran.code, 0);
                assert!(ran.err.is_empty());
                if matches!(flag, "-h" | "--help") {
                    assert_eq!(ran.out.contains('\x1b'), color, "{}", ran.out);
                    assert!(ran.out.contains("Signing:"));
                    assert!(ran.out.contains("Accepted for loggers that pass them:"));
                    assert!(ran.out.contains("--completions <SHELL>"));
                    assert!(ran.out.contains("the key's password is asked for"));
                }
            }
            if !color {
                assert!(!ran.out.contains('\x1b') && !ran.err.contains('\x1b'));
            }
        }
    }
}

#[test]
fn signing_messages_follow_the_color_choice_and_leave_the_status_plain() {
    let trust = Trust::with_roots(&[&read("pki/root.pem")]).expect("the test root");
    let backup = tbk::read(&read("standard.tbk"), &trust).expect("the backup");
    let now = backup
        .certificates
        .iter()
        .find(|entry| entry.callsign == "W4W")
        .expect("W4W")
        .certificate
        .as_ref()
        .expect("W4W's")
        .validity()
        .0
        + Duration::from_secs(3600);
    let dir = scratch();
    let mixed = dir.join("mixed.adi");
    let mut log = read("adif/KN4YU-CLUB.adi");
    log.extend_from_slice(
        b"<CALL:5>M0EHA <QSO_DATE:8>20261103 <TIME_ON:4>0100 <BAND:4>99mm <MODE:2>CW <EOR>\n",
    );
    std::fs::write(&mixed, log).expect("write");
    for color in [false, true] {
        for (input, code, status) in [
            (
                set("adif/KN4YU-CLUB.adi"),
                Exit::Success,
                "Final Status: Success(0)",
            ),
            (
                mixed.clone(),
                Exit::QsosSuppressed,
                "Final Status: Some QSOs not processed(9)",
            ),
        ] {
            let output = dir.join("signed.tq8");
            let ran = run_with_color(
                &[
                    "-i",
                    path(&set("standard.tbk")),
                    "-l",
                    "KN4YU-CLUB",
                    "-o",
                    path(&output),
                    "-x",
                    "-q",
                    "-d",
                    path(&input),
                ],
                None,
                &trust,
                now,
                color,
            );
            assert_eq!(ran.code, code as u8, "{}", ran.err);
            assert_eq!(final_status(&ran), status);
            let signed = ran
                .err
                .lines()
                .find(|line| line.contains("signed 3 QSOs"))
                .expect("signed");
            assert_eq!(signed.contains("\x1b[32m"), color, "{signed}");
            if code == Exit::QsosSuppressed {
                let warning = ran
                    .err
                    .lines()
                    .find(|line| line.contains("not signed:"))
                    .expect("left out");
                assert_eq!(warning.contains("\x1b[33m"), color, "{warning}");
            }
            assert!(!final_status(&ran).contains('\x1b'));
            if !color {
                assert!(!ran.out.contains('\x1b') && !ran.err.contains('\x1b'));
            }
        }
    }
}

#[test]
fn unsupported_tqsl_options_are_refused_on_sight() {
    for (flag, message) in [
        (
            "-n",
            "qg-trust does not update itself: it is updated by your package manager (apt, dnf, Homebrew) or its installer",
        ),
        (
            "--updates",
            "qg-trust does not update itself: it is updated by your package manager (apt, dnf, Homebrew) or its installer",
        ),
        (
            "-s",
            "qg-trust has no location editor window: use qg-trust location add or qg-trust location edit",
        ),
        (
            "--editlocation",
            "qg-trust has no location editor window: use qg-trust location add or qg-trust location edit",
        ),
    ] {
        for args in [vec![flag], vec![flag, "unused-value"]] {
            let ran = qg_trust(&args, None);
            assert_eq!(ran.code, 10);
            assert!(ran.err.contains(message), "{}", ran.err);
            assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
        }
    }
}

#[test]
fn password_options_are_never_echoed_even_beside_a_parse_error() {
    for args in [
        vec!["--password=hunter2"],
        vec!["--password", "hunter2"],
        vec!["-phunter2"],
        vec!["-xqp", "hunter2"],
        vec!["--bogus", "--password=hunter2"],
        vec!["-i", "--password=hunter2"],
    ] {
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, Exit::CommandError as u8, "{args:?}: {}", ran.err);
        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
        assert!(!ran.out.contains("hunter2") && !ran.err.contains("hunter2"));
        assert!(ran.prompts.is_empty());
    }
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

#[test]
fn round_two_parse_errors_never_echo_arguments() {
    for args in [
        vec!["--", "log.adi", "--password=SECRET"],
        vec!["--begindate=--password=SECRET"],
        vec!["-bpSECRET"],
        vec!["--completions", "SECRET"],
        vec!["--location", "--SECRET"],
        vec!["--SECRET"],
        vec!["-ZSECRET"],
        vec!["--bégin=SECRET"],
        vec!["-p", "SECRET"],
        vec!["-pSECRET"],
        vec!["--password=SECRET"],
        vec!["-xqp", "SECRET"],
    ] {
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, Exit::CommandError as u8, "{args:?}");
        assert!(
            !ran.out.contains("SECRET") && !ran.err.contains("SECRET"),
            "{args:?}: {}",
            ran.err
        );
        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
        assert!(ran.prompts.is_empty());
    }
}

#[test]
fn help_does_not_bypass_clap_parse_errors_or_an_earlier_refusal() {
    for args in [
        vec!["--SECRET", "--help"],
        vec!["--completions", "SECRET", "-h"],
    ] {
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, Exit::CommandError as u8, "{args:?}: {}", ran.err);
        assert!(ran.out.is_empty());
        assert!(!ran.err.contains("SECRET"));
        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
        assert!(ran.prompts.is_empty());
    }
}

#[test]
fn round_two_repeated_options_use_the_last_value() {
    let dir = scratch();
    let output = dir.join("last.tq8");
    let ran = qg_trust(
        &[
            "-x",
            "-x",
            "-q",
            "-q",
            "-d",
            "-d",
            "-i",
            "missing.tbk",
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "NOWHERE",
            "-l",
            "KN4YU-CLUB",
            "-b",
            "20990101",
            "-b",
            "20261101",
            "-e",
            "20000101",
            "-e",
            "20261130",
            "-o",
            "unused.tq8",
            "-o",
            path(&output),
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        None,
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(output.is_file());
    assert_eq!(final_status(&ran), "Final Status: Success(0)");
}

#[test]
fn round_two_values_may_start_with_a_hyphen() {
    use clap::Parser;

    let options = super::Options::try_parse_from([
        "qg-trust",
        "-i",
        "-file.tbk",
        "-l",
        "-home",
        "-o",
        "-out.tq8",
        "log.adi",
    ])
    .expect("hyphen-leading values");
    assert_eq!(options.backup.as_deref(), Some(Path::new("-file.tbk")));
    assert_eq!(options.location.as_deref(), Some("-home"));
    assert_eq!(options.output.as_deref(), Some(Path::new("-out.tq8")));
    let ran = qg_trust(&["-i", "-file.tbk", "-l", "-home", "log.adi"], None);
    assert_eq!(ran.code, Exit::InputError as u8, "{}", ran.err);
    assert!(ran.err.contains("the certificate file (-i)"));
    assert!(!ran.err.contains("-file.tbk"));
    for flag in ["-b", "-e"] {
        let ran = qg_trust(&[flag, "-SECRET"], None);
        assert_eq!(ran.code, Exit::CommandError as u8);
        assert!(!ran.err.contains("SECRET"), "{}", ran.err);
        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
    }
}

#[cfg(unix)]
#[test]
fn round_two_invalid_unicode_is_refused_without_echo_or_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let args = [OsStr::from_bytes(b"-p\xffSECRET").to_os_string()];
    let trust = Trust::lotw();
    for color in [false, true] {
        let ran = run_os_with_colors(&args, None, &trust, SystemTime::now(), color, color);
        assert_eq!(ran.code, Exit::CommandError as u8);
        assert!(ran.out.is_empty());
        assert!(ran.err.contains("an argument is not valid text"));
        assert!(!ran.err.contains("SECRET"));
        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
        assert!(ran.prompts.is_empty());
    }
}

#[test]
fn round_two_color_is_chosen_for_each_stream() {
    let trust = Trust::lotw();
    for color_out in [false, true] {
        for color_err in [false, true] {
            for flag in ["--help", "--version", "--SECRET"] {
                let args = [OsString::from(flag)];
                let ran = run_os_with_colors(
                    &args,
                    None,
                    &trust,
                    SystemTime::now(),
                    color_out,
                    color_err,
                );
                assert!(!ran.out.contains("SECRET") && !ran.err.contains("SECRET"));
                match flag {
                    "--help" => {
                        assert_eq!(ran.code, 0);
                        assert_eq!(ran.out.contains('\x1b'), color_out);
                        assert!(ran.err.is_empty());
                    }
                    "--version" => {
                        assert_eq!(ran.code, 0);
                        assert!(ran.out.starts_with("qg-trust "));
                        assert!(ran.err.is_empty());
                    }
                    _ => {
                        assert_eq!(ran.code, Exit::CommandError as u8);
                        assert!(ran.out.is_empty());
                        assert_eq!(ran.err.contains('\x1b'), color_err);
                        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
                    }
                }
            }
        }
    }
}

#[test]
fn round_two_hidden_options_are_refused_after_a_successful_parse() {
    use clap::Parser;

    let trust = Trust::lotw();
    for flag in ["-n", "--updates", "-s", "--editlocation"] {
        for value in [None, Some("-SECRET")] {
            let mut args = vec!["--completions", "bash", flag];
            args.extend(value);
            let options = super::Options::try_parse_from(
                std::iter::once("qg-trust").chain(args.iter().copied()),
            )
            .expect("hidden options accept an optional hyphen-leading value");
            assert!(options.rejected.updates.is_some() || options.rejected.editlocation.is_some());
            let ran = run_with_color(&args, None, &trust, SystemTime::now(), false);
            assert_eq!(ran.code, Exit::CommandError as u8);
            assert!(ran.out.is_empty());
            assert!(!ran.err.contains("SECRET"));
            assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
            assert!(ran.err.contains(if matches!(flag, "-n" | "--updates") {
                "does not update itself"
            } else {
                "has no location editor window"
            }));
        }
    }
    let help = run_with_color(&["--help"], None, &trust, SystemTime::now(), false);
    for flag in ["--password", "--updates", "--editlocation"] {
        assert!(!help.out.contains(flag));
    }
}

#[test]
fn round_two_date_parser_and_diagnostics_use_only_fixed_text() {
    assert_eq!(
        super::date("SECRET").expect_err("invalid date"),
        "a date must be YYYY-MM-DD or YYYYMMDD"
    );
    for (args, message) in [
        (
            vec!["--begindate=SECRET"],
            "--begindate needs a date (YYYY-MM-DD or YYYYMMDD)",
        ),
        (
            vec!["--enddate=-SECRET"],
            "--enddate needs a date (YYYY-MM-DD or YYYYMMDD)",
        ),
        (
            vec!["--completions", "SECRET"],
            "--completions takes bash, zsh, fish, powershell or elvish",
        ),
        (
            vec!["--SECRET"],
            "an option qg-trust does not know was given",
        ),
        (vec!["-i"], "-i names the file with your certificate"),
        (vec!["-l"], "-l names the station location to sign for"),
        (vec!["-o"], "-o names the file for the signed log"),
    ] {
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, Exit::CommandError as u8);
        assert!(ran.err.contains(message), "{}", ran.err);
        assert!(!ran.out.contains("SECRET") && !ran.err.contains("SECRET"));
        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
    }
}

#[test]
/// A refused option anywhere on the line is refused, before help or the version; help and the
/// version otherwise follow the order they are given in.
fn round_three_control_options_follow_parser_order() {
    for (args, code, message) in [
        // -p is accepted, so -v prints the version and ends the run, as in TQSL.
        (vec!["-p", "SECRET", "--version"], 0, "qg-trust "),
        (vec!["--version", "-p", "SECRET"], 0, "qg-trust "),
        (
            vec!["-p", "SECRET", "--version", "-p", "SECRET2"],
            0,
            "qg-trust ",
        ),
        (vec!["-b", "--help"], 10, "--begindate needs a date"),
        (
            vec!["-i", "--help", "-l", "home", "log.adi"],
            6,
            "the certificate file (-i)",
        ),
        (vec!["--help"], 0, "Usage: qg-trust"),
        (vec!["--version", "--help"], 0, "qg-trust "),
        (vec!["--help", "--version"], 0, "Usage: qg-trust"),
    ] {
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, code, "{args:?}: {}", ran.err);
        assert!(!ran.out.contains("SECRET") && !ran.err.contains("SECRET"));
        if code == 0 {
            assert!(ran.out.contains(message), "{args:?}: {}", ran.out);
            assert!(ran.err.is_empty());
        } else {
            assert!(ran.out.is_empty());
            assert!(ran.err.contains(message), "{args:?}: {}", ran.err);
            assert!(final_status(&ran).starts_with("Final Status:"));
        }
        assert!(ran.prompts.is_empty());
    }
}

#[test]
fn round_three_runtime_diagnostics_never_echo_command_line_values() {
    let dir = scratch();
    let backup = set("standard.tbk");
    let log = set("adif/KN4YU-CLUB.adi");
    let bad_backup = dir.join("SECRET.tbk");
    std::fs::write(&bad_backup, b"not a backup").expect("write");
    let bad_output = dir.join("SECRET").join("output.tq8");
    for (args, code, message) in [
        (
            vec!["-i--password=SECRET", "-l", "home", "log.adi"],
            6,
            "the certificate file (-i)",
        ),
        (
            vec!["-i", "x.tbk", "-l", "--password=SECRET", "log.adi"],
            6,
            "the certificate file (-i)",
        ),
        (
            vec!["-i", path(&bad_backup), "-l", "home", "log.adi"],
            6,
            "the certificate file (-i)",
        ),
        (
            vec!["-i", path(&backup), "-l", "--password=SECRET", path(&log)],
            10,
            "the station location given to -l is not in the certificate file; there are:",
        ),
        (
            vec!["-i", path(&backup), "-l", "KN4YU-CLUB", "SECRET.adi"],
            6,
            "the log:",
        ),
        (
            vec![
                "-i",
                path(&backup),
                "-l",
                "KN4YU-CLUB",
                "-o",
                path(&bad_output),
                path(&log),
            ],
            7,
            "the output file (-o):",
        ),
        (vec!["-o", "--password=SECRET"], 10, "give the log to sign"),
    ] {
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, code, "{args:?}: {}", ran.err);
        assert!(ran.err.contains(message), "{args:?}: {}", ran.err);
        assert!(
            !ran.out.contains("SECRET") && !ran.err.contains("SECRET"),
            "{}",
            ran.err
        );
        assert!(ran.prompts.is_empty());
    }
}

#[test]
fn round_three_signing_messages_use_only_file_roles_and_certificate_calls() {
    let dir = scratch();
    let input = dir.join("SECRET.adi");
    let output = dir.join("SECRET.tq8");
    let backup = set("standard.tbk");
    let mut log = read("adif/KN4YU-CLUB.adi");
    log.extend_from_slice(
        b"<CALL:5>M0EHA <QSO_DATE:8>20261103 <TIME_ON:4>0100 <BAND:4>99mm <MODE:2>CW <EOR>\n",
    );
    std::fs::write(&input, log).expect("write");
    for explicit_output in [false, true] {
        let mut args = vec!["-i", path(&backup), "-l", "KN4YU-CLUB"];
        if explicit_output {
            args.extend(["-o", path(&output)]);
        }
        args.push(path(&input));
        let ran = qg_trust(&args, None);
        assert_eq!(ran.code, Exit::QsosSuppressed as u8, "{}", ran.err);
        assert!(
            ran.err.contains("the log's QSO 4: not signed:"),
            "{}",
            ran.err
        );
        assert!(
            ran.err.contains("qg-trust: signed 3 QSOs for KN4YU\n"),
            "{}",
            ran.err
        );
        assert_eq!(
            ran.err.contains("written beside the log, with .tq8\n"),
            !explicit_output
        );
        assert!(!ran.err.contains("SECRET") && !ran.err.contains("KN4YU-CLUB"));
        assert_eq!(
            final_status(&ran),
            "Final Status: Some QSOs not processed(9)"
        );
    }
    let ran = qg_trust(
        &[
            "-i",
            path(&backup),
            "-l",
            "KN4YU-CLUB",
            "-b",
            "20990101",
            path(&input),
        ],
        None,
    );
    assert_eq!(ran.code, Exit::NoQsos as u8, "{}", ran.err);
    assert!(
        ran.err
            .contains("the log: 3 QSOs were outside the selected date range")
    );
    assert!(ran.err.contains("the log: no QSOs to sign"));
    assert!(!ran.err.contains("SECRET"));
}

#[test]
fn a_temporary_name_already_taken_is_never_removed() {
    let dir = scratch();
    let out = dir.join("log.tq8");
    let taken = dir.join(".log.tq8.taken.partial");
    std::fs::write(&taken, b"not ours").expect("write");
    assert!(super::write_whole_via(&out, b"signed", &taken).is_err());
    assert_eq!(std::fs::read(&taken).expect("kept"), b"not ours");
    assert!(!out.exists());
}

/// The lines of a signed log's tSTATION record.
fn station_record(tq7: &[u8]) -> String {
    let text = String::from_utf8_lossy(tq7);
    let start = text.find("tSTATION").expect("a tSTATION record");
    let end = text[start..]
        .find("<eor>")
        .map_or(text.len(), |e| start + e);
    text[start..end].to_string()
}

#[test]
fn c_signs_as_the_call_given_with_that_calls_certificate() {
    let dir = scratch();
    let out = dir.join("club-as-kc4qpq.tq8");
    let pw = password("KC4QPQ");
    let ran = qg_trust(
        &[
            "-x",
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            "-c",
            " kc4qpq ",
            "-o",
            path(&out),
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        Some(&pw),
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(ran.err.contains("signed 3 QSOs for KC4QPQ"), "{}", ran.err);
    // KC4QPQ's key is the one unlocked, so KC4QPQ's certificate signs.
    assert_eq!(ran.prompts, ["Password for KC4QPQ's key: "]);
    let station = station_record(&signed(&out));
    assert!(station.contains("<CALL:6>KC4QPQ"), "{station}");
    assert!(!station.contains("KN4YU"), "{station}");
    // The rest of the location is KN4YU-CLUB's.
    assert!(station.contains("<GRIDSQUARE:4>FM02"), "{station}");
    assert_eq!(final_status(&ran), "Final Status: Success(0)");
}

#[test]
fn c_refuses_what_is_not_a_callsign_with_tqsls_syntax_code() {
    for call in ["SECRET", "", "  ", "K", "KN4YU/", "KN 4YU"] {
        let ran = qg_trust(
            &[
                "-i",
                path(&set("standard.tbk")),
                "-l",
                "KN4YU-CLUB",
                "-c",
                call,
                path(&set("adif/KN4YU-CLUB.adi")),
            ],
            None,
        );
        assert_eq!(ran.code, Exit::CommandError as u8, "{call:?}: {}", ran.err);
        assert!(
            ran.err.contains("-c takes a callsign, such as KN4YU"),
            "{call:?}: {}",
            ran.err
        );
        assert!(!ran.err.contains("SECRET"));
        assert_eq!(final_status(&ran), "Final Status: Command Syntax Error(10)");
        assert!(ran.prompts.is_empty());
    }
}

#[test]
fn c_for_a_call_with_no_certificate_fails_as_a_locations_own_call_does() {
    let trust = Trust::with_roots(&[&read("pki/root.pem")]).expect("the test root");
    let backup = tbk::read(&read("standard.tbk"), &trust).expect("the backup");
    let w4w = backup
        .certificates
        .iter()
        .find(|c| c.callsign == "W4W")
        .expect("W4W");
    // A day after W4W's certificate ends: KN4YU's and KC4QPQ's are still in force.
    let later = w4w.certificate.as_ref().expect("W4W's").validity().1 + Duration::from_secs(86400);
    let dir = scratch();
    let own = run_at(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "W4W-EVENT",
            "-o",
            path(&dir.join("own.tq8")),
            path(&set("adif/W4W-EVENT.adi")),
        ],
        None,
        &trust,
        later,
    );
    let given = run_at(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            "-c",
            "W4W",
            "-o",
            path(&dir.join("given.tq8")),
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        None,
        &trust,
        later,
    );
    for ran in [&own, &given] {
        assert_eq!(ran.code, Exit::TqslError as u8, "{}", ran.err);
        assert_eq!(final_status(ran), "Final Status: TQSL Error(4)");
    }
    assert_eq!(own.err, given.err);
    assert!(
        own.err
            .contains("there is no certificate for W4W (DXCC 291) in force now, with its key"),
        "{}",
        own.err
    );
    assert!(!dir.join("own.tq8").exists() && !dir.join("given.tq8").exists());
    // A call with no certificate at all is the same error.
    let none = qg_trust(
        &[
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KN4YU-CLUB",
            "-c",
            "N0CALL",
            path(&set("adif/KN4YU-CLUB.adi")),
        ],
        None,
    );
    assert_eq!(none.code, Exit::TqslError as u8, "{}", none.err);
    assert!(
        none.err
            .contains("there is no certificate for N0CALL (DXCC 291)")
    );
}

/// What the diagnostic log must never hold: the password, PEM armour, and every line of the
/// backup's certificates and keys (the keys encrypted, as the backup holds them).
fn secrets(pw: &[u8]) -> Vec<String> {
    let backup = gzip::decompress(&read("standard.tbk"), 64 * 1024 * 1024).expect("gzip");
    let text = String::from_utf8_lossy(&backup).into_owned();
    let mut secrets: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.len() >= 40 && !l.contains(' ') && !l.starts_with('<'))
        .map(str::to_string)
        .collect();
    assert!(
        secrets.len() > 100,
        "the backup's key and certificate lines"
    );
    secrets.push(String::from_utf8(pw.to_vec()).expect("a text password"));
    secrets.extend(["-----BEGIN".into(), "PRIVATE".into()]);
    secrets
}

#[test]
fn t_writes_a_diagnostic_log_with_no_password_or_key_in_it() {
    let dir = scratch();
    let diag = dir.join("diag.txt");
    let pw = password("KC4QPQ");
    assert!(!pw.is_empty(), "a key with a password");
    let ran = qg_trust(
        &[
            "-x",
            "-t",
            path(&diag),
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KC4QPQ-HOME",
            "-o",
            path(&dir.join("home.tq8")),
            path(&set("adif/KC4QPQ-HOME.adi")),
        ],
        Some(&pw),
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    let log = std::fs::read_to_string(&diag).expect("the diagnostic log");
    for line in [
        "QSO Graph Trust Diagnostics\n",
        &format!("qg-trust {}\n", qso_graph_trust::VERSION),
        "System: ",
        "Command Line: qg-trust -x -t ",
        "Working Directory: ",
        "Options: location \"KC4QPQ-HOME\", keys from the certificate file (-i), -c none,",
        "Certificate file (-i) read: 3 certificates, 7 station locations\n",
        "Station location \"KC4QPQ-HOME\": call KC4QPQ, DXCC 291\n",
        "Certificate: KC4QPQ (DXCC 291), serial 10001\n",
        "Key: unlocked with the password asked for\n",
        "QSOs: 3 records read, 3 signed; left out: 0 not valid,",
        "Signed log written: to -o's file\n",
        "Final Status: Success(0)\n",
    ] {
        assert!(log.contains(line), "{line:?} in:\n{log}");
    }
    let secrets = secrets(&pw);
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    assert!(super::trace::holds_none_of(&log, &secrets), "{log}");
    // Planted: the check finds them where they are, so it would find them in the log.
    let backup = gzip::decompress(&read("standard.tbk"), 64 * 1024 * 1024).expect("gzip");
    let planted = format!(
        "{log}{}{}",
        String::from_utf8_lossy(&backup),
        String::from_utf8_lossy(&pw)
    );
    assert!(!super::trace::holds_none_of(&planted, &secrets));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&diag)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn t_writes_a_passphrase_given_with_p_only_redacted() {
    let dir = scratch();
    let diag = dir.join("diag.txt");
    let ran = qg_trust(
        &[
            "-t",
            path(&diag),
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
    // A wrong passphrase: it is used, does not unlock the key, and is never written.
    assert_eq!(ran.code, Exit::BadPassphrase as u8, "{}", ran.err);
    assert!(!ran.err.contains("hunter2"));
    let log = std::fs::read_to_string(&diag).expect("the diagnostic log");
    assert!(log.contains(" -p <redacted> "), "{log}");
    assert!(log.contains("-p is TQSL's key passphrase"), "{log}");
    assert!(
        log.contains("Key: the password given does not unlock it"),
        "{log}"
    );
    assert!(super::trace::holds_none_of(&log, &["hunter2"]), "{log}");
}

#[test]
fn t_that_cannot_be_opened_warns_and_the_run_goes_on() {
    let dir = scratch();
    let diag = dir.join("no-such-folder").join("diag.txt");
    let out = dir.join("club.tq8");
    let ran = qg_trust(
        &[
            "-t",
            path(&diag),
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
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(
        ran.err.starts_with(&format!(
            "Error opening diagnostic log {}: ",
            diag.display()
        )),
        "{}",
        ran.err
    );
    assert!(out.is_file());
    assert!(!diag.exists());
    assert_eq!(final_status(&ran), "Final Status: Success(0)");
    // A file name that could hold a password is not repeated.
    let secret = dir.join("no-such-folder").join("--password=hunter2");
    let ran = qg_trust(
        &[
            "-t",
            path(&secret),
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
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(
        ran.err
            .starts_with("Error opening diagnostic log <redacted>: ")
    );
    assert!(!ran.err.contains("hunter2"));
}

#[test]
fn c_and_t_are_shown_in_help_and_no_longer_refused() {
    let trust = Trust::lotw();
    let help = run_with_color(&["--help"], None, &trust, SystemTime::now(), false);
    for flag in ["--callsign <CALL>", "--diagnose <FILE>"] {
        assert!(help.out.contains(flag), "{}", help.out);
    }
    let diag = scratch().join("diag.txt");
    for (flag, value) in [
        ("-c", "KN4YU"),
        ("--callsign", "KN4YU"),
        ("-t", path(&diag)),
        ("--diagnose", path(&diag)),
    ] {
        let ran = qg_trust(&[flag, value], None);
        assert!(
            !ran.err.contains("not supported yet"),
            "{flag}: {}",
            ran.err
        );
        // Accepted, so what is missing is the log to sign.
        assert!(
            ran.err.contains("give the log to sign"),
            "{flag}: {}",
            ran.err
        );
    }
}

#[test]
fn logger_signs_adx_by_content_even_with_adi_extension() {
    let dir = scratch();
    let input = dir.join("log.adi");
    let output = dir.join("log.tq8");
    std::fs::write(&input, b"<ADX><HEADER/><RECORDS><RECORD><CALL>KN4YU</CALL><QSO_DATE>20261103</QSO_DATE><TIME_ON>183055</TIME_ON><BAND>20m</BAND><MODE>CW</MODE></RECORD></RECORDS></ADX>").expect("test log");
    let pw = password("KC4QPQ");
    let ran = qg_trust(
        &[
            "-x",
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KC4QPQ-HOME",
            "-o",
            path(&output),
            path(&input),
        ],
        Some(&pw),
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(!signed(&output).is_empty());
}

#[test]
fn logger_signs_cabrillo_by_content_even_with_adi_extension() {
    let dir = scratch();
    let input = dir.join("log.adi");
    let output = dir.join("log.tq8");
    std::fs::write(&input, format!("START-OF-LOG: 3.0\nCONTEST: CQ-WW-CW\nQSO: 14000 CW 2026-11-03 1830 {} 599 4 Z0TEST 599 5\nEND-OF-LOG:\n", "KC4QPQ").as_bytes()).expect("test log");
    let pw = password("KC4QPQ");
    let ran = qg_trust(
        &[
            "-x",
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "KC4QPQ-HOME",
            "-o",
            path(&output),
            path(&input),
        ],
        Some(&pw),
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(!signed(&output).is_empty());
}

#[test]
fn test_signing_from_a_backup_writes_the_uncompressed_log() {
    let dir = scratch();
    let output = dir.join("test.tq8");
    let trace = dir.join("trace");
    let pw = password("W4W");
    let ran = qg_trust(
        &[
            "--test-sign",
            "-i",
            path(&set("standard.tbk")),
            "-l",
            "W4W-EVENT",
            "-o",
            path(&output),
            "-t",
            path(&trace),
            path(&set("adif/W4W-EVENT.adi")),
        ],
        (!pw.is_empty()).then_some(pw.as_slice()),
    );
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(
        body(&std::fs::read(output).unwrap()),
        body(&read("signed/W4W-EVENT.tq7"))
    );
    assert!(ran.out.contains("these QSOs were not recorded as signed"));
    assert!(
        std::fs::read_to_string(trace)
            .unwrap()
            .contains("these QSOs were not recorded as signed")
    );
}

#[test]
fn review_cli_read_file_enforces_the_actual_limit() {
    let path = std::env::temp_dir().join(format!("qgt-cli-read-limit-{}", std::process::id()));
    std::fs::write(&path, [b'x'; 2048]).unwrap();
    assert!(super::read_file(&path, 1024).is_err());
    assert_eq!(super::read_file(&path, 2048).unwrap().len(), 2048);
    std::fs::remove_file(path).unwrap();
}

#[cfg(unix)]
#[test]
fn review_cli_fifo_reader_child() {
    if let Some(path) = std::env::var_os("QGT_REVIEW_CLI_FIFO") {
        assert!(super::read_file(std::path::Path::new(&path), 1024).is_err());
    }
}

#[cfg(unix)]
#[test]
fn review_cli_read_file_refuses_a_fifo_without_waiting() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let path = std::env::temp_dir().join(format!("qgt-cli-fifo-{}", std::process::id()));
    assert!(
        Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::tests::review_cli_fifo_reader_child",
            "--nocapture",
        ])
        .env("QGT_REVIEW_CLI_FIFO", &path)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if start.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    std::fs::remove_file(path).unwrap();
    assert!(
        status.is_some_and(|s| s.success()),
        "CLI reader blocked or accepted a FIFO"
    );
}
