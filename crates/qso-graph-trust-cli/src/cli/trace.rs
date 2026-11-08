// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! TQSL's `-t FILE`: a diagnostic log of one run, for a logger's support to read. TQSL 2.8.7 writes
//! "TQSL Diagnostics", its about text, the command line and its working folder, then tqsllib's trace
//! (`apps/tqsl.cpp`, after `tqsl_openDiagFile`). `qg-trust` writes the same header and one line for
//! each step of the run: what was chosen, counts of QSOs and why some were left out, what was
//! written and sent, and the exit code.
//!
//! What it never holds: a password, a key or anything decrypted. The command line is written with
//! every value that could be a password replaced ([`redact`]), and each step writes only names,
//! calls, numbers and fixed words, never a QSO's fields or the contents of a file it read.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// What stands in the log for a value that could be a password.
pub(crate) const REDACTED: &str = "<redacted>";

/// The diagnostic log, or nothing when `-t` was not given or its file could not be opened.
#[derive(Debug, Default)]
pub(crate) struct Trace {
    file: Option<File>,
}

impl Trace {
    /// No diagnostic log: every line is dropped.
    pub(crate) fn off() -> Self {
        Self::default()
    }

    /// `path` made new or emptied, readable by its owner alone on Unix, as the store's files are.
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        // A file there already keeps its mode when emptied: made the owner's alone, but only a
        // plain file, never a device such as /dev/null.
        #[cfg(unix)]
        if file.metadata()?.is_file() {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { file: Some(file) })
    }

    /// One line, written at once so the log is whole up to a crash. A failed write ends the log.
    pub(crate) fn line(&mut self, line: fmt::Arguments<'_>) {
        if let Some(file) = &mut self.file {
            let mut text = line.to_string();
            text.push('\n');
            if file.write_all(text.as_bytes()).is_err() {
                self.file = None;
            }
        }
    }

    /// The header TQSL writes first: the program, the system, the command line, the folder.
    pub(crate) fn header(&mut self, args: &[&str]) {
        let folder = std::env::current_dir()
            .map_or_else(|_| "unknown".to_string(), |d| d.display().to_string());
        self.line(format_args!("QSO Graph Trust Diagnostics"));
        self.line(format_args!("qg-trust {}", qso_graph_trust::VERSION));
        self.line(format_args!(
            "System: {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
        self.line(format_args!("Command Line: {}", command_line(args)));
        self.line(format_args!("Working Directory: {folder}"));
        self.line(format_args!(""));
    }
}

/// The command line as the log shows it: `qg-trust` and each argument, those [`redact`] replaces
/// as [`REDACTED`].
pub(crate) fn command_line(args: &[&str]) -> String {
    std::iter::once("qg-trust".to_string())
        .chain(redact(args))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The arguments with every value that could be a password replaced. More is replaced than
/// clap would read as one: a word naming a password anywhere (`--password=…`, `--passphrase`,
/// a value that happens to hold one), `-p`'s value attached or the next word, and in a group of
/// letters (`-xqp`) everything from the `p`. A file name or a location's name lost to this is a
/// small price; a password written to a support log is not.
pub(crate) fn redact(args: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut next_is_value = false;
    for arg in args {
        if std::mem::take(&mut next_is_value) {
            out.push(REDACTED.to_string());
            // A value is a value: it never names the next one.
            continue;
        }
        let (shown, takes_next) = redact_word(arg);
        next_is_value = takes_next;
        out.push(shown);
    }
    out
}

/// Whether a word would be replaced, alone, in the log: the test the error naming `-t`'s file
/// uses too.
pub(crate) fn is_redacted(word: &str) -> bool {
    redact_word(word).0 != word
}

/// One word as shown, and whether the word after it is a password option's value.
fn redact_word(word: &str) -> (String, bool) {
    if word.to_ascii_lowercase().contains("pass") {
        // `--password` alone takes the next word; `--password=…` holds its value.
        let alone = word.starts_with("--") && !word.contains('=');
        return (REDACTED.to_string(), alone);
    }
    if let Some(letters) = word.strip_prefix('-').filter(|l| !l.starts_with('-')) {
        for (at, letter) in letters.char_indices() {
            if letter == 'p' {
                // `-p` or `-xqp` ends the word, and its value is the next; `-phunter2` holds it.
                return if at + 1 < letters.len() {
                    (format!("-{}{REDACTED}", &letters[..=at]), false)
                } else {
                    (word.to_string(), true)
                };
            }
            // A letter that takes a value: the rest of the word is that value.
            if matches!(letter, 'i' | 'l' | 'b' | 'e' | 'o' | 'a' | 'f' | 'c' | 't') {
                break;
            }
        }
    }
    (word.to_string(), false)
}

/// The check the tests apply to a diagnostic log: none of the secrets is in it.
#[cfg(test)]
pub(crate) fn holds_none_of(log: &str, secrets: &[&str]) -> bool {
    secrets.iter().all(|s| !log.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_place_a_password_can_be_given_is_replaced() {
        for args in [
            vec!["-p", "hunter2"],
            vec!["--password", "hunter2"],
            vec!["--password=hunter2"],
            vec!["-phunter2"],
            vec!["-xqp", "hunter2"],
            vec!["-xqphunter2"],
            vec!["--passphrase", "hunter2"],
            vec!["-l", "home", "-p", "hunter2", "log.adi"],
            vec!["-i--password=hunter2", "-l", "home", "log.adi"],
            vec!["-l", "--password=hunter2", "log.adi"],
            vec!["--", "log.adi", "--password=hunter2"],
            vec!["-t", "diag.txt", "-p", "hunter2", "-l", "home"],
        ] {
            let line = command_line(&args);
            assert!(holds_none_of(&line, &["hunter2"]), "{args:?}: {line}");
            assert!(line.contains(REDACTED), "{args:?}: {line}");
        }
    }

    #[test]
    fn what_is_not_a_password_is_shown_as_given() {
        let args = [
            "-x",
            "-l",
            "KN4YU-CLUB",
            "-c",
            "kc4qpq",
            "-t",
            "diag.txt",
            "-a",
            "all",
            "log.adi",
        ];
        assert_eq!(command_line(&args), format!("qg-trust {}", args.join(" ")));
        // A value after a password option is replaced, and the word after that is shown.
        assert_eq!(
            command_line(&["-p", "hunter2", "log.adi"]),
            format!("qg-trust -p {REDACTED} log.adi")
        );
        assert!(is_redacted("--password=x") && is_redacted("-phunter2"));
        assert!(!is_redacted("diag.txt") && !is_redacted("-lhome"));
    }

    /// Planted: the command line written as given. The check the sign test relies on catches it,
    /// so it would catch the log writing a password; redacted, the same line passes.
    #[test]
    fn the_check_catches_a_password_written_unredacted() {
        let args = ["-l", "home", "--password", "hunter2", "log.adi"];
        let planted = format!("Command Line: qg-trust {}", args.join(" "));
        assert!(!holds_none_of(&planted, &["hunter2"]));
        let written = format!("Command Line: {}", command_line(&args));
        assert!(holds_none_of(&written, &["hunter2"]));
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_its_owners_alone_even_over_a_file_there_before() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("qg-trust-trace-{}.txt", std::process::id()));
        std::fs::write(&path, b"old").expect("a file there before");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("mode");
        let mut trace = Trace::create(&path).expect("the log");
        trace.line(format_args!("one"));
        drop(trace);
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "one\n");
        let _ = std::fs::remove_file(&path);
    }
}
