// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The custody test (AGENTS.md: no key data is left in freed memory). A program signs the corpus
//! log as QG Trust does, from reading the key file to writing the `.tq8`, drops everything and
//! waits; this test reads every byte of its memory, heap, stack and all, from outside it, as a
//! debugger or a crash dump would see it, and looks for the key: the key file's text, the key's
//! DER, its private exponent, primes and CRT values, `e·d`, `p−1` and `q−1`, each in both byte
//! orders, and the password. None may be there.
//!
//! Two controls prove the search finds what is there: with the key still in use, it must be found;
//! and in the same program built without the wiping allocator, what an ordinary free leaves (the
//! key file's text, read into a plain buffer as any caller reads a file) must be found.
//!
//! Linux, where a parent may read its child's memory through `/proc`; run in CI on Linux, debug and
//! release, as optimisation is what removes wipes.

#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pkcs8::der::Decode;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey, pkcs8::DecodePrivateKey};

fn corpus(case: &str, file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/tqsl")
        .join(case)
        .join(file)
}

/// A field of the corpus key file, as tqsllib wrote it.
fn key_field(case: &str, name: &str) -> String {
    let bytes = std::fs::read(corpus(case, "tqsl/keys/QG0TEST")).expect("the key file");
    let records = qso_graph_trust::records::parse(&bytes).expect("records");
    records[0].text(name).expect(name).to_string()
}

/// What must not be left: labelled 16-byte pieces from the middle of each secret, so a piece
/// is found even where an allocator has overwritten a block's first bytes with its own pointers.
fn needles(case: &str, password: &[u8]) -> Vec<(String, Vec<u8>)> {
    let pem = key_field(case, "PRIVATE_KEY");
    let key = if password.is_empty() {
        RsaPrivateKey::from_pkcs8_pem(&pem).expect("the key")
    } else {
        let (_, der) = pkcs8::SecretDocument::from_pem(&pem).expect("PEM");
        let info = pkcs8::EncryptedPrivateKeyInfo::from_der(der.as_bytes()).expect("encrypted");
        let plain = info.decrypt(password).expect("decrypts");
        RsaPrivateKey::from_pkcs8_der(plain.as_bytes()).expect("the key")
    };
    let der = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&key).expect("DER");
    let [p, q] = key.primes() else {
        panic!("two primes")
    };
    let one = BigUint::from(1u8);
    let (p1, q1) = (p - &one, q - &one);
    let numbers: Vec<(&str, BigUint)> = vec![
        ("d", key.d().clone()),
        ("p", p.clone()),
        ("q", q.clone()),
        ("d mod p-1", key.d() % &p1),
        ("d mod q-1", key.d() % &q1),
        ("e*d", key.e() * key.d()),
        ("p-1", p1.clone()),
        ("q-1", q1.clone()),
    ];
    let mut out = Vec::new();
    let mut piece = |label: String, bytes: &[u8]| {
        let mid = bytes.len() / 2;
        out.push((label, bytes[mid - 8..mid + 8].to_vec()));
    };
    for (label, n) in &numbers {
        piece(format!("{label}, big-endian"), &n.to_bytes_be());
        piece(format!("{label}, little-endian"), &n.to_bytes_le());
    }
    piece("the key's DER".into(), der.as_bytes());
    // The key file's text: a line of its base64 from the middle.
    let lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    piece(
        "the key file's text".into(),
        lines[lines.len() / 2].as_bytes(),
    );
    if !password.is_empty() {
        out.push(("the password".into(), password.to_vec()));
    }
    out
}

/// Every readable byte of a process's memory, region by region, read through `/proc`. A region
/// that cannot be read fails the test, except the kernel's own (`[vvar]`, `[vsyscall]`), which hold
/// nothing of the process's.
fn memory(pid: u32) -> Vec<(String, Vec<u8>)> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("maps");
    let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).expect("mem");
    let mut regions = Vec::new();
    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (range, perms) = (fields[0], fields[1]);
        let name = fields.get(5).copied().unwrap_or("");
        if !perms.starts_with('r')
            || name == "[vvar]"
            || name == "[vvar_vclock]"
            || name == "[vsyscall]"
        {
            continue;
        }
        let (start, end) = range.split_once('-').expect("a range");
        let start = u64::from_str_radix(start, 16).expect("start");
        let end = u64::from_str_radix(end, 16).expect("end");
        let mut bytes = vec![0; (end - start) as usize];
        mem.seek(SeekFrom::Start(start)).expect("seek");
        mem.read_exact(&mut bytes)
            .unwrap_or_else(|e| panic!("{line}: {e}"));
        regions.push((line.to_string(), bytes));
    }
    assert!(!regions.is_empty());
    regions
}

/// Which needles are found in the program's memory once it says `ready`.
fn found_in(program: &str, case: &str, password: &[u8], mode: &str) -> Vec<String> {
    let dir = std::env::temp_dir().join(format!(
        "qgt-custody-{}-{case}-{mode}-{program}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    let password_file = dir.join("password");
    std::fs::write(&password_file, password).expect("the password file");
    let arg = |p: &Path| p.to_str().expect("a UTF-8 path").to_string();
    let mut child = Command::new(program)
        .args([
            arg(&corpus(case, "tqsl/keys/QG0TEST")),
            arg(&corpus(case, "tqsl/certs/user")),
            arg(&PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus/adif/qg0test-small.adi")),
            arg(&password_file),
            mode.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("starts");
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().expect("its output"))
        .read_line(&mut line)
        .expect("reads");
    assert_eq!(line, "ready\n", "{program} {case} {mode}");
    let regions = memory(child.id());
    child
        .stdin
        .as_mut()
        .expect("its input")
        .write_all(b"\n")
        .expect("writes");
    assert!(child.wait().expect("exits").success());
    let _ = std::fs::remove_dir_all(&dir);

    let needles = needles(case, password);
    if std::env::var_os("QGT_CUSTODY_WHERE").is_some() {
        for (label, n) in &needles {
            for (region, bytes) in &regions {
                for (i, _) in bytes
                    .windows(n.len())
                    .enumerate()
                    .filter(|(_, w)| *w == n.as_slice())
                {
                    let ctx = &bytes[i.saturating_sub(48)..(i + n.len() + 48).min(bytes.len())];
                    eprintln!(
                        "FOUND {label} in {region} at +{i:#x}: {:?}",
                        String::from_utf8_lossy(ctx)
                    );
                }
            }
        }
    }
    let mut found: Vec<String> = needles
        .iter()
        .filter(|(_, n)| {
            regions
                .iter()
                .any(|(_, bytes)| bytes.windows(n.len()).any(|w| w == n.as_slice()))
        })
        .map(|(label, _)| label.clone())
        .collect();
    found.sort();
    found
}

const WIPED: &str = env!("CARGO_BIN_EXE_qgt-custody");
const UNWIPED: &str = env!("CARGO_BIN_EXE_qgt-custody-unwiped");

#[test]
fn no_key_data_is_left_once_the_log_is_signed() {
    assert_eq!(found_in(WIPED, "1024", b"", "done"), Vec::<String>::new());
}

#[test]
fn no_key_data_or_password_is_left_from_a_protected_key() {
    assert_eq!(
        found_in(WIPED, "1024-password", b"qgt-key", "done"),
        Vec::<String>::new()
    );
}

#[test]
fn the_search_finds_a_key_that_is_there() {
    // Control: while the key is unlocked, its numbers are in memory, and the search must see them.
    let found = found_in(WIPED, "1024", b"", "live");
    assert!(
        found
            .iter()
            .any(|f| f.starts_with("p,") || f.starts_with("d,")),
        "{found:?}"
    );
}

#[test]
fn without_the_wiping_allocator_a_free_leaves_the_key_file_behind() {
    // Control: the same program, the allocator left out, leaves the key file's text in a freed
    // buffer; with it, nothing (above). This is what the allocator is for.
    let found = found_in(UNWIPED, "1024", b"", "done");
    assert!(
        found.contains(&"the key file's text".to_string()),
        "{found:?}"
    );
}
