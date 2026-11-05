// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The custody test (AGENTS.md: no key data is left in freed memory). A program signs the corpus
//! log as QG Trust does, from reading the key file to writing the `.tq8`, drops everything and
//! waits; this test reads every byte of its memory, heap, stack and all, from outside it, as a
//! debugger or a crash dump would see it, and looks for the key: the key file's text, the key's
//! DER, its private exponent, primes and all three CRT values (`d mod p−1`, `d mod q−1` and
//! `q⁻¹ mod p`), `e·d`, `p−1` and `q−1`, each in both byte orders, and the password. None may be
//! there. Import passwords in UTF-8 and BMP form, MAC and AES keys (including failed MACs),
//! recoverable HMAC pads/hash words and the CBC pre-XOR final key block are searched too, along
//! with generated export passwords and both export AES keys (including failed opens).
//!
//! Controls prove the search finds what is there: with the key still in use, every one of its
//! private values must be found, so each needle is shown to be right;
//! and in the same program built without the wiping allocator, what an ordinary free leaves (the
//! key file's text, read into a plain buffer as any caller reads a file) must be found. Separate
//! runs deliberately keep copies of export passwords/keys and every import needle. On x86_64,
//! scans also run with AES-NI and VAES masked off in the child's environment before AWS-LC starts.
//!
//! Linux, where a parent may read its child's memory through `/proc`; run in CI on Linux, debug and
//! release, as optimisation is what removes wipes.

#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use pkcs8::der::Decode;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey, pkcs8::DecodePrivateKey};

/// The test set's `.p12` password, from `tests/corpus/pki/p12-password`.
fn p12_password() -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus/pki/p12-password"),
    )
    .expect("the test .p12 password")
}

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
fn needles(case: &str) -> Vec<(String, Vec<u8>)> {
    let password = std::fs::read(corpus(case, "key-password")).expect("the key's password");
    let password = password.as_slice();
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
    // q^-1 mod p, by Fermat: p is prime, so it is q^(p-2) mod p.
    let qinv = q.modpow(&(p - BigUint::from(2u8)), p);
    let one = BigUint::from(1u8);
    let (p1, q1) = (p - &one, q - &one);
    let numbers: Vec<(&str, BigUint)> = vec![
        ("d", key.d().clone()),
        ("p", p.clone()),
        ("q", q.clone()),
        ("d mod p-1", key.d() % &p1),
        ("d mod q-1", key.d() % &q1),
        ("q^-1 mod p", qinv),
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

// Test-only files contain fresh generated export passwords, never operator credentials.
struct SecretsFolder(PathBuf);
impl SecretsFolder {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "qgt-custody-needles-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private test directory");
        Self(path)
    }
}
impl Drop for SecretsFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn export_needles(path: &Path) -> Vec<(String, Vec<u8>)> {
    let secrets = std::fs::read(path).expect("test-only export secrets");
    assert_eq!(secrets.len(), 56);
    // Independent test oracle, using Python 3 (also required by the repository's build checks).
    // Passwords travel over stdin. No production crate or feature exposes passwords or AES keys.
    let mut derive = Command::new("python3")
        .args([
            "-c",
            "import hashlib, sys
s = sys.stdin.buffer.read()
for p in (s[:20], s[20:40]):
    sys.stdout.buffer.write(hashlib.pbkdf2_hmac('sha256', p, s[40:], 600000, 32))",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Python PBKDF2 oracle");
    derive
        .stdin
        .take()
        .expect("oracle input")
        .write_all(&secrets)
        .expect("derive input");
    let derived = derive.wait_with_output().expect("derive");
    assert!(derived.status.success());
    assert_eq!(derived.stdout.len(), 64);
    vec![
        ("export password".into(), secrets[..20].to_vec()),
        ("failed-open password".into(), secrets[20..40].to_vec()),
        ("export AES key".into(), derived.stdout[..32].to_vec()),
        ("failed-open AES key".into(), derived.stdout[32..].to_vec()),
    ]
}

fn import_needles(case: &str, secrets_file: &Path) -> Vec<(String, Vec<u8>)> {
    let secrets = std::fs::read(secrets_file).expect("test-only export secrets");
    let mut derive = Command::new("python3")
        .args([
            "-c",
            include_str!("../../../scripts/custody-import-needles.py"),
        ])
        .arg(corpus(case, "QG0TEST.p12"))
        .arg(corpus(case, "tqsl/keys/QG0TEST"))
        .arg(corpus(case, "key-password"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Python import KDF oracle");
    derive
        .stdin
        .take()
        .expect("input")
        .write_all(&secrets[20..40])
        .expect("password input");
    let output = derive.wait_with_output().expect("derive import keys");
    assert!(output.status.success());
    let mut out = Vec::new();
    for line in std::str::from_utf8(&output.stdout)
        .expect("oracle text")
        .lines()
    {
        let (label, hex) = line.split_once('\t').expect("labelled hex");
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        if label == "envelope" {
            // AWS-LC's in-place fallback tmp is AES_decrypt(C_last), before the CBC XOR.
            // Search that recoverable representation too, including the last key bytes and pad.
            let info = pkcs8::EncryptedPrivateKeyInfo::from_der(&bytes).expect("key envelope");
            let plain = info
                .decrypt(p12_password())
                .expect("independent test decryption");
            let cipher = info.encrypted_data;
            let padding = 16 - plain.as_bytes().len() % 16;
            let mut block = vec![padding as u8; 16];
            let tail = 16 - padding;
            block[..tail].copy_from_slice(&plain.as_bytes()[plain.as_bytes().len() - tail..]);
            for (b, c) in block
                .iter_mut()
                .zip(&cipher[cipher.len() - 32..cipher.len() - 16])
            {
                *b ^= c;
            }
            out.push(("PKCS#12 CBC pre-XOR final block".into(), block));
        } else {
            out.push((label.to_owned(), bytes));
        }
    }
    assert!(out.len() > 20, "import oracle must produce every needle");
    out
}

/// Scan before reading the child's test-secret file, then construct the export needles.
fn found_in(program: &str, case: &str, mode: &str) -> Vec<String> {
    found_with_cpu(program, case, mode, false)
}

fn found_with_cpu(program: &str, case: &str, mode: &str, disable_aesni: bool) -> Vec<String> {
    let arg = |p: &Path| p.to_str().expect("a UTF-8 path").to_string();
    let folder = SecretsFolder::new();
    let secrets_file = folder.0.join("export-secrets");
    let import_password_file = folder.0.join("import-password");
    std::fs::write(&import_password_file, p12_password()).expect("test import password");
    let mut command = Command::new(program);
    // aws-lc-sys 0.45.0: cpucap/internal.h CRYPTO_is_AESNI_capable tests word 1 bit 25.
    // cpu_intel.c interprets '~' as AND-NOT on the first 64-bit pair: bit 32+25 = 57.
    // Leave SSSE3 enabled for VPAES. Clear VAES (word 3 bit 9) too for wider AES dispatch.
    if disable_aesni {
        command.env("OPENSSL_ia32cap", "~0x200000000000000:~0x20000000000");
    } else {
        command.env_remove("OPENSSL_ia32cap");
    }
    let mut child = command
        .args([
            arg(&corpus(case, "tqsl/keys/QG0TEST")),
            arg(&corpus(case, "tqsl/certs/user")),
            arg(&PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/corpus/adif/qg0test-small.adi")),
            arg(&corpus(case, "key-password")),
            arg(&import_password_file),
            arg(&secrets_file),
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
    let mut regions = memory(child.id());
    let export_needles = export_needles(&secrets_file);
    let import_needles = import_needles(case, &secrets_file);
    if mode == "export-keys" || mode == "import-secrets" {
        // After observing the completed export/restore, deliberately keep copies of both derived
        // keys in the child. The same search must find each planted key in a second snapshot.
        let input = child.stdin.as_mut().expect("its input");
        input.write_all(b"\n").expect("release first wait");
        if mode == "import-secrets" {
            let len: usize = import_needles.iter().map(|(_, bytes)| bytes.len()).sum();
            input
                .write_all(&(len as u32).to_be_bytes())
                .expect("planted length");
            for (_, bytes) in &import_needles {
                input.write_all(bytes).expect("plant import secret");
            }
        } else {
            for (_, key) in &export_needles[2..] {
                input.write_all(key).expect("plant AES key");
            }
        }
        line.clear();
        BufReader::new(child.stdout.as_mut().expect("its output"))
            .read_line(&mut line)
            .expect("second ready");
        assert_eq!(line, "ready\n");
        regions = memory(child.id());
    }
    child
        .stdin
        .as_mut()
        .expect("its input")
        .write_all(b"\n")
        .expect("writes");
    assert!(child.wait().expect("exits").success());

    let mut needles = needles(case);
    needles.push(("PKCS#12 password".into(), p12_password()));
    needles.extend(export_needles);
    needles.extend(import_needles);
    if std::env::var_os("QGT_CUSTODY_WHERE").is_some() {
        for (label, n) in &needles {
            for (region, bytes) in &regions {
                for (i, _) in bytes
                    .windows(n.len())
                    .enumerate()
                    .filter(|(_, w)| *w == n.as_slice())
                {
                    eprintln!("FOUND {label} in {region} at +{i:#x}");
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
    assert_eq!(found_in(WIPED, "1024", "done"), Vec::<String>::new());
}

#[test]
fn no_key_data_or_password_is_left_from_a_protected_key() {
    assert_eq!(
        found_in(WIPED, "1024-password", "done"),
        Vec::<String>::new()
    );
}

#[test]
fn the_search_finds_a_key_that_is_there() {
    // Control: while the key is unlocked, each of its private values is in memory, as the signer
    // holds it, and the search must see every one: a needle it cannot find would prove nothing
    // (found in review: q^-1 mod p was not searched for at all).
    let found = found_in(WIPED, "1024", "live");
    for value in ["d", "p", "q", "d mod p-1", "d mod q-1", "q^-1 mod p"] {
        assert!(
            found.iter().any(|f| f.split(", ").next() == Some(value)),
            "{value} not found in {found:?}"
        );
    }
}

#[test]
fn without_the_wiping_allocator_a_free_leaves_the_key_file_behind() {
    // Control: the same program, the allocator left out, leaves the key file's text in a freed
    // buffer; with it, nothing (above). This is what the allocator is for.
    let found = found_in(UNWIPED, "1024", "done");
    assert!(
        found.contains(&"the key file's text".to_string()),
        "{found:?}"
    );
}

#[test]
fn the_search_catches_both_planted_export_passwords() {
    let found = found_in(WIPED, "1024", "export-passwords");
    for label in [
        "export password",
        "failed-open password",
        "PKCS#12 password",
    ] {
        assert!(
            found.iter().any(|f| f == label),
            "{label} not found in {found:?}"
        );
    }
}

#[test]
fn the_search_catches_both_planted_aes_keys() {
    let found = found_in(WIPED, "1024", "export-keys");
    for label in ["export AES key", "failed-open AES key"] {
        assert!(
            found.iter().any(|f| f == label),
            "{label} not found in {found:?}"
        );
    }
}

#[test]
fn the_search_catches_every_planted_import_secret() {
    for disabled in [false, true] {
        if disabled && !cfg!(target_arch = "x86_64") {
            continue;
        }
        let found = found_with_cpu(WIPED, "1024-password", "import-secrets", disabled);
        for label in [
            "PKCS#12 BMP password",
            "failed PKCS#12 BMP password",
            "PKCS#12 CBC pre-XOR final block",
        ] {
            assert!(
                found.iter().any(|f| f == label),
                "{label} missing (AES-NI disabled={disabled}): {found:?}"
            );
        }
        for key in [
            "PKCS#12 MAC key",
            "failed PKCS#12 MAC key",
            "PKCS#12 certificate AES key",
            "PKCS#12 private AES key",
            "TQSL unlock key",
        ] {
            for suffix in ["", " fragment", " LE words", " ipad", " opad"] {
                let label = format!("{key}{suffix}");
                assert!(
                    found.contains(&label),
                    "{label} missing (AES-NI disabled={disabled}): {found:?}"
                );
            }
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn no_secrets_remain_without_aesni() {
    for case in ["1024", "1024-password"] {
        assert_eq!(
            found_with_cpu(WIPED, case, "done", true),
            Vec::<String>::new(),
            "{case}"
        );
    }
}
