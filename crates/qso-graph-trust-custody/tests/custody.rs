// SPDX-License-Identifier: GPL-3.0-or-later
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
//! Everything QG Trust writes is searched too, not only its memory. The real `qg-trust`, with a
//! temporary home folder and an OS credential store of its own (a private D-Bus session with
//! gnome-keyring, under the test service only), imports the standard set's TQSL backup (`.tbk`,
//! two password-protected keys and one without) and a password-protected `.p12`, refused first
//! under a root it does not trust yet, then once with a wrong password; adds a location; signs with
//! `sign` and with the logger's options (`-x -l … -a all -t FILE`); runs the logger's `-i` path with
//! `-p PASSWORD` on the command line, which is refused, and without it; renews a certificate (the
//! request is signed by the key being renewed), requests one (a new key), lists, abandons the request
//! and deletes a certificate with its key. The command line has no export, so the custody program
//! writes the library's encrypted export, its store folders and a `.tq8` into the same home. Then
//! every file under that home (the store, the credential store's own files, every output, the `-t`
//! logs) and the standard output and error of every run are searched for each key in every form the
//! memory search uses, and in hex and base64 too, and for every password, the `.p12`'s, a wrong
//! one typed, and the export's (which the test alone keeps, outside that home). The export holds a
//! key encrypted, so only plaintext forms are needles. Upload and `send` are not run: they connect
//! to LoTW, and nothing here calls ARRL. `qg-trust` has no IPC: it is one process that talks to
//! nobody but the OS credential store; QSO Graph Desktop's IPC is Desktop's own test (QGD-LTW-0006).
//! Controls prove that search too: a planted file deep in that home, and a planted line in a run's
//! captured standard error, must each be found.
//!
//! Linux, where a parent may read its child's memory through `/proc`; run in CI on Linux, debug and
//! release, as optimisation is what removes wipes. The search of what is written needs
//! `dbus-run-session` and `gnome-keyring-daemon`, and fails without them rather than pass unrun.

#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use num_bigint_dig::BigUint;
use pkcs8::der::Decode;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{PrivateKey, pkcs8::DecodePrivateKey};

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

/// A field of a key file, as tqsllib wrote it.
fn key_field(key_file: &Path, name: &str) -> String {
    let bytes = std::fs::read(key_file).expect("the key file");
    let records = qso_graph_trust::records::parse(&bytes).expect("records");
    records[0].text(name).expect(name).to_string()
}

/// What must not be left: labelled 16-byte pieces from the middle of each secret, so a piece
/// is found even where an allocator has overwritten a block's first bytes with its own pointers.
fn needles(case: &str) -> Vec<(String, Vec<u8>)> {
    key_needles(
        &corpus(case, "tqsl/keys/QG0TEST"),
        &corpus(case, "key-password"),
    )
    .0
}

/// Labelled needles, and the whole values some of them are pieces of.
type Needles = (Vec<(String, Vec<u8>)>, Vec<Vec<u8>>);

/// [`needles`] for any tqsllib key file and its password file, with the key's DER and private
/// exponent whole, for the encoded forms a file could hold them in.
fn key_needles(key_file: &Path, password_file: &Path) -> Needles {
    let password = std::fs::read(password_file).expect("the key's password");
    let password = password.as_slice();
    let pem = key_field(key_file, "PRIVATE_KEY");
    let key = if password.is_empty() {
        PrivateKey::from_pkcs8_pem(&pem).expect("the key")
    } else {
        let (_, der) = pkcs8::SecretDocument::from_pem(&pem).expect("PEM");
        let info = pkcs8::EncryptedPrivateKeyInfo::from_der(der.as_bytes()).expect("encrypted");
        let plain = info.decrypt(password).expect("decrypts");
        PrivateKey::from_pkcs8_der(plain.as_bytes()).expect("the key")
    };
    let der = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&key).expect("DER");
    let [p, q] = key.primes() else {
        panic!("two primes")
    };
    let p = BigUint::from_bytes_be(&p.to_be_bytes());
    let q = BigUint::from_bytes_be(&q.to_be_bytes());
    let d = BigUint::from_bytes_be(&key.d().to_be_bytes());
    let e = BigUint::from_bytes_be(&key.e().to_be_bytes());
    // q^-1 mod p, by Fermat: p is prime, so it is q^(p-2) mod p.
    let qinv = q.modpow(&(&p - BigUint::from(2u8)), &p);
    let one = BigUint::from(1u8);
    let (p1, q1) = (&p - &one, &q - &one);
    let numbers: Vec<(&str, BigUint)> = vec![
        ("d", d.clone()),
        ("p", p.clone()),
        ("q", q.clone()),
        ("d mod p-1", &d % &p1),
        ("d mod q-1", &d % &q1),
        ("q^-1 mod p", qinv),
        ("e*d", e * &d),
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
    (out, vec![der.as_bytes().to_vec(), d.to_bytes_be()])
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

#[test]
fn stale_pid_export_directory_does_not_prevent_custody_readiness() {
    let folder = SecretsFolder::new();
    let secrets = folder.0.join("test-only-secrets");
    // As in the review probe, exec preserves the shell PID after planting its old directory.
    // Also plant the first suffixed candidate to exercise collision retries, retaining sentinels.
    let script = r#"
set -eu
mkdir "$TMPDIR/qgt-custody-export-$$"
mkdir "$TMPDIR/qgt-custody-export-$$-0"
printf sentinel > "$TMPDIR/qgt-custody-export-$$/sentinel"
printf sentinel > "$TMPDIR/qgt-custody-export-$$-0/sentinel"
exec "$@"
"#;
    let output = Command::new("sh")
        .args(["-c", script, "stale-directory-probe", WIPED])
        .arg(corpus("1024-password", "tqsl/keys/QG0TEST"))
        .arg(corpus("1024-password", "tqsl/certs/user"))
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/adif/qg0test-small.adi"),
        )
        .arg(corpus("1024-password", "key-password"))
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/pki/p12-password"))
        .arg(secrets)
        .arg("inspect-drop")
        .env("TMPDIR", &folder.0)
        .stdin(Stdio::null())
        .output()
        .expect("custody probe");
    assert!(
        output.status.success(),
        "custody child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"ready\n");
    let stale: Vec<_> = std::fs::read_dir(&folder.0)
        .expect("root")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(stale.len(), 2, "fresh export directory was not cleaned up");
    for path in stale {
        assert_eq!(
            std::fs::read(path.join("sentinel")).expect("stale sentinel"),
            b"sentinel"
        );
    }
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
    needles.extend(written_key_needles());
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
fn inspected_protected_p12_and_backup_leave_no_secrets_after_cancellation_or_commit() {
    for mode in ["inspect-drop", "inspect-commit"] {
        for disabled in [false, true] {
            if disabled && !cfg!(target_arch = "x86_64") {
                continue;
            }
            assert_eq!(
                found_with_cpu(WIPED, "1024-password", mode, disabled),
                Vec::<String>::new(),
                "{mode}, AES-NI disabled={disabled}"
            );
        }
    }
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

// What QG Trust writes: files, standard output and error, the credential store's own files.

/// The `qg-trust` program, built by cargo into this test's own target folder and profile.
/// `CARGO_BIN_EXE_*` names only this package's programs, so the test builds it as cargo would.
fn qg_trust() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        // This test runs from <target>/<profile>/deps/.
        let exe = std::env::current_exe().expect("this test's path");
        let profile_dir = exe
            .parent()
            .and_then(Path::parent)
            .expect("the profile's folder");
        let target = profile_dir.parent().expect("the target folder");
        let profile = match profile_dir.file_name().and_then(|n| n.to_str()) {
            Some("debug") => "dev",
            Some(name) => name,
            None => panic!("{}: not a profile's folder", profile_dir.display()),
        };
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(cargo)
            .args(["build", "--locked", "--quiet", "-p", "qso-graph-trust-cli"])
            .args(["--bin", "qg-trust", "--profile", profile, "--target-dir"])
            .arg(target)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("cargo builds qg-trust");
        assert!(status.success(), "building qg-trust failed");
        let program = profile_dir.join("qg-trust");
        assert!(program.is_file(), "{}", program.display());
        program
    })
}

/// A temporary home folder, the owner's alone, removed when done.
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "qgt-custody-home-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut dirs = std::fs::DirBuilder::new();
        dirs.mode(0o700).recursive(true);
        for sub in ["", "run", "tmp", "out"] {
            dirs.create(path.join(sub)).expect("the temporary home");
        }
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An OS credential store of the test's own: a private D-Bus session running gnome-keyring,
/// unlocked with a throwaway password, its files in the temporary home. Nothing reaches the
/// account's own credential store.
struct Keyring {
    session: std::process::Child,
    address: String,
}
impl Keyring {
    fn start(home: &Path) -> Self {
        let mut session = Command::new("dbus-run-session")
            .args([
                "--",
                "sh",
                "-c",
                "printf throwaway | gnome-keyring-daemon --unlock --components=secrets \
                 >/dev/null || exit 1; echo \"$DBUS_SESSION_BUS_ADDRESS\"; read -r _",
            ])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("XDG_RUNTIME_DIR", home.join("run"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "dbus-run-session: {e}. This test needs a Secret Service of its own: \
                     dbus-run-session and gnome-keyring-daemon (CI installs gnome-keyring)"
                )
            });
        let mut address = String::new();
        BufReader::new(session.stdout.as_mut().expect("its output"))
            .read_line(&mut address)
            .expect("the session's address");
        let address = address.trim().to_string();
        assert!(
            address.starts_with("unix:"),
            "no private D-Bus session with gnome-keyring: {address:?}"
        );
        Self { session, address }
    }

    /// Ends the session; the credential store has written its files.
    fn stop(&mut self) {
        drop(self.session.stdin.take());
        let _ = self.session.wait();
    }
}
impl Drop for Keyring {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Every run's standard output and error, by what ran.
struct Runs<'a> {
    home: &'a Path,
    keyring: &'a Keyring,
    streams: Vec<(String, Vec<u8>)>,
}
impl Runs<'_> {
    fn command(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.home)
            .env("XDG_RUNTIME_DIR", self.home.join("run"))
            .env("TMPDIR", self.home.join("tmp"))
            .env("DBUS_SESSION_BUS_ADDRESS", &self.keyring.address)
            // The test credential-store service, as QSO Graph Desktop's tests select it.
            .env("QG_DESKTOP_TEST_KEYCHAIN", "1")
            .current_dir(self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Runs `qg-trust` with `input` on its standard input; it must exit with `code`.
    fn qg_trust(&mut self, name: &str, args: &[&str], input: &str, code: i32) -> String {
        let mut child = self
            .command(qg_trust())
            .args(args)
            .spawn()
            .expect("qg-trust");
        child
            .stdin
            .take()
            .expect("its input")
            .write_all(input.as_bytes())
            .expect("its input");
        self.finish(name, child, code)
    }

    fn finish(&mut self, name: &str, child: std::process::Child, code: i32) -> String {
        let output = child.wait_with_output().expect("it exits");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.code(), Some(code), "{name}: {text}");
        self.streams
            .push((format!("standard output of {name}"), output.stdout));
        self.streams
            .push((format!("standard error of {name}"), output.stderr));
        text
    }
}

/// Every file under `dir`, by its path from `home`, read whole; a symbolic link by its target.
fn files(home: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).expect("a folder") {
        let entry = entry.expect("an entry");
        let path = entry.path();
        let kind = entry.file_type().expect("its type");
        let name = format!(
            "file {}",
            path.strip_prefix(home).expect("in the home").display()
        );
        if kind.is_dir() {
            files(home, &path, out);
        } else if kind.is_file() {
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
            out.push((name, bytes));
        } else if kind.is_symlink() {
            let target = std::fs::read_link(&path).expect("a link");
            out.push((name, target.into_os_string().into_encoded_bytes()));
        }
        // The credential store's control socket holds nothing.
    }
}

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    bytes
        .iter()
        .flat_map(|b| [digits[usize::from(b >> 4)], digits[usize::from(b & 15)]])
        .collect()
}

fn base64(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    bytes
        .chunks(3)
        .flat_map(|c| {
            let n = c
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
            let digit = |i: usize| DIGITS[((n >> (18 - 6 * i)) & 63) as usize];
            [digit(0), digit(1), digit(2), digit(3)]
                .into_iter()
                .take(c.len() + 1)
        })
        .collect()
}

fn utf16(text: &[u8], little_endian: bool) -> Vec<u8> {
    text.iter()
        .flat_map(|&b| if little_endian { [b, 0] } else { [0, b] })
        .collect()
}

/// A password in UTF-8 and in UTF-16 of either byte order.
fn password(label: String, bytes: &[u8], out: &mut Vec<(String, Vec<u8>)>) {
    out.push((format!("{label}, UTF-16LE"), utf16(bytes, true)));
    out.push((format!("{label}, UTF-16BE"), utf16(bytes, false)));
    out.push((label, bytes.to_vec()));
}

/// The plaintext needles for what is written: each key the runs handle, in every form the
/// memory search uses and in hex and base64, and every password, in UTF-8 and UTF-16.
fn written_needles(export_secrets: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = written_key_needles();
    password("the .p12 password".into(), &p12_password(), &mut out);
    password("a wrong .p12 password typed".into(), WRONG, &mut out);
    for (label, bytes) in export_needles(export_secrets) {
        if label.ends_with("password") {
            password(label, &bytes, &mut out);
        } else {
            out.push((format!("{label}, hex"), hex(&bytes, false)));
            out.push((label, bytes));
        }
    }
    out
}

/// The keys' needles for what is written, with their keys' passwords.
fn written_key_needles() -> Vec<(String, Vec<u8>)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus");
    let keys = [
        (
            "KC4QPQ",
            "standard/tqsl/keys/KC4QPQ",
            "standard/keys/KC4QPQ.password",
        ),
        (
            "KN4YU",
            "standard/tqsl/keys/KN4YU",
            "standard/keys/KN4YU.password",
        ),
        (
            "W4W",
            "standard/tqsl/keys/W4W",
            "standard/keys/W4W.password",
        ),
        (
            "QG0TEST",
            "tqsl/1024-password/tqsl/keys/QG0TEST",
            "tqsl/1024-password/key-password",
        ),
    ];
    let mut out = Vec::new();
    for (call, key, key_password) in keys {
        let (pieces, wholes) = key_needles(&root.join(key), &root.join(key_password));
        for (label, bytes) in pieces {
            let label = format!("{call}: {label}");
            if label.ends_with("the password") {
                password(label, &bytes, &mut out);
                continue;
            }
            if !label.ends_with("the key file's text") {
                out.push((format!("{label}, hex"), hex(&bytes, false)));
                out.push((format!("{label}, HEX"), hex(&bytes, true)));
            }
            out.push((label, bytes));
        }
        for (what, whole) in ["the key's DER", "d, big-endian"].iter().zip(wholes) {
            // Base64 from each of the three byte offsets a value can start at in a stream.
            for offset in 0..3 {
                let text = base64(&whole[offset..]);
                let mid = text.len() / 2;
                out.push((
                    format!("{call}: {what}, base64 at offset {offset}"),
                    text[mid - 8..mid + 8].to_vec(),
                ));
            }
        }
    }
    out
}

const WRONG: &[u8] = b"qgt-not-the-p12s";

/// Which needles are where: every file and stream is searched as it is and with its line breaks
/// taken out, so text wrapped across lines is found too.
fn search(needles: &[(String, Vec<u8>)], places: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut found = Vec::new();
    for (place, bytes) in places {
        let unwrapped: Vec<u8> = bytes
            .iter()
            .copied()
            .filter(|b| !matches!(b, b'\n' | b'\r'))
            .collect();
        for (label, needle) in needles {
            if [bytes, &unwrapped]
                .iter()
                .any(|b| b.windows(needle.len()).any(|w| w == needle.as_slice()))
            {
                found.push(format!("{label} in {place}"));
            }
        }
    }
    found.sort();
    found
}

/// Where the planted file goes, deep in the store's own folder.
const PLANTED: &str = ".local/share/qso-graph-trust/planted/notes.txt";

/// Runs every flow that handles a key, then searches all they wrote. With `plant`, a file holding
/// one of KC4QPQ's primes in hex is put in the home, and its password in one run's standard error.
fn what_qg_trust_writes(plant: bool) -> Vec<String> {
    let tests = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus");
    let at = |p: &str| tests.join(p).to_str().expect("a UTF-8 path").to_string();
    let home = Home::new();
    let out = |name: &str| {
        home.0
            .join("out")
            .join(name)
            .to_str()
            .expect("a UTF-8 path")
            .to_string()
    };
    let mut keyring = Keyring::start(&home.0);
    let mut runs = Runs {
        home: &home.0,
        keyring: &keyring,
        streams: Vec::new(),
    };
    let tbk = at("standard/standard.tbk");
    let p12 = at("tqsl/1024-password/QG0TEST.p12");
    let kc4qpq_log = at("standard/adif/KC4QPQ-HOME.adi");
    let passwords = "qgt-kc4qpq\nqgt-w4w\n";

    // TQSL's backup: KC4QPQ's and W4W's keys are password-protected, asked for in that order.
    runs.qg_trust("import standard.tbk", &["import", &tbk], passwords, 0);
    // A .p12 under a root not trusted yet is refused, naming the root to confirm.
    let p12_text = String::from_utf8(p12_password()).expect("text");
    let refused = runs.qg_trust(
        "import QG0TEST.p12",
        &["import", &p12],
        &format!("{p12_text}\n"),
        4,
    );
    let fingerprint = refused
        .split("--trust-root ")
        .nth(1)
        .expect("the root to confirm")
        .trim()
        .to_string();
    let wrong = format!("{}\n", std::str::from_utf8(WRONG).expect("text"));
    runs.qg_trust(
        "import QG0TEST.p12 with a wrong password",
        &["import", &p12, "--trust-root", &fingerprint],
        &wrong,
        4,
    );
    runs.qg_trust(
        "import QG0TEST.p12 --trust-root",
        &["import", &p12, "--trust-root", &fingerprint],
        &format!("{p12_text}\n"),
        0,
    );
    let location = [
        "location",
        "add",
        "QG0TEST-HOME",
        "--call",
        "QG0TEST",
        "--dxcc",
        "291",
        "--grid",
        "EM17",
        "US_STATE=KS",
        "US_COUNTY=Sedgwick",
        "CQZ=4",
        "ITUZ=7",
    ];
    runs.qg_trust("location add", &location, "", 0);
    runs.qg_trust(
        "sign with the .p12's key",
        &["sign", &at("adif/qg0test-small.adi"), "-l", "QG0TEST-HOME"]
            .into_iter()
            .chain(["-o", &out("qg0test.tq8")])
            .collect::<Vec<_>>(),
        "",
        0,
    );
    runs.qg_trust(
        "sign with the backup's key",
        &["sign", &kc4qpq_log, "-l", "KC4QPQ-HOME"]
            .into_iter()
            .chain(["-o", &out("kc4qpq.tq8")])
            .collect::<Vec<_>>(),
        "",
        0,
    );
    // The logger's options, keys from the store, with TQSL's diagnostic log.
    let logger = ["-x", "-l", "KC4QPQ-HOME", "-a", "all"];
    runs.qg_trust(
        "the logger's -x -l -t",
        &logger
            .into_iter()
            .chain([
                "-t",
                &out("store.trace"),
                "-o",
                &out("logger.tq8"),
                &kc4qpq_log,
            ])
            .collect::<Vec<_>>(),
        "",
        0,
    );
    // The logger's -i with the key's passphrase on the command line, as TQSL's -p takes it:
    // accepted, with a warning; the backup is checked against LoTW's own roots only, so the test
    // set's backup stops there (6), as the next run does. Nothing written may keep the passphrase.
    runs.qg_trust(
        "the logger's -x -i -p -t",
        &["-x", "-i", &tbk, "-l", "KC4QPQ-HOME", "-p", "qgt-kc4qpq"]
            .into_iter()
            .chain(["-t", &out("p.trace"), "-o", &out("p.tq8"), &kc4qpq_log])
            .collect::<Vec<_>>(),
        "",
        6,
    );
    // -i without -p: the backup is read for the run, and checked against LoTW's own roots only,
    // so the test set's backup stops there (6), with the passwords waiting on its input.
    runs.qg_trust(
        "the logger's -x -i -t",
        &logger
            .into_iter()
            .chain([
                "-i",
                &tbk,
                "-t",
                &out("i.trace"),
                "-o",
                &out("i.tq8"),
                &kc4qpq_log,
            ])
            .collect::<Vec<_>>(),
        passwords,
        6,
    );
    let person = [
        "--name",
        "Test Operator",
        "--address",
        "1 Test St",
        "--city",
        "Charleston",
        "--state",
        "SC",
        "--postcode",
        "29401",
        "--country",
        "USA",
        "--email",
        "test@example.org",
    ];
    // A renewal is signed by the key it renews, and makes a new one.
    runs.qg_trust(
        "cert renew",
        &["cert", "renew", "KC4QPQ", "-o", &out("renew.tq5")]
            .into_iter()
            .chain(person)
            .collect::<Vec<_>>(),
        "",
        0,
    );
    runs.qg_trust(
        "cert request",
        &[
            "cert",
            "request",
            "--call",
            "QG1REQ",
            "--dxcc",
            "291",
            "--from",
            "2020-01-01",
        ]
        .into_iter()
        .chain(["-o", &out("request.tq5")])
        .chain(person)
        .collect::<Vec<_>>(),
        "",
        0,
    );
    let list = runs.qg_trust("cert list", &["cert", "list"], "", 0);
    runs.qg_trust("cert list --json", &["cert", "list", "--json"], "", 0);
    runs.qg_trust("root list", &["root", "list"], "", 0);
    runs.qg_trust("location list", &["location", "list"], "", 0);
    let id = |call: &str, request: bool| {
        list.lines()
            .find(|l| {
                let words: Vec<&str> = l.split_whitespace().collect();
                words.get(1) == Some(&call) && l.contains("request sent") == request
            })
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("{call} in {list}"))
            .to_string()
    };
    let request = id("QG1REQ", true);
    runs.qg_trust(
        "cert abandon",
        &["cert", "abandon", &request, "--force"],
        "",
        0,
    );
    let w4w = id("W4W", false);
    runs.qg_trust("cert delete", &["cert", "delete", &w4w, "--force"], "", 0);

    // The command line has no export: the custody program writes the library's encrypted export,
    // its store folders and a .tq8 into the home's temporary folder.
    let secrets = SecretsFolder::new();
    let export_secrets = secrets.0.join("export-secrets");
    let import_password_file = secrets.0.join("import-password");
    std::fs::write(&import_password_file, p12_password()).expect("test import password");
    let case = |file: &str| {
        corpus(CUSTODY_CASE, file)
            .to_str()
            .expect("UTF-8")
            .to_string()
    };
    let mut child = runs
        .command(Path::new(WIPED))
        .args([
            case("tqsl/keys/QG0TEST"),
            case("tqsl/certs/user"),
            at("adif/qg0test-small.adi"),
            case("key-password"),
            import_password_file.to_str().expect("UTF-8").to_string(),
            export_secrets.to_str().expect("UTF-8").to_string(),
            "files".to_string(),
        ])
        .spawn()
        .expect("qgt-custody");
    // Answers its one wait at once.
    child
        .stdin
        .take()
        .expect("its input")
        .write_all(b"\n")
        .expect("its input");
    runs.finish("qgt-custody files", child, 0);

    let mut streams = std::mem::take(&mut runs.streams);
    keyring.stop();
    let mut places = Vec::new();
    files(&home.0, &home.0, &mut places);
    for expected in [
        ".local/share/qso-graph-trust/store.xml",
        ".local/share/keyrings/login.keyring",
        "out/qg0test.tq8",
        "out/store.trace",
        "out/p.trace",
        "out/renew.tq5",
        "tmp/qgt-custody-export-",
    ] {
        assert!(
            places
                .iter()
                .any(|(name, _)| name.starts_with(&format!("file {expected}"))),
            "{expected} was not written: {:?}",
            places.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
    }
    assert!(
        places.iter().any(|(name, _)| name.ends_with("export.qgt")),
        "no export was written"
    );
    let needles = written_needles(&export_secrets);
    if plant {
        let (_, kc4qpq) = &needles
            .iter()
            .find(|(label, _)| label == "KC4QPQ: p, big-endian, hex")
            .expect("KC4QPQ's prime");
        let planted = home.0.join(PLANTED);
        std::fs::create_dir_all(planted.parent().expect("a folder")).expect("planted folder");
        std::fs::write(&planted, [b"notes\n".as_slice(), kc4qpq, b"\n"].concat())
            .expect("planted file");
        places.push((
            format!("file {PLANTED}"),
            std::fs::read(planted).expect("it"),
        ));
        let (_, stderr) = streams
            .iter_mut()
            .find(|(name, _)| name == "standard error of cert list")
            .expect("a run's standard error");
        stderr.extend_from_slice(b"qg-trust: qgt-kc4qpq\n");
    }
    places.extend(streams);
    search(&needles, &places)
}

/// The case whose key the custody program signs and exports with.
const CUSTODY_CASE: &str = "1024-password";

#[test]
fn nothing_qg_trust_writes_holds_a_key_or_a_password() {
    assert_eq!(what_qg_trust_writes(false), Vec::<String>::new());
}

#[test]
fn the_search_finds_a_planted_file_and_a_planted_line_of_standard_error() {
    let found = what_qg_trust_writes(true);
    for expected in [
        format!("KC4QPQ: p, big-endian, hex in file {PLANTED}"),
        "KC4QPQ: the password in standard error of cert list".to_string(),
    ] {
        assert!(found.contains(&expected), "{expected} not in {found:?}");
    }
    // Nothing but what was planted.
    for f in &found {
        assert!(
            f.ends_with(PLANTED) || f.ends_with("standard error of cert list"),
            "{f}"
        );
    }
}

#[test]
fn the_encoded_needles_are_the_keys_own() {
    // Control: KN4YU's key file is tqsllib's, unencrypted, so it holds the key's DER in base64,
    // as its PEM text: the base64 needle must find it there, as the key file's text does. And
    // each password-protected key file holds its key only encrypted: no plaintext needle of its
    // own may match it.
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/standard");
    let needles = written_key_needles();
    let place = |call: &str| {
        let file = corpus.join("tqsl/keys").join(call);
        vec![(call.to_string(), std::fs::read(file).expect("the key file"))]
    };
    let found = search(&needles, &place("KN4YU"));
    for expected in [
        "KN4YU: the key's DER, base64 at offset 0 in KN4YU",
        "KN4YU: the key file's text in KN4YU",
    ] {
        assert!(found.iter().any(|f| f == expected), "{expected}: {found:?}");
    }
    let found = search(&needles, &place("KC4QPQ"));
    assert_eq!(found, vec!["KC4QPQ: the key file's text in KC4QPQ"]);
}
