// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;

#[test]
fn generated_passwords_are_unbiased_alphanumeric_and_debug_is_opaque() {
    let a = Password::generate().expect("random");
    let b = Password::generate().expect("random");
    assert_ne!(a.expose_secret(), b.expose_secret());
    assert_eq!(format!("{a:?}"), "Password(..)");
    let mut counts = [0u32; 62];
    for _ in 0..3100 {
        let password = Password::generate().expect("random");
        assert_eq!(password.expose_secret().len(), 20);
        for byte in password.expose_secret().bytes() {
            let index = ALPHABET.iter().position(|&c| c == byte).expect("alphabet");
            counts[index] += 1;
        }
    }
    let chi_square: f64 = counts
        .iter()
        .map(|&n| (f64::from(n) - 1000.0).powi(2) / 1000.0)
        .sum();
    // 61 degrees of freedom; generous threshold, but detects byte % 62 without rejection.
    assert!(chi_square < 160.0, "chi square {chi_square}");
}

#[test]
fn typed_passwords_cannot_seal_and_invalid_passwords_are_refused() {
    for text in [
        "",
        "a",
        "Abc0123456789012345",
        "Abc01234567890123456!",
        "Abc01234567890123456é",
    ] {
        assert_eq!(
            Password::from_typed(text).err(),
            Some(ExportError::Password)
        );
    }
    let typed = Password::from_typed("Abc012345678901234567").expect("typed");
    assert_eq!(
        seal(LOTW_PART, b"plaintext", &typed),
        Err(ExportError::Password)
    );
}

#[test]
fn roundtrip_is_randomized_and_every_byte_and_part_name_is_authenticated() {
    let password = Password::generate().expect("random");
    let typed = Password::from_typed(password.expose_secret()).expect("typed");
    let sealed = seal(LOTW_PART, b"secret", &password).expect("seal");
    assert_ne!(seal(LOTW_PART, b"secret", &password).expect("seal"), sealed);
    assert_eq!(&*open(LOTW_PART, &sealed, &typed).expect("open"), b"secret");
    let wrong = Password::generate().expect("random");
    assert_eq!(
        open(LOTW_PART, &sealed, &wrong).err(),
        Some(ExportError::Open)
    );
    assert_eq!(
        open("other", &sealed, &typed).err(),
        Some(ExportError::Open)
    );
    for index in 0..sealed.len() {
        let mut altered = sealed.clone();
        altered[index] ^= 1;
        assert_eq!(
            open(LOTW_PART, &altered, &typed).err(),
            Some(ExportError::Open)
        );
    }
    for length in 0..sealed.len() {
        assert_eq!(
            open(LOTW_PART, &sealed[..length], &typed).err(),
            Some(ExportError::Open)
        );
    }
    let mut appended = sealed.clone();
    appended.push(0);
    assert_eq!(
        open(LOTW_PART, &appended, &typed).err(),
        Some(ExportError::Open)
    );
    let sealed = seal("", b"", &password).expect("empty");
    assert!(open("", &sealed, &typed).expect("empty").is_empty());
}

#[test]
fn hostile_work_factors_are_refused_before_deriving() {
    let password = Password::generate().expect("random");
    let mut bytes = vec![0; HEADER + 16];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8] = VERSION;
    for count in [0, 1, ITERATIONS - 1, ITERATIONS + 1, u32::MAX] {
        bytes[9..13].copy_from_slice(&count.to_be_bytes());
        assert_eq!(
            open_with(LOTW_PART, &bytes, &password, |_, _, _| panic!(
                "must not derive"
            ))
            .err(),
            Some(ExportError::Open)
        );
    }
    bytes[9..13].copy_from_slice(&ITERATIONS.to_be_bytes());
    let called = std::cell::Cell::new(false);
    assert!(
        open_with(LOTW_PART, &bytes, &password, |_, _, _| {
            called.set(true);
            Zeroizing::new([0; 32])
        })
        .is_err()
    );
    assert!(called.get(), "the supported count reaches derivation");
}
