// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use super::*;

#[test]
fn service_selection_uses_only_fixed_names_and_os_test_always_isolates() {
    assert_eq!(selected_service(false, false), SERVICE);
    assert_eq!(selected_service(false, true), TEST_SERVICE);
    assert_eq!(selected_service(true, false), TEST_SERVICE);
    assert_eq!(selected_service(true, true), TEST_SERVICE);
    assert_eq!(OsKeyStore::new(true).service, TEST_SERVICE);
    let expected = selected_service(
        false,
        std::env::var_os("QG_DESKTOP_TEST_KEYCHAIN").is_some(),
    );
    assert_eq!(OsKeyStore::new(false).service, expected);
}

#[test]
fn invalid_os_inputs_are_refused_before_contacting_a_service() {
    let keys = OsKeyStore::new(true);
    assert_eq!(keys.put("callsign", &[1]), Err(KeyStoreError::InvalidInput));
    assert!(matches!(
        keys.get("callsign"),
        Err(KeyStoreError::InvalidInput)
    ));
    assert_eq!(keys.exists("callsign"), Err(KeyStoreError::InvalidInput));
    assert_eq!(keys.delete("callsign"), Err(KeyStoreError::InvalidInput));
    let name = "key:00000000-0000-4000-8000-000000000001";
    assert_eq!(keys.put(name, &[]), Err(KeyStoreError::InvalidInput));
    assert_eq!(
        keys.put(name, &vec![0; MAX_KEY_LEN + 1]),
        Err(KeyStoreError::InvalidInput)
    );
}

#[test]
fn secret_results_are_wiping_bytes_bounded_and_never_passwords() {
    let secret: Zeroizing<Vec<u8>> = secret_result(Ok(vec![0, 255, 128]))
        .expect("read")
        .expect("present");
    assert!(secret.as_slice() == [0, 255, 128]);
    assert!(
        secret_result(Err(keyring::Error::NoEntry))
            .expect("missing")
            .is_none()
    );
    assert!(matches!(
        secret_result(Ok(vec![0; MAX_KEY_LEN + 1])),
        Err(KeyStoreError::InvalidInput)
    ));
    assert!(matches!(
        secret_result(Ok(Vec::new())),
        Err(KeyStoreError::InvalidInput)
    ));
}

#[test]
fn backend_errors_expose_only_fixed_store_categories() {
    for (error, expected) in [
        (
            keyring::Error::Invalid("private input".into(), "private reason".into()),
            KeyStoreError::InvalidInput,
        ),
        (
            keyring::Error::TooLong("private input".into(), 42),
            KeyStoreError::InvalidInput,
        ),
        (
            keyring::Error::NoStorageAccess(Box::new(std::io::Error::other("private failure"))),
            KeyStoreError::AccessDenied,
        ),
        (
            keyring::Error::PlatformFailure(Box::new(std::io::Error::other("private failure"))),
            KeyStoreError::Unavailable,
        ),
        (
            keyring::Error::BadEncoding(vec![0, 255, 128]),
            KeyStoreError::Unavailable,
        ),
        (
            keyring::Error::BadDataFormat(
                vec![0, 255, 128],
                Box::new(std::io::Error::other("private failure")),
            ),
            KeyStoreError::Unavailable,
        ),
    ] {
        let mapped = keyring_error(error);
        assert_eq!(mapped, expected);
        assert!(!mapped.to_string().contains("private"));
        assert!(!format!("{mapped:?}").contains("private"));
    }
}

#[test]
fn credential_names_are_validated_and_bounded_before_collection() {
    let mut names = Vec::new();
    assert_eq!(
        push_name(&mut names, "callsign".into()),
        Err(KeyStoreError::InvalidInput)
    );
    assert!(names.is_empty());
    let name = "key:00000000-0000-4000-8000-000000000001";
    for _ in 0..MAX_KEYS {
        push_name(&mut names, name.into()).expect("within limit");
    }
    assert_eq!(
        push_name(&mut names, name.into()),
        Err(KeyStoreError::InvalidInput)
    );
    assert_eq!(names.len(), MAX_KEYS);
}

#[test]
fn windows_discovery_is_explicitly_unavailable_without_touching_a_provider() {
    assert_eq!(windows::ORPHAN_DETECTION, OrphanDetection::Unavailable);
    for service in [SERVICE, TEST_SERVICE] {
        assert_eq!(
            windows::names(service),
            Err(KeyStoreError::EnumerationUnavailable)
        );
    }
}

#[test]
fn linux_match_limits_apply_to_presence_and_enumeration_responses() {
    assert_eq!(check_match_count(MAX_KEYS, 0), Ok(()));
    assert_eq!(check_match_count(0, MAX_KEYS), Ok(()));
    assert_eq!(check_match_count(MAX_KEYS / 2, MAX_KEYS / 2), Ok(()));
    for (unlocked, locked) in [
        (MAX_KEYS + 1, 0),
        (0, MAX_KEYS + 1),
        (MAX_KEYS, 1),
        (usize::MAX, 1),
    ] {
        assert_eq!(
            check_match_count(unlocked, locked),
            Err(KeyStoreError::InvalidInput)
        );
    }
}
