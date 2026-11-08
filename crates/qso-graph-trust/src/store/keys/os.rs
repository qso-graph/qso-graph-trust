// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Desktop's default keyring backends, with metadata-only enumeration where supported. Windows
//! checks only file-named keys and cannot enumerate without reading unrelated secrets. No error
//! is formatted here. Returned secret buffers (including malformed data in errors) are wiped.

use std::sync::Mutex;
use zeroize::Zeroizing;

use super::{
    KeyStore, KeyStoreError, MAX_KEY_LEN, MAX_KEYS, OrphanDetection, SERVICE, TEST_SERVICE,
    valid_name,
};

pub(in crate::store) struct OsKeyStore {
    service: &'static str,
}

// Serialize check-and-create across backend instances in this process. Store's file lock also
// serializes cooperating processes using the shared folder, throughout credential publication.
static CREATE_LOCK: Mutex<()> = Mutex::new(());

impl OsKeyStore {
    pub(in crate::store) fn new(test: bool) -> Self {
        Self {
            service: selected_service(test, std::env::var_os("QG_DESKTOP_TEST_KEYCHAIN").is_some()),
        }
    }

    fn entry(&self, name: &str) -> Result<keyring::Entry, KeyStoreError> {
        check_name(name)?;
        keyring::Entry::new(self.service, name).map_err(keyring_error)
    }
}

fn selected_service(test: bool, desktop_test: bool) -> &'static str {
    // QGD-LTW-0007 requires Desktop and the command line to select the same namespace.
    // Presence selects a fixed name; no environment value becomes a credential-store service.
    if test || desktop_test {
        TEST_SERVICE
    } else {
        SERVICE
    }
}

fn check_name(name: &str) -> Result<(), KeyStoreError> {
    if valid_name(name, "key:") {
        Ok(())
    } else {
        Err(KeyStoreError::InvalidInput)
    }
}

fn keyring_error(error: keyring::Error) -> KeyStoreError {
    match error {
        keyring::Error::NoStorageAccess(_) => KeyStoreError::AccessDenied,
        keyring::Error::Invalid(_, _) | keyring::Error::TooLong(_, _) => {
            KeyStoreError::InvalidInput
        }
        keyring::Error::BadEncoding(bytes) | keyring::Error::BadDataFormat(bytes, _) => {
            // Even error payloads can contain secret bytes. Never pass them into our errors.
            drop(Zeroizing::new(bytes));
            KeyStoreError::Unavailable
        }
        _ => KeyStoreError::Unavailable,
    }
}

fn secret_result(
    result: keyring::Result<Vec<u8>>,
) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    // Wrap at the API boundary, before even inspecting its length. An oversized buffer is
    // wiped too, with no extra QGT secret copy. The provider has already allocated/copied the
    // complete response; MAX_KEY_LEN limits acceptance here, not those earlier allocations.
    match result.map(Zeroizing::new) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_KEY_LEN => Ok(Some(bytes)),
        Ok(_) => Err(KeyStoreError::InvalidInput),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(keyring_error(error)),
    }
}

impl KeyStore for OsKeyStore {
    fn orphan_detection(&self) -> OrphanDetection {
        platform::ORPHAN_DETECTION
    }
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError> {
        check_name(name)?;
        if der.is_empty() || der.len() > MAX_KEY_LEN {
            return Err(KeyStoreError::InvalidInput);
        }
        let _creation = CREATE_LOCK.lock().map_err(|_| KeyStoreError::Unavailable)?;
        // Store holds its file lock over the presence check, credential creation and file
        // replacement. Names are fresh random UUIDs, never derived from another store's record.
        // set_secret itself is an upsert, so refuse an existing entry before calling it.
        if self.exists(name)? {
            return Err(KeyStoreError::AlreadyExists);
        }
        if self.orphan_detection() == OrphanDetection::Available && self.names()?.len() >= MAX_KEYS
        {
            return Err(KeyStoreError::InvalidInput);
        }
        self.entry(name)?.set_secret(der).map_err(keyring_error)
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        secret_result(self.entry(name)?.get_secret())
    }

    fn delete(&self, name: &str) -> Result<(), KeyStoreError> {
        match self.entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(keyring_error(error)),
        }
    }

    fn exists(&self, name: &str) -> Result<bool, KeyStoreError> {
        check_name(name)?;
        platform::exists(self.service, name)
    }

    fn names(&self) -> Result<Vec<String>, KeyStoreError> {
        let mut names = platform::names(self.service)?;
        names.sort();
        names.dedup();
        Ok(names)
    }
}

#[cfg(any(unix, test))]
fn push_name(names: &mut Vec<String>, name: String) -> Result<(), KeyStoreError> {
    check_name(&name)?;
    if names.len() >= MAX_KEYS {
        return Err(KeyStoreError::InvalidInput);
    }
    names.push(name);
    Ok(())
}

#[cfg(any(all(unix, not(target_os = "macos")), test))]
fn check_match_count(unlocked: usize, locked: usize) -> Result<(), KeyStoreError> {
    if unlocked.saturating_add(locked) > MAX_KEYS {
        return Err(KeyStoreError::InvalidInput);
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use std::collections::HashMap;

    use secret_service::{EncryptionType, blocking::SecretService};

    use super::*;

    pub(super) const ORPHAN_DETECTION: OrphanDetection = OrphanDetection::Available;

    fn service_error(error: secret_service::Error) -> KeyStoreError {
        match error {
            secret_service::Error::Locked
            | secret_service::Error::Prompt
            | secret_service::Error::PromptDisconnected => KeyStoreError::AccessDenied,
            _ => KeyStoreError::Unavailable,
        }
    }

    pub(super) fn exists(service: &str, name: &str) -> Result<bool, KeyStoreError> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(service_error)?;
        let found = ss
            .search_items(HashMap::from([("service", service), ("username", name)]))
            .map_err(service_error)?;
        // SearchItems has already materialized every Item. Reject excessive matches at the
        // first point QGT controls, for presence checks as well as enumeration.
        check_match_count(found.unlocked.len(), found.locked.len())?;
        // SearchItems includes locked items. Never call unlock or read their secrets here.
        Ok(!found.unlocked.is_empty() || !found.locked.is_empty())
    }

    pub(super) fn names(service: &str) -> Result<Vec<String>, KeyStoreError> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(service_error)?;
        let found = ss
            .search_items(HashMap::from([("service", service)]))
            .map_err(service_error)?;
        // The provider has already allocated this batch. Bound acceptance before collecting
        // QGT's names or requesting item attributes; this cannot bound provider allocations.
        check_match_count(found.unlocked.len(), found.locked.len())?;
        let mut names = Vec::new();
        for item in found.unlocked.into_iter().chain(found.locked) {
            // Attributes are readable even when the item is locked, as in Desktop's check.
            let mut attributes = item.get_attributes().map_err(service_error)?;
            if attributes.get("service").map(String::as_str) != Some(service) {
                return Err(KeyStoreError::InvalidInput);
            }
            let name = attributes
                .remove("username")
                .ok_or(KeyStoreError::InvalidInput)?;
            push_name(&mut names, name)?;
        }
        Ok(names)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use security_framework::item::{ItemClass, ItemSearchOptions};
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};

    use super::*;

    pub(super) const ORPHAN_DETECTION: OrphanDetection = OrphanDetection::Available;

    fn service_error(error: security_framework::base::Error) -> KeyStoreError {
        match error.code() {
            -25293 | -25308 | -128 => KeyStoreError::AccessDenied,
            _ => KeyStoreError::Unavailable,
        }
    }

    fn search(
        service: &str,
        name: Option<&str>,
        limit: i64,
    ) -> Result<Vec<security_framework::item::SearchResult>, KeyStoreError> {
        // Match apple-native-keyring-store's default User-domain store, rather than searching
        // every keychain in the search list. Presence, listing, reads and writes share this scope.
        let keychains = [
            SecKeychain::default_for_domain(SecPreferencesDomain::User).map_err(service_error)?
        ];
        let mut options = ItemSearchOptions::new();
        options
            .keychains(&keychains)
            .class(ItemClass::generic_password())
            .service(service)
            .load_attributes(true)
            .limit(limit);
        if let Some(name) = name {
            options.account(name);
        }
        // No load_data: neither a key read nor a Keychain unlock prompt is needed.
        match options.search() {
            Ok(items) => Ok(items),
            Err(error) => match error.code() {
                -25300 => Ok(Vec::new()), // errSecItemNotFound
                _ => Err(service_error(error)),
            },
        }
    }

    pub(super) fn exists(service: &str, name: &str) -> Result<bool, KeyStoreError> {
        Ok(!search(service, Some(name), 1)?.is_empty())
    }

    pub(super) fn names(service: &str) -> Result<Vec<String>, KeyStoreError> {
        let found = search(service, None, MAX_KEYS as i64 + 1)?;
        if found.len() > MAX_KEYS {
            return Err(KeyStoreError::InvalidInput);
        }
        let mut names = Vec::new();
        for item in found {
            let mut attributes = item.simplify_dict().ok_or(KeyStoreError::InvalidInput)?;
            if attributes.get("svce").map(String::as_str) != Some(service) {
                return Err(KeyStoreError::InvalidInput);
            }
            let name = attributes
                .remove("acct")
                .ok_or(KeyStoreError::InvalidInput)?;
            push_name(&mut names, name)?;
        }
        Ok(names)
    }
}

// Compile the no-enumeration branch in Linux unit tests too, without accessing any OS store.
#[cfg(any(windows, test))]
mod windows {
    use super::*;

    pub(super) const ORPHAN_DETECTION: OrphanDetection = OrphanDetection::Unavailable;

    #[cfg(windows)]
    pub(super) fn exists(service: &str, name: &str) -> Result<bool, KeyStoreError> {
        let entry = keyring::Entry::new(service, name).map_err(keyring_error)?;
        // CredReadW returns ONLY this QGT credential, including its secret. The provider wipes
        // that native blob after extracting attributes. No unrelated credential is read.
        match entry.inner.get_attributes() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(keyring_error(error)),
        }
    }

    pub(super) fn names(_: &str) -> Result<Vec<String>, KeyStoreError> {
        // Credential Manager cannot enumerate without returning other credentials' secrets.
        // Do not initialize a provider or search, even for TEST_SERVICE.
        Err(KeyStoreError::EnumerationUnavailable)
    }
}

#[cfg(windows)]
use windows as platform;

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;

    pub(super) const ORPHAN_DETECTION: OrphanDetection = OrphanDetection::Unavailable;
    pub(super) fn exists(_: &str, _: &str) -> Result<bool, KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
    pub(super) fn names(_: &str) -> Result<Vec<String>, KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
}

#[cfg(test)]
mod tests;
