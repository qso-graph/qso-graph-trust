// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::{MAX_KEY_LEN, StoreError};

mod os;
pub(super) use os::OsKeyStore;

/// QG Trust's production credential-store service. A backend instance is scoped to this service.
pub const SERVICE: &str = "io.qso-graph.trust";
/// The separate service for integration tests; never point tests at the production service.
pub const TEST_SERVICE: &str = "io.qso-graph.trust.test";
/// Maximum names QGT accepts from a provider response and collects for orphan detection.
/// Provider and OS allocations made before returning that response are outside QGT's control.
pub const MAX_KEYS: usize = 8192;

/// Whether a backend can discover credentials absent from the public store file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OrphanDetection {
    /// Enumeration is supported; a successful open checked for orphaned credentials.
    #[default]
    Available,
    /// Enumeration is unavailable. Windows cannot enumerate without reading unrelated secrets,
    /// so it checks only credentials named by the file. An empty orphan list is inconclusive.
    Unavailable,
}

/// A credential failure, deliberately limited to fixed categories so errors cannot expose secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStoreError {
    /// The credential service cannot be reached or its state is unavailable.
    Unavailable,
    /// Access was refused or cancelled by the operator.
    AccessDenied,
    /// `put` never overwrites an existing name.
    AlreadyExists,
    /// An invalid name, secret length, or enumeration exceeding `MAX_KEYS`.
    InvalidInput,
    /// This backend cannot enumerate credentials without reading unrelated secrets.
    EnumerationUnavailable,
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "unavailable",
            Self::AccessDenied => "access denied",
            Self::AlreadyExists => "entry already exists",
            Self::InvalidInput => "invalid entry or too many entries",
            Self::EnumerationUnavailable => "credential enumeration is unavailable",
        })
    }
}
impl std::error::Error for KeyStoreError {}

/// The seam to an OS credential store. Instances are scoped to `SERVICE` or `TEST_SERVICE`;
/// all names are `key:<uuid v4>`. Backends apply `MAX_KEY_LEN` and `MAX_KEYS` at the first point
/// QGT controls, wipe secret temporaries, and return only fixed errors, never backend messages.
/// These limits cannot bound allocations/copies already made by a provider before it returns.
/// Secret DER is handed to the backend only for custody; the Store API never exports it.
pub(crate) trait KeyStore: Send + Sync {
    /// Whether `names` can discover orphaned keys. This is a capability, not service health;
    /// a failure of a supported provider still returns an error rather than skipping discovery.
    fn orphan_detection(&self) -> OrphanDetection {
        OrphanDetection::Available
    }
    /// Atomically create a credential containing PKCS#8 DER. On error nothing was created;
    /// existing names are refused, never overwritten.
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError>;
    /// Read a secret into wiped memory, or `None` if absent. Wrap provider-owned bytes immediately
    /// and check `MAX_KEY_LEN` before QGT uses or copies them; the provider may already have copied
    /// or allocated the complete secret. An oversized response is wiped and refused too.
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;
    /// Remove a credential. An absent name is already deleted and succeeds.
    fn delete(&self, name: &str) -> Result<(), KeyStoreError>;
    /// Check presence without prompting to unlock it. Linux/macOS use metadata only. Windows
    /// reads only this named credential (including its native blob), which the provider wipes.
    fn exists(&self, name: &str) -> Result<bool, KeyStoreError>;
    /// Enumerate names in this service without reading secrets, or `EnumerationUnavailable` when
    /// unsupported. Check the provider's response count before QGT collects names; the provider's
    /// own response allocations are outside QGT's control. Never include another service's entries.
    fn names(&self) -> Result<Vec<String>, KeyStoreError>;
}

/// A volatile, thread-safe credential store, owned exclusively by Store outside this crate's tests.
/// Every owned secret, including a copy returned by `get`, is `Zeroizing`. It is never durable
/// storage and must not be used to keep an operator's keys at rest.
#[derive(Default)]
pub(super) struct MemoryKeyStore {
    secrets: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemoryKeyStore {
    /// An empty test store.
    pub(super) fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError> {
        if !valid_name(name, "key:") || der.is_empty() || der.len() > MAX_KEY_LEN {
            return Err(KeyStoreError::InvalidInput);
        }
        let mut secrets = self
            .secrets
            .lock()
            .map_err(|_| KeyStoreError::Unavailable)?;
        if secrets.contains_key(name) {
            return Err(KeyStoreError::AlreadyExists);
        }
        if secrets.len() >= MAX_KEYS {
            return Err(KeyStoreError::InvalidInput);
        }
        secrets.insert(name.into(), Zeroizing::new(der.to_vec()));
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        Ok(self
            .secrets
            .lock()
            .map_err(|_| KeyStoreError::Unavailable)?
            .get(name)
            .cloned())
    }

    fn delete(&self, name: &str) -> Result<(), KeyStoreError> {
        self.secrets
            .lock()
            .map_err(|_| KeyStoreError::Unavailable)?
            .remove(name);
        Ok(())
    }

    fn exists(&self, name: &str) -> Result<bool, KeyStoreError> {
        Ok(self
            .secrets
            .lock()
            .map_err(|_| KeyStoreError::Unavailable)?
            .contains_key(name))
    }

    fn names(&self) -> Result<Vec<String>, KeyStoreError> {
        Ok(self
            .secrets
            .lock()
            .map_err(|_| KeyStoreError::Unavailable)?
            .keys()
            .cloned()
            .collect())
    }
}

pub(super) fn new_name(prefix: &str) -> Result<String, StoreError> {
    let mut bytes = [0u8; 16];
    qso_graph_trust_awslc::random(&mut bytes).map_err(|_| StoreError::Random)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut name = String::from(prefix);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in bytes.into_iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            name.push('-');
        }
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(name)
}

pub(super) fn valid_name(name: &str, prefix: &str) -> bool {
    let Some(uuid) = name.strip_prefix(prefix) else {
        return false;
    };
    let b = uuid.as_bytes();
    b.len() == 36
        && b[14] == b'4'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        })
}
