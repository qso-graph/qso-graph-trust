// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::{MAX_KEY_LEN, StoreError};

/// QG Trust's production credential-store service. A backend instance is scoped to this service.
pub const SERVICE: &str = "io.qso-graph.trust";
/// The separate service for integration tests; never point tests at the production service.
pub const TEST_SERVICE: &str = "io.qso-graph.trust.test";
/// Bound enumeration too: a broken backend must not make opening a store unbounded.
pub const MAX_KEYS: usize = 8192;

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
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "unavailable",
            Self::AccessDenied => "access denied",
            Self::AlreadyExists => "entry already exists",
            Self::InvalidInput => "invalid entry or too many entries",
        })
    }
}
impl std::error::Error for KeyStoreError {}

/// The seam to an OS credential store. Instances are scoped to `SERVICE` or `TEST_SERVICE`;
/// all names are `key:<uuid v4>`. Backends must bound secrets by `MAX_KEY_LEN` and enumeration by
/// `MAX_KEYS`, wipe secret temporaries, and return only these fixed errors, never backend messages.
/// Secret DER is handed to the backend only for custody; the Store API never exports it.
pub trait KeyStore: Send + Sync {
    /// Atomically create a credential containing PKCS#8 DER. On error nothing was created;
    /// existing names are refused, never overwritten.
    fn put(&self, name: &str, der: &[u8]) -> Result<(), KeyStoreError>;
    /// Read a secret into wiped memory, or `None` if absent. Refuse oversized secrets before copying.
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;
    /// Remove a credential. An absent name is already deleted and succeeds.
    fn delete(&self, name: &str) -> Result<(), KeyStoreError>;
    /// Check presence without reading secret bytes or prompting to unlock them.
    fn exists(&self, name: &str) -> Result<bool, KeyStoreError>;
    /// Enumerate names in this service without reading secrets, for orphan reporting. Never include
    /// another service's entries. Bound the result before allocating more than `MAX_KEYS` names.
    fn names(&self) -> Result<Vec<String>, KeyStoreError>;
}

/// A volatile, thread-safe credential store for this crate's tests and callers' own tests.
/// Every owned secret, including a copy returned by `get`, is `Zeroizing`. It is never durable
/// storage and must not be used to keep an operator's keys at rest.
#[derive(Default)]
pub struct MemoryKeyStore {
    secrets: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemoryKeyStore {
    /// An empty test store.
    pub fn new() -> Self {
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
