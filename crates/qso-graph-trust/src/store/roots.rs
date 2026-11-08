// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The roots the store has accepted, beside LoTW's pinned ones. ARRL changes roots now and then and
//! delivers a new one only inside the files it issues, so a root a file brings may be kept here, by
//! [`crate::certificate`]'s rules: from a TQSL backup or QG Trust's own export part automatically,
//! from a `.tq6` or `.p12` once the operator confirms its SHA-256 fingerprint. The CA certificates on
//! the chains to such a root are kept with it, so the certificates under it still chain when the
//! store is exported and restored. LoTW's pinned roots and CAs are always trusted and never stored.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{Data, Store, StoreError, format};
use crate::certificate::{self, FoundRoot, Trust, fingerprint, parse_fingerprint};
use crate::tbk::Backup;

/// The most accepted roots in a store, and separately the most CA certificates kept under them.
pub const MAX_ROOTS: usize = 16;

/// Where a trusted root or CA came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootSource {
    /// Pinned in this library: LoTW's own ([`Trust::lotw`]).
    BuiltIn,
    /// Confirmed by the operator importing a `.tq6`.
    Tq6,
    /// Confirmed by the operator importing a `.p12`.
    P12,
    /// From the operator's TQSL backup.
    Tbk,
    /// From QG Trust's own encrypted export part, restored.
    Part,
}

impl RootSource {
    /// The name this source has in the store file and in lists: `built in`, `tq6`, `p12`, `tbk`
    /// or `part`.
    pub fn name(self) -> &'static str {
        match self {
            Self::BuiltIn => "built in",
            Self::Tq6 => "tq6",
            Self::P12 => "p12",
            Self::Tbk => "tbk",
            Self::Part => "part",
        }
    }

    pub(super) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "tq6" => Self::Tq6,
            "p12" => Self::P12,
            "tbk" => Self::Tbk,
            "part" => Self::Part,
            _ => return None,
        })
    }
}

/// Whether a trusted certificate is a root or a CA under one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootKind {
    /// A self-signed root.
    Root,
    /// A CA certificate issued under a root.
    Ca,
}

/// A root or CA certificate QG Trust trusts, as a list shows one. Public data only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedRoot {
    /// A root or a CA under one.
    pub kind: RootKind,
    /// Its subject's common name.
    pub subject: String,
    /// Its serial number, uppercase hexadecimal without leading zero bytes.
    pub serial: String,
    /// When it comes into force.
    pub not_before: SystemTime,
    /// When it ends. TQSL, and so QG Trust, accept a root or CA past its end in a chain.
    pub not_after: SystemTime,
    /// Its SHA-256 fingerprint, uppercase hexadecimal pairs separated by colons.
    pub fingerprint: String,
    /// Where it came from.
    pub source: RootSource,
    /// When it was accepted, in whole seconds since the Unix epoch; `None` for a built-in one.
    pub accepted_at: Option<u64>,
}

/// An accepted root or CA as the store file holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AcceptedRoot {
    pub der: Vec<u8>,
    pub kind: RootKind,
    pub source: RootSource,
    pub accepted_at: u64,
}

impl AcceptedRoot {
    fn describe(&self) -> Option<TrustedRoot> {
        describe(&self.der, self.kind, self.source, Some(self.accepted_at))
    }
}

fn describe(
    der: &[u8],
    kind: RootKind,
    source: RootSource,
    accepted_at: Option<u64>,
) -> Option<TrustedRoot> {
    let d = certificate::describe(der)?;
    Some(TrustedRoot {
        kind,
        subject: d.subject,
        serial: d.serial,
        not_before: d.not_before,
        not_after: d.not_after,
        fingerprint: fingerprint(der),
        source,
        accepted_at,
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `base` with the store's accepted roots and CAs.
pub(super) fn extend(base: &Trust, data: &Data) -> Trust {
    base.extended(
        data.roots
            .iter()
            .filter(|r| r.kind == RootKind::Root)
            .map(|r| r.der.as_slice()),
        data.roots
            .iter()
            .filter(|r| r.kind == RootKind::Ca)
            .map(|r| r.der.as_slice()),
    )
}

/// Keeps the roots `found` names, and the CAs on their chains, that the store does not hold yet;
/// returns the roots newly kept.
pub(super) fn add(
    data: &mut Data,
    found: &[FoundRoot],
    source: RootSource,
) -> Result<Vec<TrustedRoot>, StoreError> {
    let accepted_at = now();
    let mut added = Vec::new();
    for f in found {
        let entries = std::iter::once((RootKind::Root, &f.root))
            .chain(f.authorities.iter().map(|a| (RootKind::Ca, a)));
        for (kind, der) in entries {
            if data.roots.iter().any(|r| &r.der == der) {
                continue;
            }
            if data.roots.iter().filter(|r| r.kind == kind).count() >= MAX_ROOTS {
                return Err(StoreError::Limit("accepted roots"));
            }
            let entry = AcceptedRoot {
                der: der.clone(),
                kind,
                source,
                accepted_at,
            };
            if kind == RootKind::Root {
                added.extend(entry.describe());
            }
            data.roots.push(entry);
        }
    }
    Ok(added)
}

/// LoTW's pinned roots and CAs, then the roots `data` has accepted: what [`Store::trusted_roots`] and
/// [`super::Listing::trusted_roots`] both give.
pub(super) fn trusted_roots(data: &Data) -> Vec<TrustedRoot> {
    let (roots, authorities) = Trust::lotw().certificates();
    let built_in = roots
        .iter()
        .map(|d| (d, RootKind::Root))
        .chain(authorities.iter().map(|d| (d, RootKind::Ca)))
        .filter_map(|(d, kind)| describe(d, kind, RootSource::BuiltIn, None));
    built_in
        .chain(data.roots.iter().filter_map(AcceptedRoot::describe))
        .collect()
}

impl Store {
    /// The trust to import and check certificates with: LoTW's pinned roots and CAs, and the roots
    /// this store has accepted with the CAs kept under them. [`Trust::lotw`] stays pinned only.
    pub fn trust(&self) -> Result<Trust, StoreError> {
        self.trust_with(&Trust::lotw())
    }

    /// `base` with this store's accepted roots and the CAs kept under them, as tests use a test
    /// root's trust in place of LoTW's.
    pub fn trust_with(&self, base: &Trust) -> Result<Trust, StoreError> {
        let _lock = self.lock()?;
        Ok(extend(base, &self.read()?))
    }

    /// Every root and CA QG Trust trusts: LoTW's pinned ones first ([`RootSource::BuiltIn`]), then
    /// those this store has accepted, in the order accepted.
    pub fn trusted_roots(&self) -> Result<Vec<TrustedRoot>, StoreError> {
        let data = {
            let _lock = self.lock()?;
            self.read()?
        };
        Ok(trusted_roots(&data))
    }

    /// Stops trusting a root or CA this store accepted, by its SHA-256 fingerprint (colons
    /// optional, either case). CA certificates kept under a root that no longer chain to a trusted
    /// one go with it. LoTW's pinned roots and CAs cannot be removed. Certificates already in the
    /// store are kept; a later import under the removed root needs it accepted again.
    pub fn remove_root(&self, fingerprint: &str) -> Result<TrustedRoot, StoreError> {
        let given = parse_fingerprint(fingerprint).ok_or(StoreError::Invalid(
            "a root is named by its SHA-256 fingerprint",
        ))?;
        let lotw = Trust::lotw();
        let (roots, authorities) = lotw.certificates();
        if roots
            .iter()
            .chain(&authorities)
            .any(|d| certificate::fingerprint(d) == given)
        {
            return Err(StoreError::BuiltInRoot);
        }
        let _lock = self.lock()?;
        let mut data = self.read()?;
        let i = data
            .roots
            .iter()
            .position(|r| certificate::fingerprint(&r.der) == given)
            .ok_or(StoreError::NotFound)?;
        let removed = data.roots.remove(i);
        // A CA whose root is gone is no longer trusted for anything: it goes too.
        loop {
            let trust = extend(&lotw, &data);
            let Some(orphan) = data.roots.iter().position(|r| {
                r.kind == RootKind::Ca
                    && certificate::verify_imported(&r.der, &trust, &[], true).is_err()
            }) else {
                break;
            };
            data.roots.remove(orphan);
        }
        self.replace(&format::write(&data)?)?;
        removed
            .describe()
            .ok_or(StoreError::Invalid("accepted root"))
    }

    /// Keeps the roots a TQSL backup brings that its own certificates chain to and `trust` (with
    /// the store's accepted roots) does not hold, by [`crate::certificate`]'s rules: the backup is
    /// the operator's own, so no confirmation is asked. Read the backup with
    /// [`crate::tbk::read_trusting_roots`]. Returns the roots newly kept, for the operator to see;
    /// a backup with none changes nothing.
    pub fn trust_backup_roots(
        &self,
        backup: &Backup,
        trust: &Trust,
    ) -> Result<Vec<TrustedRoot>, StoreError> {
        let _lock = self.lock()?;
        let mut data = self.read()?;
        let found = backup.found_roots(&extend(trust, &data));
        let added = add(&mut data, &found, RootSource::Tbk)?;
        if !found.is_empty() {
            self.replace(&format::write(&data)?)?;
        }
        Ok(added)
    }
}
