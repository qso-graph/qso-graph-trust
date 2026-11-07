// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A read-only, public listing of a store folder, for programs that show what the store holds and
//! must not change it or reach its keys (QSO Graph Desktop's `lotw:read`).
//!
//! [`Store::open`](super::Store::open) is the wrong tool for that: it creates the folder and
//! `store.lock`, and checks every named credential, which on Windows reads the secret. [`Listing`]
//! takes only a path, so it has no credential backend to call, and holds nothing but public data.
//!
//! **Reading without the lock is safe.** Writers publish a complete `store.xml.partial` and rename
//! it over `store.xml` (`Store::replace`), so a reader sees the old file or the new, never a torn
//! one; the lock exists to serialise writers, which each reload under it. A listing is a snapshot
//! of the file as it was when read, and may be one write behind. On Windows, Rust's standard library
//! opens files sharing delete access, so a reader's open handle does not stop a writer's rename.

use std::path::Path;

use super::{Data, StoreError, TrustedRoot, read_file, roots};
use crate::certificate::Certificate;

/// A certificate in the store, as a listing shows it. It carries no credential name.
///
/// There is no way to name the credential entry from a listing:
///
/// ```compile_fail,E0609
/// use qso_graph_trust::store::ListedCertificate;
/// fn name(c: &ListedCertificate) {
///     let _ = &c.key_name;
/// }
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ListedCertificate {
    /// The store's opaque certificate identifier, as [`StoredCertificate::id`](super::StoredCertificate::id).
    pub id: String,
    /// The certificate, which is public.
    pub certificate: Certificate,
    /// Whether the store file records a key for this certificate. This is only what `store.xml`
    /// says: the credential store is not asked, so a key since lost or removed there still shows
    /// as present. [`Store::open`](super::Store::open) reports those as missing.
    pub has_key: bool,
}

/// The public contents of a store folder: its certificates and its trusted roots.
///
/// Reading it writes nothing (no folder, no `store.lock`, no file), takes no lock and never calls a
/// credential store, on any platform. A missing folder or `store.xml` is an empty store. A file the
/// full store refuses is refused with the same error, since both use one reader.
///
/// Reading a listing cannot be given a credential backend:
///
/// ```compile_fail,E0061
/// use qso_graph_trust::store::{KeyBackend, Listing};
/// let _ = Listing::read("folder", KeyBackend::Os);
/// ```
#[derive(Clone, Debug)]
pub struct Listing {
    certificates: Vec<ListedCertificate>,
    trusted_roots: Vec<TrustedRoot>,
}

impl Listing {
    /// Read the store folder `dir` once, read-only.
    pub fn read(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self::from_data(read_file(&dir.as_ref().join("store.xml"))?))
    }

    fn from_data(data: Data) -> Self {
        Self {
            trusted_roots: roots::trusted_roots(&data),
            certificates: data
                .certificates
                .into_iter()
                .map(|c| ListedCertificate {
                    id: c.id,
                    certificate: c.certificate,
                    has_key: c.key_name.is_some(),
                })
                .collect(),
        }
    }

    /// The store's certificates, in the file's order, as [`Store::certificates`](super::Store::certificates)
    /// lists them.
    pub fn certificates(&self) -> &[ListedCertificate] {
        &self.certificates
    }

    /// Every root and CA trusted: LoTW's pinned ones, then those the store has accepted, as
    /// [`Store::trusted_roots`](super::Store::trusted_roots) gives them.
    pub fn trusted_roots(&self) -> &[TrustedRoot] {
        &self.trusted_roots
    }
}
