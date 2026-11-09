// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{Store, StoreError};
use crate::certificate::Trust;
use crate::import::{ImportError, ImportedCertificate};

/// A certificate whose UTC validity-end date is within the warning interval, or already past.
/// QSO-end dates do not determine expiry. Includes public-only certificates as well as signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiringCertificate {
    /// The certificate's store ID.
    pub id: String,
    /// Its callsign.
    pub callsign: String,
    /// Its X.509 notAfter timestamp.
    pub expires_at: SystemTime,
    /// UTC calendar days until notAfter; negative after the validity-end date.
    pub days_left: i64,
    /// The validity-end date has passed (the end date itself is not expired).
    pub expired: bool,
}

fn utc_day(time: SystemTime) -> i64 {
    let seconds = match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i128::from(d.as_secs()),
        Err(e) => {
            -i128::from(e.duration().as_secs()) - i128::from(e.duration().subsec_nanos() != 0)
        }
    };
    // SystemTime's seconds fit u64; its days fit i64 even at the platform's extremes.
    seconds.div_euclid(86_400) as i64
}

impl Store {
    /// Load ARRL's gzip/XML `.tq6` (plain XML is also accepted). Validate every certificate to
    /// `trust` and this store's accepted roots before publication. Matching pending requests attach
    /// by SPKI, callsign and DXCC, exactly as `add_requested_certificate` does; other certificates
    /// are stored without keys. All attachments and additions share one lock and atomic
    /// public-file replacement. A missing or invalid pending key is an error, never silently
    /// downgraded to a keyless import.
    ///
    /// A file whose certificates chain to a root it brings, not trusted yet, is refused with
    /// [`ImportError::UntrustedRoot`] naming it, unless `accept_root` is that root's SHA-256
    /// fingerprint: then the root is trusted from now on, kept in the same file replacement as the
    /// certificates (`crate::certificate` says which roots may be). A fingerprint that is not such
    /// a root's is refused with [`ImportError::RootMismatch`].
    pub fn import_tq6(
        &self,
        bytes: &[u8],
        trust: &Trust,
        accept_root: Option<&str>,
    ) -> Result<Vec<ImportedCertificate>, ImportError> {
        let pending = self.inspect_tq6(bytes, trust)?;
        Ok(self
            .commit(
                pending,
                super::ImportChoices {
                    accept_roots: &accept_root.into_iter().collect::<Vec<_>>(),
                    ..Default::default()
                },
            )?
            .certificates)
    }

    /// Load a password-authenticated PKCS#12 `.p12`. Supports PBES2/PBKDF2 with SHA-1 or SHA-256
    /// and AES-128/256-CBC or 3DES-CBC, and PKCS#12 SHA-1/3DES PBE. SHA-1 and SHA-256 MACs are
    /// required and verified before decrypting. RC2 (including TQSL's weak certificate bags),
    /// other algorithms and multiple user certificates/keys are refused. Passwords are UTF-8
    /// BMP text (empty allowed), at most `MAX_PASSWORD_LEN`; they are borrowed and never stored.
    /// Only public metadata and the backend's credential name leave this method. A root the file
    /// brings is confirmed with `accept_root`, as for [`Store::import_tq6`].
    pub fn import_pkcs12(
        &self,
        bytes: &[u8],
        password: &[u8],
        trust: &Trust,
        accept_root: Option<&str>,
    ) -> Result<ImportedCertificate, ImportError> {
        let pending = self.inspect_pkcs12(bytes, password, trust)?;
        let imported = self
            .commit(
                pending,
                super::ImportChoices {
                    accept_roots: &accept_root.into_iter().collect::<Vec<_>>(),
                    ..Default::default()
                },
            )?
            .certificates
            .into_iter()
            .next()
            .ok_or(ImportError::Malformed)?;
        if imported.already_here {
            Err(StoreError::AlreadyExists.into())
        } else {
            Ok(imported)
        }
    }

    /// List certificates with fewer than `days` UTC calendar days until their X.509 validity
    /// end, plus every already-expired certificate. The strict threshold and date comparison
    /// follow TQSL 2.8.7 (`apps/tqsl.cpp:4092-4095`, `openssl_cert.cpp:2042-2063`); its default
    /// is 60 days. Unlike its startup UI, this list also includes expired and keyless records.
    /// Results follow store order. A zero threshold lists only already-expired certificates.
    pub fn expiring_certificates(
        &self,
        now: SystemTime,
        days: u32,
    ) -> Result<Vec<ExpiringCertificate>, StoreError> {
        Ok(self
            .certificates()?
            .into_iter()
            .filter_map(|c| {
                let expires_at = c.certificate.validity().1;
                let days_left = utc_day(expires_at) - utc_day(now);
                (days_left < i64::from(days)).then(|| ExpiringCertificate {
                    id: c.id,
                    callsign: c.certificate.callsign().into(),
                    expires_at,
                    days_left,
                    expired: days_left < 0,
                })
            })
            .collect())
    }
}
