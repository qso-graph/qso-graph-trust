// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::time::{SystemTime, UNIX_EPOCH};

use super::roots::{self, RootSource};
use super::{
    MAX_KEY_LEN, Store, StoreError, StoredCertificate, check_certificate, format, keyless_twin,
    keys,
};
use crate::certificate::Trust;
use crate::import::{self, ImportError, ImportedCertificate};
use crate::pkcs12;
use crate::signing::TqslKey;

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
        let trust = self.trust_with(trust)?;
        let import::Checked { certificates, root } = import::tq6(bytes, &trust, accept_root)?;
        let _lock = self.lock()?;
        let mut data = self.read()?;
        roots::add(&mut data, root.as_slice(), RootSource::Tq6)?;
        let mut report: Vec<ImportedCertificate> = Vec::new();
        for certificate in certificates {
            // One already here is reported and the rest of the file still imported, unless it has
            // no key and its pending request is here: then it takes the request's key below.
            let pending_for = |data: &super::Data| {
                data.pending_requests.iter().any(|r| {
                    r.public_key_der == certificate.public_key_der()
                        && r.callsign == certificate.callsign()
                        && r.dxcc == certificate.dxcc()
                })
            };
            if let Some(existing) = data
                .certificates
                .iter()
                .find(|c| c.certificate.der() == certificate.der())
                && (existing.key_name.is_some() || !pending_for(&data))
            {
                report.push(ImportedCertificate {
                    id: existing.id.clone(),
                    has_key: existing.key_name.is_some(),
                    attached_request: false,
                    already_here: true,
                });
                continue;
            }
            let keyless = keyless_twin(&data, &certificate);
            if keyless.is_none() {
                check_certificate(&data, &certificate)?;
            }
            let pending = data.pending_requests.iter().position(|r| {
                r.public_key_der == certificate.public_key_der()
                    && r.callsign == certificate.callsign()
                    && r.dxcc == certificate.dxcc()
            });
            let key_name = if let Some(i) = pending {
                let name = data.pending_requests[i].key_name.clone();
                let der = self
                    .keys
                    .get(&name)
                    .map_err(StoreError::from)?
                    .ok_or(StoreError::NotFound)?;
                if der.len() > MAX_KEY_LEN {
                    return Err(StoreError::Limit("credential bytes").into());
                }
                TqslKey::from_pkcs8_der(&der, certificate.public_key_der())?;
                data.pending_requests.remove(i);
                Some(name)
            } else {
                None
            };
            if let Some(i) = keyless {
                // Here already without a key, and its request's key is here: attach it.
                data.certificates[i].key_name = key_name;
                report.push(ImportedCertificate {
                    id: data.certificates[i].id.clone(),
                    has_key: true,
                    attached_request: true,
                    already_here: false,
                });
                continue;
            }
            let id = keys::new_name("cert:")?;
            if data.certificates.iter().any(|c| c.id == id) {
                return Err(StoreError::AlreadyExists.into());
            }
            report.push(ImportedCertificate {
                id: id.clone(),
                has_key: key_name.is_some(),
                attached_request: pending.is_some(),
                already_here: false,
            });
            data.certificates.push(StoredCertificate {
                id,
                certificate,
                key_name,
            });
        }
        self.replace(&format::write(&data)?)?;
        Ok(report)
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
        let trust = self.trust_with(trust)?;
        let loaded = pkcs12::read_confirming(bytes, password, &trust, accept_root)?;
        let _lock = self.lock()?;
        let mut data = self.read()?;
        roots::add(&mut data, loaded.root.as_slice(), RootSource::P12)?;
        // The same certificate already here without its key takes this one.
        if let Some(i) = keyless_twin(&data, &loaded.certificate) {
            let name = keys::new_name("key:")?;
            if self.keys.exists(&name).map_err(StoreError::from)? {
                return Err(StoreError::AlreadyExists.into());
            }
            data.certificates[i].key_name = Some(name.clone());
            let id = data.certificates[i].id.clone();
            let xml = format::write(&data)?;
            self.put_and_replace(&name, &loaded.key, &xml)?;
            return Ok(ImportedCertificate {
                id,
                has_key: true,
                attached_request: false,
                already_here: false,
            });
        }
        check_certificate(&data, &loaded.certificate)?;
        let name = keys::new_name("key:")?;
        let id = keys::new_name("cert:")?;
        if self.keys.exists(&name).map_err(StoreError::from)?
            || data.certificates.iter().any(|c| c.id == id)
        {
            return Err(StoreError::AlreadyExists.into());
        }
        data.certificates.push(StoredCertificate {
            id: id.clone(),
            certificate: loaded.certificate,
            key_name: Some(name.clone()),
        });
        let xml = format::write(&data)?;
        self.put_and_replace(&name, &loaded.key, &xml)?;
        Ok(ImportedCertificate {
            id,
            has_key: true,
            attached_request: false,
            already_here: false,
        })
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
