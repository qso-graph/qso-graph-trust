// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::collections::{BTreeMap, BTreeSet};

use base64ct::{Base64, Encoding};
use x509_cert::der::Decode;
use x509_cert::spki::SubjectPublicKeyInfoRef;

use crate::certificate::{Certificate, MAX_CERTIFICATE_LEN};
use crate::station::{MAX_FIELDS, MAX_LEN, StationLocation};
use crate::xml::{self, Element};

use super::{
    Data, MAX_CERTIFICATES, MAX_FILE_LEN, MAX_LOCATIONS, MAX_NAME_LEN, MAX_PENDING_REQUESTS,
    MAX_SIGNED_KEY_LEN, MAX_SIGNED_QSOS, MAX_SIGNED_STATION_LEN, MAX_SIGNED_STATIONS,
    PendingRequest, SignedQso, StoreError, StoredCertificate, StoredLocation, VERSION, keys,
    signed,
};

pub(super) fn read(text: &str) -> Result<Data, StoreError> {
    let root = xml::parse(text).map_err(|_| StoreError::Invalid("XML"))?;
    if root.name != "qgt-store" {
        return Err(StoreError::Invalid("root element"));
    }
    let version = attribute(&root, "version", 10)?;
    if !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(StoreError::Invalid("version"));
    }
    let version = version
        .parse::<u32>()
        .map_err(|_| StoreError::Invalid("version"))?;
    if version > VERSION {
        return Err(StoreError::NewerVersion {
            found: version,
            supported: VERSION,
        });
    }
    // Version readers are separate: a future reader must not change what version 1 meant.
    match version {
        1 => read_v1(&root),
        2 => read_sections(&root, false),
        _ => Err(StoreError::Invalid("unsupported version")),
    }
}

fn read_v1(root: &Element<'_>) -> Result<Data, StoreError> {
    read_sections(root, true)
}

fn read_sections(root: &Element<'_>, legacy: bool) -> Result<Data, StoreError> {
    container(root, &["version"])?;
    if root.children.iter().any(|c| {
        ![
            "certificates",
            "locations",
            "signed-qsos",
            "pending-requests",
        ]
        .contains(&c.name)
    }) {
        return Err(StoreError::Invalid("store sections"));
    }
    let certificates = section(root, "certificates")?;
    let locations = section(root, "locations")?;
    let signed = section(root, "signed-qsos")?;
    container(certificates, &[])?;
    container(locations, &[])?;
    container(signed, &["version"])?;
    if attribute(signed, "version", 10)? != "1" || (legacy && !signed.children.is_empty()) {
        return Err(StoreError::Invalid(
            "signed-QSO section version or contents",
        ));
    }
    if certificates.children.len() > MAX_CERTIFICATES {
        return Err(StoreError::Limit("certificates"));
    }
    if locations.children.len() > MAX_LOCATIONS {
        return Err(StoreError::Limit("locations"));
    }
    let mut data = Data {
        signed_qsos: read_signed(signed)?,
        ..Data::default()
    };
    let mut ids = BTreeSet::new();
    let mut key_names = BTreeSet::new();
    let mut ders = BTreeSet::new();
    for c in &certificates.children {
        if c.name != "certificate" || !c.children.is_empty() {
            return Err(StoreError::Invalid("certificate element"));
        }
        attributes(c, &["id", "key"])?;
        let id = attribute(c, "id", 41)?;
        if !keys::valid_name(&id, "cert:") || !ids.insert(id.clone()) {
            return Err(StoreError::Invalid("certificate identifier"));
        }
        let key_name = if c.attribute("key").is_some() {
            let name = attribute(c, "key", 40)?;
            if !keys::valid_name(&name, "key:") || !key_names.insert(name.clone()) {
                return Err(StoreError::Invalid("key name"));
            }
            Some(name)
        } else {
            None
        };
        let encoded = c.text();
        if encoded.len() > MAX_CERTIFICATE_LEN.div_ceil(3) * 4 {
            return Err(StoreError::Limit("certificate bytes"));
        }
        let der =
            Base64::decode_vec(&encoded).map_err(|_| StoreError::Invalid("certificate base64"))?;
        if der.len() > MAX_CERTIFICATE_LEN {
            return Err(StoreError::Limit("certificate bytes"));
        }
        let certificate = Certificate::from_pem_or_der(&der)
            .map_err(|_| StoreError::Invalid("certificate DER"))?;
        if certificate.der() != der {
            return Err(StoreError::Invalid("certificate is not DER"));
        }
        if !ders.insert(der) {
            return Err(StoreError::Invalid("duplicate certificate"));
        }
        data.certificates.push(StoredCertificate {
            id,
            certificate,
            key_name,
        });
    }
    let mut names = BTreeSet::new();
    for l in &locations.children {
        if l.name != "location" {
            return Err(StoreError::Invalid("location element"));
        }
        container(l, &["name"])?;
        let name = attribute(l, "name", MAX_NAME_LEN)?;
        check_name(&name)?;
        if !names.insert(name.clone()) {
            return Err(StoreError::Invalid("duplicate location name"));
        }
        if l.children.len() > MAX_FIELDS {
            return Err(StoreError::Limit("station fields"));
        }
        let mut fields = Vec::new();
        for f in &l.children {
            if f.name != "field" || !f.children.is_empty() {
                return Err(StoreError::Invalid("station field element"));
            }
            attributes(f, &["name"])?;
            let name = attribute(f, "name", MAX_LEN)?;
            let value = f.text();
            if value.len() > MAX_LEN {
                return Err(StoreError::Limit("station field bytes"));
            }
            fields.push((name, value));
        }
        let borrowed: Vec<(&str, &str)> = fields
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let station =
            StationLocation::new(&borrowed).map_err(|_| StoreError::Invalid("station location"))?;
        data.locations.push(StoredLocation { name, station });
    }
    // Optional in version 1: stores written before request support remain readable. An older
    // reader refuses the new section rather than silently discarding pending-key custody.
    if root.children.iter().any(|c| c.name == "pending-requests") {
        let pending = section(root, "pending-requests")?;
        container(pending, &[])?;
        if pending.children.len() > MAX_PENDING_REQUESTS {
            return Err(StoreError::Limit("pending requests"));
        }
        let mut public_keys = BTreeSet::new();
        for r in &pending.children {
            if r.name != "request" || !r.children.is_empty() {
                return Err(StoreError::Invalid("pending request element"));
            }
            attributes(r, &["id", "call", "dxcc", "created", "key"])?;
            let id = attribute(r, "id", 44)?;
            if !keys::valid_name(&id, "request:") || !ids.insert(id.clone()) {
                return Err(StoreError::Invalid("request identifier"));
            }
            let key_name = attribute(r, "key", 40)?;
            if !keys::valid_name(&key_name, "key:") || !key_names.insert(key_name.clone()) {
                return Err(StoreError::Invalid("key name"));
            }
            let callsign = attribute(r, "call", 20)?;
            if !crate::qso::is_callsign(&callsign) {
                return Err(StoreError::Invalid("request callsign"));
            }
            let dxcc = attribute(r, "dxcc", 10)?
                .parse()
                .map_err(|_| StoreError::Invalid("request DXCC"))?;
            if crate::lotw::dxcc(dxcc).is_none() {
                return Err(StoreError::Invalid("request DXCC"));
            }
            let created_at = attribute(r, "created", 20)?
                .parse()
                .map_err(|_| StoreError::Invalid("request creation time"))?;
            let encoded = r.text();
            // A generated RSA-1024 SPKI is 162 bytes. Allow bounded DER overhead, without
            // allocating arbitrarily large public keys from an edited store file.
            if encoded.len() > 512 {
                return Err(StoreError::Limit("request SPKI bytes"));
            }
            let public_key_der = Base64::decode_vec(&encoded)
                .map_err(|_| StoreError::Invalid("request SPKI base64"))?;
            let spki = SubjectPublicKeyInfoRef::from_der(&public_key_der)
                .map_err(|_| StoreError::Invalid("request SPKI DER"))?;
            if spki.algorithm.oid
                != x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
                || !public_keys.insert(public_key_der.clone())
            {
                return Err(StoreError::Invalid("request public key"));
            }
            data.pending_requests.push(PendingRequest {
                id,
                callsign,
                dxcc,
                public_key_der,
                created_at,
                key_name,
            });
        }
    }
    Ok(data)
}

fn section<'a, 'b>(root: &'a Element<'b>, name: &str) -> Result<&'a Element<'b>, StoreError> {
    let mut found = root.children.iter().filter(|c| c.name == name);
    let first = found.next().ok_or(StoreError::Invalid("missing section"))?;
    if found.next().is_some() {
        return Err(StoreError::Invalid("duplicate section"));
    }
    Ok(first)
}

fn attributes(e: &Element<'_>, allowed: &[&str]) -> Result<(), StoreError> {
    if e.attributes().any(|(name, _)| !allowed.contains(&name)) {
        return Err(StoreError::Invalid("unknown attribute"));
    }
    Ok(())
}

fn container(e: &Element<'_>, allowed: &[&str]) -> Result<(), StoreError> {
    attributes(e, allowed)?;
    if !e.text().trim().is_empty() {
        return Err(StoreError::Invalid("unexpected text"));
    }
    Ok(())
}

fn attribute(e: &Element<'_>, name: &str, max: usize) -> Result<String, StoreError> {
    let value = e
        .attribute(name)
        .ok_or(StoreError::Invalid("missing attribute"))?;
    if value.len() > max {
        return Err(StoreError::Limit("attribute bytes"));
    }
    Ok(value.to_string())
}

pub(super) fn check_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() {
        return Err(StoreError::Invalid("empty location name"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(StoreError::Limit("location name bytes"));
    }
    Ok(())
}

// Encode line ends and tabs as references too, preserving names across XML's normalization.
fn escape(out: &mut String, value: &str) -> Result<(), StoreError> {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c if c < ' ' || c == '\u{fffe}' || c == '\u{ffff}' => {
                return Err(StoreError::Invalid("character forbidden by XML"));
            }
            c => out.push(c),
        }
    }
    Ok(())
}

pub(super) fn write(data: &Data) -> Result<String, StoreError> {
    signed::validate(&data.signed_qsos)?;
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<qgt-store version=\"2\">\n  <certificates>\n",
    );
    for c in &data.certificates {
        out.push_str("    <certificate id=\"");
        escape(&mut out, &c.id)?;
        if let Some(key) = &c.key_name {
            out.push_str("\" key=\"");
            escape(&mut out, key)?;
        }
        out.push_str("\">");
        out.push_str(&Base64::encode_string(c.certificate.der()));
        out.push_str("</certificate>\n");
    }
    out.push_str("  </certificates>\n  <locations>\n");
    for l in &data.locations {
        out.push_str("    <location name=\"");
        escape(&mut out, &l.name)?;
        out.push_str("\">\n");
        for (name, value) in l.station.fields() {
            out.push_str("      <field name=\"");
            escape(&mut out, name)?;
            out.push_str("\">");
            escape(&mut out, value)?;
            out.push_str("</field>\n");
        }
        out.push_str("    </location>\n");
    }
    out.push_str("  </locations>\n");
    write_signed(&mut out, &data.signed_qsos)?;
    if !data.pending_requests.is_empty() {
        out.push_str("  <pending-requests>\n");
        for r in &data.pending_requests {
            out.push_str("    <request");
            for (name, value) in [
                ("id", r.id.as_str()),
                ("call", &r.callsign),
                ("dxcc", &r.dxcc.to_string()),
                ("created", &r.created_at.to_string()),
                ("key", &r.key_name),
            ] {
                out.push(' ');
                out.push_str(name);
                out.push_str("=\"");
                escape(&mut out, value)?;
                out.push('"');
            }
            out.push('>');
            out.push_str(&Base64::encode_string(&r.public_key_der));
            out.push_str("</request>\n");
        }
        out.push_str("  </pending-requests>\n");
    }
    out.push_str("</qgt-store>\n");
    if out.len() > MAX_FILE_LEN {
        return Err(StoreError::Limit("file bytes"));
    }
    Ok(out)
}

// Dictionary encoding avoids repeating station descriptions for every contact. IDs are local to
// this file; records retain their description when a named station is renamed or deleted.
fn read_signed(section: &Element<'_>) -> Result<BTreeMap<String, SignedQso>, StoreError> {
    if section.children.len() > MAX_SIGNED_QSOS + MAX_SIGNED_STATIONS {
        return Err(StoreError::Limit("signed QSO elements"));
    }
    if section.children.iter().filter(|e| e.name == "q").count() > MAX_SIGNED_QSOS {
        return Err(StoreError::Limit("signed QSOs"));
    }
    if section.children.iter().filter(|e| e.name == "s").count() > MAX_SIGNED_STATIONS {
        return Err(StoreError::Limit("signed stations"));
    }
    let mut stations = BTreeMap::new();
    let mut descriptions = BTreeSet::new();
    for entry in &section.children {
        if entry.name == "s" {
            attributes(entry, &["id"])?;
            if !entry.children.is_empty() {
                return Err(StoreError::Invalid("signed station element"));
            }
            let id = station_id(entry, "id")?;
            let value = entry.text();
            if value.len() > MAX_SIGNED_STATION_LEN {
                return Err(StoreError::Limit("signed station bytes"));
            }
            if stations.insert(id, value.to_string()).is_some()
                || !descriptions.insert(value.to_string())
            {
                return Err(StoreError::Invalid("duplicate signed station"));
            }
            if stations.len() > MAX_SIGNED_STATIONS {
                return Err(StoreError::Limit("signed stations"));
            }
        } else if entry.name != "q" {
            return Err(StoreError::Invalid("signed QSO element"));
        }
    }
    let mut records = BTreeMap::new();
    for entry in section.children.iter().filter(|e| e.name == "q") {
        container(entry, &["k", "s", "t"])?;
        if !entry.children.is_empty() {
            return Err(StoreError::Invalid("signed QSO children"));
        }
        let key = attribute(entry, "k", MAX_SIGNED_KEY_LEN)?;
        let station = stations
            .get(&station_id(entry, "s")?)
            .ok_or(StoreError::Invalid("signed station reference"))?
            .clone();
        let signed_at = if entry.attribute("t").is_some() {
            let value = attribute(entry, "t", 20)?;
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(StoreError::Invalid("signed QSO time"));
            }
            Some(
                value
                    .parse()
                    .map_err(|_| StoreError::Invalid("signed QSO time"))?,
            )
        } else {
            None
        };
        let record = SignedQso {
            key: key.clone(),
            station,
            signed_at,
        };
        signed::check_record(&record)?;
        if records.insert(key, record).is_some() {
            return Err(StoreError::Invalid("duplicate signed QSO"));
        }
        if records.len() > MAX_SIGNED_QSOS {
            return Err(StoreError::Limit("signed QSOs"));
        }
    }
    Ok(records)
}

fn station_id(entry: &Element<'_>, name: &str) -> Result<usize, StoreError> {
    let value = attribute(entry, name, 4)?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(StoreError::Invalid("signed station identifier"));
    }
    value
        .parse::<usize>()
        .ok()
        .filter(|&id| id < MAX_SIGNED_STATIONS)
        .ok_or(StoreError::Invalid("signed station identifier"))
}

fn write_signed(out: &mut String, records: &BTreeMap<String, SignedQso>) -> Result<(), StoreError> {
    if records.is_empty() {
        out.push_str("  <signed-qsos version=\"1\"/>\n");
        return Ok(());
    }
    out.push_str("  <signed-qsos version=\"1\">\n");
    let stations: BTreeSet<&str> = records.values().map(|q| q.station.as_str()).collect();
    let stations: BTreeMap<&str, usize> = stations
        .into_iter()
        .enumerate()
        .map(|(i, s)| (s, i))
        .collect();
    for (station, id) in &stations {
        out.push_str(&format!("    <s id=\"{id}\">"));
        escape(out, station)?;
        out.push_str("</s>\n");
    }
    for record in records.values() {
        out.push_str("    <q k=\"");
        escape(out, &record.key)?;
        out.push_str(&format!("\" s=\"{}\"", stations[record.station.as_str()]));
        if let Some(at) = record.signed_at {
            out.push_str(&format!(" t=\"{at}\""));
        }
        out.push_str("/>\n");
        if out.len() > MAX_FILE_LEN {
            return Err(StoreError::Limit("file bytes"));
        }
    }
    out.push_str("  </signed-qsos>\n");
    Ok(())
}
