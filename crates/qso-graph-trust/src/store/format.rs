// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::collections::BTreeSet;

use base64ct::{Base64, Encoding};

use crate::certificate::{Certificate, MAX_CERTIFICATE_LEN};
use crate::station::{MAX_FIELDS, MAX_LEN, StationLocation};
use crate::xml::{self, Element};

use super::{
    Data, MAX_CERTIFICATES, MAX_FILE_LEN, MAX_LOCATIONS, MAX_NAME_LEN, StoreError,
    StoredCertificate, StoredLocation, VERSION, keys,
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
        _ => Err(StoreError::Invalid("unsupported version")),
    }
}

fn read_v1(root: &Element<'_>) -> Result<Data, StoreError> {
    container(root, &["version"])?;
    if root.children.len() != 3 {
        return Err(StoreError::Invalid("store sections"));
    }
    let certificates = section(root, "certificates")?;
    let locations = section(root, "locations")?;
    let signed = section(root, "signed-qsos")?;
    container(certificates, &[])?;
    container(locations, &[])?;
    container(signed, &["version"])?;
    if attribute(signed, "version", 10)? != "1" || !signed.children.is_empty() {
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
    let mut data = Data::default();
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
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<qgt-store version=\"1\">\n  <certificates>\n",
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
    out.push_str("  </locations>\n  <signed-qsos version=\"1\"/>\n</qgt-store>\n");
    if out.len() > MAX_FILE_LEN {
        return Err(StoreError::Limit("file bytes"));
    }
    Ok(out)
}
