// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::collections::{BTreeMap, BTreeSet};

use base64ct::{Base64, Encoding};
use x509_cert::der::Decode;
use x509_cert::spki::SubjectPublicKeyInfoRef;

use crate::certificate::{Certificate, MAX_CERTIFICATE_LEN, acceptable_shape};
use crate::station::{MAX_FIELDS, MAX_LEN, StationLocation};
use crate::xml::{self, Element};

use super::roots::{AcceptedRoot, MAX_ROOTS, RootKind, RootSource};
use super::{
    Data, MAX_CERTIFICATES, MAX_FILE_LEN, MAX_LOCATIONS, MAX_NAME_LEN, MAX_PENDING_REQUESTS,
    MAX_SIGNED_KEY_LEN, MAX_SIGNED_QSOS, MAX_SIGNED_STATION_LEN, MAX_SIGNED_STATIONS,
    PendingRequest, SignedQso, StoreError, StoredCertificate, StoredLocation, VERSION, keys,
    signed,
};

pub(super) fn read(text: &str) -> Result<Data, StoreError> {
    let root =
        xml::parse_with_limits(text, &xml_limits()).map_err(|_| StoreError::Invalid("XML"))?;
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
        2 => read_sections(&root, false, false),
        // Version 3 adds the optional section of accepted roots; versions 1 and 2 refuse it.
        3 => read_sections(&root, false, true),
        _ => Err(StoreError::Invalid("unsupported version")),
    }
}

// Bound the borrowed XML tree as it is built, before the version/section readers allocate records.
// Counts are document-wide, so moving entries into an unexpected section cannot bypass a limit.
fn xml_limits() -> xml::Limits<'static> {
    xml::Limits {
        elements: 6
            + MAX_CERTIFICATES
            + MAX_LOCATIONS * (1 + MAX_FIELDS)
            + MAX_PENDING_REQUESTS
            + MAX_SIGNED_QSOS
            + MAX_SIGNED_STATIONS
            + 2 * MAX_ROOTS,
        elements_named: &[
            ("qgt-store", 1),
            ("certificates", 1),
            ("locations", 1),
            ("signed-qsos", 1),
            ("pending-requests", 1),
            ("roots", 1),
            ("root", MAX_ROOTS),
            ("ca", MAX_ROOTS),
            ("certificate", MAX_CERTIFICATES),
            ("location", MAX_LOCATIONS),
            ("field", MAX_LOCATIONS * MAX_FIELDS),
            ("request", MAX_PENDING_REQUESTS),
            ("q", MAX_SIGNED_QSOS),
            ("s", MAX_SIGNED_STATIONS),
        ],
        attribute_len: |element, name| match (element, name) {
            (_, "version" | "dxcc") => 10,
            ("q", "k") => MAX_SIGNED_KEY_LEN,
            ("q", "s") | ("s", "id") => 4,
            ("q", "t") | ("request", "call" | "created") | ("root" | "ca", "accepted") => 20,
            ("root" | "ca", "source") => 4,
            ("certificate", "id") => 41,
            ("request", "id") => 44,
            (_, "key") => 40,
            ("location", "name") => MAX_NAME_LEN,
            ("field", "name") => MAX_LEN,
            _ => MAX_SIGNED_KEY_LEN,
        },
        text_len: |element| match element {
            "certificate" | "root" | "ca" => MAX_CERTIFICATE_LEN.div_ceil(3) * 4,
            "request" => 512,
            "field" => MAX_LEN,
            "s" => MAX_SIGNED_STATION_LEN,
            // Container whitespace can span the file (e.g. one newline per signed QSO).
            _ => MAX_FILE_LEN,
        },
    }
}

fn read_v1(root: &Element<'_>) -> Result<Data, StoreError> {
    read_sections(root, true, false)
}

fn read_sections(root: &Element<'_>, legacy: bool, roots: bool) -> Result<Data, StoreError> {
    container(root, &["version"])?;
    if root.children.iter().any(|c| {
        ![
            "certificates",
            "locations",
            "signed-qsos",
            "pending-requests",
        ]
        .contains(&c.name)
            && !(roots && c.name == "roots")
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
        let key_name = if c.attribute_names().any(|n| n == "key") {
            let name = attribute(c, "key", 40)?;
            if !keys::valid_name(&name, "key:") || !key_names.insert(name.clone()) {
                return Err(StoreError::Invalid("key name"));
            }
            Some(name)
        } else {
            None
        };
        let encoded = text(c, MAX_CERTIFICATE_LEN.div_ceil(3) * 4)?;
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
            let value = text(f, MAX_LEN)?;
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
            // A generated RSA-1024 SPKI is 162 bytes. Allow bounded DER overhead, without
            // allocating arbitrarily large public keys from an edited store file.
            let encoded = text(r, 512)?;
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
    // Optional in version 3, omitted when empty: the roots this store accepted, and the CAs kept
    // under them, read by the rules they were accepted by.
    if roots && root.children.iter().any(|c| c.name == "roots") {
        data.roots = read_roots(section(root, "roots")?)?;
    }
    Ok(data)
}

fn read_roots(section: &Element<'_>) -> Result<Vec<AcceptedRoot>, StoreError> {
    container(section, &[])?;
    let mut roots: Vec<AcceptedRoot> = Vec::new();
    for e in &section.children {
        let kind = match e.name {
            "root" => RootKind::Root,
            "ca" => RootKind::Ca,
            _ => return Err(StoreError::Invalid("accepted root element")),
        };
        if !e.children.is_empty() {
            return Err(StoreError::Invalid("accepted root element"));
        }
        if roots.iter().filter(|r| r.kind == kind).count() >= MAX_ROOTS {
            return Err(StoreError::Limit("accepted roots"));
        }
        attributes(e, &["source", "accepted"])?;
        let source = RootSource::from_name(&attribute(e, "source", 4)?)
            .ok_or(StoreError::Invalid("accepted root source"))?;
        let accepted = attribute(e, "accepted", 20)?;
        if accepted.is_empty() || !accepted.bytes().all(|b| b.is_ascii_digit()) {
            return Err(StoreError::Invalid("accepted root time"));
        }
        let accepted_at = accepted
            .parse()
            .map_err(|_| StoreError::Invalid("accepted root time"))?;
        let encoded = text(e, MAX_CERTIFICATE_LEN.div_ceil(3) * 4)?;
        let der = Base64::decode_vec(&encoded)
            .map_err(|_| StoreError::Invalid("accepted root base64"))?;
        if der.len() > MAX_CERTIFICATE_LEN {
            return Err(StoreError::Limit("certificate bytes"));
        }
        let canonical = x509_cert::Certificate::from_der(&der)
            .and_then(|c| x509_cert::der::Encode::to_der(&c))
            .map_err(|_| StoreError::Invalid("accepted root DER"))?;
        if canonical != der || !acceptable_shape(&der, kind == RootKind::Root) {
            return Err(StoreError::Invalid("accepted root certificate"));
        }
        if roots.iter().any(|r| r.der == der) {
            return Err(StoreError::Invalid("duplicate accepted root"));
        }
        roots.push(AcceptedRoot {
            der,
            kind,
            source,
            accepted_at,
        });
    }
    Ok(roots)
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
    if e.attribute_names().any(|name| !allowed.contains(&name)) {
        return Err(StoreError::Invalid("unknown attribute"));
    }
    Ok(())
}

fn container(e: &Element<'_>, allowed: &[&str]) -> Result<(), StoreError> {
    attributes(e, allowed)?;
    if !text(e, MAX_FILE_LEN)?.trim().is_empty() {
        return Err(StoreError::Invalid("unexpected text"));
    }
    Ok(())
}

fn attribute(e: &Element<'_>, name: &str, max: usize) -> Result<String, StoreError> {
    let value = e
        .attribute_bounded(name, max)
        .map_err(|_| StoreError::Limit("attribute bytes"))?
        .ok_or(StoreError::Invalid("missing attribute"))?;
    Ok(value.to_string())
}

fn text(e: &Element<'_>, max: usize) -> Result<zeroize::Zeroizing<String>, StoreError> {
    e.text_bounded(max)
        .map_err(|_| StoreError::Limit("text bytes"))
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
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<qgt-store version=\"{VERSION}\">\n  <certificates>\n",
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
    if !data.roots.is_empty() {
        out.push_str("  <roots>\n");
        for r in &data.roots {
            let name = match r.kind {
                RootKind::Root => "root",
                RootKind::Ca => "ca",
            };
            out.push_str(&format!(
                "    <{name} source=\"{}\" accepted=\"{}\">",
                r.source.name(),
                r.accepted_at
            ));
            out.push_str(&Base64::encode_string(&r.der));
            out.push_str(&format!("</{name}>\n"));
        }
        out.push_str("  </roots>\n");
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
            let value = text(entry, MAX_SIGNED_STATION_LEN)?;
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
        let signed_at = if entry.attribute_names().any(|n| n == "t") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_xml_refuses_processing_instructions() {
        let good = "<qgt-store version=\"1\"/>";
        assert!(xml::parse_with_limits(good, &xml_limits()).is_ok());
        let planted = "<qgt-store version=\"1\"><?p x?></qgt-store>";
        assert!(matches!(read(planted), Err(StoreError::Invalid("XML"))));
    }

    #[test]
    fn signed_record_counts_stop_the_xml_reader_before_the_remaining_entries() {
        for (name, max) in [("q", MAX_SIGNED_QSOS), ("s", MAX_SIGNED_STATIONS)] {
            let prefix = format!(
                "<qgt-store><signed-qsos>{}",
                format!("<{name}/>").repeat(max)
            );
            let boundary = format!("{prefix}</signed-qsos></qgt-store>");
            assert!(xml::parse_with_limits(&boundary, &xml_limits()).is_ok());
            // The first excess start tag has deliberately malformed attributes. Count refusal
            // takes place before reading those, or building any of the many entries after it.
            let oversized = format!("{prefix}<{name} invalid{}", "<q/>".repeat(10_000));
            let error = xml::parse_with_limits(&oversized, &xml_limits()).expect_err("count cap");
            assert_eq!(error.problem, "too many named elements");
            assert_eq!(error.column, prefix.len() + name.len() + 2);
            assert!(matches!(read(&oversized), Err(StoreError::Invalid("XML"))));
        }
    }

    #[test]
    fn signed_key_and_station_caps_apply_during_xml_parsing() {
        let key = "&#65;".repeat(MAX_SIGNED_KEY_LEN);
        let exact = format!("<q k=\"{key}\"/>");
        let doc = xml::parse_with_limits(&exact, &xml_limits()).expect("exact key cap");
        assert_eq!(
            attribute(&doc, "k", MAX_SIGNED_KEY_LEN).expect("key").len(),
            MAX_SIGNED_KEY_LEN
        );
        let oversized = format!("<q k=\"{key}&#65;&unknown;\"/>");
        assert_eq!(
            xml::parse_with_limits(&oversized, &xml_limits())
                .expect_err("key cap")
                .problem,
            "attribute value too long"
        );
        let station = "&#233;".repeat(MAX_SIGNED_STATION_LEN / 2);
        let exact = format!("<s>{station}</s>");
        assert!(xml::parse_with_limits(&exact, &xml_limits()).is_ok());
        let oversized = format!("<s>{station}<!-- split -->x&unknown;</s>");
        assert_eq!(
            xml::parse_with_limits(&oversized, &xml_limits())
                .expect_err("station cap")
                .problem,
            "text too long"
        );
    }
}
