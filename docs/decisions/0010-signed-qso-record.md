<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE. -->

# 0010: Keep TQSL's duplicate keys in the shared store

**Status: accepted**, 2026-11-05: it does what TQSL 2.8.7 does.

The library keeps the public record of signed QSOs in `store.xml`. It imports the same keys and
station descriptions that TQSL puts in a `.tbk`, without a database dependency. Applications choose
which QSOs to sign after inspecting a snapshot; signing still uses the existing `sign_log` path.

## TQSL 2.8.7's definition

These line numbers refer to the unmodified 2.8.7 library source used to generate the test corpus:

- `location.cpp:3760–3825` builds QSO details by concatenating the trimmed contact fields in ARRL's
  signature specification order. Our generated `SIGN_CONTACT` currently specifies `BAND`, `BAND_RX`,
  `CALL`, `FREQ`, `FREQ_RX`, `MODE`, `PROP_MODE`, `QSO_DATE`, `QSO_TIME`, `SAT_NAME`. Missing optional
  fields contribute nothing; there are no separators. Date is `YYYY-MM-DD`; time is `HH:MM:SSZ`.
  Frequency is the signed text, including trailing zeros. Mode is already mapped to LoTW's mode
  (`tqslconvert.cpp:1403–1431`). Satellite and propagation fields are included when present.
- `tqslconvert.cpp:1825–1839` prefixes the local callsign, using `snprintf` into 128 bytes: at most
  127 key bytes, with no hash, base64 or other encoding. The key contains neither station-location
  name/fields nor certificate serial. `Qso` and `StationLocation` already normalize these fields;
  `duplicate_key` uses exactly the QSO data that `sign_log` signs.
- Seconds are not rounded. TQSL defaults to retaining them (`tqslconvert.cpp:129`); its optional
  ignore-seconds setting clears seconds before both signing and duplicate checking
  (`1022–1023`, `1316–1317`). That preference is not applied by this task: the key must describe the
  actual `Qso` being signed, never a separately rounded contact.
- `location.cpp:858–887` separately builds the station description from the nonempty signature
  station fields, in configuration order, as `NAME: value` joined with `, `. The description excludes
  the local callsign and DXCC, just as the signature specification does.
- `tqslconvert.cpp:1881–1942` treats an equal station description (ignoring ASCII case) as signed
  before, and also refuses a change to a previously nonempty shared field. Otherwise it permits a
  station-details update. The library follows that comparison, including TQSL's comma splitting
  and ASCII-space removal. A different location is therefore not automatically a new contact.
- The SQLite table stores the key and description directly (`tqslconvert.cpp:775–782`, `448–494`).
  There is no signing timestamp. Older signature-plus-certificate-serial keys are also looked up by
  TQSL (`1832–1856`); QGT preserves these as bounded opaque records but the station-only partition
  API cannot recognize that legacy form without a certificate. Current-format corpus keys all match.

The standard set's 21 contacts at seven locations prove exact key parity and station-description
comparison against TQSL's own backup. Existing differential signing tests remain unchanged.

## Store format and limits

The root version becomes **2**. Version 1 still means an empty signed-QSO section and remains readable;
nonempty version-1 contents remain invalid. Mutations write version 2. Older builds refuse this root
before mutation, preventing silent record loss. The section keeps version 1:

```xml
<signed-qsos version="1">
  <s id="0">GRIDSQUARE: FM02</s>
  <q k="KC4QPQ20MM0EHA14.074FT82026-11-0300:00:00Z" s="0" t="1793664000"/>
</signed-qsos>
```

Station descriptions are a dictionary, stored once each; IDs are file-local integers, not location
names. XML parsing enforces entry counts and decoded value lengths before retaining them; bounded
decoding reserves only the decoded size and refuses oversized values before allocation. Keys are exact,
case-sensitive ASCII text, up to 1024 bytes to preserve older backup formats.
Station descriptions are bounded to 2048 UTF-8 bytes and valid XML characters. `t`, omitted for TQSL
imports, is unsigned Unix seconds when QGT signed the contact. Records sort by key. Unknown fields,
invalid references, duplicate keys/IDs/descriptions, invalid timestamps and exceeded limits are refused.

Capacity is **100,000 contacts and 4096 distinct descriptions**, also subject to the existing **32 MiB**
whole-file limit, including certificates, locations and requests. Typical current-format keys and
repeated station details fit 100,000 entries; unusually large imported keys can reach the byte limit
first. The test fills the count limit and proves compact XML round-trips. Reads and mutations use the
store's OS lock; every mutation reloads and replaces the whole file. Import merges without overwriting
an existing entry or timestamp; repeated import adds zero. Wipe removes just this record.

The encrypted export part uses the same reader and writer: no new envelope or plaintext version is
needed because its embedded XML already has independent version dispatch. Restore validates entries
and bounds before touching the destination. `RestoreReport::signed_qsos` reports the installed count.

## Signing and recording

`Store::prepare_signing` returns a `SigningPlan` with input indices for new contacts and
`PreviouslySigned` entries with the previous station and optional timestamp. Repeated contacts in
one input are checked against earlier new entries too. `choose(DuplicateChoice::{NewOnly, SignAgain,
Cancel})` returns a `SigningSelection`, or `None` on cancel. An empty selection is refused by signing.
`SigningSelection::sign` returns a `SignedLog`, keeping the exact QSOs, metadata and `.tq8` together;
it changes no store state. Applications can use `Store::with_key` to sign without exposing a key.

`SignedLog::write_to` locks and reloads the store, preflights the merged XML and all limits, creates a
new output file, writes and syncs it, syncs its parent on Unix, then atomically replaces the record.
It refuses existing output and every output path whose parent identifies the store directory:
Unix compares device and inode, including bind mounts and case-insensitive aliases; Windows compares
canonical paths, resolved to the final path via a handle, including junctions and case differences
(the stable standard library exposes no Windows file ID). It also reserves `store.xml`,
`store.xml.partial` and `store.lock`, ignoring ASCII case, in every output directory.
A contact counts as signed **after successful output writing**, without waiting for upload: tqsllib inserts during conversion (`tqslconvert.cpp:1956`)
and exposes explicit commit/rollback (`2080–2108`). The reference corpus driver closes successful output
before committing (`tests/tqsllib/qgt-tqsllib.cpp:230–241`), with no upload involved.

Plans are snapshots, so concurrent signers can select the same contact. Recording reloads under the
lock and preserves other writers' entries. A failed output write never records QSOs; a partial output
may remain. A store failure after a successful output leaves that file for recovery and returns the
store error; a durability error after replacement retains the visible record, as other mutations do.
There is no atomic transaction across an arbitrary output filesystem and the store: a crash between
output persistence and record replacement can leave an unrecorded signed log. This favors retaining
signed output and allowing a later explicit repeat over recording output that was never written.
