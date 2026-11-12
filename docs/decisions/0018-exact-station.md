<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# 0018: Sign with exactly the station the operator selected

Decided 2026-11-11.

## What was decided

`SigningOptions::with_exact_station(true)` selects an independent station check for every QSO.
Construct QSOs with the same options used to prepare and sign the log. Exact mode overrides
`qth` and `ignore_log_callsigns`: every named `STATION_CALLSIGN`, `OPERATOR`, `MY_DXCC`,
`MY_GRIDSQUARE`, `MY_VUCC_GRIDS`, `MY_STATE`, `MY_CNTY`, `MY_ITU_ZONE`, `MY_CQ_ZONE`, and
`MY_IOTA` must agree with the input station. A missing station value refuses the QSO with
`QsoFromAnotherStation`, naming its ADIF field. A subdivision the entity does not have is missing,
too. List codes, aliases, labels, county prefixes, and numeric forms use the existing signing
conversions. Both callsign fields are checked when both are supplied.

A single four-character grid can abbreviate the station's six-character grid. A finer log grid
cannot supply precision the station lacks. VUCC lists compare as sets of complete grids, normalized
for case and surrounding whitespace, on every QSO; they never match a single grid. Each named
grid field is checked, even when both are present. The location, including its original grid order
and formatting, stays unchanged for every QSO and every signature.

Exact mode validates every named station value using signing's conversions before comparing any
field with the selected Location. Invalid list values, county prefixes, and coupled zones use the
existing `Location` error and identify the ADIF field, even when the Location leaves that field
empty. Only a valid value can produce `QsoFromAnotherStation` for an empty Location field; adding
an invalid log value to the Location cannot resolve it. Preview refusals and signing share this
order of checks. Compatibility signing and exact validation call one value converter; exact
comparison consumes its result without converting again. The selected subdivision's own label
has priority over another code sharing that label, within the same dependency list. A county
prefix is checked against the entity's primary subdivision, including Japan's prefecture.

`station_refusals` is a pure per-QSO check in exact mode. In the existing modes it carries forward
only accepted locations and counts the first accepted QSO for the VUCC exception. Every station
refusal exposes its ADIF field through `LogError::adif_field`, including invalid values reported
through the existing `Location` variant. Coupled zone errors identify the last explicitly supplied
zone, or the primary subdivision that changed the allowed zones.

## Why

Desktop displays the Location the operator chose and promises that its signatures carry that
station. Filling a field from the log, ignoring the first QSO's VUCC list, or comparing only list
lengths cannot establish that promise. Exact mode checks agreement without deriving a new station.
It does not change the signature algorithm, field order, signed string, or record format.

## Deliberate departures from tqsllib

The compatibility modes retain TQSL 2.8.7's `QTH` settings. In particular, `Refuse` fills empty
fields, ignores `MY_VUCC_GRIDS` for the first QSO, and regards equal-size VUCC lists as matching
(`src/tqslconvert.cpp:1651–1694`, the source reference documented in `options.rs`). It gives VUCC
precedence over `MY_GRIDSQUARE` and uses `OPERATOR` as a station call only without
`STATION_CALLSIGN`. Exact mode deliberately departs from those behaviors and checks every named
field on every QSO. Compatibility mode's first-accepted-QSO correction preserves those conversions
while making removal of refused QSOs independent of their original indices.

`QthHandling` remains unchanged: it mirrors TQSL and permits exhaustive matches. `SigningOptions`
already has public fields and permits exhaustive struct literals; adding `exact_station` breaks
those literals. This change therefore requires **0.2.0**, not 0.1.10. Callers can use
`SigningOptions::default().with_exact_station(true)` or add `exact_station: false` to an exhaustive
literal. Version numbers remain for the separate release pull request.

## Evidence

Permanent regressions retain every independent review demonstration, including controls. Exact
mode tests cover empty fields, aliases, labels, numbers, county prefixes, both callsigns, grid
precision, grid sets on the first and later QSOs, override precedence, field-bearing errors, and
refused-prefix independence. An exhaustive regression walks every subdivision code and label
across all 15 entities with subdivisions (8,132 cases in the pinned configuration), requiring exact
mode and compatibility signing to agree. ADX regressions cover legal comments and processing
instructions before the root without a declaration, unchanged XML validation, and bounded format
detection. A whole log's signed station equals the input station through both
signing APIs. For agreeing inputs, output matches the existing TQSL-compatible signing path; the
existing corpus differential still checks signatures and records against container-produced
tqsllib results. No reference library runs on the host and no test contacts ARRL.

Each fix was proved by restoring the defective behavior, watching its regression test fail on an
assertion, and restoring the source.

A `MY_STATE` or `MY_CNTY` for an entity where LoTW has no such field is left out, not refused: it
can never be signed, so the operator could not resolve the refusal by adding it to the location.
tqsllib and `StationLocation::from_adif` leave it out the same way.
