<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# 0016: Read and sign Cabrillo logs as ADIF records

Decided 2026-11-09 for qso-graph-desktop#172, Gate C.

## What was decided

ADIF 3.1.7 is the source of truth for values. WWROF defines structure:
[version compatibility](https://wwrof.org/cabrillo/),
[headers](https://wwrof.org/cabrillo/cabrillo-v3-header/),
[QSO data](https://wwrof.org/cabrillo/cabrillo-qso-data/), and
[notes, including legacy exchanges](https://wwrof.org/cabrillo/cabrillo-specification-notes/).
Both `START-OF-LOG: 2.0` and `3.0` are accepted. `records::parse` recognizes structural `START-OF-LOG:`, `END-OF-LOG:`, or `QSO:` claims on physical lines
after whitespace and an optional UTF-8 BOM, without consulting a filename. Misplaced markers
still select Cabrillo and receive a structural refusal.
A failed claim is refused, never retried as ADI.

The header and QSO tags are case insensitive. A log must have one start, one contest before its
QSOs, and a final empty `END-OF-LOG:`. Unused headers and `X-QSO:` lines are discarded, as ADI
headers are. Space and tab delimit QSO fields; CR, LF, and CRLF end lines. UTC dates and four-digit
UTC times must be valid. Invalid structure refuses the whole log before signing. QG Trust accepts
UTF-8 header text but requires ASCII date and QSO syntax. Other legacy encodings must be converted
before reading. Content after the end marker is refused.

The reader limits input to 64 MiB, lines and values to 64 KiB, physical lines to 200,020 (including empty
lines, with CRLF counted once), QSO tokens to 256, token values to 64 bytes, records to 100,010, and emitted fields
to 2,000,200. Limits refuse excess input instead of truncating it. Decoded values use the same
`Zeroizing<Vec<u8>>` fields as ADI and ADX. Temporary date and frequency strings are wiped too.
Each Cabrillo record retains its physical source line. The shared QSO conversion, preparation,
certificate dates, duplicate decisions, and signing remain in charge of what may be signed.
The CLI and differential driver refuse the whole Cabrillo log on conversion failure before
writing signed output, even when an ADIF handling option would permit skipping a bad record.
Their fixed refusal names the line and LoTW requirements without exposing a value. Explicit
signing options still govern conversion; parsing does not impose default signing plausibility.
The differential reports LoTW conversion refusals separately from specification refusals. No dependency was added.

## ADIF data and exchanges

The [ADIF 3.1.7 resources](https://adif.org.uk/317/ADIF_317_resources_2026_03_22.zip), released
2026-03-22, have SHA-256
`1a70caf3a152c67c23ce9c4681f24b8e5f814862d8153d9a72e741375358e6d9`.
The source files are its `317/exports/xml/enumerations_contest_id.xml`,
`enumerations_band.xml`, and `enumerations_mode.xml`. The original file hashes are:

| Source | SHA-256 |
|---|---|
| Contest_ID | `a01ee6a0e6ff872e49633450ccb3642a5a4681cfce6f8cf1596d259fb1a15cd0` |
| Band | `8f63fa3586b45b6af3996a954286a200591b2cdbddd43c59ca01d694badd83ea` |
| Mode | `e79353ca43d38de43598b80040274f6319ee5dc11efd851d7d48e733d72a3663` |

These sources are under `data/adif-317/`, with a project SPDX comment inserted after each XML
declaration. `scripts/gen-cabrillo-tables.py` removes that exact comment, verifies the original
hashes and version, and generates the checked-in Rust tables. `--check` verifies regeneration.
There are exactly **256 identifiers**. Contest matching ignores case and surrounding whitespace;
spelling and punctuation are never repaired. No tqsllib contest aliases or tables were imported.

`exchanges.tsv` records zero-based received-call token positions (frequency is token zero).
**24 entries cite sponsor exchange templates or rules; 234 are marked guessed.** Of the
256 ADIF identifiers, 22 are cited and 234 guessed. Two additional, explicitly supported sponsor
identifiers, `WRTC` and `WRTC-2018`, are absent from ADIF 3.1.7; they are documented exchanges,
not spelling aliases. The cited entries cover CQ WW CW/SSB/RTTY, CQ WPX CW/SSB/RTTY, CQ 160
CW/SSB, Sweepstakes CW/SSB, NAQP CW/SSB/RTTY, RSGB IOTA, WW Digi, IARU HF, ARRL DX CW/SSB,
RTTY Roundup, International Digital, 10 Meter, 160 Meter, and WRTC. Each entry carries its exact
source URL. Other exchanges are tentative; a guessed position is accepted only if it agrees with
a unique plausible received-call candidate.

ARRL DX uses signal report plus state/province or power; both sides place the received call at
token 7. RTTY Roundup and 10 Meter use report plus state/province or serial number (10 Meter also
accepts Mexican states and maritime ITU regions), again token 7. IARU HF and WRTC use report plus
zone or HQ abbreviation at token 7. International Digital exchanges only a grid, at token 6.
ARRL 160 uses report plus section for W/VE, but only report for DX. For a cited `6/7` entry,
QGT chooses a position once per log when it has plausible calls on a strict majority of QSOs and
the other has them on a strict minority; otherwise it refuses the ambiguity. It then converts
every QSO from that position, leaving individual calls to LoTW's call validation.

The ARRL entries cite the sponsor's current contest-rule PDFs, which define the exchanges. The
WRTC 2010 rules are hosted at wrtc.info. Its [2018 archive](https://wrtc.info/archive/2018-germany/)
links the official event site, which hosts the cited 2018 competition rules. No requested contest
remains guessed for lack of a sponsor source.

For unknown contests, candidates start at token six, following tqsllib's search: alphanumeric or
slash, at least four letters/digits in total, at least one letter and one digit, excluding
four-character locators. Zero or multiple candidates refuse the log. QG Trust repeats this check
on every QSO, so a later ambiguous exchange cannot inherit an earlier guessed position. Unknown
contests must also use the same unique received-call field on every QSO. Cited
positions follow the sponsor's exchange rather than candidate inference.

## Bands, modes, and the tqsllib answer key

The [Band and Mode enumerations](https://www.adif.org.uk/317/ADIF_317.htm#Enumerations)
provide ADIF output values. Numeric kHz values are converted exactly to integer Hz (up to three
fractional kHz digits), then matched against inclusive ADIF band edges. WWROF's VHF and microwave
designators map to their ADIF bands, including `122G` → `2.5mm`, `134G` → `2mm`, and
`LIGHT` → `submm`. A designator describes a band; representative frequencies preserve LoTW
compatibility where tqsllib supplies one. `LIGHT` emits no frequency.

The answer key is tqsllib **2.8.7**, commit `d9e01726e54887f8241e86e789c5b91f02043ebd`;
[source with line numbers](https://sourceforge.net/p/trustedqsl/tqsl/ci/d9e01726e54887f8241e86e789c5b91f02043ebd/tree/src/cabrillo.cpp).
Its code is read as a reference and independently implemented, never copied into the library.
These are the mappings that ADIF alone does not select:

| Case | QG Trust output and reason | tqsllib source |
|---|---|---|
| `PH` | ADIF `SSB`, signed as LoTW `SSB` | `cabrillo.cpp:418` |
| `DG` | ADIF `MFSK`, mapped by the existing LoTW mode table to `DATA`; Cabrillo supplies no finer digital mode | `cabrillo.cpp:421` maps `DG` to `DATA`, which is not an ADIF Mode |
| `CW`, `FM`, `RY` | ADIF `CW`, `FM`, `RTTY` | `cabrillo.cpp:417-420` |
| `50`, `70`, `144`, `222`, `432`, `902` | Corresponding band and representative MHz of the designator | `cabrillo.cpp:319-331` |
| `1.2G`, `2.3G`, `3.4G`, `5.7G` | ADIF bands with representative MHz 1240, 2300, 3300, 5650 | `cabrillo.cpp:332-339` |
| `10G`, `24G`, `47G`, `75G`, `241G` | ADIF bands with representative MHz 10000, 24000, 47000, 75500, 241000 | `cabrillo.cpp:340-357` |
| `122G`, `134G` | ADIF bands with representative MHz 119980 and 134000 (ADIF lower edges) | These WWROF tokens are absent from tqsllib's mapping; its older tokens are at `cabrillo.cpp:350-353` |
| `LIGHT` | ADIF `submm`, without a measured frequency | `cabrillo.cpp:300-302` preserves the text; QG Trust omits a nonnumeric ADIF frequency |

Nonstandard shorthand such as numeric `7` for 7000 kHz, and tqsllib's additional microwave
spellings, are not imported. Numeric input always follows kHz and the ADIF edges. ADIF values that
LoTW's current configuration does not accept remain refused by the existing QSO checks.

## Specification adherence and refusals

QG Trust refuses input outside the Cabrillo structure or ADIF values defined above, even if
tqsllib accepts it. Users correct the source log before signing. Version text other than `2.0`
or `3.0`, non-UTF-8 headers, and QSO mode codes outside `CW`, `PH`, `FM`, `RY`, and `DG` remain
refusals.

WWROF's [CONTEST header rule](https://wwrof.org/cabrillo/cabrillo-v3-header/) explicitly limits
identifiers to letters A–Z, digits 0–9, and hyphens, with a maximum of 32 characters. Matching
remains case insensitive and ignores surrounding spaces and tabs. Internal spaces, tabs, commas,
and other punctuation are refused; digits are allowed. Empty identifiers and identifiers longer
than 32 characters are refused. All five contest values in the first lab refusal sample contain
internal spaces; the longest also contains a comma and exceeds 32 characters. These are syntax
refusals, not failures of ADIF membership. Every syntactically valid identifier absent from ADIF's
Contest_ID list takes the unknown-contest inference path, including the two sampled identifiers
that had no received-call candidate. The reader does not repair contest names or exchange fields.

Every Cabrillo refusal gives a one-based physical line number and the fixed requirement to meet.
Errors contain no input text, calls, or offending values. A field-position conflict identifies the
CONTEST line and both conflicting QSO lines. End-of-file errors identify the last physical line;
the whole-input limit identifies line 1. `RecordError::Cabrillo` carries positions and a bounded
`CabrilloError` reason, consistent with ADI's position-bearing variants; ADX retains its existing
static reasons. Display and Debug never retain input text, and `qg-trust sign` prints Display.
The lab artifact uses the reason's fixed `kind()` string instead of the diagnostic message.

## Evidence

The reader tests cover equivalent ADI values, v2/v3, BOM/whitespace, every ADIF band edge, mode
codes, microwave bands, malformed input, bounds, excluded QSOs, and ambiguity on later lines.
Both CLI forms sign Cabrillo by content. The custody test searches written artifacts and process
memory after protected and unprotected test-key signing. The `cabrillo` fuzz target uses the same
signing and readback invariants as ADI/ADX, and is discovered by CI's `cargo fuzz list` loop.
`scripts/test-cabrillo-faults.py` proves ambiguity, inclusive edges, no format fallback, content-free
refusals, time normalization, and unknown-contest inference by planting each fault, observing its
failing test, and passing again after restoration. Artifact regressions run in CI through
`scripts/test_cabrillo_differential.py`.

The offline reference differential against tqsllib, over 5,000 public contest logs, and its counts
are in [CABRILLO-DIFFERENTIAL.md](../CABRILLO-DIFFERENTIAL.md): no log on which the two readers
disagree.
