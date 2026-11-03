<!-- SPDX-License-Identifier: GPL-3.0-only -->
# ARRL's TQSL configuration

`config.xml` is ARRL's TQSL configuration, version 11.35, as TrustedQSL 2.8.7 ships it
(`src/config.xml` at tag `v2.8.7`, commit d9e0172). It is the data LoTW checks a signed log
against: bands, modes, the ADIF mode map, propagation modes, satellites, DXCC entities, the
station-location fields and pages, and the signature specification.

It is ARRL's, not QG Trust's, and is redistributed unchanged under ARRL's terms in `LICENSE.txt`,
which must stay beside it. QG Trust reads it only through `scripts/gen-lotw-tables.py`, which
generates `crates/qso-graph-trust/src/lotw/tables.rs`; CI checks the two agree.

| File | SHA-256 |
|---|---|
| `config.xml` | `5a0747d35f5788f8b14757be2fc2f1ce7d0857bd0c0c4def0a30aef72d2f3538` |
| `LICENSE.txt` | `dcaa6b515c503ae57805f0168c65bd5755d7998d092a08144a079099a423ef7d` |

**Updating it:** replace `config.xml` with ARRL's newer one, run `scripts/gen-lotw-tables.py`, update
the version and checksum here, and run the tests.
