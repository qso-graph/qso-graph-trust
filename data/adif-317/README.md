<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADIF 3.1.7 sources for Cabrillo conversion

The XML files come from the [ADIF 3.1.7 resource archive](https://adif.org.uk/317/ADIF_317_resources_2026_03_22.zip),
`317/exports/xml/`. The archive SHA-256 is
`1a70caf3a152c67c23ce9c4681f24b8e5f814862d8153d9a72e741375358e6d9`.
The specification and enumeration data are the ADIF group's work; the SPDX comment identifies this
project's use and is the only insertion. The generator checks upstream bytes after removing it.
Original file hashes are in `SHA256SUMS` and pinned in the generator.

`exchanges.tsv` is QG Trust's exchange metadata, independently assembled from the cited sponsor
templates. Uncited entries use the guessed default in the generator. No tqsllib table is imported.
Run `uv run --no-project python scripts/gen-cabrillo-tables.py --check` to verify the hashes and
checked-in table. See [decision 0016](../../docs/decisions/0016-cabrillo.md).
