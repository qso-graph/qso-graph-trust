<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADIF 3.1.8 sources for Cabrillo conversion

The XML files come from the [ADIF 3.1.8 resource archive](https://adif.org.uk/318/ADIF_318_resources_2026_10_12.zip),
`318/exports/xml/`. The archive SHA-256 is
`d211e1d41adaf7fc341c73a8a3a56c343534aac57043b7474f7df2d528e56d8c`.
The specification and enumeration data are the ADIF group's work; the SPDX comment identifies this
project's use and is the only insertion. The generator checks upstream bytes after removing it.
Original file hashes are in `SHA256SUMS` and pinned in the generator.

`exchanges.tsv` is QG Trust's exchange metadata, independently assembled from the cited sponsor
templates. Uncited entries use the guessed default in the generator. No tqsllib table is imported.
Run `uv run --no-project python scripts/gen-cabrillo-tables.py --check` to verify the hashes and
checked-in table. See [decision 0016](../../docs/decisions/0016-cabrillo.md).
