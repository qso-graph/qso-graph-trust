<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# 0017: Read TQSL station locations

Decided 2026-11-10.

## What was decided

On request, QG Trust opens only `station_data` for reading, never creating, locking, or changing files in TQSL's folder. A missing file or folder means no locations. The input is bounded and may be plain XML or gzip: tqsllib 2.8.7 uses `gzopen` (`src/xml.cpp:107–116`). The filename and missing-file behavior are in `src/location.cpp:2858–2883`. TQSL enumerates named `StationData` entries and their calls at `src/location.cpp:3306–3328`, retrieves fields by element name and text at `src/location.cpp:2926–2971`, and writes the XML at `src/location.cpp:2898–2913`. The writer constructs the root, named entries and field elements at `src/location.cpp:3456–3494, 3549–3594`; the TQSL-written corpus provides examples.

A malformed document, unknown element, missing, empty, repeated or oversized name, excessive count or oversized file refuses the whole file. Names repeated ignoring ASCII case are refused, following TQSL’s case-insensitive save check (`src/location.cpp:3563–3574`). A structurally valid location that fails LoTW validation is reported by name and a correction reason; other locations remain available. Refusals do not expose field values. Comparisons use exact names and normalized validated fields, with both values shown for differences. Import adds selected new locations through the existing store operation and never replaces a stored location.

The default is nonempty `TQSLDIR`; otherwise `%APPDATA%/TrustedQSL` on Windows and `$HOME/.tqsl` on other systems, including macOS (`src/tqsllib.cpp:367–392`). The app creates the `tqslapp` wxConfig (`apps/tqsl.cpp:5981–5990`), reads its `rsrcDir` setting during initialization and sets `TQSLDIR` to that value only when nonempty (`apps/tqsl.cpp:6158–6159, 6210–6215`), before its explicit `tqsl_init` (`apps/tqsl.cpp:6514`). The source tree does not assign a fixed macOS path to `rsrcDir`. That setting can select a different folder, so callers can supply one explicitly. In particular, a macOS installation using `~/Library/Application Support/TrustedQSL` must pass it explicitly; it is not the library default shown in the source.
