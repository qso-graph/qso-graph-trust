#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
"""Copy the repository's LICENSE, NOTICE and AUTHORS into each crate published on crates.io, so each
package carries the GPL's text and the notices its source headers point to. A package holds only its
own crate's folder, and a crate may hold only .rs, .toml and .md files (cargo xtask policy), so each
copy is the original's bytes under a .md name.

    scripts/package-files.py           write the copies
    scripts/package-files.py --check   fail if a copy is missing or is not its original (CI, release)

A developer tool only, never shipped; standard library only.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLISHED = ["crates/qso-graph-trust", "crates/qso-graph-trust-awslc"]
FILES = {"LICENSE": "LICENSE.md", "NOTICE": "NOTICE.md", "AUTHORS": "AUTHORS.md"}


def copies():
    for crate in PUBLISHED:
        for original, copy in FILES.items():
            yield ROOT / original, ROOT / crate / copy


def main(argv):
    if argv == ["--check"]:
        wrong = [c for o, c in copies() if not c.is_file() or c.read_bytes() != o.read_bytes()]
        if wrong:
            names = ", ".join(str(c.relative_to(ROOT)) for c in wrong)
            sys.exit(f"not the repository's file: {names}; run scripts/package-files.py")
        return
    if argv:
        sys.exit(__doc__)
    for original, copy in copies():
        copy.write_bytes(original.read_bytes())


if __name__ == "__main__":
    main(sys.argv[1:])
