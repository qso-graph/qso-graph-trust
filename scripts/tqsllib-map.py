#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
"""Check docs/TQSLLIB-MAP.md, the map from each of tqsllib 2.8.7's public functions and variables to
QG Trust's Rust, its command line and the test proving it, or the reason there is none.

    scripts/tqsllib-map.py --check                    the map against this repository (CI)
    scripts/tqsllib-map.py --check --tqsl-src DIR     and against tqsllib 2.8.7's own headers
    scripts/tqsllib-map.py --self-test                planted faults, each of which must be caught

Always, with no TQSL source: the map lists the 215 names it was made from, in header order (their
SHA-256 is pinned below, so a row removed, added or renamed is caught), every row is either mapped
with a test or says "Not needed:" or "Not applicable:" with its reason, and every Rust path,
`qg-trust` command and test the map names exists in the repository.

With --tqsl-src (a tqsllib 2.8.7 tree, or a folder holding its headers): the names are read from the
headers CMakeLists.txt installs, exactly as the map says it counts them, and must be the map's and
match the pinned SHA-256. tqsllib's source is ARRL's and is never in this repository, so CI runs
the first form and says the second was skipped; it is run wherever the source is at hand.

A developer tool only, never shipped; standard library only.
"""

import hashlib
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAP = ROOT / "docs" / "TQSLLIB-MAP.md"
CRATES = ROOT / "crates"
LIBRARY = CRATES / "qso-graph-trust" / "src"
CLI = CRATES / "qso-graph-trust-cli" / "src"

# The headers tqsllib 2.8.7's src/CMakeLists.txt installs (HEADERS_TO_INSTALL), in that order.
HEADERS = ["tqsllib.h", "tqslerrno.h", "cabrillo.h", "adif.h", "tqslconvert.h"]
# The 215 names (204 functions, 11 variables), in header order, one per line: their SHA-256.
NAMES = 215
NAMES_SHA256 = "84e6d06d4317552cdc12510343cbd528e37b257b32104f3b4296a953598e28a6"
STATUSES = ("Not needed: ", "Not applicable: ")


def header_names(text):
    """The DLLEXPORT and DLLEXPORTDATA names a header declares, comments aside, each once."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    names = []
    for m in re.finditer(r"^\s*DLLEXPORT(?:DATA)?\s+[^;#]*?\b(\w+)\s*[(;\[]", text, flags=re.M):
        if m.group(1) not in names:
            names.append(m.group(1))
    return names


def tqsl_names(src):
    src = Path(src)
    folder = src / "src" if (src / "src" / "tqsllib.h").is_file() else src
    names = []
    for header in HEADERS:
        for name in header_names((folder / header).read_text(encoding="utf-8", errors="replace")):
            if name not in names:
                names.append(name)
    return names


def digest(names):
    return hashlib.sha256("\n".join(names).encode()).hexdigest()


def rows(text):
    """Each table row between the markers: (name, QG Trust cell, test cell)."""
    body = text.split("<!-- tqsllib-map:begin -->", 1)[-1].split("<!-- tqsllib-map:end -->", 1)[0]
    out = []
    for line in body.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            out.append((line, None, None))
            continue
        out.append((cells[0].strip("`"), cells[2], cells[3]))
    return out


def ticks(cell):
    return re.findall(r"`([^`]+)`", cell)


class Repo:
    """The repository's files, with planted changes for the self-test."""

    def __init__(self, planted=None):
        self.planted = planted or {}

    def read(self, path):
        if path in self.planted:
            return self.planted[path]
        return path.read_text(encoding="utf-8") if path.is_file() else None

    def rust_files(self, folder, module):
        """A module's own files: `module.rs` and everything under `module/`, tests left out."""
        if not module:
            return [folder / "lib.rs"]
        base = folder.joinpath(*module)
        files = [base.with_suffix(".rs")] if base.with_suffix(".rs").is_file() else []
        if base.is_dir():
            files += sorted(base.rglob("*.rs"))
        return [f for f in files if f.name != "tests.rs" and "tests" not in f.relative_to(folder).parts]


def defined(texts, name, member):
    kinds = r"(?:fn|const|static|struct|enum|trait|type|mod)"
    patterns = [rf"\b{kinds}\s+{re.escape(name)}\b"]
    if member:
        # A field, or an enum's variant.
        patterns += [rf"^\s*pub {re.escape(name)}\s*:", rf"^\s*{re.escape(name)}\s*[,({{]"]
    return any(re.search(p, t, flags=re.M) for t in texts for p in patterns)


def check_rust_path(repo, path):
    segments = path.split("::")[1:]
    if not segments:
        return f"{path}: names no item"
    module = []
    while (
        len(segments) > 1
        and segments[0][:1].islower()
        and (LIBRARY.joinpath(*module, segments[0] + ".rs").is_file() or LIBRARY.joinpath(*module, segments[0]).is_dir())
    ):
        module.append(segments.pop(0))
    texts = [t for t in (repo.read(f) for f in repo.rust_files(LIBRARY, module)) if t is not None]
    for i, name in enumerate(segments):
        if i < len(segments) - 1:
            if not re.search(rf"\b(?:struct|enum|trait|type)\s+{re.escape(name)}\b", "\n".join(texts)):
                return f"{path}: no type {name} in qso_graph_trust::{'::'.join(module)}"
        elif not defined(texts, name, i > 0):
            return f"{path}: no {name} in qso_graph_trust::{'::'.join(module) or '(crate root)'}"
    return None


def check_command(repo, command):
    words = command.split()[1:]
    if not words:
        return f"{command}: names no command"
    commands = repo.read(CLI / "commands.rs") or ""
    cli = repo.read(CLI / "cli.rs") or ""
    first = words[0]
    if first.startswith("-"):
        letter = re.fullmatch(r"-(\w)", first)
        if not (letter and f"short = '{letter.group(1)}'" in cli):
            return f"{command}: qg-trust has no option {first}"
        return None
    for short in [w for w in words[1:] if re.fullmatch(r"-\w", w)]:
        if f"short = '{short[1]}'" not in commands:
            return f"{command}: qg-trust {first} has no option {short}"
    listed = re.search(r"pub\(crate\) const COMMANDS: &\[&str\] = &\[(.*?)\];", commands, flags=re.S)
    if not listed or f'"{first}"' not in listed.group(1):
        return f"{command}: qg-trust has no command {first}"
    rest = [w for w in words[1:] if not w.startswith("-") and w != "…"]
    flags = [w for w in words[1:] if w.startswith("--")]
    if rest:
        group = re.search(rf"enum {first.capitalize()} \{{(.*?)\n\}}", commands, flags=re.S)
        if not group or not re.search(rf"^\s*{rest[0].capitalize()}\(", group.group(1), flags=re.M):
            return f"{command}: qg-trust {first} has no {rest[0]}"
    for flag in flags:
        long = flag[2:]
        named = f'long = "{long}"' in commands or re.search(
            rf"^\s*(?:pub )?{re.escape(long.replace('-', '_'))}\s*:", commands, flags=re.M
        )
        if not named:
            return f"{command}: qg-trust has no option {flag}"
    return None


def check_test(repo, ref):
    file, sep, name = ref.partition("::")
    if not sep or not name.isidentifier():
        return f"{ref}: not FILE::TEST"
    text = repo.read(CRATES / file)
    if text is None:
        return f"{ref}: no file crates/{file}"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.match(rf"\s*(?:pub )?fn {re.escape(name)}\s*\(", line):
            if any(re.match(r"\s*#\[test\]", lines[j]) for j in range(max(0, i - 4), i)):
                return None
            return f"{ref}: {name} is not a test"
    return f"{ref}: no test {name} in crates/{file}"


def check(repo, text, tqsl_src=None):
    errors = []
    table = rows(text)
    names = [name for name, _, _ in table]
    for name, qgt, tests in table:
        if qgt is None:
            errors.append(f"not a row of four cells: {name}")
            continue
        refs = ticks(tests)
        reasoned = qgt.startswith(STATUSES)
        if reasoned and len(qgt) < len("Not needed: ") + 10:
            errors.append(f"{name}: says it is not needed but gives no reason")
        if not reasoned and not refs:
            errors.append(f"{name}: mapped, but names no test")
        if not reasoned and not any(t.startswith(("qso_graph_trust", "qg-trust")) for t in ticks(qgt)):
            errors.append(f"{name}: names neither a Rust path nor a qg-trust command, nor a reason")
        for t in ticks(qgt):
            if t.startswith("qso_graph_trust"):
                problem = check_rust_path(repo, t)
            elif t.startswith("qg-trust "):
                problem = check_command(repo, t)
            elif "::" in t:
                problem = f"{t}: a Rust path is written in full, from qso_graph_trust::"
            elif re.fullmatch(r"tqsl\w+", t) and t not in names:
                problem = f"{t}: not a name in this map"
            else:
                problem = None
            if problem:
                errors.append(f"{name}: {problem}")
        for ref in refs:
            problem = check_test(repo, ref)
            if problem:
                errors.append(f"{name}: {problem}")
    if len(names) != NAMES or len(set(names)) != len(names):
        errors.append(f"the map lists {len(names)} rows, {len(set(names))} names; tqsllib 2.8.7 has {NAMES}")
    if digest(names) != NAMES_SHA256:
        errors.append("the map's names are not tqsllib 2.8.7's, in header order (SHA-256 differs)")
    if tqsl_src is not None:
        source = tqsl_names(tqsl_src)
        if digest(source) != NAMES_SHA256:
            errors.append(f"{tqsl_src}: its headers' names are not the pinned 2.8.7 list (another version?)")
        for name in source:
            if name not in names:
                errors.append(f"{name}: in the headers, not in the map")
        for name in names:
            if name not in source:
                errors.append(f"{name}: in the map, not in the headers")
        if not errors and source != names:
            errors.append("the map's rows are not in the headers' order")
    return errors


def self_test():
    """Each planted fault must be caught, and the map as it is must pass."""
    text = MAP.read_text(encoding="utf-8")
    assert check(Repo(), text) == [], "the map must pass before faults are planted"
    lines = text.splitlines(keepends=True)
    row = next(i for i, l in enumerate(lines) if l.startswith("| `tqsl_signDataBlock`"))
    test_file = CRATES / "qso-graph-trust" / "tests" / "differential.rs"
    planted = {
        "a removed row": (Repo(), "".join(lines[:row] + lines[row + 1 :]), "SHA-256 differs"),
        "a renamed test": (
            Repo({test_file: test_file.read_text(encoding="utf-8").replace(
                "fn a_1024_bit_key_signs_as_tqsllib(", "fn a_1024_bit_key_signs_like_tqsllib(")}),
            text,
            "no test a_1024_bit_key_signs_as_tqsllib",
        ),
        "a renamed Rust function": (
            Repo(),
            text.replace("`qso_graph_trust::signing::TqslKey::sign`", "`qso_graph_trust::signing::TqslKey::sign_it`", 1),
            "no sign_it",
        ),
        "a mapped row without a test": (
            Repo(),
            text.replace(lines[row], re.sub(r"\| `[^|]*` \|\n$", "|  |\n", lines[row]), 1),
            "mapped, but names no test",
        ),
        "a reason left out": (
            Repo(),
            text.replace("| Not needed: LoTW checks", "| LoTW checks", 1),
            "names neither",
        ),
        "a command qg-trust lacks": (
            Repo(), text.replace("`qg-trust cert delete`", "`qg-trust cert remove`", 1), "has no remove"),
    }
    for what, (repo, planted_text, expected) in planted.items():
        assert planted_text != text or repo.planted, f"{what}: nothing was planted"
        errors = check(repo, planted_text)
        if not any(expected in e for e in errors):
            print(f"tqsllib-map: self-test: {what} was not caught: {errors}", file=sys.stderr)
            return 1
        print(f"caught {what}: {next(e for e in errors if expected in e)}")
    # The headers' half, without ARRL's source: headers written from the map's own names, in a
    # temporary folder, must agree; with one declaration taken out, they must not. Declarations
    # are written as tqsllib writes them, comments and spacing included.
    names = [name for name, _, _ in rows(text)]
    with tempfile.TemporaryDirectory() as folder:
        for header in HEADERS:
            Path(folder, header).write_text("", encoding="utf-8")

        def headers(declared):
            lines = ["/* DLLEXPORT int CALLCONVENTION tqsl_inAComment(void); */"]
            for n in declared:
                kind = "DLLEXPORTDATA extern int" if n.startswith("tQSL_") else "DLLEXPORT int  CALLCONVENTION"
                lines.append(f"{kind} {n}{';' if n.startswith('tQSL_') else '(void);'}  ///< {n}")
            Path(folder, "tqsllib.h").write_text("\n".join(lines) + "\n", encoding="utf-8")

        headers(names)
        errors = check(Repo(), text, folder)
        if errors:
            print(f"tqsllib-map: self-test: headers made from the map disagree with it: {errors}", file=sys.stderr)
            return 1
        headers([n for n in names if n != "tqsl_endADIF"])
        errors = check(Repo(), text, folder)
        if not any("tqsl_endADIF: in the map, not in the headers" in e for e in errors):
            print(f"tqsllib-map: self-test: a function gone from the headers was not caught: {errors}", file=sys.stderr)
            return 1
        print(f"caught a function gone from the headers: {errors[-1]}")
    print("tqsllib-map: self-test: every planted fault was caught")
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if not argv or argv[0] != "--check" or len(argv) not in (1, 3) or (len(argv) == 3 and argv[1] != "--tqsl-src"):
        print(__doc__, file=sys.stderr)
        return 2
    tqsl_src = argv[2] if len(argv) == 3 else None
    if tqsl_src is not None and not (Path(tqsl_src) / "src" / "tqsllib.h").is_file() and not (Path(tqsl_src) / "tqsllib.h").is_file():
        print(f"tqsllib-map: {tqsl_src}: no tqsllib.h there", file=sys.stderr)
        return 2
    errors = check(Repo(), MAP.read_text(encoding="utf-8"), tqsl_src)
    for e in errors:
        print(f"tqsllib-map: {e}", file=sys.stderr)
    if errors:
        return 1
    table = rows(MAP.read_text(encoding="utf-8"))
    mapped = sum(1 for _, qgt, _ in table if not qgt.startswith(STATUSES))
    print(f"tqsllib-map: {len(table)} names, {mapped} mapped with a test, {len(table) - mapped} with a reason; "
          "every Rust path, command and test exists")
    if tqsl_src is None:
        print("tqsllib-map: tqsllib's headers not given (--tqsl-src): the names were checked against "
              "their pinned SHA-256 only")
    else:
        print(f"tqsllib-map: the names are exactly {tqsl_src}'s headers', in order")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
