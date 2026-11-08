#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
"""Generate signing-option oracles with tqsllib 2.8.7 and existing generated test keys.

Usage: python3 tests/tqsllib/make-options.py /path/to/qgt-tqsllib
The driver must be built from this directory's qgt-tqsllib.cpp. No network is used.
"""

import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tests/corpus/signing-options"
PREAMBLE = (
    "SPDX-License-Identifier: GPL-3.0-or-later\n"
    "Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.\n\n"
)


def record(**fields):
    values = dict(CALL="KN4YU", QSO_DATE="20261103", TIME_ON="183055", BAND="20m", MODE="CW")
    values.update(fields)
    return "".join(f"<{key}:{len(value.encode('utf-8'))}>{value}" for key, value in values.items()) + "<EOR>\n"


# Each case gets a fresh store, including its duplicate database. The Rust differential tests
# name these same cases. Failure cases plant a mismatch or invalid contact, with no usable output.
CASES = [
    ("default", {}, record(), True),
    ("custom", {"MODE_MAP": "LEGACY=FT8"}, record(MODE="LEGACY"), True),
    ("custom-pair", {"MODE_MAP": "MFSK%SPECIAL=CW"}, record(MODE="MFSK", SUBMODE="SPECIAL"), True),
    ("custom-submode", {"MODE_MAP": "SPECIAL=RTTY"}, record(MODE="MFSK", SUBMODE="SPECIAL"), True),
    ("custom-remap", {"MODE_MAP": "MFSK%FT8=CW"}, record(MODE="MFSK", SUBMODE="FT8") + record(MODE="MFSK", SUBMODE="FT8", TIME_ON="183155"), True),
    ("seconds", {"IGNORE_SECONDS": "1"}, record() + record(TIME_ON="183159"), True),
    ("seconds-dupe", {"IGNORE_SECONDS": "1"}, record() + record(TIME_ON="183059"), True),
    ("callsign", {"IGNORE_CALLSIGNS": "1"}, record(STATION_CALLSIGN="KN4YU"), True),
    ("operator", {"IGNORE_CALLSIGNS": "1"}, record() + record(TIME_ON="183155", OPERATOR="KN4YU"), True),
    ("callsign-refused", {}, record(STATION_CALLSIGN="KN4YU"), False),
    ("operator-refused", {}, record() + record(TIME_ON="183155", OPERATOR="KN4YU"), False),
    ("bad-call", {"ALLOW_BAD_CALLS": "1"}, record(CALL="TEST"), True),
    ("bad-prefix", {"ALLOW_BAD_CALLS": "1"}, record(CALL="0ABC"), True),
    ("bad-punctuation", {"ALLOW_BAD_CALLS": "1"}, record(CALL="/"), True),
    ("bad-unicode", {"ALLOW_BAD_CALLS": "1"}, record(CALL="TESTÉ"), True),
    ("bad-long", {"ALLOW_BAD_CALLS": "1"}, record(CALL="NOTANAMATEURCALLSIGN012345"), False),
    ("bad-call-refused", {}, record(CALL="TEST"), False),
    ("ignore", {"QTH": "0"}, record(STATION_CALLSIGN="KN4YU", MY_DXCC="1", MY_STATE="KS", MY_GRIDSQUARE="EM17", MY_IOTA="BOGUS"), True),
    ("report", {}, record(MY_STATE="KS"), False),
    ("report-fill", {}, record(MY_IOTA="NA-110"), True),
    ("report-label", {}, record(MY_STATE="South Carolina"), True),
    ("report-zone", {}, record(MY_CQ_ZONE="05", MY_ITU_ZONE="008"), True),
    ("update", {"QTH": "2"}, record(MY_GRIDSQUARE="EM93", MY_CNTY="SC,Richland") + record(TIME_ON="183155") + record(TIME_ON="183255", MY_GRIDSQUARE="FM02", MY_CNTY="SC,Charleston"), True),
    ("update-state", {"QTH": "2"}, record(MY_STATE="KS", MY_GRIDSQUARE="EM17", MY_CNTY="KS,Sedgwick") + record(TIME_ON="183155"), True),
    ("update-neighbor", {"QTH": "2"}, record(MY_STATE="NC", MY_CNTY="NC,Brunswick"), True),
    ("update-label", {"QTH": "2"}, record(MY_STATE="North Carolina", MY_CNTY="NC,Brunswick"), True),
    ("update-vucc", {"QTH": "2"}, record(MY_VUCC_GRIDS="EM93,EM94") + record(TIME_ON="183155", MY_VUCC_GRIDS="EM93,EM94") + record(TIME_ON="183255", MY_VUCC_GRIDS="EM95,EM96"), True),
    ("update-county-state", {"QTH": "2"}, record(MY_CNTY="KS,Richland"), False),
    ("update-dxcc", {"QTH": "2"}, record(MY_DXCC="1"), False),
]


def main():
    driver = str(Path(sys.argv[1]).resolve())
    OUT.mkdir(exist_ok=True)
    for name, options, adif, success in CASES:
        with tempfile.TemporaryDirectory(prefix="qgt-options-") as temp:
            store = Path(temp) / "tqsl"
            shutil.copytree(ROOT / "tests/corpus/standard/tqsl", store)
            for path in store.glob("uploaded.db*"):
                path.unlink()
            shutil.copyfile(ROOT / "data/tqsl-config/config.xml", store / "config.xml")
            env = dict(os.environ, TQSLDIR=str(store), QGT_QTH="1")
            env.update({f"QGT_{key}": value for key, value in options.items()})
            env["QGT_TEST_KEYPASS"] = (ROOT / "tests/corpus/standard/keys/KC4QPQ.password").read_text()
            log = OUT / f"{name}.adi"
            log.write_text(PREAMBLE + "Test QSOs only.\n" + adif)
            output = OUT / f"{name}.tq7"
            result = subprocess.run([driver, "sign", "KC4QPQ-HOME", str(log), str(output)], env=env, capture_output=True, text=True)
            if (result.returncode == 0) != success:
                raise RuntimeError(f"{name}: unexpected result: {result.stderr}")
            if success:
                with sqlite3.connect(store / "uploaded.db") as db:
                    rows = db.execute("SELECT tContact, QTH FROM QSOs ORDER BY tContact").fetchall()
                (OUT / f"{name}.keys").write_text(PREAMBLE + "".join(f"{key}\t{station}\n" for key, station in rows))
                output.write_bytes(PREAMBLE.encode() + output.read_bytes())
            else:
                output.unlink(missing_ok=True)
            print(f"{name}: {'signed' if success else 'refused'}")


if __name__ == "__main__":
    main()
