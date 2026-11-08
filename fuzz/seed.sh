#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
#
# Seed each fuzz target's corpus, fuzz/corpus/<target>/, from the test corpus in tests/corpus: test
# data only, made from test keys. Copied, not committed twice: tests/corpus stays the one source.
# A gzipped .tq6 or .tbk is also given decompressed, since the readers take the XML itself and a
# mutated gzip stream mostly fails its checksum before the XML is reached.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
from="$here/../tests/corpus"
to="$here/corpus"

seed() { # seed <target> <corpus file>...
  target=$1
  shift
  mkdir -p "$to/$target"
  for f in "$@"; do
    name=$(printf '%s' "${f#"$from"/}" | tr '/' '_')
    cp "$f" "$to/$target/$name"
    if gzip -t "$f" 2>/dev/null; then
      gzip -dc "$f" >"$to/$target/$name.xml"
    fi
  done
}

mkdir -p "$to/adx"
printf '%s' '<ADX><HEADER/><RECORDS><RECORD><CALL>QG0TEST</CALL><QSO_DATE>20261103</QSO_DATE><TIME_ON>183055</TIME_ON><BAND>20m</BAND><MODE>CW</MODE></RECORD></RECORDS></ADX>' >"$to/adx/synthetic.adx"
seed adif "$from"/adif/*.adi "$from"/standard/adif/*.adi "$from"/signing-options/*.adi
seed tq6 "$from"/pki/*.tq6 "$from"/tqsl/*/*.tq6 "$from"/standard/certs/*.tq6
seed p12 "$from"/pki/*.p12 "$from"/roots/*.p12 "$from"/tqsl/*/*.p12
seed tbk "$from"/standard/standard.tbk
