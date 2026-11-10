#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Runs only inside the existing harness image, with --network=none.
set -euo pipefail
umask 077
sanitize=()
if [ "${QGT_REFERENCE_SANITIZERS:-0}" = 1 ]; then
  sanitize=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
g++ "${sanitize[@]}" -std=c++17 -O2 -Wall -Wextra -Werror -I/src/tqsl/src -I/build/src \
  /driver.cpp -L/build/src -ltqsllib -o /tmp/qgt-cabrillo-reference
export TQSLDIR=/tmp/cabrillo-store
cp -a /corpus/tqsl/1024/tqsl "$TQSLDIR"
/tmp/qgt-cabrillo-reference location Cabrillo QG0TEST 291 US_STATE=KS US_COUNTY=Sedgwick GRIDSQUARE=EM17 CQZ=4 ITUZ=7 >/dev/null
export QGT_IGNORE_CALLSIGNS=1
while IFS=$'\t' read -r index relative; do
  /tmp/qgt-cabrillo-reference read-cabrillo "/logs/$relative" "/out/$index.records"
  # Conversion failures are evidence too; keep partial output and its exit status privately.
  status=0
  /tmp/qgt-cabrillo-reference sign-cabrillo Cabrillo "/logs/$relative" "/out/$index.tq7" \
    >"/out/$index.stdout" 2>"/out/$index.stderr" || status=$?
  printf '%s\n' "$status" >"/out/$index.status"
done </manifest
