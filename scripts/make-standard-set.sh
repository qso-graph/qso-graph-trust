#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
#
# Makes tests/corpus/standard: KI7MT's standard test set (qso-graph-desktop#172), the certificates,
# station locations, signed logs and .tbk backup a ham's TQSL 2.8.7 would hold, from test keys only. It
# builds the harness image (tests/tqsllib), runs tests/tqsllib/make-standard-set.sh inside it with no
# network, and installs what that made. Nothing is installed on this machine.
#
# Keys are random and W4W's certificate covers one month from the day it runs, so the set is made once
# and committed; tests read the committed files, at times inside the certificates. Run it again only
# to change the set, and say why in the pull request. Needs podman.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd -P)
dest="$root/tests/corpus/standard"
image=qgt-tqsllib:2.8.7

podman build -q -t "$image" "$root/tests/tqsllib" >/dev/null

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/out"
podman run --rm --network=none \
  -v "$root/tests/tqsllib/make-standard-set.sh:/make-standard-set.sh:ro,Z" \
  -v "$work/out:/out:Z" \
  "$image" bash /make-standard-set.sh

[ ! -L "$root/tests" ] && [ ! -L "$root/tests/corpus" ] && [ ! -L "$dest" ] \
  || { echo "tests/corpus/standard or a folder above it is a link: refusing to write" >&2; exit 1; }
rm -rf -- "$root/tests/corpus/.standard.new"
cp -a "$work/out" "$root/tests/corpus/.standard.new"
rm -rf -- "$dest"
mv -- "$root/tests/corpus/.standard.new" "$dest"
echo "made $(find "$dest" -type f | wc -l) files in tests/corpus/standard"
