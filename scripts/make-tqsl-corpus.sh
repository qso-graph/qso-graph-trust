#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
#
# Makes tests/corpus/tqsl: the files tqsllib 2.8.7 itself writes, from test keys only, for QGT's
# differential tests (qso-graph-desktop#171). It builds the harness image (tests/tqsllib), runs
# tests/tqsllib/make-corpus.sh inside it, and installs what that made. Nothing is installed on this
# machine: tqsllib, its tools and OpenSSL are all in the container, which is removed after.
#
# Keys are random, so the corpus is made once and committed; tests read the committed files. Run it
# again only to change the corpus, and say why in the pull request. Needs podman.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd -P)
dest="$root/tests/corpus/tqsl"
image=qgt-tqsllib:2.8.7

podman build -q -t "$image" "$root/tests/tqsllib" >/dev/null

# Made in a fresh folder of this run's own, removed when done; the corpus is replaced only at the end.
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/out"
podman run --rm --network=none \
  -v "$root/tests/corpus/adif:/corpus/adif:ro,Z" \
  -v "$root/tests/tqsllib/make-corpus.sh:/make-corpus.sh:ro,Z" \
  -v "$work/out:/out:Z" \
  "$image" bash /make-corpus.sh

# Install: the destination must really be tests/corpus/tqsl inside this repository, not a link, and
# the old corpus goes only once the new one is complete.
[ ! -L "$root/tests" ] && [ ! -L "$root/tests/corpus" ] && [ ! -L "$dest" ] \
  || { echo "tests/corpus/tqsl or a folder above it is a link: refusing to write" >&2; exit 1; }
rm -rf -- "$root/tests/corpus/.tqsl.new"
cp -a "$work/out" "$root/tests/corpus/.tqsl.new"
rm -rf -- "$dest"
mv -- "$root/tests/corpus/.tqsl.new" "$dest"
echo "made $(find "$dest" -type f | wc -l) files in tests/corpus/tqsl"
