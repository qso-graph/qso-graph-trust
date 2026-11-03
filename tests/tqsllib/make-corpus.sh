#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
#
# Runs inside the harness image (Containerfile), started by scripts/make-tqsl-corpus.sh: makes the
# files tqsllib 2.8.7 writes, from test keys only, into /out. A test CA plays the part ARRL plays
# for a real certificate: tqsllib makes the key and the request, the test CA issues the
# certificate, and tqsllib loads it, as a ham's TQSL does.
#
#   /out/pki                    the test root and CA, with their keys (test keys, nothing trusts them)
#   /out/<case>/tqsl            tqsllib's own folder: keys/, certs/, station_data, uploaded.db
#   /out/<case>/QG0TEST.tq5     the request tqsllib made
#   /out/<case>/QG0TEST.tq6     the certificate, as ARRL would send it
#   /out/<case>/QG0TEST.p12     tqsllib's export, AES-256, password qgt-test
#   /out/<case>/QG0TEST-weak.p12  the same, its weak-crypto option
#   /out/<case>/qg0test-small.tq7  the test log, signed
#   /out/<case>/key-password    the key's password, empty for none: tests read it from here
#
# Cases: 1024 (a key tqsllib made, no password) and 1024-password (a key tqsllib made, password
# qgt-key). LoTW keys are 1024-bit: tqsllib 2.8.7 makes no other size (src/openssl_cert.cpp:653).
set -euo pipefail

CALL=QG0TEST
DXCC=291
EMAIL=test@example.invalid
P12_PASSWORD=qgt-test
KEY_PASSWORD=qgt-key
LOG=/corpus/adif/qg0test-small.adi
LOCATION="QG0TEST Home"
LOCATION_FIELDS=(US_STATE=KS US_COUNTY=Sedgwick GRIDSQUARE=EM17 CQZ=4 ITUZ=7)

hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# The certificate's LoTW extensions, as scripts/make-test-pki.sh writes them.
cat > "$work/ext.cnf" <<EOF
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[user]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.3.6.1.4.1.12348.1.2 = DER:$(hex 2020-01-01)
1.3.6.1.4.1.12348.1.3 = DER:$(hex 2099-12-31)
1.3.6.1.4.1.12348.1.4 = DER:$(hex "$DXCC")
EOF
cat > "$work/req.cnf" <<EOF
oid_section = oids
[oids]
AROcallsign = 1.3.6.1.4.1.12348.1.1
[req]
distinguished_name = dn
[dn]
EOF

echo "== the test root and CA"
mkdir -p /out/pki
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /out/pki/root.key
openssl req -new -x509 -key /out/pki/root.key -days 36500 -sha256 \
  -subj "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Test Root" -extensions ca -config "$work/ext.cnf" \
  -out /out/pki/root.pem
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /out/pki/ca.key
openssl req -new -key /out/pki/ca.key -subj "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Test CA" -out "$work/ca.csr"
openssl x509 -req -in "$work/ca.csr" -CA /out/pki/root.pem -CAkey /out/pki/root.key -CAserial "$work/root.srl" \
  -CAcreateserial -days 36500 -sha256 -extfile "$work/ext.cnf" -extensions ca -out /out/pki/ca.pem 2>/dev/null

for case in 1024 1024-password; do
  echo "== case $case"
  dir=/out/$case
  mkdir -p "$dir/tqsl"
  export TQSLDIR=$dir/tqsl
  keypass=()
  [ "$case" = 1024-password ] && keypass=("$KEY_PASSWORD")
  printf '%s' "${keypass[@]}" > "$dir/key-password"

  {
    qgt-tqsllib request "$CALL" "$DXCC" "$EMAIL" "$dir/$CALL.tq5" "${keypass[@]}"
    awk '/-----BEGIN CERTIFICATE REQUEST-----/ { f = 1; sub(/^.*-----BEGIN/, "-----BEGIN") } f { print }
         /-----END CERTIFICATE REQUEST-----/ { exit }' "$dir/$CALL.tq5" > "$work/user.csr"
  }

  # The test CA issues it, and sends it as ARRL does: a .tq6, gzipped XML of root, CA and user
  # certificates (src/location.cpp:4281-4334), gzip -n so no name or time is inside.
  openssl x509 -req -in "$work/user.csr" -CA /out/pki/ca.pem -CAkey /out/pki/ca.key -CAserial "$work/ca.srl" \
    -CAcreateserial -days 36500 -sha256 -extfile "$work/ext.cnf" -extensions user -out "$work/user.pem" 2>/dev/null
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<tqsldata>\n<tqslcerts>\n'
    printf '<rootcert>\n'; cat /out/pki/root.pem; printf '</rootcert>\n'
    printf '<cacert>\n'; cat /out/pki/ca.pem; printf '</cacert>\n'
    printf '<usercert>\n'; cat "$work/user.pem"; printf '</usercert>\n'
    printf '</tqslcerts>\n</tqsldata>\n'
  } | gzip -n -9 > "$dir/$CALL.tq6"

  load_cert "$dir/$CALL.tq6"
  [ -s "$TQSLDIR/certs/user" ] || { echo "tqsllib did not store the user certificate" >&2; exit 1; }
  qgt-tqsllib location "$LOCATION" "$CALL" "$DXCC" "${LOCATION_FIELDS[@]}"
  # A protected key must not sign without its password: proved before it signs with it.
  if [ "${#keypass[@]}" -gt 0 ] && qgt-tqsllib sign "$LOCATION" "$LOG" "$work/nopass.tq7" 2>/dev/null; then
    echo "the protected key signed without its password" >&2; exit 1
  fi
  qgt-tqsllib sign "$LOCATION" "$LOG" "$dir/qg0test-small.tq7" "${keypass[@]}"
  [ "$(grep -c 'tCONTACT' "$dir/qg0test-small.tq7")" = 6 ] || { echo "not all six QSOs were signed" >&2; exit 1; }
  qgt-tqsllib export-p12 "$CALL" "$dir/$CALL.p12" "$P12_PASSWORD" "${keypass[@]}"
  if [ "${#keypass[@]}" -gt 0 ]; then
    qgt-tqsllib export-p12 "$CALL" "$dir/$CALL-weak.p12" "$P12_PASSWORD" "${keypass[@]}" weak
  else
    qgt-tqsllib export-p12 "$CALL" "$dir/$CALL-weak.p12" "$P12_PASSWORD" "" weak
  fi
done
echo "== done"
