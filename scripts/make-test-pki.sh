#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
#
# Makes tests/corpus/pki: a TEST certificate authority and TEST operator certificates shaped the way
# LoTW's are, for QGT's tests. Nothing here is ARRL's, and LoTW would refuse all of it.
#
# The shape follows TQSL 2.8.7's reading of a certificate:
#   - the callsign is a subject attribute, AROcallsign, OID 1.3.6.1.4.1.12348.1.1 (src/openssl_cert.cpp:1769);
#   - QSONotBeforeDate (.2), QSONotAfterDate (.3) and dxccEntity (.4) are extensions whose value is the
#     text itself, YYYY-MM-DD or the entity number, not DER-wrapped (src/openssl_cert.cpp:5414-5461);
#   - a .tq6 is gzipped XML: <tqsldata><tqslcerts> holding rootcert, cacert and usercert PEMs
#     (src/location.cpp:4281-4334).
#
# Keys are random, so the corpus is made once and committed; tests read the committed files. Run it
# again only to change the corpus, and say why in the pull request. Needs OpenSSL 3 (a test tool here,
# never part of QGT).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/tests/corpus/pki"
work="$root/tests/corpus/.work"
rm -rf "$work"
mkdir -p "$out" "$work"
trap 'rm -rf "$work"' EXIT

openssl version | grep -q '^OpenSSL 3\.' || { echo "needs OpenSSL 3" >&2; exit 1; }

CALL=QG0TEST          # Q prefixes are never issued to stations
DXCC=291              # United States, in LoTW's numbering
NOT_BEFORE=2020-01-01
NOT_AFTER=2099-12-31
P12_PASSWORD=qgt-test # also in tests/corpus/README.md: a test password for test keys

# The extension value is the text's own bytes (DER:<hex>), as TQSL reads it.
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

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
1.3.6.1.4.1.12348.1.2 = DER:$(hex "$NOT_BEFORE")
1.3.6.1.4.1.12348.1.3 = DER:$(hex "$NOT_AFTER")
1.3.6.1.4.1.12348.1.4 = DER:$(hex "$DXCC")
EOF

# Requests name the callsign attribute TQSL looks for.
cat > "$work/req.cnf" <<EOF
oid_section = oids
[oids]
AROcallsign = 1.3.6.1.4.1.12348.1.1
[req]
distinguished_name = dn
[dn]
EOF

# The root and the issuing CA.
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/root.key"
openssl req -new -x509 -key "$work/root.key" -days 36500 -sha256 \
  -subj "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Test Root" \
  -extensions ca -config "$work/ext.cnf" -out "$out/root.pem"
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/ca.key"
openssl req -new -key "$work/ca.key" -subj "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Test CA" \
  -out "$work/ca.csr"
openssl x509 -req -in "$work/ca.csr" -CA "$out/root.pem" -CAkey "$work/root.key" -CAcreateserial \
  -days 36500 -sha256 -extfile "$work/ext.cnf" -extensions ca -out "$out/ca.pem"

# One operator certificate per key size: TQSL generates 1024-bit keys, and imported ones can be larger.
for bits in 1024 2048; do
  name="user-$bits"
  openssl genpkey -quiet -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" -out "$out/$name.key.pem"
  openssl req -new -config "$work/req.cnf" -key "$out/$name.key.pem" \
    -subj "/AROcallsign=$CALL/CN=QGT Test Operator $bits/emailAddress=test@example.invalid" \
    -out "$work/$name.csr"
  openssl x509 -req -in "$work/$name.csr" -CA "$out/ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
    -days 36500 -sha256 -extfile "$work/ext.cnf" -extensions user -out "$out/$name.pem"

  # The .tq6 ARRL would send: gzipped XML (gzip -n, so no name or time inside).
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<tqsldata>\n<tqslcerts>\n'
    printf '<rootcert>\n%s</rootcert>\n' "$(cat "$out/root.pem")
"
    printf '<cacert>\n%s</cacert>\n' "$(cat "$out/ca.pem")
"
    printf '<usercert>\n%s</usercert>\n' "$(cat "$out/$name.pem")
"
    printf '</tqslcerts>\n</tqsldata>\n'
  } | gzip -n -9 > "$out/$name.tq6"

  # PKCS#12 backups: TQSL's default (AES-256, PBES2) and its weak-crypto option (RC2-40 for the
  # certificate, 3DES for the key, SHA-1 MAC), src/openssl_cert.cpp:2436-2469.
  openssl pkcs12 -export -inkey "$out/$name.key.pem" -in "$out/$name.pem" -certfile "$out/ca.pem" \
    -name "$CALL" -passout "pass:$P12_PASSWORD" -out "$out/$name-aes.p12"
  openssl pkcs12 -export -legacy -inkey "$out/$name.key.pem" -in "$out/$name.pem" -certfile "$out/ca.pem" \
    -name "$CALL" -passout "pass:$P12_PASSWORD" -out "$out/$name-legacy.p12"
done

# Prove what was made: each chain verifies, and each certificate carries what TQSL reads.
for bits in 1024 2048; do
  openssl verify -CAfile "$out/root.pem" -untrusted "$out/ca.pem" "$out/user-$bits.pem" >/dev/null
  subject=$(openssl x509 -in "$out/user-$bits.pem" -noout -subject -nameopt oid,sep_comma_plus)
  grep -q "1\.3\.6\.1\.4\.1\.12348\.1\.1=$CALL," <<<"$subject"
  text=$(openssl x509 -in "$out/user-$bits.pem" -noout -text)
  # Each extension's value, on the line under its own OID.
  for pair in "2:$NOT_BEFORE" "3:$NOT_AFTER" "4:$DXCC"; do
    got=$(awk -v oid="1.3.6.1.4.1.12348.1.${pair%%:*}:" '$1 == oid { getline; print $1; exit }' <<<"$text")
    [ "$got" = "${pair#*:}" ] || { echo "extension .${pair%%:*} is '$got', not '${pair#*:}'" >&2; exit 1; }
  done
  keytext=$(openssl rsa -in "$out/user-$bits.key.pem" -noout -text 2>/dev/null)
  [ "${keytext%%$'\n'*}" = "Private-Key: ($bits bit, 2 primes)" ]
  openssl pkcs12 -in "$out/user-$bits-aes.p12" -passin "pass:$P12_PASSWORD" -noout
  openssl pkcs12 -legacy -in "$out/user-$bits-legacy.p12" -passin "pass:$P12_PASSWORD" -noout
  gzip -t "$out/user-$bits.tq6"
done
rm -f "$out"/*.srl
echo "made $(find "$out" -type f | wc -l) files in tests/corpus/pki"
