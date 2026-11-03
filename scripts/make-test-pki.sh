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

root=$(cd "$(dirname "$0")/.." && pwd -P)
dest="$root/tests/corpus/pki"

openssl version | grep -q '^OpenSSL 3\.' || { echo "needs OpenSSL 3" >&2; exit 1; }

# Everything is made in a fresh directory of its own, removed when done, so the script never deletes
# or writes through anything it did not create; the corpus is replaced only at the end, by renaming
# (found by Codex review).
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
out="$work/stage"
mkdir "$out"

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
openssl x509 -req -in "$work/ca.csr" -CA "$out/root.pem" -CAkey "$work/root.key" -CAserial "$work/root.srl" -CAcreateserial \
  -days 36500 -sha256 -extfile "$work/ext.cnf" -extensions ca -out "$out/ca.pem"

# One operator certificate per key size: TQSL generates 1024-bit keys, and imported ones can be larger.
for bits in 1024 2048; do
  name="user-$bits"
  openssl genpkey -quiet -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" -out "$out/$name.key.pem"
  openssl req -new -config "$work/req.cnf" -key "$out/$name.key.pem" \
    -subj "/AROcallsign=$CALL/CN=QGT Test Operator $bits/emailAddress=test@example.invalid" \
    -out "$work/$name.csr"
  openssl x509 -req -in "$work/$name.csr" -CA "$out/ca.pem" -CAkey "$work/ca.key" -CAserial "$work/ca.srl" -CAcreateserial \
    -days 36500 -sha256 -extfile "$work/ext.cnf" -extensions user -out "$out/$name.pem"

  # The .tq6 ARRL would send: gzipped XML (gzip -n, so no name or time inside). Written as a file
  # first, one command at a time, so a failed read stops the script instead of leaving an empty
  # element (found by Codex review).
  xml="$work/$name.xml"
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<tqsldata>\n<tqslcerts>\n' > "$xml"
  for part in "rootcert:root" "cacert:ca" "usercert:$name"; do
    printf '<%s>\n' "${part%%:*}" >> "$xml"
    cat "$out/${part#*:}.pem" >> "$xml"
    printf '</%s>\n' "${part%%:*}" >> "$xml"
  done
  printf '</tqslcerts>\n</tqsldata>\n' >> "$xml"
  gzip -n -9 -c "$xml" > "$out/$name.tq6"

  # PKCS#12 files made by OpenSSL with the two encryptions TQSL uses: its default (AES-256, PBES2)
  # and its weak-crypto option (RC2-40 for the certificates, 3DES for the key, SHA-1 MAC),
  # src/openssl_cert.cpp:2436-2469, with the chain to the root. They are not TQSL's own backups:
  # TQSL also adds bag attributes (callsign, QSO dates, DXCC), so its backups are made by tqsllib
  # itself in phase 2 (found by Codex review).
  cat "$out/ca.pem" "$out/root.pem" > "$work/chain.pem"
  openssl pkcs12 -export -inkey "$out/$name.key.pem" -in "$out/$name.pem" -certfile "$work/chain.pem" \
    -name "$CALL" -passout "pass:$P12_PASSWORD" -out "$out/$name-aes.p12"
  openssl pkcs12 -export -legacy -inkey "$out/$name.key.pem" -in "$out/$name.pem" -certfile "$work/chain.pem" \
    -name "$CALL" -passout "pass:$P12_PASSWORD" -out "$out/$name-legacy.p12"
done

# Prove what was made: each chain verifies, and each certificate carries what TQSL reads.
for bits in 1024 2048; do
  openssl verify -CAfile "$out/root.pem" -untrusted "$out/ca.pem" "$out/user-$bits.pem" >/dev/null
  subject=$(openssl x509 -in "$out/user-$bits.pem" -noout -subject -nameopt oid,sep_comma_plus)
  grep -q "1\.3\.6\.1\.4\.1\.12348\.1\.1=$CALL," <<<"$subject"
  text=$(openssl x509 -in "$out/user-$bits.pem" -noout -text)
  # Each extension's value, exactly: the whole octet string, read from the DER, must be the text's
  # own bytes and nothing more (found by Codex review: a printed first word accepted trailing data).
  der="$work/user-$bits.der"
  openssl x509 -in "$out/user-$bits.pem" -outform DER -out "$der"
  asn=$(openssl asn1parse -inform DER -in "$der")
  for pair in "2:$NOT_BEFORE" "3:$NOT_AFTER" "4:$DXCC"; do
    oid="1.3.6.1.4.1.12348.1.${pair%%:*}"
    # The OCTET STRING after the OID: its offset, header length and length, as asn1parse prints them.
    read -r off hl len < <(awk -v oid=":$oid" '
      index($0, oid) && substr($0, length($0) - length(oid) + 1) == oid { f = 1; next }
      f && /prim: OCTET STRING/ {
        o = $0; sub(/^ */, "", o); sub(/:.*/, "", o)
        match($0, /hl= *[0-9]+/); h = substr($0, RSTART + 3, RLENGTH - 3)
        match($0, / l= *[0-9]+/); l = substr($0, RSTART + 3, RLENGTH - 3)
        print o + 0, h + 0, l + 0; exit }' <<<"$asn")
    [ -n "${len:-}" ] || { echo "extension $oid not found" >&2; exit 1; }
    got=$(od -An -tx1 -j $((off + hl)) -N "$len" "$der" | tr -d ' \n' | tr 'a-f' 'A-F')
    want=$(hex "${pair#*:}" | tr 'a-f' 'A-F')
    [ "$got" = "$want" ] || { echo "extension $oid holds '$got', not '$want' ('${pair#*:}')" >&2; exit 1; }
  done
  keytext=$(openssl rsa -in "$out/user-$bits.key.pem" -noout -text 2>/dev/null)
  [ "${keytext%%$'\n'*}" = "Private-Key: ($bits bit, 2 primes)" ]
  openssl pkcs12 -in "$out/user-$bits-aes.p12" -passin "pass:$P12_PASSWORD" -noout
  openssl pkcs12 -legacy -in "$out/user-$bits-legacy.p12" -passin "pass:$P12_PASSWORD" -noout
  # The .tq6 holds exactly the three elements, in order, each exactly its certificate.
  tq6=$(gzip -dc "$out/user-$bits.tq6")
  tags=$(grep -o '^</\?[a-z]*>' <<<"$tq6" | tr '\n' ' ')
  [ "$tags" = "<tqsldata> <tqslcerts> <rootcert> </rootcert> <cacert> </cacert> <usercert> </usercert> </tqslcerts> </tqsldata> " ] \
    || { echo "user-$bits.tq6 has the wrong elements: $tags" >&2; exit 1; }
  for part in "rootcert:root" "cacert:ca" "usercert:user-$bits"; do
    awk -v t="${part%%:*}" '$0 == "</" t ">" { f = 0 } f { print } $0 == "<" t ">" { f = 1 }' <<<"$tq6" \
      | cmp -s - "$out/${part#*:}.pem" || { echo "user-$bits.tq6: <${part%%:*}> is not ${part#*:}.pem" >&2; exit 1; }
  done
done
# Install: the destination must really be tests/corpus/pki inside this repository, not a link to
# somewhere else, and each file is renamed into place, which replaces a link there rather than
# writing through it.
[ ! -L "$root/tests" ] && [ ! -L "$root/tests/corpus" ] && [ ! -L "$dest" ] \
  || { echo "tests/corpus/pki or a folder above it is a link: refusing to write" >&2; exit 1; }
mkdir -p "$dest"
case "$(cd "$dest" && pwd -P)" in
  "$root/tests/corpus/pki") ;;
  *) echo "tests/corpus/pki resolves outside the repository: refusing to write" >&2; exit 1 ;;
esac
for f in "$out"/*; do
  mv -f -- "$f" "$dest/"
done
echo "made $(find "$dest" -maxdepth 1 -type f | wc -l) files in tests/corpus/pki"
