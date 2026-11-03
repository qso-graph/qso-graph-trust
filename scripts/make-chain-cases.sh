#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
#
# Makes tests/corpus/chains: certificate chains under a test root, each with one thing wrong, for the
# chain checks (src/certificate.rs, Certificate::verify). Test keys only; nothing trusts them. Run once
# and commit; tests read the files. Needs openssl.
#
#   root.pem                 the test root
#   ca-good.pem              a CA as it should be
#   ca-pathlen0.pem          a CA that may have no CA under it (pathlen:0)
#   ca-under-pathlen0.pem    a CA it signs anyway
#   ca-nosign.pem            a CA whose key usage does not allow signing certificates
#   ca-critical.pem          a CA with a critical extension nothing here reads
#   leaf-good.pem            a LoTW-shaped certificate under ca-good: trusted
#   leaf-pathlen.pem         under ca-under-pathlen0: one CA too many below ca-pathlen0
#   leaf-nosign.pem          under ca-nosign
#   leaf-critical-ca.pem     under ca-critical
#   leaf-critical.pem        under ca-good, itself with an unknown critical extension
#   leaf-is-ca.pem           under ca-good, claiming to be a CA
#   leaf-bad-constraints.pem under ca-good, its critical basic constraints not decodable
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd -P)
dest="$root/tests/corpus/chains"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"

hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
cat > ext.cnf <<EOF
oid_section = oids
[oids]
AROcallsign = 1.3.6.1.4.1.12348.1.1
[req]
distinguished_name = dn
[dn]
[root]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
[ca_pathlen0]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
[ca_nosign]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature
[ca_critical]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
1.3.6.1.4.1.99999.1 = critical, DER:0500
[leaf_bad_constraints]
2.5.29.19 = critical, DER:0500
keyUsage = critical, digitalSignature
1.3.6.1.4.1.12348.1.2 = DER:$(hex 2020-01-01)
1.3.6.1.4.1.12348.1.3 = DER:$(hex 2099-12-31)
1.3.6.1.4.1.12348.1.4 = DER:$(hex 291)
[leaf]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
1.3.6.1.4.1.12348.1.2 = DER:$(hex 2020-01-01)
1.3.6.1.4.1.12348.1.3 = DER:$(hex 2099-12-31)
1.3.6.1.4.1.12348.1.4 = DER:$(hex 291)
[leaf_critical]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
1.3.6.1.4.1.12348.1.2 = DER:$(hex 2020-01-01)
1.3.6.1.4.1.12348.1.3 = DER:$(hex 2099-12-31)
1.3.6.1.4.1.12348.1.4 = DER:$(hex 291)
1.3.6.1.4.1.99999.1 = critical, DER:0500
[leaf_is_ca]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, keyCertSign
1.3.6.1.4.1.12348.1.2 = DER:$(hex 2020-01-01)
1.3.6.1.4.1.12348.1.3 = DER:$(hex 2099-12-31)
1.3.6.1.4.1.12348.1.4 = DER:$(hex 291)
EOF

key() { openssl genpkey -quiet -algorithm RSA -pkeyopt "rsa_keygen_bits:$2" -out "$1.key"; }
# issue NAME SUBJECT ISSUER SECTION [SERIAL]
issue() {
  openssl req -new -key "$1.key" -config ext.cnf -subj "$2" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -set_serial "${5:-$RANDOM}" -days 36500 -sha256 \
    -extfile ext.cnf -extensions "$4" -out "$1.pem" 2>/dev/null
}

key root 2048
openssl req -new -x509 -key root.key -days 36500 -sha256 -config ext.cnf -extensions root \
  -subj "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Chain Test Root" -out root.pem
for ca in ca-good ca-pathlen0 ca-nosign ca-critical; do key "$ca" 2048; done
key ca-under-pathlen0 2048
issue ca-good "/O=QSO Graph Trust TEST ONLY/CN=Good CA" root ca
issue ca-pathlen0 "/O=QSO Graph Trust TEST ONLY/CN=Pathlen 0 CA" root ca_pathlen0
issue ca-under-pathlen0 "/O=QSO Graph Trust TEST ONLY/CN=Under Pathlen 0 CA" ca-pathlen0 ca
issue ca-nosign "/O=QSO Graph Trust TEST ONLY/CN=No Cert Sign CA" root ca_nosign
issue ca-critical "/O=QSO Graph Trust TEST ONLY/CN=Critical CA" root ca_critical

leaf_subject="/AROcallsign=QG0TEST/CN=QGT Chain Test"
for leaf in leaf-good leaf-pathlen leaf-nosign leaf-critical-ca leaf-critical leaf-is-ca leaf-bad-constraints; do
  key "$leaf" 1024
done
issue leaf-good "$leaf_subject" ca-good leaf 1
issue leaf-pathlen "$leaf_subject" ca-under-pathlen0 leaf 2
issue leaf-nosign "$leaf_subject" ca-nosign leaf 3
issue leaf-critical-ca "$leaf_subject" ca-critical leaf 4
issue leaf-critical "$leaf_subject" ca-good leaf_critical 5
issue leaf-is-ca "$leaf_subject" ca-good leaf_is_ca 6
issue leaf-bad-constraints "$leaf_subject" ca-good leaf_bad_constraints 8

[ ! -L "$root/tests" ] && [ ! -L "$root/tests/corpus" ] && [ ! -L "$dest" ] \
  || { echo "tests/corpus/chains or a folder above it is a link: refusing to write" >&2; exit 1; }
rm -rf -- "$dest"
mkdir -p "$dest"
cp -- *.pem "$dest/"
echo "made $(ls "$dest" | wc -l) certificates in tests/corpus/chains"
