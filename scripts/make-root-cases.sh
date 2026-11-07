#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
#
# Makes tests/corpus/roots: a root QG Trust does not trust yet, as when ARRL starts issuing under a
# new one, and roots that must never be accepted, for the root checks (src/certificate.rs,
# file_roots, and Store's accepted roots). Test keys only; nothing trusts them. Run once and commit;
# tests read the files. Needs OpenSSL 3.
#
#   new-root.pem     a new test root, self-signed, a CA that may sign certificates
#   new-ca.pem       a CA under it
#   user-a.pem       a LoTW-shaped certificate under new-ca (QG0TEST, serial 1)
#   user-b.pem       another under new-ca (QG0TEST, serial 2): a later certificate under the same root
#   user-a.p12       user-a's key with the chain to new-root, password in ../pki/p12-password
#   other-root.pem   another self-signed test root that no certificate here chains to
#   noca-root.pem    self-signed, but not a CA (CA:false)
#   user-noca.pem    a LoTW-shaped certificate issued by noca-root
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd -P)
dest="$root/tests/corpus/roots"
openssl version | grep -q '^OpenSSL 3\.' || { echo "needs OpenSSL 3" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"

P12_PASSWORD=$(cat "$root/tests/corpus/pki/p12-password")
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
[noca]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyCertSign
subjectKeyIdentifier = hash
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
[leaf]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
1.3.6.1.4.1.12348.1.2 = DER:$(hex 2020-01-01)
1.3.6.1.4.1.12348.1.3 = DER:$(hex 2099-12-31)
1.3.6.1.4.1.12348.1.4 = DER:$(hex 291)
EOF

key() { openssl genpkey -quiet -algorithm RSA -pkeyopt "rsa_keygen_bits:$2" -out "$1.key"; }
# selfsign NAME SUBJECT SECTION
selfsign() {
  openssl req -new -x509 -key "$1.key" -days 36500 -sha256 -config ext.cnf -extensions "$3" \
    -subj "$2" -out "$1.pem"
}
# issue NAME SUBJECT ISSUER SECTION SERIAL
issue() {
  openssl req -new -key "$1.key" -config ext.cnf -subj "$2" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -set_serial "$5" -days 36500 -sha256 \
    -extfile ext.cnf -extensions "$4" -out "$1.pem" 2>/dev/null
}

for k in new-root new-ca other-root noca-root; do key "$k" 2048; done
for k in user-a user-b user-noca; do key "$k" 1024; done
selfsign new-root "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT New Test Root" root
selfsign other-root "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Unused Test Root" root
selfsign noca-root "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Not A CA Root" noca
issue new-ca "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT New Test CA" new-root ca 10
leaf_subject="/AROcallsign=QG0TEST/CN=QGT New Root Test"
issue user-a "$leaf_subject" new-ca leaf 1
issue user-b "$leaf_subject" new-ca leaf 2
issue user-noca "$leaf_subject" noca-root leaf 3

# Prove what was made: the good chains verify, and the not-a-CA root does not issue.
openssl verify -CAfile new-root.pem -untrusted new-ca.pem user-a.pem user-b.pem >/dev/null
! openssl verify -CAfile noca-root.pem user-noca.pem >/dev/null 2>&1 \
  || { echo "noca-root must not verify as an issuer" >&2; exit 1; }

cat new-ca.pem new-root.pem > chain.pem
openssl pkcs12 -export -inkey user-a.key -in user-a.pem -certfile chain.pem \
  -name QG0TEST -passout "pass:$P12_PASSWORD" -out user-a.p12
openssl pkcs12 -in user-a.p12 -passin "pass:$P12_PASSWORD" -noout

[ ! -L "$root/tests" ] && [ ! -L "$root/tests/corpus" ] && [ ! -L "$dest" ] \
  || { echo "tests/corpus/roots or a folder above it is a link: refusing to write" >&2; exit 1; }
rm -rf -- "$dest"
mkdir -p "$dest"
cp -- new-root.pem new-ca.pem user-a.pem user-b.pem user-a.p12 other-root.pem noca-root.pem \
  user-noca.pem "$dest/"
echo "made $(ls "$dest" | wc -l) files in tests/corpus/roots"
