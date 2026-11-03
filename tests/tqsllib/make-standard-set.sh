#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
#
# Runs inside the harness image (Containerfile), started by scripts/make-standard-set.sh: makes the
# standard test set (KI7MT, 2026-11-03; qso-graph-desktop#172), the certificates, locations and backup a
# ham's TQSL would hold, into /out. A test CA plays the part ARRL plays: "TEST ONLY, Not ARRL". The calls
# are KI7MT's former ones, his choice; every key, certificate and password here is a test one.
#
#   KC4QPQ   North Charleston, SC: KC4QPQ-HOME (Charleston County, FM02) and four parks, MN35 Fort
#            Sumter, NS09 Charles Pinckney (Charleston, FM02), NP12 Congaree (Richland, EM93) and
#            TR10,MP06 Overmountain Victory NHT + Kings Mountain (York, EM95). Key password set.
#   KN4YU    the club call: KN4YU-CLUB (Charleston, FM02). No key password.
#   W4W      the special-event call, its certificate in force and covering QSOs for one month from the
#            day this runs: W4W-EVENT (Charleston, FM02). Key password set.
#
# tqsllib makes each key and request and loads each certificate, as TQSL's app does through it; then
# TQSL's app itself runs, in a virtual display with no network, and its own automatic backup on exit
# (apps/tqsl.cpp, MyFrame::OnExit -> AutoBackup) writes the .tbk.
#
#   /out/pki                      the test root and CA, with their keys
#   /out/requests/<call>.tq5      the request tqsllib made
#   /out/certs/<call>.tq6         the certificate, as ARRL would send it
#   /out/keys/<call>.password     the key's password, exactly, empty for none
#   /out/adif/<location>.adi      a test log for each location, dated the day this runs
#   /out/signed/<location>.tq7    that log signed by tqsllib at that location
#   /out/tqsl                     tqsllib's own folder: keys/, certs/, station_data, uploaded.db
#   /out/standard.tbk             TQSL's backup of all of it, as its app writes it
#   /out/MANIFEST                 what was made, and when
set -euo pipefail

DXCC=291
EMAIL=test@example.invalid
TODAY=$(date -u +%Y-%m-%d)
MONTH_ON=$(date -u -d '+30 days' +%Y-%m-%d)

# call | serial | key password | first QSO date | last QSO date | days in force. Serials are small
# numbers, as ARRL's are: tqsllib reads one into a long, and tells a call's certificates apart by it.
CERTS=(
  "KC4QPQ|10001|qgt-kc4qpq|2000-01-01|2099-12-31|1095"
  "KN4YU|10002||2000-01-01|2099-12-31|1095"
  "W4W|10003|qgt-w4w|$TODAY|$MONTH_ON|30"
)

# location | call | county | grid | park
LOCATIONS=(
  "KC4QPQ-HOME|KC4QPQ|Charleston|FM02|"
  "KC4QPQ-MN35|KC4QPQ|Charleston|FM02|MN35"
  "KC4QPQ-NS09|KC4QPQ|Charleston|FM02|NS09"
  "KC4QPQ-NP12|KC4QPQ|Richland|EM93|NP12"
  "KC4QPQ-TR10-MP06|KC4QPQ|York|EM95|TR10,MP06"
  "KN4YU-CLUB|KN4YU|Charleston|FM02|"
  "W4W-EVENT|W4W|Charleston|FM02|"
)

hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export TQSLDIR=/out/tqsl HOME=$work/home
mkdir -p /out/pki /out/requests /out/certs /out/keys /out/adif /out/signed "$TQSLDIR" "$HOME"

cat > "$work/ca.cnf" <<EOF
[req]
distinguished_name = dn
[dn]
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

echo "== the test root and CA (TEST ONLY, Not ARRL)"
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /out/pki/root.key
openssl req -new -x509 -key /out/pki/root.key -days 36500 -sha256 -config "$work/ca.cnf" \
  -subj "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Test Root" -extensions ca -out /out/pki/root.pem
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /out/pki/ca.key
openssl req -new -key /out/pki/ca.key -config "$work/ca.cnf" \
  -subj "/O=QSO Graph Trust TEST ONLY/OU=Not ARRL/CN=QGT Test CA" -out "$work/ca.csr"
openssl x509 -req -in "$work/ca.csr" -CA /out/pki/root.pem -CAkey /out/pki/root.key -CAserial "$work/root.srl" \
  -CAcreateserial -days 36500 -sha256 -extfile "$work/ca.cnf" -extensions ca -out /out/pki/ca.pem 2>/dev/null

for entry in "${CERTS[@]}"; do
  IFS='|' read -r call serial pass first last days <<<"$entry"
  echo "== $call: key, request, certificate $serial (QSOs $first to $last, in force $days days)"
  printf '%s' "$pass" > "/out/keys/$call.password"
  keypass=()
  [ -n "$pass" ] && keypass=("$pass")
  qgt-tqsllib request "$call" "$DXCC" "$EMAIL" "/out/requests/$call.tq5" "${keypass[@]}"
  awk '/-----BEGIN CERTIFICATE REQUEST-----/ { f = 1; sub(/^.*-----BEGIN/, "-----BEGIN") } f { print }
       /-----END CERTIFICATE REQUEST-----/ { exit }' "/out/requests/$call.tq5" > "$work/$call.csr"
  # LoTW's extensions: the first and last QSO date the certificate covers, and the DXCC entity.
  cat > "$work/$call.cnf" <<EOF
[user]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.3.6.1.4.1.12348.1.2 = DER:$(hex "$first")
1.3.6.1.4.1.12348.1.3 = DER:$(hex "$last")
1.3.6.1.4.1.12348.1.4 = DER:$(hex "$DXCC")
EOF
  openssl x509 -req -in "$work/$call.csr" -CA /out/pki/ca.pem -CAkey /out/pki/ca.key -set_serial "$serial" \
    -days "$days" -sha256 -extfile "$work/$call.cnf" -extensions user -out "$work/$call.pem" 2>/dev/null
  # Sent as ARRL sends one: a .tq6, gzipped XML of root, CA and user certificates, gzip -n so no name
  # or time is inside (src/location.cpp:4281-4334).
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<tqsldata>\n<tqslcerts>\n'
    printf '<rootcert>\n'; cat /out/pki/root.pem; printf '</rootcert>\n'
    printf '<cacert>\n'; cat /out/pki/ca.pem; printf '</cacert>\n'
    printf '<usercert>\n'; cat "$work/$call.pem"; printf '</usercert>\n'
    printf '</tqslcerts>\n</tqsldata>\n'
  } | gzip -n -9 > "/out/certs/$call.tq6"
  load_cert "/out/certs/$call.tq6"
done
[ "$(grep -c 'BEGIN CERTIFICATE' "$TQSLDIR/certs/user")" = 3 ] \
  || { echo "tqsllib did not store all three certificates" >&2; exit 1; }

for entry in "${LOCATIONS[@]}"; do
  IFS='|' read -r name call county grid park <<<"$entry"
  fields=(US_STATE=SC "US_COUNTY=$county" "GRIDSQUARE=$grid" CQZ=5 ITUZ=8)
  [ -n "$park" ] && fields+=("US_PARK=$park")
  qgt-tqsllib location "$name" "$call" "$DXCC" "${fields[@]}"
done

# A test log for each location, dated today so every certificate covers it, W4W's included. Each
# location's QSOs are its own (tqsllib signs a QSO once, wherever from: its duplicate check). The calls
# worked are KI7MT's former ones and the set's own.
d=$(date -u +%Y%m%d)
n=0
for entry in "${LOCATIONS[@]}"; do
  IFS='|' read -r name call _ <<<"$entry"
  worked=(M0EHA KE1HA KC4QPQ KN4YU)
  {
    printf 'Test log for QSO Graph Trust'"'"'s standard test set: %s at %s. Test QSOs only.\n' "$call" "$name"
    printf '<ADIF_VER:5>3.1.7 <PROGRAMID:21>qso-graph-trust-tests <EOH>\n\n'
    for q in "<BAND:3>20m <FREQ:6>14.074 <MODE:4>MFSK <SUBMODE:3>FT8" "<BAND:3>40m <FREQ:5>7.030 <MODE:2>CW" \
             "<BAND:2>2m <FREQ:7>146.520 <MODE:2>FM"; do
      other=${worked[$((n % 4))]}
      [ "$other" = "$call" ] && other=${worked[$(((n + 1) % 4))]}
      printf '<CALL:%d>%s <QSO_DATE:8>%s <TIME_ON:4>%04d %s <EOR>\n' "${#other}" "$other" "$d" "$n" "$q"
      n=$((n + 1))
    done
  } > "/out/adif/$name.adi"
  pass=$(cat "/out/keys/$call.password")
  keypass=()
  [ -n "$pass" ] && keypass=("$pass")
  echo "== signing $name's log"
  qgt-tqsllib sign "$name" "/out/adif/$name.adi" "/out/signed/$name.tq7" "${keypass[@]}"
  [ "$(grep -c tCONTACT "/out/signed/$name.tq7")" = 3 ] || { echo "$name: not all three QSOs signed" >&2; exit 1; }
done

echo "== TQSL's app: started, then closed as a ham closes it, so it writes its backup"
# As a TQSL that has been run before, that checks for no updates: no first-run help, no network.
printf 'HasRun=yes\nAutoUpdateCheck=0\n' > "$HOME/.tqslapp"
Xvfb :9 -screen 0 1280x1024x24 -nolisten tcp >/dev/null 2>&1 &
xvfb=$!
export DISPLAY=:9
for _ in $(seq 20); do xdotool getmouselocation >/dev/null 2>&1 && break; sleep 0.5; done
tqsl >"$work/tqsl.log" 2>&1 &
app=$!
main=
for _ in $(seq 60); do
  main=$( (xdotool search --onlyvisible --name '^TQSL$' 2>/dev/null || true) | head -1)
  [ -n "$main" ] && break
  sleep 0.5
done
if [ -z "$main" ]; then
  echo "TQSL's window did not open" >&2
  for w in $(xdotool search --onlyvisible --name . 2>/dev/null || true); do
    echo "  open: $(xdotool getwindowname "$w" 2>/dev/null || true)" >&2
  done
  echo "TQSL said:" >&2; cat "$work/tqsl.log" >&2
  exit 1
fi
# Any other window open beside the main one is a dialog the backup would wait behind: stop and say.
others=$( (xdotool search --onlyvisible --name . 2>/dev/null || true) | grep -vx "$main" | while read -r w; do
  xdotool getwindowname "$w" 2>/dev/null || true; done | grep -v '^$' || true)
[ -z "$others" ] || { echo "TQSL opened a dialog: $others" >&2; exit 1; }
xdotool key --window "$main" alt+x 2>/dev/null || true
for _ in $(seq 60); do kill -0 "$app" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$app" 2>/dev/null; then
  echo "TQSL did not exit" >&2; kill "$app"; exit 1
fi
kill "$xvfb" 2>/dev/null || true
[ -s "$TQSLDIR/tqslconfig.tbk" ] || { echo "TQSL wrote no backup" >&2; cat "$work/tqsl.log" >&2; exit 1; }
mv "$TQSLDIR/tqslconfig.tbk" /out/standard.tbk

{
  echo "QSO Graph Trust's standard test set, made $(date -u +%Y-%m-%dT%H:%M:%SZ) by tests/tqsllib/make-standard-set.sh"
  echo "tqsllib and TQSL 2.8.7 (commit $(git -C /src/tqsl rev-parse HEAD))"
  for entry in "${CERTS[@]}"; do
    IFS='|' read -r call serial pass first last days <<<"$entry"
    echo "certificate $call: serial $serial, QSOs $first to $last, in force $days days, key password $([ -n "$pass" ] && echo set || echo none)"
  done
  for entry in "${LOCATIONS[@]}"; do echo "location ${entry//|/ }"; done
} > /out/MANIFEST
echo "== done"
