#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# The .deb and .rpm of one Linux build, for packages.qso-graph.net's apt and dnf repositories
# (qso-graph/qso-graph-packages), which sign them:
#
#   scripts/linux-packages.sh <qg-trust> <version> <linux-x86_64|linux-arm64> <out-dir>
#
# Writes qso-graph-trust-<version>-linux-{amd64|arm64}.deb and -linux-{x86_64|aarch64}.rpm to <out-dir>
# and prints their paths. They hold the program as built (static, so no dependencies), its shell
# completions, and its README, licence, NOTICE and AUTHORS. A beta's version is X.Y.Z~beta.N inside
# the package, which both apt and dnf sort before X.Y.Z. Needs dpkg-deb and rpmbuild.
set -euo pipefail

exe=${1:?usage: linux-packages.sh <qg-trust> <version> <linux-x86_64|linux-arm64> <out-dir>}
version=${2:?version}
platform=${3:?platform}
out=${4:?out-dir}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-beta\.[1-9][0-9]*)?$ ]] || { echo "Not a version: $version" >&2; exit 2; }
case "$platform" in
  linux-x86_64) deb_arch=amd64 rpm_arch=x86_64 ;;
  linux-arm64) deb_arch=arm64 rpm_arch=aarch64 ;;
  *) echo "Not a Linux platform: $platform" >&2; exit 2 ;;
esac
here=$(cd "$(dirname "$0")/.." && pwd)
pkg_version=${version/-beta./\~beta.}
name=qso-graph-trust
summary="Sign and upload your logs to ARRL's Logbook of The World, with your key in your computer's credential store"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$here" log -1 --format=%ct)}
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# One tree for both: the program, its completions, and its documents.
root="$work/root"
install -D -m 0755 "$exe" "$root/usr/bin/qg-trust"
"$exe" --completions bash > "$work/bash"
"$exe" --completions zsh > "$work/zsh"
"$exe" --completions fish > "$work/fish"
install -D -m 0644 "$work/bash" "$root/usr/share/bash-completion/completions/qg-trust"
install -D -m 0644 "$work/zsh" "$root/usr/share/zsh/site-functions/_qg-trust"
install -D -m 0644 "$work/fish" "$root/usr/share/fish/vendor_completions.d/qg-trust.fish"
install -D -m 0644 "$here/crates/qso-graph-trust-cli/README.md" "$root/usr/share/doc/$name/README.md"
for f in LICENSE NOTICE AUTHORS; do install -D -m 0644 "$here/$f" "$root/usr/share/doc/$name/$f"; done

# .deb
deb="$work/deb"
cp -a "$root" "$deb"
mkdir -m 0755 "$deb/DEBIAN"
cat > "$deb/DEBIAN/control" <<CONTROL
Package: $name
Version: $pkg_version
Architecture: $deb_arch
Maintainer: QSO Graph contributors <maintainers@qso-graph.io>
Homepage: https://github.com/qso-graph/qso-graph-trust
Section: hamradio
Priority: optional
Description: $summary
 qg-trust signs your ADIF log for LoTW, byte for byte as TQSL signs it, and
 uploads it. Your certificates, keys and station locations are kept in QSO
 Graph's store, with each key in your computer's credential store. It takes
 TQSL's command-line options, so loggers can call it as they call tqsl.
CONTROL
find "$deb" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
deb_file="$out/$name-$version-linux-$deb_arch.deb"
dpkg-deb --root-owner-group -Zxz --build "$deb" "$deb_file" >/dev/null

# .rpm
top="$work/rpmbuild"
mkdir -p "$top/SPECS"
cat > "$top/SPECS/$name.spec" <<SPEC
%global debug_package %{nil}
%global __strip /bin/true
%global _build_id_links none
Name: $name
Version: $pkg_version
Release: 1
Summary: $summary
License: GPL-3.0-only
URL: https://github.com/qso-graph/qso-graph-trust
%description
qg-trust signs your ADIF log for LoTW, byte for byte as TQSL signs it, and
uploads it. Your certificates, keys and station locations are kept in QSO
Graph's store, with each key in your computer's credential store. It takes
TQSL's command-line options, so loggers can call it as they call tqsl.
%install
cp -a $root/. %{buildroot}/
%files
/usr/bin/qg-trust
/usr/share/bash-completion/completions/qg-trust
/usr/share/zsh/site-functions/_qg-trust
/usr/share/fish/vendor_completions.d/qg-trust.fish
%doc /usr/share/doc/$name
SPEC
rpmbuild --quiet --define "_topdir $top" --define "use_source_date_epoch_as_buildtime 1" \
  --define "clamp_mtime_to_source_date_epoch 1" --target "$rpm_arch" -bb "$top/SPECS/$name.spec" >/dev/null 2>&1 \
  || { rpmbuild --define "_topdir $top" --target "$rpm_arch" -bb "$top/SPECS/$name.spec" >&2; exit 1; }
rpm_file="$out/$name-$version-linux-$rpm_arch.rpm"
cp "$top"/RPMS/"$rpm_arch"/*.rpm "$rpm_file"

# Each is the program as built, under the name and version given.
[ "$(dpkg-deb -f "$deb_file" Package) $(dpkg-deb -f "$deb_file" Version) $(dpkg-deb -f "$deb_file" Architecture)" = "$name $pkg_version $deb_arch" ] \
  || { echo "The .deb is not $name $pkg_version $deb_arch" >&2; exit 1; }
[ "$(rpm -qp --qf '%{NAME} %{VERSION} %{ARCH}' "$rpm_file" 2>/dev/null)" = "$name $pkg_version $rpm_arch" ] \
  || { echo "The .rpm is not $name $pkg_version $rpm_arch" >&2; exit 1; }
cmp <(dpkg-deb --fsys-tarfile "$deb_file" | tar -xO ./usr/bin/qg-trust) "$exe" \
  || { echo "The .deb's qg-trust is not the program built" >&2; exit 1; }
cmp <(rpm2cpio "$rpm_file" | cpio -i --quiet --to-stdout ./usr/bin/qg-trust) "$exe" \
  || { echo "The .rpm's qg-trust is not the program built" >&2; exit 1; }
echo "$deb_file"
echo "$rpm_file"
