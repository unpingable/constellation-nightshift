#!/usr/bin/env bash
# Assemble constellation-nightshift_VERSION_ARCH.deb from release binaries.
# Usage: packaging/build-deb.sh VERSION ARCH BIN_DIR OUT_DIR
set -euo pipefail; export LC_ALL=C TZ=UTC; umask 022
[[ $# -eq 4 ]] || { echo "usage: $0 VERSION ARCH BIN_DIR OUT_DIR" >&2; exit 2; }
version=$1 arch=$2 bin_dir=$(cd "$3" && pwd -P) out_dir=$4
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
for b in nightshift nightshift-observation-resolver; do [[ -x "$bin_dir/$b" ]] || { echo "missing binary $b" >&2; exit 2; }; done
"$bin_dir/nightshift" --help >/dev/null
mkdir -p "$out_dir"; stage=$(mktemp -d "$out_dir/.stage.XXXXXX"); trap 'rm -rf "$stage"' EXIT
d=$stage/constellation-nightshift_${version}_${arch}
install -d -m 0755 "$d/DEBIAN" "$d/usr/bin" "$d/lib/systemd/system" "$d/usr/share/doc/constellation-nightshift"
install -m 0755 "$bin_dir/nightshift" "$bin_dir/nightshift-observation-resolver" "$d/usr/bin/"
install -m 0644 "$root/packaging/systemd/nightshift-observation-cycle.service" "$root/packaging/systemd/nightshift-observation-cycle.timer" "$d/lib/systemd/system/"
install -m 0644 "$root/deploy/systemd/observation-cycle.env.example" "$root/deploy/systemd/README.md" "$d/usr/share/doc/constellation-nightshift/"
sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" "$root/packaging/debian/control.in" > "$d/DEBIAN/control"
for s in postinst prerm postrm; do install -m 0755 "$root/packaging/debian/$s" "$d/DEBIAN/$s"; done
find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$d" "$out_dir/constellation-nightshift_${version}_${arch}.deb" >/dev/null
( cd "$out_dir" && sha256sum "constellation-nightshift_${version}_${arch}.deb" > "constellation-nightshift_${version}_${arch}.deb.sha256" )
echo "built $out_dir/constellation-nightshift_${version}_${arch}.deb"
