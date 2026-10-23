#!/bin/sh
# Builds the Hyprland plugin for the installed Hyprland (its headers and build ID).
#   omastation-plugin-build [SOURCE_DIR [OUTPUT]]
# Environment: HYPRLAND (default /usr/bin/Hyprland), CXX.
set -eu
src=${1:-/usr/share/omastation/plugin}
out=${2:-/usr/lib/omastation/omastation-plugin.so}
hyprland=${HYPRLAND:-/usr/bin/Hyprland}

id=$(LC_ALL=C readelf -n "$hyprland" 2>/dev/null | sed -n 's/^ *Build ID: *\([0-9a-f]*\)$/\1/p' | head -n 1)
if [ -z "$id" ]; then
	echo "omastation-plugin-build: no GNU build ID in $hyprland" >&2
	exit 1
fi

# Without STB_GNU_UNIQUE symbols glibc can unmap the plugin on unload.
cxx=${CXX:-g++}
nounique=
if echo 'int x;' | $cxx -x c++ -fno-gnu-unique -fsyntax-only - 2>/dev/null; then nounique=-fno-gnu-unique; fi

# Renamed over the output so a running Hyprland keeps the old file mapped.
tmp=$(mktemp "$(dirname "$out")/.omastation-plugin.XXXXXX")
trap 'rm -f "$tmp"' EXIT
# shellcheck disable=SC2046 # pkg-config's flags are words
$cxx -std=c++26 -O2 -fPIC -shared $nounique -o "$tmp" \
	-DOMASTATION_HYPRLAND_BUILD_ID="\"$id\"" \
	"$src/omastation-plugin.cpp" $(pkg-config --cflags hyprland)
chmod 0755 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
echo "omastation-plugin-build: $out for Hyprland $(pkg-config --modversion hyprland 2>/dev/null || echo '?') (build $id)"
