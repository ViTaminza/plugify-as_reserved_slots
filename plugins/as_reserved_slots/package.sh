#!/bin/bash
# Assembles build/package/as_reserved_slots: the library and manifest from build/, everything else from dist/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT="$ROOT/build/package/as_reserved_slots"
rm -rf "$OUT"
mkdir -p "$OUT/bin"
cp "$ROOT/build/plugins/as_reserved_slots/libas_reserved_slots.so" "$OUT/bin/"
cp "$ROOT/build/plugins/as_reserved_slots/as_reserved_slots.pplugin" "$OUT/"
if [ -d "$HERE/dist" ]; then cp -r "$HERE/dist/." "$OUT/"; fi
echo "package: $OUT"
