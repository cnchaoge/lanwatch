#!/bin/sh
# Rebuild the Wi-Fi helper only when its source is newer than the binary.
cd "$(dirname "$0")/.." || exit 0
src="src-tauri/resources/wifi-helper.swift"
out="src-tauri/resources/wifi-helper"
if [ -x "$out" ] && [ "$out" -nt "$src" ]; then
  exit 0
fi
swiftc -O -framework CoreWLAN -o "$out" "$src" || echo '[warn] wifi-helper build failed; Wi-Fi signal will be limited'
