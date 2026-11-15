#!/usr/bin/env bash
# Make the release zips: self-contained, single-file .exe files for x64 and Arm64 Windows.
# Usage (from the demo folder):   ./build/publish.sh
# Needs the .NET 8 SDK. Works on Linux, macOS and Windows (Git Bash).
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(pwd)/artifacts"
mkdir -p "$out"
for rid in win-x64 win-arm64; do
  dir="$out/HPSP-Demo-$rid"
  mkdir -p "$dir"
  for app in HpspAcuSimulator HpspReaderSimulator; do
    dotnet publish "src/$app" -c Release -r "$rid" --self-contained true -p:PublishSingleFile=true -o "$dir"
  done
  find "$dir" -name '*.pdb' -delete
  cp ../RUNNING.md ../RUNNING.fr.md "$dir/"
  cp ../LICENSE "$dir/LICENSE.txt"
  (cd "$out" && zip -qr -9 "HPSP-Demo-$rid.zip" "HPSP-Demo-$rid")
done
echo "Made: $out/HPSP-Demo-win-x64.zip and $out/HPSP-Demo-win-arm64.zip"
