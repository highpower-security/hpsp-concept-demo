#!/usr/bin/env bash
# Make the release zips: self-contained, single-file .exe files for x64 and Arm64 Windows.
# Usage (from the demo folder):   ./build/publish.sh <build number>     e.g.  ./build/publish.sh 3
# The zips are named HPSP-Demo-<version>-build<n>-<win-x64|win-arm64>.zip, so every build
# can be told apart. Raise the build number for each new set you hand out.
# Needs the .NET 8 SDK. Works on Linux, macOS and Windows (Git Bash).
set -euo pipefail
build="${1:?give a build number, e.g. ./build/publish.sh 3}"
cd "$(dirname "$0")/.."
version="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' src/HpspAcuSimulator/HpspAcuSimulator.csproj)"
name="HPSP-Demo-$version-build$build"
out="$(pwd)/artifacts"
mkdir -p "$out"
for rid in win-x64 win-arm64; do
  dir="$out/$name-$rid"
  mkdir -p "$dir"
  for app in HpspAcuSimulator HpspReaderSimulator; do
    dotnet publish "src/$app" -c Release -r "$rid" --self-contained true -p:PublishSingleFile=true -o "$dir"
  done
  find "$dir" -name '*.pdb' -delete
  cp ../RUNNING.md ../RUNNING.fr.md "$dir/"
  cp ../LICENSE "$dir/LICENSE.txt"
  (cd "$out" && zip -qr -9 "$name-$rid.zip" "$name-$rid")
done
echo "Made: $out/$name-win-x64.zip and $out/$name-win-arm64.zip"
