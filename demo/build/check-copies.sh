#!/usr/bin/env bash
# The ACU and Reader folders each carry their own copy of the shared code, so that each
# folder builds on its own. This check fails if the copies have drifted apart.
# Usage (from the demo folder):   ./build/check-copies.sh
# After changing shared code in one folder, copy it to the other, for example:
#   cp -r AcuSimulator/Hpsp.Core/. ReaderSimulator/Hpsp.Core/
set -euo pipefail
cd "$(dirname "$0")/.."
status=0
for part in Hpsp.Core Hpsp.Demo.Ui Tests; do
  if ! diff -r -q -x bin -x obj "AcuSimulator/$part" "ReaderSimulator/$part"; then
    echo "DIFFERENT: AcuSimulator/$part and ReaderSimulator/$part"
    status=1
  fi
done
[ $status -eq 0 ] && echo "Shared code is identical in both folders."
exit $status
