#!/usr/bin/env bash
# Immutable upstream crypto implementation. No global installation or shared ABI.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
REV=e651545da6e26e1f4420723a3b69a78ed1b9c51d
SOURCE="$ROOT/build/vendor/boringssl-src"
OUT="$ROOT/build/vendor/boringssl"
mkdir -p "$ROOT/build/vendor"
exec 9>"$ROOT/build/vendor/pake-build.lock"
flock 9
if [[ ! -d $SOURCE/.git ]]; then
 git init -q "$SOURCE"
 git -C "$SOURCE" remote add origin https://github.com/google/boringssl.git
fi
if [[ $(git -C "$SOURCE" rev-parse HEAD 2>/dev/null || :) != "$REV" ]]; then
 git -C "$SOURCE" fetch --depth 1 origin "$REV"
 git -C "$SOURCE" checkout --detach "$REV"
fi
[[ $(git -C "$SOURCE" rev-parse HEAD) == "$REV" ]]
cmake -S "$SOURCE" -B "$OUT" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build "$OUT" --target crypto -j "${DPDP_BUILD_JOBS:-2}"
cp "$SOURCE/LICENSE" "$OUT/LICENSE"
