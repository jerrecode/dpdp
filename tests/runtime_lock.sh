#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TEMP=$(mktemp -d);PID=''
cleanup(){ [[ -z $PID ]] || { kill "$PID" 2>/dev/null || :;wait "$PID" 2>/dev/null || :; };rm -rf "$TEMP"; }
trap cleanup EXIT
cat > "$TEMP/config" <<CFG
interface=absent-test
name=lock-test
registry=$TEMP/peers.json
CFG
PREFIX='' "$ROOT/build/dpdp" run --config "$TEMP/config" > "$TEMP/first.log" 2>&1 & PID=$!
for i in {1..100};do
 grep -q 'started: lock-test' "$TEMP/first.log" && break
 kill -0 "$PID" 2>/dev/null || { cat "$TEMP/first.log";exit 1; }
 sleep 0.05
done
if PREFIX='' "$ROOT/build/dpdp" run --config "$TEMP/config" > "$TEMP/second.log" 2>&1;then
 echo 'FAIL: duplicate runtime accepted';exit 1
fi
grep -q 'daemon already running' "$TEMP/second.log"
kill -0 "$PID"
kill "$PID";wait "$PID";PID=''
printf 'OK: one runtime per configuration, lock does not terminate existing instance\n'
