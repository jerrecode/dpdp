#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TEMP=$(mktemp -d)
PID=''
cleanup(){ [[ -z $PID ]] || { kill "$PID" 2>/dev/null || :;wait "$PID" 2>/dev/null || :; };rm -rf "$TEMP"; }
trap cleanup EXIT
mkdir -p "$TEMP/bin"
cat > "$TEMP/bin/termux-wifi-connectioninfo" <<'API'
#!/bin/sh
cat "$DPDP_FAKE_WIFI"
API
chmod +x "$TEMP/bin/termux-wifi-connectioninfo"
IFACE=${DPDP_TEST_IFACE:-}
if [[ -z $IFACE ]] && command -v ip >/dev/null;then
 IFACE=$(ip -o -4 addr show up | awk '$2!="lo"{print $2;exit}')
fi
[[ -n $IFACE ]] || { echo 'SKIP: no IPv4 interface for platform sleep-state test';exit 0; }
cat > "$TEMP/config" <<CFG
interface=$IFACE
name=mock-termux
expected_ssid=correct-ssid
registry=$TEMP/peers.json
port=47981
announce_seconds=2
expiry_seconds=10
sleep_no_wifi_seconds=60
sleep_wrong_wifi_seconds=15
CFG
for state in missing wrong correct;do
 case "$state" in
 missing) printf '{"ssid":"<unknown ssid>"}\n' > "$TEMP/wifi";want='no Wi-Fi/IP';;
 wrong) printf '{"ssid":"another-ssid"}\n' > "$TEMP/wifi";want='wrong SSID';;
 correct) printf '{"ssid":"correct-ssid"}\n' > "$TEMP/wifi";want=connected;;
 esac
 PREFIX="$TEMP/com.termux/files/usr" DPDP_FAKE_WIFI="$TEMP/wifi" PATH="$TEMP/bin:$PATH" \
 "$ROOT/build/dpdp" run --config "$TEMP/config" > "$TEMP/$state.log" 2>&1 & PID=$!
 sleep 2
 kill "$PID" 2>/dev/null || :
 wait "$PID" 2>/dev/null || :
 PID=''
 if ! grep -Fq "network state: $want" "$TEMP/$state.log";then
   echo "FAIL mock Termux state $state" >&2;cat "$TEMP/$state.log" >&2;exit 1
 fi
done
printf 'OK: Termux API mock distinguishes missing, wrong, correct Wi-Fi SSID\n'