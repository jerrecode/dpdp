#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DPDP="$ROOT/build/dpdp"
TEMP=$(mktemp -d);PIDS=()
cleanup(){ for pid in "${PIDS[@]}";do kill "$pid" 2>/dev/null || :;done;wait 2>/dev/null || :;rm -rf "$TEMP"; }
trap cleanup EXIT
mkdir -p "$TEMP/a" "$TEMP/b"
for x in a b;do
 cat > "$TEMP/$x/config" <<CFG
interface=eth0
name=smoke-$x
registry=$TEMP/$x/peers.json
port=47981
announce_seconds=2
expiry_seconds=10
sleep_no_wifi_seconds=5
sleep_wrong_wifi_seconds=5
CFG
 "$DPDP" init --config "$TEMP/$x/config" >/dev/null
 [[ -f "$TEMP/$x/peers.json" ]] || exit 1
done
export DPDP_TEST_HOOK_MARKER="$TEMP/hook.log"
"$DPDP" run --config "$TEMP/a/config" >"$TEMP/a/log" 2>&1 & PIDS+=("$!")
"$DPDP" run --config "$TEMP/b/config" >"$TEMP/b/log" 2>&1 & PIDS+=("$!")
seen=0
for i in {1..12};do
 if grep -q '"name": "smoke-b"' "$TEMP/a/peers.json" && grep -q '"name": "smoke-a"' "$TEMP/b/peers.json";then seen=1;break;fi
 sleep 1
done
if ((seen==0));then
 echo 'No multicast loopback detection; diagnostic logs:' >&2
 cat "$TEMP/a/log" "$TEMP/b/log" >&2
 exit 1
fi
# Locally authorized hook should start once; the process receives peer IP in env.
cat > "$TEMP/hook.sh" <<'HOOK'
#!/bin/sh
printf '%s\n' "$DPDP_PEER_IP" >> "$DPDP_TEST_HOOK_MARKER"
HOOK
chmod +x "$TEMP/hook.sh"
export DPDP_TEST_HOOK_MARKER="$TEMP/hook.log"
# Modify a user-controlled section and ensure discovery refresh leaves it intact.
python3 - "$TEMP/a/peers.json" "$TEMP/hook.sh" <<'PY'
import json,sys
p=sys.argv[1]
o=json.load(open(p));peer=next(iter(o['peers'].values()))
peer['trusted']=True
peer['services']=[{'name':'example','exec':sys.argv[2],'args':[],'enabled':True}]
peer['custom']={'preserved':'yes'}
with open(p,'w') as f:json.dump(o,f)
PY
sleep 4
python3 - "$TEMP/a/peers.json" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]));p=next(iter(o['peers'].values()))
assert p['services'][0]['name']=='example', p
assert p['custom']['preserved']=='yes', p
assert p['online'] is True, p
print('OK: discovery, identity, atomic registry and preservation')
PY
test -f "$TEMP/hook.log"
test "$(wc -l < "$TEMP/hook.log")" -eq 1
printf 'OK: trusted local service launched exactly once with peer IP\n'
