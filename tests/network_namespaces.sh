#!/usr/bin/env bash
# Optional privileged Linux test. All network changes stay in temporary namespaces.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DPDP="$ROOT/build/dpdp"
TEMP=$(mktemp -d)
TEST_USER=$(id -un)
NSA="dpdp-a-$$";NSB="dpdp-b-$$"
cleanup(){
 for ns in "$NSA" "$NSB";do
  pids=$(sudo -n ip netns pids "$ns" 2>/dev/null || :)
  [[ -z $pids ]] || sudo -n kill $pids 2>/dev/null || :
  sudo -n ip netns delete "$ns" 2>/dev/null || :
 done
 rm -rf "$TEMP"
}
trap cleanup EXIT
sudo -n ip netns add "$NSA"
sudo -n ip netns add "$NSB"
sudo -n ip link add dpa-$$ type veth peer name dpb-$$
sudo -n ip link set dpa-$$ netns "$NSA"
sudo -n ip link set dpb-$$ netns "$NSB"
for side in a b;do
 [[ $side == a ]] && ns=$NSA && link=dpa-$$ && address=10.77.0.1 || { ns=$NSB;link=dpb-$$;address=10.77.0.2; }
 sudo -n ip -n "$ns" link set "$link" name eth0
 sudo -n ip -n "$ns" address add "$address/24" dev eth0
 sudo -n ip -n "$ns" link set lo up
 sudo -n ip -n "$ns" link set eth0 up
 sudo -n ip -n "$ns" route add 224.0.0.0/4 dev eth0
 mkdir -p "$TEMP/$side"
 cat > "$TEMP/$side/config" <<CFG
interface=eth0
name=namespace-$side
registry=$TEMP/$side/peers.json
announce_seconds=2
expiry_seconds=10
auto_ssh=0
CFG
 "$DPDP" init --config "$TEMP/$side/config" >/dev/null
 sudo -n ip netns exec "$ns" runuser -u "$TEST_USER" -- env HOME="$TEMP/$side" DPDP_TEST_HOOK_MARKER="$TEMP/hook.log" \
  "$DPDP" run --config "$TEMP/$side/config" > "$TEMP/$side/log" 2>&1 &
done
wait_state(){
 local a_ip=$1 b_ip=$2 auth=$3
 for i in {1..160};do
  if python3 - "$TEMP" "$a_ip" "$b_ip" "$auth" <<'PY' 2>/dev/null
import json,sys
from pathlib import Path
root=Path(sys.argv[1]);ips=[sys.argv[3],sys.argv[2]];auth=sys.argv[4]=='yes'
for side,ip in zip(('a','b'),ips):
 peers=list(json.loads((root/side/'peers.json').read_text())['peers'].values())
 assert len(peers)==1 and peers[0]['ip']==ip and peers[0]['online'] is True
 if auth: assert peers[0]['authenticated'] is True
PY
  then return;fi
  sleep 0.1
 done
 cat "$TEMP/a/log" "$TEMP/b/log" >&2
 echo "FAIL: namespace discovery/verification $a_ip $b_ip $auth" >&2;exit 1
}
wait_state 10.77.0.1 10.77.0.2 no
cat > "$TEMP/hook.sh" <<'HOOK'
#!/bin/sh
printf '%s\n' "$DPDP_PEER_IP" >> "$DPDP_TEST_HOOK_MARKER"
HOOK
chmod +x "$TEMP/hook.sh"
python3 - "$TEMP" <<'PY'
import fcntl,json,os,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]);p=root/'a/peers.json'
with open(str(p)+'.lock','a+') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX);data=json.loads(p.read_text());peer=next(iter(data['peers'].values()))
 peer.update(trusted=True,custom={'preserved':'yes'},services=[{'name':'hook','exec':str(root/'hook.sh'),'enabled':True,'args':[]}])
 with tempfile.NamedTemporaryFile('w',dir=p.parent,delete=False) as out:
  json.dump(data,out);out.flush();os.fsync(out.fileno());name=out.name
 os.replace(name,p)
PY
DPDP_CLIENT_NS="$NSA" DPDP_SERVER_NS="$NSB" python3 "$ROOT/tests/pair_cli.py" "$DPDP" "$TEMP/a/config" "$TEMP/b/config" namespace-b
wait_state 10.77.0.1 10.77.0.2 yes
for i in {1..30};do [[ -f "$TEMP/hook.log" ]] && break;sleep 0.1;done
[[ $(wc -l < "$TEMP/hook.log") == 1 ]]
sudo -n ip -n "$NSA" address delete 10.77.0.1/24 dev eth0
sudo -n ip -n "$NSA" address add 10.77.0.3/24 dev eth0
wait_state 10.77.0.3 10.77.0.2 yes
sudo -n ip -n "$NSA" address delete 10.77.0.3/24 dev eth0
sudo -n ip -n "$NSB" address delete 10.77.0.2/24 dev eth0
sudo -n ip -n "$NSA" address add 10.77.0.5/24 dev eth0
sudo -n ip -n "$NSB" address add 10.77.0.6/24 dev eth0
wait_state 10.77.0.5 10.77.0.6 yes
python3 - "$TEMP/a/peers.json" <<'PY'
import json,sys
peer=next(iter(json.load(open(sys.argv[1]))['peers'].values()))
assert peer['custom']=={'preserved':'yes'} and peer['trusted'] is True and peer['services'][0]['name']=='hook'
PY
printf 'OK: distinct-IP mutual pairing/proofs, authenticated hook, one-sided and simultaneous address changes\n'
