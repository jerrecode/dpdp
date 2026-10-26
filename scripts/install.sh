#!/usr/bin/env bash
# Build/install same C daemon on Debian and unrooted Android/Termux.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ACTION=${1:-help}; (($#==0)) || shift
IFACE=''; SSID=''; AUTOSTART=1; WIFI_SETUP=1; LINGER=1; YES=0
while (($#)); do
 case "$1" in
  --interface) IFACE=${2:?};shift 2;;
  --ssid) SSID=${2:?};shift 2;;
  --no-autostart) AUTOSTART=0;shift;;
  --no-wifi-config) WIFI_SETUP=0;shift;;
  --no-linger) LINGER=0;shift;;
  --yes) YES=1;shift;;
  -h|--help) ACTION=help;shift;;
  *) echo "Unknown argument: $1" >&2;exit 2;;
 esac
done
TERMUX=0;[[ ${PREFIX:-} == *com.termux* ]] && TERMUX=1
BIN="$HOME/.local/bin/dpdp"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/dpdp/config"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/dpdp"
log(){ printf '[dpdp install] %s\n' "$*"; }
need(){ command -v "$1" >/dev/null 2>&1; }
choose(){
 local caption=$1;shift;local choices=("$@") selected j=1
 ((${#choices[@]})) || return 1
 if ((${#choices[@]}==1));then printf '%s\n' "${choices[0]}";return;fi
 if [[ ! -t 0 ]];then log "Ambiguous $caption; specify --interface and --ssid" >&2;return 1;fi
 printf 'Choose %s:\n' "$caption" >&2
 for selected in "${choices[@]}";do printf '  %d. %s\n' "$j" "$selected" >&2;((j+=1));done
 read -r -p "Number [1-$((j-1))]: " selected
 [[ $selected =~ ^[0-9]+$ ]] && ((selected>=1 && selected<j)) || return 1
 printf '%s\n' "${choices[selected-1]}"
}
deps(){
 if ((TERMUX)); then
   if ! need termux-wifi-connectioninfo || ! need timeout;then
     log 'Installing Android API CLI and timeout for WLAN state monitoring'
     pkg install -y termux-api coreutils
   fi
 fi
 if need cc && need make && need pkg-config && pkg-config --exists json-c;then return;fi
 if ((TERMUX));then
   log 'Installing Termux clang, make, pkg-config, json-c and termux-api'
   pkg install -y clang make pkg-config json-c termux-api
 else
   if ((!YES)) && [[ -t 0 ]];then
      read -r -p 'Install build dependencies using sudo apt? [y/N] ' a
      [[ $a == [Yy] ]] || exit 1
   fi
   sudo apt-get update;sudo apt-get install -y build-essential pkg-config libjson-c-dev
 fi
}
find_iface(){
 [[ -n $IFACE ]] && return
 if ((TERMUX));then IFACE=wlan0;return;fi
 local usb=() other=() iface target
 for path in /sys/class/net/*;do
  [[ -d $path/wireless ]] || continue
  iface=${path##*/};target=$(readlink -f "$path/device" 2>/dev/null || :)
  [[ $target == *usb* ]] && usb+=("$iface") || other+=("$iface")
 done
 if ((${#usb[@]}==1));then IFACE=${usb[0]};log "Selected USB Wi-Fi adapter $IFACE";return;fi
 if ((${#usb[@]}+${#other[@]}==0));then
   log 'No wireless adapter detected; provide --interface IFACE --no-wifi-config' >&2;exit 2
 fi
 IFACE=$(choose 'Wi-Fi adapter' "${usb[@]}" "${other[@]}") || exit 2
}
phone_ssid(){
 ((TERMUX)) || return 0
 [[ -n $SSID ]] && return 0
 if need termux-wifi-connectioninfo;then
  SSID=$(termux-wifi-connectioninfo 2>/dev/null | sed -nE 's/^[[:space:]]*"ssid"[[:space:]]*:[[:space:]]*"([^"\\]*)".*/\1/p' | head -n 1 || :)
  [[ $SSID == '<unknown ssid>' || $SSID == 'unknown ssid' ]] && SSID=''
 fi
 if [[ -z $SSID ]];then
  if [[ -t 0 ]];then
    read -r -p 'Android target Wi-Fi SSID (required for safe discovery): ' SSID
  fi
  if [[ -z $SSID ]];then
    log 'Unable to determine required phone Wi-Fi SSID: pass --ssid NETWORK' >&2
    exit 2
  fi
 fi
}
select_profile(){
 need nmcli || { log 'NetworkManager unavailable; skipping Wi-Fi setup'; return 1; }
 local -a visible=() matches=()
 local row uuid type stored network
 while IFS= read -r network;do [[ -n $network ]] && visible+=("$network");done < <(nmcli -g SSID device wifi list ifname "$IFACE" --rescan yes 2>/dev/null || :)
 while IFS=: read -r uuid type;do
  [[ $type == *wireless* || $type == wifi ]] || continue
  stored=$(nmcli -g 802-11-wireless.ssid connection show uuid "$uuid" 2>/dev/null | head -1 || :)
  [[ -n $stored && ( -z $SSID || $stored == "$SSID" ) ]] || continue
  for network in "${visible[@]}";do
   [[ $network == "$stored" ]] && { matches+=("$uuid|$stored"); break; }
  done
 done < <(nmcli -t -f UUID,TYPE connection show 2>/dev/null || :)
 if ((${#matches[@]}==0));then log 'No reachable saved Wi-Fi connection found';return 1;fi
 row=$(choose 'reachable saved Wi-Fi profile (phone network)' "${matches[@]}") || return 1
 UUID=${row%%|*};SSID=${row#*|}
}
setup_wifi(){
 ((TERMUX==0 && WIFI_SETUP==1)) || return 0
 if ! select_profile;then
  log 'Wi-Fi setup skipped; connect the chosen adapter using NetworkManager first'
  return 0
 fi
 local name="dpdp-$IFACE-${UUID:0:8}"
 if ! nmcli -g NAME connection show | grep -Fxq "$name";then
  log "Cloning saved Wi-Fi profile as $name (no password extraction)"
  nmcli connection clone uuid "$UUID" "$name"
 fi
 # Clone to avoid changing Ethernet and existing user-managed Wi-Fi profiles.
 nmcli connection modify "$name" connection.interface-name "$IFACE" connection.autoconnect yes \
    ipv4.never-default yes ipv6.never-default yes ipv4.route-metric 2000 ipv6.route-metric 2000
 nmcli connection up "$name" ifname "$IFACE" || log 'Connection unavailable now; NetworkManager will retry'
 log 'Wi-Fi clone cannot replace the Ethernet default gateway'
}
config_write(){
 mkdir -p "$(dirname "$CONF")" "$STATE";chmod 700 "$(dirname "$CONF")" "$STATE"
 if [[ -f $CONF ]];then
  log "Existing $CONF preserved (edit this file for changed settings)";return
 fi
 local host;host=$(hostname | tr -cd '[:alnum:]._-')
 umask 077
 cat > "$CONF" <<EOT
# DPDP C discovery settings
interface=$IFACE
name=${host:-device}
expected_ssid=$SSID
registry=$STATE/peers.json
port=47981
announce_seconds=15
expiry_seconds=70
sleep_no_wifi_seconds=60
sleep_wrong_wifi_seconds=15
EOT
 log "Initialized $CONF"
}
autostart(){
 ((AUTOSTART)) || return 0
 if ((TERMUX));then
  mkdir -p "$HOME/.termux/boot"
  cat > "$HOME/.termux/boot/90-dpdp" <<EOT
#!${PREFIX}/bin/sh
exec '$BIN' run --config '$CONF' >> '$STATE/termux.log' 2>&1
EOT
  chmod 700 "$HOME/.termux/boot/90-dpdp"
  log 'Termux:Boot entry created. Install Termux:Boot and open it once; allow background processing.'
  log 'No permanent wake lock: Android may still suspend the process in Doze mode.'
 else
  if ! need systemctl;then log 'systemctl unavailable; configure startup manually';return 0;fi
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/dpdp.service" <<EOT
[Unit]
Description=Dynamic Peer Discovery Protocol
[Service]
Type=simple
ExecStart=$BIN run --config $CONF
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$STATE $(dirname "$CONF")
PrivateTmp=true
[Install]
WantedBy=default.target
EOT
  systemctl --user daemon-reload
  systemctl --user enable --now dpdp.service || log 'Could not start user systemd service; run systemctl --user status dpdp.service'
  if ((LINGER)) && need loginctl;then
   if sudo -n loginctl enable-linger "$(id -un)" 2>/dev/null;then
    log 'Enabled boot service without graphical login (linger)'
   elif [[ -t 0 ]];then
    sudo loginctl enable-linger "$(id -un)" || log 'Linger not enabled; starts at user login'
   else
    log 'For boot without login: sudo loginctl enable-linger USER'
   fi
  fi
 fi
}
case $ACTION in
 help) cat <<HELP
Usage: bash scripts/install.sh {install|build|update|diagnose|uninstall|help} [OPTIONS]
install: builds, detects USB Wi-Fi, uses saved reachable NM profile, enables startup
build: build only | update: fast-forward git update and reinstall
uninstall: removes binary and startup, preserves peers/config/identity
diagnose: read-only adapter, USB, profiles, routes, startup status
Options: --interface IFACE --ssid SSID --no-wifi-config --no-autostart --no-linger --yes
HELP
 ;;
 diagnose) exec bash "$ROOT/scripts/diagnose.sh";;
 build) deps; make -C "$ROOT" all;;
 install|update)
  if [[ $ACTION == update ]];then
   [[ -d $ROOT/.git ]] || { log 'Update requires git clone';exit 2; }
   git -C "$ROOT" pull --ff-only
  fi
  deps;make -C "$ROOT" all
  mkdir -p "$(dirname "$BIN")";install -m 0755 "$ROOT/build/dpdp" "$BIN"
  find_iface;phone_ssid;setup_wifi;config_write
  "$BIN" init --config "$CONF"
  autostart
  log "Done. Peer registry: $STATE/peers.json"
 ;;
 uninstall)
  if ((TERMUX));then rm -f "$HOME/.termux/boot/90-dpdp"
  elif need systemctl;then
   systemctl --user disable --now dpdp.service 2>/dev/null || :
   rm -f "$HOME/.config/systemd/user/dpdp.service"
   systemctl --user daemon-reload || :
  fi
  rm -f "$BIN";log 'Removed binary and autostart; preserved configuration and registry'
 ;;
 *)log "Invalid command $ACTION";exit 2;;
esac
