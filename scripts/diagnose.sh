#!/usr/bin/env bash
# Read-only network inventory; intentionally never print saved Wi-Fi secrets.
set -u
printf 'DPDP diagnostic | %s | %s\n' "$(date -u +%FT%TZ)" "$(uname -srm)"
printf '\nSYSTEM\n'; id
printf '\nNETWORK INTERFACES / USB / RADIO\n'
if [ -d /sys/class/net ]; then
  for dir in /sys/class/net/*; do
    iface=${dir##*/}; printf 'Interface: %s' "$iface"
    [ -d "$dir/wireless" ] && printf ' [wireless]'
    path=$(readlink -f "$dir/device" 2>/dev/null || :)
    [[ "$path" == *usb* ]] && printf ' [USB]'
    printf ' device=%s\n' "${path:-unknown}"
    [ -r "$dir/operstate" ] && printf '  operational_state=%s\n' "$(cat "$dir/operstate")"
  done
fi
command -v lsusb >/dev/null && lsusb || :
command -v ip >/dev/null && { ip -brief link; ip -brief address; ip route show; ip -6 route show; } || :
printf '\nNETWORKMANAGER (no secrets)\n'
if command -v nmcli >/dev/null; then
  nmcli -f DEVICE,TYPE,STATE,CONNECTION device status
  nmcli -f NAME,UUID,TYPE,DEVICE connection show
  nmcli -f IN-USE,SSID,MODE,SIGNAL,SECURITY device wifi list --rescan no || :
else printf 'nmcli not installed\n'; fi
printf '\nTERMUX (safe API report)\n'
if command -v termux-wifi-connectioninfo >/dev/null; then
  termux-wifi-connectioninfo 2>&1 | sed -E 's/("bssid"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"<redacted>"/'
else printf 'Termux Wi-Fi API command not installed\n'; fi
printf '\nSERVICE / ACCESS\n'
command -v systemctl >/dev/null && { systemctl --user is-enabled dpdp.service 2>&1 || :; systemctl --user is-active dpdp.service 2>&1 || :; } || :
command -v ss >/dev/null && ss -lun 2>/dev/null | grep ':47981\b' || :
printf '\nNo Wi-Fi passwords or tokens are included. Review IP addresses before sharing this report.\n'
