# DPDP — Dynamic Peer Discovery Protocol

A small, decentralized **C** daemon for recognizing machines on the same IPv4 multicast-capable LAN despite DHCP address changes. Built for **Debian Linux** and **Android/Termux** with no root requirement for discovery. Each node is symmetric: it sends discovery messages, responds to queries, and maintains a local peer registry. No coordinator or Internet service is required for peer discovery.

> **Maturity:** early functional release, **not a secure authentication protocol**. Test on trusted LANs first. The implementation currently supports IPv4 only. Android background scheduling, Wi-Fi multicast delivery, and NetworkManager integration depend on the device, permissions and AP settings.

## How it works

- Every installation gets a random 128-bit persistent node ID, stored as `<config file>.id` (mode 0600). Concurrent initializers use an advisory `<config file>.id.lock` to agree on one ID. Existing invalid or unreadable identities are preserved and initialization fails for operator recovery. That ID, **not a DHCP address**, is the peer identity.
- DPDP periodically multicasts short query/announcement messages to `239.255.77.81:47981` (TTL 1). Queries are answered with unicast announcements. Responses are processed only on the selected network interface using Linux `IP_PKTINFO`. The IP address in the registry comes from the actual UDP packet source, not untrusted payload text.
- A changing interface address causes the daemon to reopen its bound discovery socket and announce again. Periodic discovery also recovers after **both peers** change addresses simultaneously.
- Peers become offline when no packets arrive for the configured timeout. The registry retains their identity, last endpoint, and **all locally edited metadata**.
- `peers.json` is updated via an advisory lock, a same-directory temporary file, `fsync`, and atomic rename. The daemon re-reads the existing registry before every write, preserving `services`, `trusted` and custom peer fields. Applications should use the lock file when modifying the registry concurrently; uncoordinated editors can otherwise lose a simultaneous edit.
- Optional executable service hooks run **once per peer/endpoint transition within a daemon session**. Only locally configured, explicitly `trusted` peers can trigger them. The wire protocol has **no command-execution field**. Commands use direct `execv`, not a shell; local service scripts can connect or exchange data using environment variables.

## Download

```sh
git clone https://github.com/jerrecode/dpdp.git
cd dpdp
```

You need an IP LAN where peers can deliver UDP multicast/unicast to each other. Access-point client isolation, firewalls and separate VLANs can prevent discovery even when SSIDs look identical.

## Debian installation

Run from **your own account**, not under `sudo` (the installer requests elevated privileges only when needed).

```sh
bash scripts/install.sh diagnose  # read-only: adapters, USB, routes, saved Wi-Fi profile names
bash scripts/install.sh install
```

The installer builds the C program, prefers the **USB Wi-Fi adapter**, offers an adapter picker when necessary, scans the Wi-Fi networks, and matches them against **existing NetworkManager profiles**. It will auto-select a unique matching profile or ask you to choose among several. It does **not extract saved passwords** or attempt to guess the phone's SSID. If there are multiple matches, select the SSID your phone uses. For an explicit selection:

```sh
bash scripts/install.sh install --interface wlx0123456789ab --ssid 'PHONE_WIFI_SSID'
```

For the selected saved network it **clones** the NetworkManager profile into `dpdp-IFACE-UUID`, binds the clone to the selected Wi-Fi adapter, enables autoconnect, and sets both `ipv4.never-default` and `ipv6.never-default`. This prevents the Wi-Fi connection becoming the default Internet route; the existing wired Ethernet route remains unchanged. If Ethernet does not already have a working default route, the installer cannot create one safely without knowing your network. Check `ip route` and adjust your Ethernet profile if needed.

If NetworkManager is not managing the Wi-Fi adapter, the installer skips Wi-Fi configuration; configure your Wi-Fi independently. Use `--no-wifi-config` to leave all NetworkManager profiles untouched. Non-interactive installations with ambiguous choices require explicit `--interface`/`--ssid`.

On Debian the user service is `~/.config/systemd/user/dpdp.service`. The installer enables and starts it. It tries to enable systemd **linger** (via `sudo loginctl enable-linger USER`) so it starts without a desktop login, otherwise it starts when the user session starts.

```sh
systemctl --user status dpdp.service
journalctl --user -u dpdp.service -f
systemctl --user restart dpdp.service
```

## Android / Termux installation

Install Termux from a compatible source, alongside **Termux:API** and **Termux:Boot** from the same signing ecosystem. Launch the two Android add-ons at least once and grant the required location / Wi-Fi permissions. Then in Termux:

```sh
pkg install git
termux-wifi-connectioninfo   # verifies API accessibility and current SSID
# clone the repository as shown above
bash scripts/install.sh install --ssid 'PHONE_WIFI_SSID'
```

The installer can detect the current SSID from `termux-wifi-connectioninfo`; if Android hides the SSID, pass it explicitly with `--ssid`. **An expected SSID is required for safe Termux installation.** A `~/.termux/boot/90-dpdp` script starts DPDP after Android boot once Termux:Boot is configured and the OS permits it. No root required.

Termux uses the Android `termux-wifi-connectioninfo` API to distinguish:

| Network state | Default reconnection check | Discovery behavior |
|---|---:|---|
| No Wi-Fi IP / no connection | Every 60 s | No packets sent |
| Connected to a different SSID | Every 15 s | No packets sent |
| Correct Wi-Fi SSID | Every 5 s | Listen continuously while Android schedules Termux; send discovery every 15 s |
| SSID API unavailable | Every 15 s | Fail closed: no packets sent |

All sleep durations are configurable in the config file. **Important:** These are daemon *polling/sleep intervals*, **not an Android AlarmManager wake-up guarantee**. Without a persistent wake-lock the OS may defer or suspend background work. We intentionally avoid an always-on wake-lock by default to reduce battery usage. Adjust Android battery restrictions if continuous availability matters more than battery life. Termux cannot silently switch the phone to a saved Wi-Fi network on modern unrooted Android; reconnection is handled by Android.

## Configuration / manual operation

Default config: `~/.config/dpdp/config`; default registry: `~/.local/state/dpdp/peers.json`. Environment variables `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are supported. Key settings:

```ini
interface=wlan0
name=my-phone
expected_ssid=MyHomeWiFi
registry=/absolute/path/to/peers.json
port=47981
announce_seconds=15
expiry_seconds=70
sleep_no_wifi_seconds=60
sleep_wrong_wifi_seconds=15
```

`expected_ssid` enforcement is implemented on Termux using Termux:API. On Debian the installer selects the saved Wi-Fi profile; the daemon binds to the interface but does **not** independently verify the SSID. Restrict your NetworkManager clone to the intended profile if necessary. Config values have straightforward `key=value` syntax (not shell commands; no quoting/escaping). Restart after editing.

```sh
~/.local/bin/dpdp init
~/.local/bin/dpdp run --config "$HOME/.config/dpdp/config" --debug
~/.local/bin/dpdp status
```

## Peer registry and external services

The registry is automatically created, even with no peers. After discovery, it looks like:

```json
{
  "schema_version": 1,
  "peers": {
    "my-phone": {
      "id": "00112233445566778899aabbccddeeff",
      "name": "my-phone",
      "ip": "192.168.1.42",
      "online": true,
      "last_seen_unix": 1790000000,
      "trusted": false,
      "services": []
    }
  }
}
```

Peer keys normally match peer-advertised names. If names collide, DPDP adds the full identity as a suffix and, if necessary, a numeric suffix to select a free key. Existing keys are labels, never authorization identifiers. Names can change; IDs remain stable. If you edit the registry, do not change IDs or the machine-managed `name`, `ip`, `online`, and `last_seen_unix` fields. Add services like:

```json
"trusted": true,
"services": [
  {
    "name": "my-local-connector",
    "enabled": true,
    "exec": "/home/myuser/bin/connect-to-peer",
    "args": ["--mode", "client"]
  }
]
```

This is a **fragment inside one peer object**, not a complete JSON document. `exec` must be an **absolute executable path**. Up to 16 enabled/disabled service definitions are inspected per peer, with at most 24 explicit arguments each. An executable receives `DPDP_PEER_ID`, `DPDP_PEER_NAME`, `DPDP_PEER_IP` and `DPDP_DISCOVERY_PORT` as environment variables. Its network application protocol and TCP/UDP ports are the responsibility of that service. A service starts when its peer is seen online and trusted; an IP change can trigger another launch. DPDP does **not** supervise child services or guarantee exactly-once execution across daemon restarts. Design hooks to be idempotent and to handle reconnects; a service can run as a persistent process if it manages its own lifecycle.

A service will not execute just because a stranger advertises an ID. You must manually authorize that ID with `trusted=true` and add an executable; **however, the current wire messages are unauthenticated and can be spoofed on a hostile LAN**, even for a trusted ID. Avoid dangerous hooks until cryptographic mutual authentication is implemented.

Editing `peers.json` by writing a replacement in place can race with the daemon. For safe automation, obtain an exclusive `flock` on `<registry>.lock`, read/modify the JSON object, write a same-directory temporary file, flush, rename atomically, release the lock. DPDP itself uses this procedure. To share discovery state with applications, watch or parse this JSON file, or consume your own service's environment variables.

## Build, test, update and uninstall

```sh
make                 # C compiler, make, pkg-config and json-c required
make unit-test       # registry, identity concurrency and packet parsing; no network required
make test            # two local daemon processes plus mocked Android SSID states; requires Python 3 for registry assertions
make sanitize        # ASan/UBSan build of daemon AND tests, then full suite
bash scripts/install.sh update           # git pull --ff-only + rebuild + reinstall
bash scripts/install.sh uninstall        # preserves config, identity, peer registry
```

Build dependencies: Debian `build-essential pkg-config libjson-c-dev`; Termux `clang make pkg-config json-c`. Installer offers to install missing dependencies. Runtime dependency: `json-c`. Termux CLI `termux-api` additionally requires the Android Termux:API app and permissions.

## Limitations / security

**This version does not support** IPv6 discovery, mDNS/DNS-SD service advertisement, encryption, cryptographic peer verification, AP isolation traversal, routing across subnets, robust kernel netlink event subscriptions, privilege-separated hook execution, authenticated remote service handshakes, or true Android suspend-resilient wake scheduling. The protocol is intentionally confined to IPv4 link-local multicast scope (TTL=1). `online` means *recently heard*, not cryptographically authenticated or proof that an arbitrary downstream service is accepting connections. Do not automatically open firewall ports, change the Ethernet default route or trust discovered peers. Service hooks must be treated as privileged local configuration.

Read `docs/ARCHITECTURE.md` and `docs/PLAN.md` for design choices and outstanding production hardening.

## License

MIT License, see [LICENSE](LICENSE).
