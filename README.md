# DPDP — Dynamic Peer Discovery Protocol

DPDP finds your Debian computer and Android/Termux phone on the same IPv4 LAN,
pairs them with a six-digit code, and verifies saved cryptographic identities when
their addresses change. No central discovery server or Internet connection is
required after installation. It provides native C discovery/pairing and uses
OpenSSH for persistent connections, SSH control, SFTP browsing, file transfer and
optional TCP forwarding.

**Status:** experimental cryptographic protocol integration, not an independently
audited product. Upgrade both devices before relying on pairing. Physical USB
Wi-Fi, Android Doze and background/multicast behavior still need device testing.
Names help you recognize devices; they never establish trust by themselves.

## Install on Debian

Run installation from your normal account. Do not run the whole installer as root.
It requests sudo only for dependency/service setup.

```sh
git clone https://github.com/jerrecode/dpdp.git
cd dpdp
bash scripts/install.sh diagnose
bash scripts/install.sh install --enable-ssh
```

`--enable-ssh` explicitly installs/enables the Debian SSH server and allows future
successful pairings to receive SSH/SFTP access to **your user account**. It does
not grant root or bypass sudo. Omit it for discovery/pairing without inbound SSH.
To enable later, rerun installation with this option, unpair and pair again so the
new SSH offer is exchanged.

The installer prefers a unique USB Wi-Fi adapter and reuses saved NetworkManager
credentials. Multiple choices require selection. It clones the selected profile
and sets IPv4/IPv6 `never-default` to preserve an existing Ethernet Internet route.
It does not invent missing Ethernet routing or change firewall rules. For explicit
selection or independently managed networking:

```sh
bash scripts/install.sh install --interface wlx0123456789ab --ssid 'YOUR_WIFI' --enable-ssh
bash scripts/install.sh install --interface wlan0 --no-wifi-config
```

The systemd user service starts at login, or at boot if linger is enabled. Verify
with `systemctl --user status dpdp.service` and `journalctl --user -u dpdp.service`.
Actual routing and DNS behavior must be checked on the physical machine.

## Install on Android / Termux

Use compatible Termux, Termux:API and Termux:Boot add-ons from the same signing
source. Open the add-ons once and grant Android's Wi-Fi/location permissions.

```sh
pkg install git
git clone https://github.com/jerrecode/dpdp.git
cd dpdp
bash scripts/install.sh install --ssid 'YOUR_WIFI' --enable-ssh
```

This installs native build/crypto tools and starts Termux's sshd on its standard
port **8022** when SSH was enabled. The boot entry restarts sshd and DPDP when
Termux:Boot and Android permit. On Debian the standard SSH port is **22**. No root
or permanent wake lock is required. Android storage and background restrictions
still apply; pairing does not expose files Termux cannot normally access.

If the Termux daemon is not already running, start it in a second Termux session:

```sh
"$HOME/.local/bin/dpdp" run
```

Or reboot after enabling Termux:Boot. Keep one daemon per configuration; the new
runtime rejects duplicate instances. **When upgrading the old pre-pairing Termux
version, stop that old process or reboot once** so it cannot continue its legacy
unauthenticated hook policy. Debian updates restart the systemd service.

Both devices need the same reachable LAN. AP client isolation, firewalls and
separate VLANs can prevent UDP discovery or the temporary TCP pairing connection.

## Pair once using the six-digit code

The boot daemon has no interactive terminal. Keep it running and open a terminal
on each device for the pairing assistant:

```sh
"$HOME/.local/bin/dpdp" pair-watch
```

On Debian, a newly discovered unpaired device causes a fresh **six-digit code** to
be displayed. On Termux, the assistant reports the new device and prompts you to
enter the code shown on your Debian screen. A window permits three connection
attempts and lasts at most 120 seconds. The code is temporary and is not sent over
the network; SPAKE2 authenticates a TLS 1.3 pairing channel. Public signing and SSH
keys are exchanged inside it with proofs bound to that channel.

You can instead pair one device explicitly. On Debian:

```sh
"$HOME/.local/bin/dpdp" pair-server
```

On Termux, use the discovered Debian name or full node ID:

```sh
"$HOME/.local/bin/dpdp" status
"$HOME/.local/bin/dpdp" pair my-debian
"$HOME/.local/bin/dpdp" paired
```

Leading zeroes in the code matter. Identical reported names are ambiguous: use the
full ID shown by `status` or `paired`. A known name with a different identity needs
pairing again. Incomplete enrollments stay pending and can be retried; a different
key can never silently overwrite an existing pinned identity. Key rotation to a
new node identity requires explicit new pairing; there is no automatic key rollover.

After pairing, press Ctrl+C to close the two assistants; discovery continues.

After pairing, the background daemons verify each other silently with fresh signed
challenges. `status` records `authenticated: true` only after a verified endpoint
response. Legacy discovery remains visible as unverified information; it cannot
launch hooks or overwrite an authenticated endpoint.

## SSH, files and filesystem access

Use the saved name or full ID after authenticated discovery. These helpers require
OpenSSH 9 or later and a running sshd with an SSH offer exchanged during pairing.
They pin the exchanged Ed25519 SSH host key and use a dedicated client key: no
password prompts, trust-on-first-use fallback or disabled host-key verification.

```sh
"$HOME/.local/bin/dpdp" ssh my-debian
"$HOME/.local/bin/dpdp" ssh my-debian -- uname -a
"$HOME/.local/bin/dpdp" sftp my-debian
"$HOME/.local/bin/dpdp" send my-debian ./photo.jpg /home/myuser/Pictures/photo.jpg
"$HOME/.local/bin/dpdp" receive my-debian /home/myuser/report.txt ./report.txt
"$HOME/.local/bin/dpdp" forward my-debian 8080:127.0.0.1:8080
```

SFTP opens an interactive filesystem browser/transfer prompt. Paths and permissions
are those of the paired account; Android shared storage may require
`termux-setup-storage`. This is not a root filesystem mount or unrestricted Android
storage access. Forwarding explicitly carries another TCP application through SSH;
DPDP does not implement that application's protocol.

The daemon starts at most eight managed SSH masters for peers offering SSH. Several
SSH/SFTP/file-transfer channels can share a master. Failed masters retry after 30
seconds. `auto_ssh=0` disables automatic masters while preserving explicit commands.
Each master is tied to the pinned identity and verified endpoint. Upon an IP change,
signed unicast hints to remembered peers accelerate a fresh challenge/response;
periodic multicast handles missed hints and simultaneous changes. A new master
replaces the old endpoint. **Existing TCP streams and active transfers cannot be
transparently migrated**; retry interrupted transfers/commands.

For independently configured sshd, explicitly publish its Ed25519 host public key
and port before pairing (the account name comes from your local user):

```sh
"$HOME/.local/bin/dpdp" access-init /etc/ssh/ssh_host_ed25519_key.pub 22
# Termux: use "$PREFIX/etc/ssh/ssh_host_ed25519_key.pub" and port 8022
```

`access-init` does not itself start sshd. Existing custom SSH configurations must
allow the selected account, Ed25519 keys, SFTP and any forwarding you need.

## Configuration, persistence and revocation

Default config: `~/.config/dpdp/config`; peer status:
`~/.local/state/dpdp/peers.json`. `XDG_CONFIG_HOME`/`XDG_STATE_HOME` are supported.

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
auto_ssh=1
```

UDP uses the configured port; foreground pairing temporarily listens on TCP
**port plus one**, bound to the selected interface address. Signed unicast traffic
explicitly selects that interface/source IP, including when Ethernet has a preferred
route. No pairing TCP listener runs in the boot daemon.

Termux verifies `expected_ssid` using Termux:API: no Wi-Fi retries every 60 seconds;
wrong/unverifiable SSID every 15 seconds; connected state checks every five seconds.
These are application sleep intervals, not guarantees of execution through Doze.
Debian binds the chosen adapter; SSID selection is managed by NetworkManager.

Files next to the config include `.id` (stable legacy node ID), `.signing.pem`
(private Ed25519 key), `.paired.json` (pinned public identities and SSH offers),
`.ssh`/`.ssh.pub` (dedicated SSH client key), and optional `.access.json` (local SSH
offer). Preserve these when updating/backing up; keep private files private. Pairing
and identity writes use cooperative locks, fsync and atomic rename. Existing peer
registry metadata and service definitions are retained.

```sh
"$HOME/.local/bin/dpdp" unpair my-phone
```

Unpairing revokes native discovery authorization, cancels pending enrollments,
removes DPDP-managed authorized_keys lines and requests closure of **local outbound**
DPDP SSH masters. Running/starting helpers recheck authorization every second while
scheduled and stop their SSH child if revoked or the verified endpoint changes.
It does **not** terminate already authenticated inbound sshd
connections or their channels: those sessions are managed by the external SSH
server and require separate server-side termination if immediate cutoff matters.
Revocation is therefore a ban on new authentication, not a universal session kill.

Updates preserve configuration. Uninstall preserves identities, pairings and SSH
settings; unpair devices first if you also want their managed SSH keys removed.
The independently enabled SSH server remains enabled; disable it separately if desired.

## Local service hooks

Within a peer object in `peers.json`, keep local-only definitions such as:

```json
{"trusted":true,"services":[{"name":"connector","enabled":true,"exec":"/absolute/path/to/connector","args":["--mode","client"]}]}
```

This is a peer-object fragment. Hooks require **both** current cryptographic
endpoint verification and a local boolean `trusted=true`. Executables are never
received from the network. Direct `execv` supplies `DPDP_PEER_ID`, `DPDP_PEER_NAME`,
`DPDP_PEER_IP`, and `DPDP_DISCOVERY_PORT`. Active hook children are capped at 32.
Hooks remain one-shot transition notifications, not fully supervised services;
make them idempotent. Cooperating editors must lock `<registry>.lock` and atomically
replace the file to avoid lost concurrent edits.

## Build, tests, updating and uninstalling

Debian dependencies: C11/C++17 compilers, make, CMake 3.22+, git, pkg-config,
json-c/GnuTLS development packages and OpenSSH. Termux equivalents are installed
by the installer. Python is used only by development tests, not the runtime.

The first build fetches a fixed BoringSSL commit and builds its static crypto
library for SPAKE2. This needs Internet once and takes longer than rebuilding DPDP.
The version is pinned in `scripts/build-pake.sh`; no cryptographic primitives are
implemented by DPDP. `make clean` retains the cached dependency build. GnuTLS and
json-c remain shared runtime dependencies; the C++ linker handles the upstream
static crypto library. Upstream license notices are retained in its build directory.

```sh
make
make unit-test
make test
make sanitize
make ssh-test        # optional Linux-only real sshd test; normal account + passwordless sudo
bash scripts/install.sh update
bash scripts/install.sh uninstall
```

Tests cover real PAKE/TLS exchanges, wrong code, wrong target, pending retry,
forged/replayed/stale endpoint proofs, name collisions, pinning/revocation, legacy
hook denial, SSH pin arguments/authorization cleanup, explicit unicast source IP,
real TCP pairing plus two-process UDP discovery, and an optional isolated loopback
sshd test for actual SSH/SFTP/file transfers in CI. ASan/UBSan instrument
DPDP and its test binaries; dependency libraries use their own upstream builds.

For read-only diagnosis:

```sh
bash scripts/install.sh diagnose > dpdp-diagnostics.txt 2>&1
```

Review IP addresses and device names before sharing. See `docs/ARCHITECTURE.md`,
`docs/PLAN.md` and `docs/HANDOFF.md` for protocol details and remaining work.

MIT license for DPDP; upstream dependency licenses remain their own.
