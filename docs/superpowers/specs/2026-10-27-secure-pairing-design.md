# Six-digit pairing, authenticated discovery and SSH access

User request: recognize names, pair Termux to Debian using a six-digit code shown
on Debian, reconnect automatically by cryptographic identity, send signed endpoint
updates, and provide file transfer, filesystem browsing and SSH control.
Technical decisions below are maintainer choices under the user's autonomous
implementation authorization, not additional user-provided requirements.

## Approach

Use upstream BoringSSL SPAKE2 through a small C API bridge, statically linked at
pinned commit e651545da6e26e1f4420723a3b69a78ed1b9c51d. Use its 64-byte high-entropy
result as an external TLS 1.3 PSK in GnuTLS. The six-digit code is never sent or used
as a raw TLS PSK. Each explicit pairing window lasts at most 120 seconds / three
attempts; handshake and application exchange have an absolute ten-second deadline.
The library performs PAKE and TLS primitives; DPDP implements bounded orchestration.
This replaces the initially investigated TLS-SRP route: SRP is disabled in current
GnuTLS defaults and Termux OpenSSL explicitly builds with no-srp. Do not enable
legacy TLS/CBC as a workaround. BoringSSL adds a CMake/C++ build dependency but no
new shared crypto ABI; the runtime remains a C program using maintained libraries.

Exchange native Ed25519 signing public keys and bind node IDs/names inside that
channel, with proof of private-key possession bound to the TLS exporter. Persist
pairings atomically with cooperative locking. Names are mutable display labels;
known names with different IDs or keys require new explicit pairing. Existing keys
cannot be overwritten through automatic discovery. Provide explicit revocation.

Keep random legacy node IDs for compatibility. Add signed v2 discovery challenges
and responses; accept a paired endpoint only after a fresh locally issued nonce
is echoed and its signature verified. Signed IP-change hints unicast to each last
known paired address and multicast as fallback. A hint starts endpoint verification;
it never directly authorizes services. Source IP metadata defines the endpoint.
Old v1 traffic remains visible as unverified discovery but cannot launch hooks.
No timestamp synchronization is required. Bound packet size, challenge lifetime,
response rate, peers and work per packet. Reload pairing records for revocation.

Reuse OpenSSH for encrypted application traffic. Dedicated SSH client keys and
pinned SSH server host keys are exchanged during pairing. Keep host checking strict;
never use accept-new or disable verification. Explicit local access setup selects
which SSH host key/port/account to offer. Pairing grants user-account access only
when SSH access was explicitly configured. Both directions work when both devices
run sshd. SFTP gives filesystem browsing within each account's OS permissions;
Android storage restrictions remain in effect. A stable ControlMaster supports
multiple SSH/SFTP/SCP/forwarding channels. On address change, a new authenticated
master replaces the old connection; active transfers are not transparently migrated.

## Interaction

Debian: `dpdp pair-server` displays a fresh six-digit code for 120 seconds.
Termux: `dpdp pair NAME` resolves a discovered candidate, prompts for that code,
and establishes the authenticated TCP pairing connection. Ambiguous names fail
with IDs for explicit selection. Background daemons list pairing-required devices
without attempting to read stdin or logging codes. Known pairings verify silently.
CLI helpers provide `paired`, `unpair`, `ssh`, `sftp`, `send`, `receive`, and a
persistent SSH master. Pairing TCP uses the configured discovery port plus one,
with interface/IP and expected-SSID checks; no listener is exposed by default.

## Alternatives considered

- Unauthenticated TLS + code sent inside: rejected, MITM can relay it.
- Six-digit raw TLS PSK: rejected, permits passive offline guessing.
- Custom PAKE primitives: rejected, unsafe maintenance burden.
- Full new multiplexed file/control protocol: rejected in favor of maintained SSH.
- GnuTLS TLS-SRP: rejected after a real package test showed it disabled.
- Pinned BoringSSL SPAKE2 + GnuTLS TLS1.3: chosen and verified with wrong/right codes.

## Validation

Real-library tests must reject wrong codes, tampered keys, altered signatures,
replayed responses, stale challenges, unpaired IDs and name collisions. Check pairing
persistence/restart/revocation, metadata preservation, bounded attempts, malformed
packets, strict SSH pinning and command arguments. Run normal and sanitizer CI,
real loopback TCP pairing and existing discovery tests. Physical Android and Debian
routing/background behavior remain external validation dependencies.

Primary references:
https://github.com/google/boringssl/blob/main/include/openssl/curve25519.h
https://gnutls.org/manual/html_node/PSK-credentials.html
https://github.com/termux/termux-packages/blob/master/packages/libgnutls/build.sh
https://man.openbsd.org/ssh_config (ControlMaster, HostKeyAlias, StrictHostKeyChecking)
