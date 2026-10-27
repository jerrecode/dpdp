# DPDP — secure pairing continuation checkpoint, 2026-10-27

Repository: https://github.com/jerrecode/dpdp ; canonical branch: main.
Feature branch: feature/secure-pairing-ssh ; integration PR: #6.
Base main: 5d46f92e74ccda0e68be667999d6e050a2ba0967 (merged PR #5).
Fetch live refs and inspect PR #6/Actions before resuming; this handoff travels
with the implementation, so its containing commit is the current code checkpoint.
Do not assume PR #6 is unmerged or repeat completed work from PR #5.

## User goal / final route

Debian displays a six-digit code, Termux accepts it, both exchange cryptographic
identities over TCP and later verify silently. Changed IPs produce signed unicast
hints followed by a fresh challenge; multicast remains the simultaneous-change
fallback. OpenSSH masters share SSH/SFTP/file-transfer/forwarding channels.
Names are presentation labels; full pinned public keys establish trust.

C modules: security.c/h (GnuTLS Ed25519, strict/atomic pin storage, nonce proofs,
revocation epoch/transaction commit); pairing.c (bounded native PAKE/TLS and CLI);
pake_bridge.c/h (upstream BoringSSL SPAKE2 only); access.c (SSH key offers/grants,
strict pins, exact owner sidecars, supervised SSH child). dpdp.c integrates signed
UDP, paired-slot priority, hook authorization and pairing/access/watch CLI.

GnuTLS TLS-SRP was rejected after real package tests: it is disabled in current
GnuTLS defaults; Termux OpenSSL explicitly disables SRP. A pinned BoringSSL crypto
archive implements SPAKE2 instead, yielding a 64-byte high-entropy TLS1.3 PSK for
GnuTLS. Six digits are never used as a raw TLS PSK or sent inside unauthenticated TLS.
Pinned upstream revision: e651545da6e26e1f4420723a3b69a78ed1b9c51d.
First build needs CMake/C++17/git; Python is test-only. No crypto primitives are
implemented by DPDP. See architecture and design/plan documents for exact framing.

## Fixes found during implementation/review

- Generic GnuTLS Ed25519 export yielded UNKNOWN PEM, failing restart. Use PKCS#8;
  a test reloads the same key and compares the public identity.
- Plain sendto on an ANY-bound socket could source signed unicast from preferred
  Ethernet instead of selected Wi-Fi. All sends now use IP_PKTINFO source/interface
  selection; a real UDP source-IP test covers this.
- Delayed pairing could undo unpair. Pending records, random transaction tokens,
  pre-handshake revocation epochs, and one lock around grant/final commit/revoke
  prevent both reported interleavings. Tests revoke before/after staging.
- A helper could start after unpair's socket scan. Helpers now supervise OpenSSH,
  rechecking authorization/endpoint each second while scheduled and terminating
  their child on revocation, endpoint change or shutdown. No detached persistence.
- Long full-ID control sockets did not fit normal Termux paths plus OpenSSH's
  temporary suffix. Hash full identity/endpoint and keep full-ID owner sidecars.
- Unverified table entries could crowd out paired devices; verified pairings may
  replace unverified memory entries without deleting persistent user metadata.

## Validation / how to reproduce

make; make unit-test; make test; make sanitize. Dependencies are documented in README.
Local warning builds and seven native suites passed during implementation. These
include real correct/wrong-code SPAKE2/TLS1.3, wrong target and interrupted retry,
stalled stream deadlines, private-key reload, forged/replayed/stale proofs, exact
source-IP validation, conflicting pins, revoked/stale enrollment transactions,
legacy-hook denial, SSH key/blob/pin/master ownership arguments, running helper
cancellation and single-runtime locking. The selected-source UDP regression also
passed locally. Existing registry/protocol/identity tests remain.

Local full integration was limited by interface enumeration restrictions; ASan/UBSan
unit checks used ASAN_OPTIONS=detect_leaks=0 because /proc inspection is blocked here.
Early draft CI failures were real (missing dependencies initially, then the UNKNOWN
PEM reload defect); do not report those drafts as passed. Check the latest PR run for
full normal/TCP/UDP and sanitizer evidence. CI uses default leak detection.
No physical Debian/Android tests or actual remote sshd transfer tests occurred.
Access tests use real SSH key generation with a controlled executable fixture;
real SSH/SFTP behavior still depends on each device's sshd configuration.

Changed files: Makefile/.gitignore/CI, src/dpdp.c plus the new security/access
source/header modules, scripts/build-pake.sh and install.sh, tests/security.c,
pairing.c, authorization.c, access.c, source_interface.c, runtime_lock.sh,
pair_cli.py and smoke.sh; README, architecture, plan, design and this handoff.

## Remaining boundaries and next work

All original issues #1–#4 remain open. Cryptography is experimental integration,
not independently audited. Unpair denies new authentication and stops local outbound
helpers/masters, but cannot terminate already authenticated inbound external sshd
connections/channels. Full server-side cutoff and signed key rotation remain work.
No event socket/durable per-service supervision or exactly-once hooks yet.
Physical USB/Ethernet routing/DNS and Android Doze/multicast/battery are unverified;
never infer them from Linux CI. NetworkManager clone idempotence/rollback and IPv6/
netlink remain future work. First native dependency build is relatively large.

Both devices must upgrade; stop/reboot an old pre-pairing Termux daemon once.
Foreground pair-watch needs a terminal and a separate running discovery daemon.
SSH account access is explicitly enabled before pairing by --enable-ssh/access-init;
it never grants root or bypasses Android filesystem permissions. Existing TCP
sessions cannot migrate IPs; masters reconnect and users retry interrupted transfers.

Continue by inspecting final PR #6 review/checks, fixing remaining findings before
merge, then focusing on physical validation or one bounded follow-up from PLAN.
Preserve identities/pins/user metadata; keep SSH host verification strict; never
replace the PAKE with a plaintext code or raw six-digit TLS PSK. Publish tested work
and keep issue states honest. Direct Git push lacks credentials in this environment;
the connected GitHub tools can publish exact tested trees with expected-head leases.
