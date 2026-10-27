# DPDP implementation status

## Implemented

- [x] Native C11 IPv4 multicast/unicast discovery on a selected interface; persistent IDs and automatic address rebinding.
- [x] Identity-owned JSON metadata preservation, duplicate-name/rename collision isolation, atomic persistence and concurrent initialization tests.
- [x] Ed25519 private key generation, private PKCS#8 persistence/reload and pinned peer public identities.
- [x] Six-digit SPAKE2 pairing via pinned upstream BoringSSL, followed by TLS1.3 with the high-entropy derived PSK and exporter-bound mutual key proofs.
- [x] Foreground Debian code display / Termux input, interactive pair-watch, bounded 120-second/three-attempt window and absolute exchange deadline.
- [x] Pending enrollment recovery, conflicting-key rejection, serialized commit/grant and revocation-epoch protection against in-flight reauthorization.
- [x] Enrollment allowlist excludes remote endpoint/authorization assertions, preserves local extensions and requires fresh endpoint proof after pairing.
- [x] Signed nonce-bound/source-IP-bound endpoint proofs, replay/duplicate rejection and signed unicast address-change hints with multicast fallback.
- [x] Explicit unicast source/interface selection through IP_PKTINFO; paired-state priority over unverified table entries; bounded packet/reply work.
- [x] Legacy discovery is informational only: no unauthorized hooks or replacement of verified addresses.
- [x] Explicit SSH offers, dedicated client keys, exchanged/pinned Ed25519 sshd keys, managed authorized_keys updates/removal.
- [x] Supervised endpoint-specific OpenSSH masters and helpers for SSH, SFTP, transfers and TCP forwarding; selected local source binding and strict host-key policy.
- [x] Single daemon per config; at most eight SSH workers and 32 hook children; Debian update restarts its user service.
- [x] Debian USB Wi-Fi/NetworkManager selection, no-default-route profile cloning, systemd/linger; Termux Boot/API and fail-closed SSID sleep policy.
- [x] Native regression suites, real PAKE/TLS streams, real TCP pairing CLI + UDP integration tests, unicast source test, runtime lock and ASan/UBSan CI wiring.
- [x] Real isolated SSH/SFTP binary transfers and two-namespace multicast-loss/one-sided/simultaneous address-change tests, both normal and sanitized.

Implementation checkboxes describe code delivered by PR #6; final merge/CI evidence
must be read from the actual PR and Actions state, not inferred from this checklist.

## Security and lifecycle work still open (#1, #3)

- [ ] Independent cryptographic/protocol audit; broader fuzz/property and hostile-load tests.
- [ ] Explicit signed key rotation/onboarding recovery UI; different keys must not overwrite pins automatically.
- [ ] Immediate server-side termination of already authenticated inbound SSH sessions. Current unpair removes authorization for new authentications and stops local managed outbound sessions; external sshd sessions have a narrower revocation contract.
- [ ] UNIX event/subscription API, per-service instance supervision, durable idempotency and observable execution/restart state.
- [ ] Improve fair per-source rate limiting and resilience under sustained hostile packet floods.
- [ ] Transactional CLI for concurrent registry edits; strict parsing/config validation throughout remaining legacy code.

## Deployment and network work still open (#2, #4)

- [ ] Physical Debian USB Wi-Fi + preferred Ethernet routing/DNS validation.
- [ ] Physical two-device pairing, SSH/SFTP, DHCP changes, simultaneous changes and device reboot tests.
- [ ] Android Wi-Fi permission/multicast delivery, SSID transitions, Doze/termination and measured power usage.
- [ ] NetworkManager profile idempotence, exclusion of managed clones, rollback/dry-run and adapter renaming tests.
- [ ] IPv6, scoped link-local endpoints, netlink subscriptions with reconciliation and optional mDNS/DNS-SD interoperability.
- [ ] Expand namespace coverage to multiple interfaces, asymmetric loss and packet reordering.
- [ ] CPU/memory/packet/battery benchmarks and signed release packaging to avoid large first-build dependencies on phones.

All four original issues remain open until their full acceptance criteria are met.
Old pre-pairing Termux daemons must be stopped/rebooted after upgrading; a new binary
cannot retroactively secure an already running old process.
