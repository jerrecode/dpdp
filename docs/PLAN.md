# DPDP delivery status and next-phase development plan

## Implemented baseline (C)

- [x] C11 UDP discovery daemon with persistent 128-bit identity, bounded parsing and per-interface multicast.
- [x] Symmetric query/response/announcement, automatic IP address rebinding and periodic rediscovery.
- [x] Peer registry JSON, offline retention, atomic persistence, metadata/service preservation.
- [x] Local allowlisted service hooks with trusted-peer opt-in, environment variables and no remote command strings.
- [x] Debian/Termux build and install scripts; Debian USB Wi-Fi preference, saved reachable NM profile selection, cloned no-default-route Wi-Fi connection.
- [x] Debian systemd user startup/linger attempt, Termux:Boot entry, Termux SSID-based 60 s/15 s sleep states.
- [x] Local two-process integration test and GitHub Actions Linux build/test.

## Priority 1: security and reliability before untrusted LAN deployment

- [ ] Cryptographic device keys and authenticated signed announcements, replay-resistant handshake.
- [ ] Verify peer challenge/response on the reported endpoint before service hooks trigger.
- [ ] Add explicit trusted-peer onboarding/pairing CLI, revocation and signed key rotation.
- [ ] Durable event queue or local UNIX socket API, and supervised/deduplicated service lifecycle.
- [ ] Harden input limits, parsers, concurrent JSON editors, hostile-LAN rate limiting and fuzz tests.
- [ ] Test real phone + USB dongle + LAN Internet routing, shutdown, DHCP reassignment, simultaneous address changes, Wi-Fi reconnect and app suspension.

## Priority 2: deployment portability and power efficiency

- [ ] Netlink (`RTM_NEWADDR`, `RTM_NEWLINK`) instead of periodic Linux address enumeration.
- [ ] Android JobScheduler/AlarmManager integration and adaptive battery policy that explicitly states OS wake limitations.
- [ ] IPv6 link-local multicast/scoped addresses and multi-address peers.
- [ ] DNS-SD/mDNS adapter for interoperable discovery, if justified by deployment tests.
- [ ] Installer transactional NetworkManager changes and rollback/dry-run; route invariants test for wired default Internet access.
- [ ] Stronger test harness using network namespaces, `tc netem`, IPv4 multicast fault injection and sanitizer builds.

## Priority 3: performance and usability

- [ ] Property-based and fuzz testing on protocol messages, JSON inputs and reloads.
- [ ] Benchmark packet/CPU/memory/battery use across peer counts and idle/wrong-network states.
- [ ] Structured logging, diagnostics JSON, service-hook status and per-peer metrics.
- [ ] Package binaries and cross-platform release distribution with signatures.

## Acceptance criteria for physical deployment

1. Both Debian/Termux instances start automatically after the platform's permitted boot startup, with no Internet discovery server.
2. Debian can retain Ethernet as its Internet route while a USB Wi-Fi adapter connects via an existing saved NM profile to the phone's WLAN.
3. Correct phone WLAN yields peer discovery; wrong WLAN or no WLAN produces no outgoing DPDP packets and uses the configured polling interval.
4. Each device's registry contains the other's stable ID, name and updated IP; user-written `trusted`, `services` and custom metadata survive registry refreshes and restarts.
5. Authorized local services run at most once per detected peer/IP transition within one daemon session and receive correct environment variables.
6. Following independently changed DHCP addresses, periodic rediscovery re-establishes both peers within bounded time on a multicast-capable network.
7. No unauthenticated packet can embed executable commands; for deployment on hostile LANs, full cryptographic identity verification is mandatory and currently **not implemented**.
