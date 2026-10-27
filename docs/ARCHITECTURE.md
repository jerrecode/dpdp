# Architecture decision record — C on Debian and Termux

## Goal and constraints

Two or more peers on the same multicast-capable IPv4 LAN must find each other without fixed addresses or a mandatory controller. Prefer low idle CPU and reasonable Android battery impact; never modify Ethernet routing incidentally. C code should be identical on Linux and Android/Termux, with platform-specific orchestration in shell. Persist identity across DHCP renewal and reboot. Peer registry must preserve operator-defined service hooks during updates.

## Alternative evaluation

| Approach | Strengths | Weaknesses | Decision |
|---|---|---|---|
| DNS-SD/mDNS | Broad interoperability and standards (RFC 6762/6763) | DNS record registration, Avahi dependencies and service identity mapping | Consider for future compatibility adapter |
| Custom UDP broadcast | Simple protocol and no daemon dependency | IPv4-only, may be restricted by APs; broadcast overhead | Not preferred |
| Custom UDP multicast with unicast response | Compact C implementation, symmetric, periodic recovery, low packet rate | Requires multicast-capable local network; lacks standards-level discovery interoperability | **Chosen initial core** |
| Hybrid multicast + secure unicast sessions | Strong future trust and endpoint confirmation | Authentication/key exchange and state complexity beyond initial discovery scope | Future extension |

Hard constraints include no central server, independent endpoint changes, bounded state, and no remote-code execution. The custom IPv4 multicast implementation fits the user-specified **two local devices** without requiring Avahi/DBus; it is not claimed to dominate DNS-SD on wider heterogeneous networks. RFC 6762/6763 remain recommended interoperability standards for future adapters.

## Protocol v1 (experimental, not standardized)

Multicast group: `239.255.77.81`, UDP port `47981`, TTL=1. Source interface is specified by `IP_MULTICAST_IF`, and listeners join that group on the chosen local IPv4 address. Receiving interface is checked using `IP_PKTINFO` to prevent cross-interface discovery contamination.

Packet payloads are ASCII with five `|`-separated fields: `DPDP/1|KIND|IDENTITY|NAME|SEQUENCE`. `KIND` is `Q` (query) or `A` (announcement). `IDENTITY` is 32 lowercase hexadecimal characters, `NAME` is 1–48 characters from `A-Za-z0-9._-`, and `SEQUENCE` is an unsigned 64-bit decimal integer. Empty or additional fields, trailing separators, embedded NUL bytes and overflowing sequences are rejected. Maximum packet length: 255 bytes. Receivers ignore their own persistent ID and packets with invalid fields. `Q` gets a unicast `A` response sent back to the UDP source IP and source port. Each node sends periodic multicast `Q` and `A`. `SEQUENCE` is currently informational; it does not provide anti-replay security.

The registry learns actual source IPs from `recvmsg` metadata. Advertised application ports or private addresses are not trusted. A `peer` is simply a node heard from in the last expiration interval. Expires to offline but retains last endpoint. Limits: 128 peers, 1 MiB maximum registry read, 16 configured service entries per peer, 24 arguments per service. JSON read-modify-write preserves unrecognized keys and operator-defined `services`/`trusted`. Registry updates use advisory lock and atomic rename. Entries are found by full immutable ID before selecting a display key. Occupied keys (including JSON null values) are never reused for another ID: collisions use the full ID suffix and, if needed, a numeric suffix. Renaming preserves metadata and existing long operator keys are matched without truncation. This remains schema version 1; existing shortened suffix keys migrate naturally on refresh. Identity initialization holds `<config>.id.lock` across reading, generating and atomically writing the ID; cooperating concurrent initializers therefore reuse one identity. Existing invalid/unreadable identity paths are never silently replaced. Restarts mark restored peers offline until packets return.

## Network state and Android power modes

- Running: poll receiving socket up to 1 s; check interface IP (and Termux current SSID) at 5 s intervals; multicast discovery at configurable 15 s.
- No interface/IP: close socket and retry at 60 s.
- Wrong Termux SSID: close socket and retry at 15 s.
- Missing Termux API when SSID required: fail closed and retry at 15 s.
- Interface address change: reopen membership and immediately send Q/A.
- Peer timeout: mark offline at 70 s without receiving packets.

Termux uses `termux-wifi-connectioninfo` with a 4 s command timeout. The sleep state is not an Android wake-up service; the OS may suspend the process. Termux:Boot only provides the boot entry point, and the Android OS must allow Termux to run.

## Threat model

Local untrusted devices may spoof peer IDs, names and UDP packets. Discovery does not authenticate identities, prove service reachability or attest the device. To limit exploitation, no received packet contains executable commands. Only `trusted=true` and locally configured absolute `exec` paths can spawn hooks, with no shell interpolation. Be aware: spoofing a *trusted* ID could still trigger a locally authorized executable! Only use on trusted networks until cryptographic ID verification, signed announcements and challenge-response are shipped. Lock+rename protects cooperating writers but does not make unmanaged external edits transactional. An attacker with local write access to the registry already has authority to configure service execution.

## Scope not yet implemented

Cryptographic identities and mutual authentication, IPv6 scope handling, multicast failure fallback, netlink-based change subscriptions, event socket for downstream clients, peer endpoint liveness probes, supervised hook lifecycles, and physical device tests on the user's USB adapter/phone. These are tracked in `docs/PLAN.md`.
