# Secure pairing and SSH implementation plan

Goal: code-authenticated pairing, signed endpoint discovery and pinned SSH channels.
Architecture: GnuTLS Ed25519/TLS1.3 and pinned BoringSSL SPAKE2; existing UDP loop; OpenSSH transports.
Spec: ../specs/2026-10-27-secure-pairing-design.md
Constraints: native C, no custom crypto, bounded parsing/work, names never authorize,
no root filesystem access, no implicit sshd enablement or firewall/routing changes.
Review focus: wrong PIN; endpoint replay; duplicate names; stale SSH master;
revocation including previously granted SSH keys.

1. Add src/security.h and src/security.c: atomic private identity/pair storage,
   key pinning, revocation, signed Q/A/U packets and challenge validation.
   Test tests/security.c against real GnuTLS: tampering, wrong keys, replay,
   endpoint mismatch, pair conflicts, reload and revocation. Demonstrate red/green.
2. Add src/pairing.c: SPAKE2/TLS1.3/120-second/three-attempt TCP window, six-digit input,
   exporter-bound signed identity exchange; secure limits and complete JSON parsing.
   Real-library socketpair/TCP tests: correct/wrong code, reflection/target mismatch.
3. Integrate daemon and CLI in src/dpdp.c: signed discovery, unicast address hints,
   authenticated hook guard, pairing CLI and list/revoke. Preserve unverified v1
   visibility. Test legacy traffic cannot dispatch or replace an authenticated IP.
4. Add src/access.c: explicit SSH offer setup, dedicated client key, strict pinned
   host verification, atomic authorized_keys edits and safe exec arguments for
   master/ssh/sftp/send/receive/forward. Test with temporary fake SSH executables
   and real ssh-keygen; cover revocation and changed address control sockets.
5. Update installer dependencies and docs; compile, unit/integration and sanitizer
   suites plus analyzer. Review full diff, publish PR, inspect automatic review/CI,
   fix findings, merge validated work and update handoff. Hardware remains untested.
