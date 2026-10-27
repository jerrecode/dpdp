# DPDP continuation checkpoint — 2026-10-27

Repository: https://github.com/jerrecode/dpdp (canonical branch: main).
Implementation checkpoint: `99dd9383e212332b277165a789399fbe75199bab` on
`fix/identity-registry-and-wire-validation`, PR #5. This document is a subsequent
documentation commit. Fetch current main and inspect PR #5 before resuming; do not
assume the checkpoint is still the latest commit or an unmerged branch needs merging.

## Completed in this increment

1. Reproduced a registry bug: three equal names with a shared eight-character ID
   prefix could transfer an existing peer's metadata, trusted flag and services to
   another ID. Rename destinations could also overwrite unrelated entries.
   Entries now resolve by full ID and select a free name/full-ID/numeric display
   key. Null values and long operator keys are preserved. Schema remains version 1;
   old shortened keys migrate on refresh, without losing identity-owned metadata.
2. Reproduced simultaneous first-start processes generating different IDs for the
   same configuration. Identity initialization now holds `<config>.id.lock` across
   read/generate/write. Existing unreadable or invalid identity paths are preserved.
3. Reproduced acceptance of malformed frames via collapsed empty fields, trailing
   separators and embedded NUL suffixes. Parsing now requires exactly five fields,
   no embedded NUL, and an unsigned 64-bit decimal sequence without overflow.
4. Added network-independent C tests; fixed `make sanitize` to instrument the daemon
   and every regression binary, with C11 and warning flags; enabled full sanitizer
   integration tests in GitHub Actions.

Changed files: `src/dpdp.c`, `Makefile`, `tests/registry.c`, `tests/protocol.c`,
`tests/identity.c`, `.github/workflows/ci.yml`, `README.md`,
`docs/ARCHITECTURE.md`, `docs/PLAN.md`, and this handoff.

## Evidence

All three regressions failed against pre-fix production code and passed after fixes.
Warning-enabled C11 build, shell syntax checks, `git diff --check`, and GCC 13
`-fanalyzer` compilation passed locally. Unit tests also passed under ASan/UBSan
with `ASAN_OPTIONS=detect_leaks=0` locally because this environment denies the
`/proc` inspection required by LeakSanitizer.

Local multicast smoke testing failed on the unchanged baseline: interface enumeration
and netlink access are restricted here. This is an environment limitation, not a
successful integration test. GitHub Actions PR run **40487450868** on implementation
checkpoint **99dd938** passed the full normal suite AND full `make sanitize`, including
multicast discovery, trusted local hooks and mocked Termux SSID states. GitHub CI
uses default leak detection; it does not apply the local workaround.

Direct Git push lacked credentials here. The GitHub connector published the exact
locally tested tree (`1f117a66c6640077c54790db8d274ffd64819448`), with parent
`9cb931e49966a75e162153159b35fc2198bb59d3`. Local preparatory commits 6bbbe15 and
94e7000 are equivalent-tree development history, not additional remote work to merge.

## Remaining work and boundaries

No issue is fully completed: **#1, #2, #3, #4 remain open**. This increment fixes
prerequisite defects; it does not satisfy their complete acceptance criteria.

**Highest priority: #1 authentication.** Random IDs and trusted=true are still
unauthenticated. A LAN attacker can spoof an already authorized ID and trigger a
locally configured hook. Strict parsing and collision isolation do not prevent this.
Research libsodium/OpenSSL using primary sources, choose a standard library, design
key-backed identity plus authenticated endpoint challenge/response, pairing,
revocation, replay protection and explicit v1 migration. Do not write crypto primitives.
Do not enable authenticated-service claims before adversarial tests demonstrate them.

**#3 runtime:** child count/lifecycle supervision, per-service deduplication and an
endpoint/event API remain absent. Registry locking only coordinates cooperating
writers. Further audit targets visible in code, not yet regression-reproduced in
this increment: JSON parsing does not verify complete input consumption; registry
lock opens lack O_NOFOLLOW/O_CLOEXEC; hook authorization booleans use permissive
JSON coercion; repeated endpoint changes can spawn unbounded children.

**Installer:** saved-profile selection includes DPDP-created clones, potentially
causing ambiguous selection or clone proliferation on reinstall. Reproduce with a
fake nmcli harness before fixing. Transactional rollback, DNS isolation, profile
idempotence and adapter renaming remain unverified. Numeric config parsing also
uses unchecked strtoul conversions; add rejection tests before changing it.

**#2 external dependency:** physical Debian USB adapter/Ethernet routing and Android
Termux/Boot/Doze/multicast tests require access to the user's devices. None occurred
in this session. Do not infer hardware compatibility or battery use from Linux CI.
Do not modify user routes or request diagnostics as a prerequisite for independent work.

**#4:** IPv6, mDNS, netlink subscriptions, packet-loss/network-namespace tests and
measured resource/battery benchmarks remain future work. Core stays native C on
Debian and Termux, json-c remains the runtime dependency; sleep policy is unchanged.

## Resume without repeating completed work

Fetch main; inspect PR #5, latest CI/reviews and open issues. Read this handoff,
README, architecture and plan. Build with `make`; run `make unit-test`, `make test`
and `make sanitize` where interface and /proc access permit. Keep genuine failures
visible; do not silently skip tests to obtain a green result. Continue with one
focused authentication or safe-dispatch increment, adding failing tests first.
Use branches/PRs, inspect CI and reviews, fix findings, merge validated work, and
keep all four issues open until their actual acceptance criteria are satisfied.
