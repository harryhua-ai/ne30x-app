# tests/spec-v3 — `.neapp` v3 spec vectors (Issue #19)

Independent, offline, stdlib-only vector suite for the v3 spec
[docs/app-package-protocol-v3.md](../../docs/app-package-protocol-v3.md)
(Harry Dev Issue #19; frozen A semantics: [NE301 #54](https://github.com/harryhua-ai/ne301/issues/54)).

## Run

```bash
python3 tests/spec-v3/run_all_tests.py
sh tests/spec-v3/run_tests.sh
```

Requirements: Python 3.8+ (stdlib only) and the OpenSSL CLI (independent
signature cross-proof). No `cryptography` package, no network, no device.

## What it proves / does not prove

Proves (host side): byte-exact rebuild of the spec §12.1 golden v3 package
(314B, SHA-256 pinned), pure-Python + OpenSSL cross-verified ECDSA-P-256
signature, structural/manifest/policy acceptance in spec §2.3 order
(structure -> Host-local publisher trust mapping -> signature over the
original TBS -> policy), v3 capability/quota coupling (bits 6/7,
`control_max`/`snapshot_max`, reserved [184..191], profile 2, line-crossing-64
minimums), Host capability-subset fail-closed rejection, golden control-plane
wire vectors (CONFIG_APPLY 184B / COUNTERS_RESET 32B / APPLIED reply 32B /
snapshot 397B), command/reply/snapshot negative encodings (unknown flags,
zero session/request ids, duplicate JSON keys, invalid UTF-8, oversize
quotas), the §9 host-side command state machine (single pending, BUFFER_TOO_
SMALL non-consumption, dedup CACHED vs DUPLICATE_ID_CONFLICT, CONFLICT on
stale generation, session-end UNKNOWN with read-only snapshot
reconciliation, 5s/10s snapshot freshness), the §9.5 app transaction model
(CAS conflict / IO error / STORAGE_UNKNOWN never masquerade as APPLIED and
preserve previously confirmed data, restricted state blocks destructive
commands, counters reset keeps config_generation while state_revision
advances), v2→v3 same-identity migration vs cross-identity refusal, the
session-generation no-wrap rule, and the §10 v1/v2/v3 interop rejection
matrix (v1/v2 goldens rebuilt against their pinned TBS hashes; the v2
package also against its pinned DER/package hashes from the integrated v2
spec §10.1).

Does NOT prove (spec §14): any device-side v3 parser, real Host compilation
or static asserts, target resource or device writes, device mbedTLS/PKA,
Line Crossing Web, sustained AI event delivery, cooperative stop/reclaim, or
storage atomicity/power-loss. The signing key is the public non-production
scalar `d=1` (same key as the v1/v2 goldens) and must never become a
production trust anchor.

## Independence

`v3lib.py` implements the v3 spec from scratch; it imports nothing from
`package/` (v1/v2 tooling) or `tests/spec-v2/`. The minimal v1/v2 gates
inside are interop-simulation only (spec §10); the integrated v1/v2 specs
remain the authorities for old packages. All hashes pinned in the spec and
tests are byte-stable across runs (RFC6979 deterministic signing); the TBS
and content hashes do not depend on the signing key, only the DER bytes do.

## Files

- `v3lib.py` — v3 container/manifest/native/policy/control-wire/state-machine
  rules + pure P-256 (verify + RFC6979 deterministic sign + strict DER) +
  minimal v1/v2 interop gates + host/app state-machine models.
- `run_all_tests.py` — the full positive/negative matrix + evidence writer.
- `run_tests.sh` — PASS/FAIL wrapper.

Evidence is written deterministically to `docs/evidence/spec-v3/`
(`golden.neapp.v3`, `golden-tbs.bin`, `golden-sig.der`,
`test-publisher.spki.der`, `golden-command-config-apply.bin`,
`golden-command-counters-reset.bin`, `golden-reply-applied.bin`,
`golden-snapshot.bin`, `report.md`, `report.json`).
