# tests/spec-v2 — `.neapp` v2 candidate spec vectors (Issue #12)

Independent, offline, stdlib-only vector suite for the v2 candidate spec
[docs/app-package-protocol-v2-draft.md](../../docs/app-package-protocol-v2-draft.md)
(Harry Dev Issue #12; A design input: issuecomment-6092256674).

## Run

```bash
python3 tests/spec-v2/run_all_tests.py
```

Requirements: Python 3.8+ (stdlib only) and the OpenSSL CLI (independent
signature cross-proof). No `cryptography` package, no network, no device.

## What it proves / does not prove

Proves (host side): byte-exact rebuild of the spec §10.1 golden v2 package
(314B, SHA-256 pinned), pure-Python + OpenSSL cross-verified ECDSA-P-256
signature, structural/manifest/policy acceptance in spec §2.3 order
(Host-local publisher trust mapping -> signature -> trust-data cross-checks ->
policy), host capability-subset fail-closed rejection, Host-owned loader
base/range and actual-exec-region admission, and the §8/§10.3 negative matrix
(true signed-payload tamper with DER untouched, DER tail/truncation/corruption,
re-signed policy rejections with rejection-attribution detail checks,
unknown/altered publisher identities, v1/v2 interop discrimination,
1024/4096 archive as resource-insufficient negative, event-wire rejections,
strict model_meta malformed-wire rejections, tick_ms mod-2^32 wraparound
semantics with the signed-int32 misreading trap documented).

Does NOT prove (spec §12): any device-side v2 parser, STM32 target build or
static asserts, device mbedTLS/PKA, sustained AI event delivery, cooperative
stop/reclaim, storage atomicity/power-loss, or real host resource capacities.
The signing key is the public non-production scalar `d=1` and must never become
a production trust anchor.

## Files

- `v2lib.py` — v2 container/manifest/native/policy/event-wire rules + pure
  P-256 (verify + RFC6979 deterministic sign + strict DER). Implements the v2
  spec only; it deliberately does not import any v1 packaging tool (P3 #6
  boundary). The small frozen-v1 structural gate inside is interop-simulation
  only; the integrated v1 spec remains the v1 authority.
- `run_all_tests.py` — the full positive/negative matrix + evidence writer.

Evidence is written deterministically to `docs/evidence/spec-v2/`
(`golden.neapp.v2`, `golden-tbs.bin`, `golden-sig.der`,
`test-publisher.spki.der`, `negative-archive-1024-4096.neapp.v2`,
`v1-golden.neapp`, `report.md`, `report.json`).
