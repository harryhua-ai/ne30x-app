# tests/spec-vnext — signed native vNext (`.neapp` v4) spec vectors (App #36)

Independent, offline, stdlib-only vector suite for the **A-frozen** v4 byte
contract: the Host #104 architecture freeze comments
[6258534821](https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258534821)
(F1–F4 container/manifest/caps/table),
[6258601629](https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258601629)
(F5–F7 v4 control wire NFC4 / ENABLE_SET / Paused receipt) and
[6258637748](https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258637748)
(F8–F10 live producer payload LVN4 / GAP conservation).

## Run

```bash
python3 tests/spec-vnext/run_all_tests.py
sh tests/spec-vnext/run_tests.sh
```

Requirements: Python 3.8+ (stdlib only) and the OpenSSL CLI (independent
signature cross-proof, skipped with a SKIP vector when absent).  The
`cryptography` package is used only for an additional RFC-6979 DER-identity
cross-proof when present.  No network, no device.

## What it proves / does not prove

Proves (host side): byte-exact rebuild of the golden v4 package (394B =
324B TBS + 70B strict-DER, every SHA pinned), pure-Python + OpenSSL +
`cryptography` triple cross-verification of the RFC-6979 d=1 signature
over `TBS = file[0:224+native_file_len]`, structural/manifest/policy
acceptance in the frozen order, the v4 capability rules (known mask
0x000003FF, bit8 ENABLE_CONTROL prerequisites, bit9 LIVE_PUBLISH
prerequisites with the `live_publish_max >= max(312, 48 + track_max*140)`
closure, zero live quotas without bit9), reserved-bytes invariants
([58..59], [192..207]), the pinned 0x00040000 ABI and 64B/14-pointer
function table (60B v3 tables and non-Thumb pointers rejected), trust
mapping fail-closed (unknown publisher, fingerprint mismatch — package
key material never self-trusts), strict-DER negatives, native
cross-checks (CRC-32, SHA-256, Thumb entry, abi pinning, caps), the
admission tier (Host without bit9 refuses whole, live capacity refuses
whole), the frozen NFC4 bytes (48B ENB1 ENABLE_SET, 48B ENR1 receipt,
32B other receipts, NFC3 foreign-input rejection, dedup
CACHED vs same-id-different-payload conflict) and the frozen LVN4 bytes
(48B header + 16B event records + 12B+N*8B track records with exact
closure, GAP/conservation session model, u32 exhaustion requiring
explicit RESYNC, SOURCE_LOSS_UNKNOWN never presented as a precise gap),
plus cross-major fail-closed rejection (v1/v2/v3 magic — including the
committed #19 v3 golden — rejected by the v4 parser).

Does NOT prove: Host admission/floor semantics, App #30 Enable state,
App #27 tracker facts, Host #91 live queueing/read-back, device capacity
(RAM/CPU/NVS), ARM static asserts (`sizeof(void*)==4` target build), any
device-side parser, production keys or issuance.  Those stay NOT_RUN in
`docs/evidence/package-vnext/README.md`.

## Independence

`v4lib.py` implements the frozen v4 contract from scratch; it imports
nothing from `package/` (the v1/v2/v3/v4 tooling) or
`tests/spec-v2/`/`tests/spec-v3/`.  The App #36 packer (an independent
implementation on `cryptography`) must produce a byte-identical golden
package; `tests/package-vnext/run.sh` asserts exactly that against the
evidence written here.  The TBS and content hashes do not depend on the
signing key; only the DER bytes do.

## Files

- `v4lib.py` — v4 container/manifest/native/table/policy rules +
  pure P-256 (verify + RFC-6979 deterministic sign + strict DER) +
  NFC4/ENABLE_SET/receipt codec + LVN4 packet codec and session model +
  OpenSSL cross-proof helper.
- `run_all_tests.py` — the full positive/negative matrix + deterministic
  evidence writer.
- `run_tests.sh` — PASS/FAIL wrapper.

Evidence is written deterministically to `docs/evidence/package-vnext/spec/`
(`golden.neapp.v4`, `golden-tbs.bin`, `golden-sig.der`, `golden-native.bin`,
`test-publisher.spki.der`, `golden-nfc4-enable-set.bin`,
`golden-nfc4-enable-receipt.bin`, `golden-lvn4-event-batch.bin`,
`golden-lvn4-tracks-snapshot.bin`, `report.json`, `report.md`).
