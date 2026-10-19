# package-vnext evidence — signed native vNext (`.neapp` v4) offline toolchain (App #36)

Issue: harryhua-ai/ne30x-app#36.  The only byte-level authority is the
A-owned Host #104 architecture freeze (harryhua-ai/ne301#104, 2026-10-19):

| Freeze | Comment |
| --- | --- |
| F1–F4 container / NMF4 manifest / caps / 64B function table | [`6258534821`](https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258534821) |
| F5–F7 v4 control wire `NFC4` / `ENB1` ENABLE_SET / `ENR1` receipt / floor semantics | [`6258601629`](https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258601629) |
| F8–F10 live producer payload `LVN4` / record closure / GAP conservation | [`6258637748`](https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258637748) |

Host-side interop anchor (claim comment `6258843064`): branch
`agent/104/de1fd467`, execution_base
`6357a04d509fb8e1851603d1efe0de51def9edb1`.  The earlier reviewed snapshot
recorded interop as NOT_RUN.  This r2 evidence closes that gap against the
read-only Host #104 PR #111 r2 source at
`f6a851a3c1c116f85d9a2609c9d8b63b1d0a66f1`; the exact App packages are rebuilt
from App `71f1850063f022b86f3b027e27eaabb992de60b0`, then passed to the real
Host C parser with matching test SPKI and policy.  See
[`joint-interoperability.md`](joint-interoperability.md), its full log, and
byte-preserving JSON report.

No competing protocol document is created in this repo; the existing
`docs/app-package-protocol-v{1,2-draft,3}.md` remain the sole old-major
authorities and are untouched.

## Rebuild commands (offline, reproducible)

```bash
# one command: legacy suites -> identities -> images -> golden + dev packages
#   -> independent verification -> 50-case rejection matrix -> evidence
bash tests/package-vnext/run.sh

# independent spec vector suite only (stdlib; 117 vectors)
python3 tests/spec-vnext/run_all_tests.py

# canonical heavyweight legacy proof (pre-existing #20 suite; run in an
# isolated clean checkout because it rebuilds its own v1/v2/v3 artifacts)
bash tests/package-v3/run_checks.sh

# standalone exact-source App/Host matrix (also run by package-vnext/run.sh)
python3 tests/package-vnext/joint_interop.py
```

The package-vnext and joint-interop runs used Python 3.14.4, cryptography
48.0.0, OpenSSL 3.6.2, and the local C compiler.  They used no network,
device, or target toolchain.  The separately captured package-v3 regression
used `arm-none-eabi-gcc` for its synthetic hello-app fixtures and fetched the
pinned ABI header; it did not build NE301 firmware.

## Golden vector digests (key-independent unless noted)

| Artifact | SHA-256 | Notes |
| --- | --- | --- |
| golden native image (100B) | `845e09288e0f1d876832dcda553580c6aa64ef17f08b9e529550aefa4db12cd1` | NEA1, ABI `0x00040000`, CRC-32 `0x990997a2`; payload = frozen 64B function table (SIMULATION Thumb pointers) + `00207047` stub |
| golden TBS (324B) | `581e3ae98afef313de0bdf7d8bc85c2a36585a7c28e609dea183a558e599e095` | `TBS = file[0:224+native_file_len]`; independent of the signing key |
| golden signature DER (70B) | `3044022072d7b4a0…b1eb593aae` | strict-DER ECDSA P-256, RFC-6979, public test scalar d=1 |
| golden package (394B) | `e6a7fedc8cda9f3900311bc077de2a3ea79002d10b23241d1690c9e28ee46e0e` | `spec/golden.neapp.v4`; rebuilt byte-identically by two independent implementations (`package/vnext` on `cryptography` and `tests/spec-vnext/v4lib.py` pure-Python) |
| NFC4 ENABLE_SET (48B) | `ce0976a6f3ce0ce0e3e55592b08d57c3b1e0701d43e31af00a539c8f87d49a98` | session 7, request 42, config_gen 9, ENB1, desired Enabled, expected rev 5 |
| NFC4 ENR1 receipt (48B) | `63db6108b97b719f833cc55c76b8e4eff1a7ce929598823a2c57604f1bc341ed` | status APPLIED, effective Enabled, readback rev == header rev |
| LVN4 EVENT_BATCH max (304B) | `555096fc4935d5cd89ebc5d81cee1a92a30f0312d9d86d7fa4b4a2ccbed360c3` | 16 × 16B records; within the 312B live_publish_min |
| LVN4 TRACKS_SNAPSHOT (104B) | `85bb6baa722e4766b9b9c95e13fe90fbee79e673376a4cd97a90f2cc54ffc6d6` | 2 tracks, points closed to the exact packet tail |

Dev-key packages (d=2, publisher `dev-publisher`, recorded in
`artifacts.json`): 4.0.0 `92308f47…`, 4.1.0 `f0ec52a3…`, alt-image
`381131a3…`, ENABLE-shaped (caps `0x173`) `1d635627…`, LIVE-shaped
(caps `0x223`, track 64 @ 9008B) `ba64faef…`.

## Test publisher provenance (AC1/AC4)

Only PUBLIC, non-production P-256 test scalars are used; both are
textbook public values reproducible by anyone — which is exactly why
they must never be a production trust root:

| publisher_id | scalar | SPKI SHA-256 |
| --- | --- | --- |
| `test-publisher` | d=1 (same public scalar as the v1/v2/v3 goldens) | `5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3` |
| `dev-publisher` | d=2 | `dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba` |

Private keys are materialized per run under `tests/package-vnext/work/keys/`
(gitignored, 0600) and never committed.  Trust is local configuration
(`publisher_id → SHA256(SPKI DER)`); no key inside or beside a package can
self-trust, and the fingerprint-mismatch / unknown-publisher negatives
prove it.

## Rejection coverage (all fail-closed, 50 tooling cases + 117 spec vectors)

- container: wrong magic (v1/v2/v3/random), `manifest_len != 208`,
  `native_file_len` < 32 / over the 2,097,152 cap, truncation, trailing
  byte, DER window 8..72, package cap 2,097,448, u64 length arithmetic
- manifest: `NMF3`-in-v4, reserved [58..59] and [192..207], abi pin
  `0x00040000`, identifier charset/padding/NUL, caps bit10..31,
  bit8-without-bit4, bit9-without-bit5, `live_publish_max` < 312,
  `live_track_max` outside 1..64, kind2 closure `48 + track_max*140`
  (track 64 needs >= 9008; 9007 rejected, 9008 accepted), zero live
  quotas without bit9, v3 profile 2, quota/capability coupling,
  32B control-wire minimum
- native: CRC-32, SHA-256, abi pin, `reserved0`, header_size,
  format_version, odd/unmapped Thumb entry, residency floor
- trust/signature: unknown publisher, fingerprint mismatch, TBS mutation
  without re-sign, signature byte flip, strict-DER negatives
  (non-minimal/negative INTEGER, truncation, trailing bytes)
- packer fail-closed: every manifest/native/policy refusal above also
  refuses to emit at pack time; there is no CLI knob for reserved or
  unknown fields
- admission tier (simulation policy): Host without bit9 refuses the live
  capability whole; live capacity below the signed declaration refuses;
  board/PSRAM/ABI/caps mismatch, loader/exec geometry
- ABI/table: 60B v3 table rejected, wrong table abi, null/non-Thumb
  pointers (table `ABI_INCOMPATIBLE`); table vectors shipped in
  `tests/spec-vnext` and the controlled image embeds the real 64B table
- frozen wire bytes: NFC4 header/ENB1/ENR1 positives + negatives (bad
  magic/lengths/generations/flags/reserved/status/readback), NFC3 as
  foreign input, dedup CACHED vs same-id-different-payload conflict;
  LVN4 kinds with exact record closure, 17-event/17-point overflows,
  duplicate/zero track ids, state/flags/reserved violations, packet_seq
  session monotonicity, GAP conservation, u32 exhaustion requiring
  explicit RESYNC, `SOURCE_LOSS_UNKNOWN` never presented as a precise gap

## Zero degradation of v1/v2/v3 (AC3)

`run.sh` re-runs, without modifying any committed evidence file:

- `tests/spec-v2/run_all_tests.py` and `tests/spec-v3/run_all_tests.py`
  (exit 0; committed evidence verified byte-identical after the run)
- unmodified `neapp_pack_v2.py` / `neapp_pack_v3.py` rebuild the
  committed #12 (TBS byte-identical; v2 signs with random k) and #19
  (whole package byte-identical) goldens inside the gitignored work dir;
  unmodified `neapp_verify.py` / `neapp_verify_v2.py` / `neapp_verify_v3.py`
  verify the committed v1 golden and both replicas PASS
- cross-major fail-closed in both directions: the v1/v2/v3 verifiers
  reject the v4 golden (`BAD_PACKAGE`), and the v4 verifier rejects the
  committed v1/v2/v3 goldens (`BAD_PACKAGE`); a v3 `NFC3` message is
  foreign input to the v4 control rules

## PASS / NOT_RUN matrix

PASS (offline software evidence only — a signed-format PASS never means
Host admission, install, execution, floor/Enable semantics, live
delivery, or device capacity):

- v4 golden generation byte-identical across two independent
  implementations; RFC-6979 DER identity across pure-Python,
  `cryptography`, and OpenSSL CLI
- the full positive/negative matrices above
- legacy v1/v2/v3 suites byte-stable; cross-major fail-closed

NOT_RUN (with reasons; also recorded in `artifacts.json`):

| Item | Reason |
| --- | --- |
| Device flash/NVS/LittleFS, install, execution | no device |
| Production keys / real issuance | non-production scope only |
| App #30 Enable/Paused business semantics | owned by #30; non-goal |
| Host #91 producer-ingest / live read, App #27 tracker | the pinned Host handler returns `APP_SESSION_ERR_UNAVAILABLE`; runtime producer-ingest and App #27 remain unimplemented |
| ARM target-build static asserts (`sizeof(void*)==4`, Thumb) | target-build proof |
| Real RAM/CPU/live-queue capacity on hardware | device measurement |
| Remaining #104 wire bytes (beyond F5/F8/F9 frozen set) | A freeze still in progress at Host #104 |

## Files

- `run.log` — deterministic log of the last `run.sh` execution
- `artifacts.json` — structured evidence (spec authority, digests,
  packages, case matrix, key discipline, PASS/NOT_RUN)
- `joint-interop.log` — complete App packer, Host C parser, matrix, and Host C-suite output
- `joint-interop.json` — exact package bytes as hex, digests, source commits, and per-case outcomes
- `joint-interoperability.md` — concise profile and App/Host comparison tables
- `package-v3-regression.log` — full isolated legacy v1/v2/v3 regression output, including the 73-entry v3 matrix
- `spec/` — deterministic outputs of `tests/spec-vnext` (golden package,
  TBS, signature, native image, SPKI, NFC4/LVN4 wire goldens, report)
