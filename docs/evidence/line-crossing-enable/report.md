# Line Crossing Enable control evidence

## Candidate and build

- Base: `1f48bdd5a78e789e2a2bd62a3ce460eda9292a10`
- v4 ELF build: `make -C apps/line-crossing/app elf-v4`
- Build result: PASS; `arm-none-eabi-gcc` linked `lc-line-crossing-v4.elf`.
- ELF SHA-256: `f8cc3913a963d69d595e8b713e4eff7d1a160866635a9a337927a60a53b40022`
- Linker emitted an RWX LOAD segment warning. The ELF was not packaged or installed.
- Golden command and receipt: [golden-enable-wire.hex](golden-enable-wire.hex)
- SHA-256 of the concatenated 96-byte golden pair: `6e266fba558364bb72ae73e20e0f4cd71a134aa4c1f8086b52f4c6cbf27b8009`

## Verification matrix

| Surface | Result | Evidence |
| --- | --- | --- |
| Enable schema codec, schema1/2 migration, paused restart, frame and idle gates, receipts and failure cases | PASS, 204 assertions | `bash tests/line-crossing-enable/run_tests.sh` |
| v4 app entry contract and paused session | PASS, 15 assertions | `bash tests/line-crossing-enable/run_tests.sh` |
| IO, revision conflict, torn write or unconfirmed readback result | UNKNOWN state and no APPLIED receipt, as required | Enable control tests verify status 5/6/7 and effective state UNKNOWN |
| Persistence study and v3 corrupt-schema rollback case | PASS, 65 checks | `bash tests/enable-persistence-study/run.sh` |
| v1/v2 app unit, business and entry contract | PASS, 50 + 214 + 52 assertions | Direct C builds using `tests/line-crossing-app/test_unit.c`, `test_business.c`, and `test_contract.c` |
| v3 unit, control transaction, snapshot and entry contract | PASS, 68 + 267 + 52 + 49 assertions | Direct C builds using `tests/line-crossing-v3/test_unit_v3.c`, `test_ctrl_txn.c`, `test_snapshot.c`, and `test_contract_v3.c` |
| Core engine and committed golden trace | PASS; byte-identical | `tests/line-crossing/test_lc_engine.c`; `tests/line-crossing/golden/lc_equiv_trace.expected.txt` SHA-256 `9d5751d675a61444e0c9db9932b1cd1aa5fd766559182f2e0f78091f1e2aa0c0` |
| Signed native package v1/v2/v3 and frozen spec-v2/spec-v3 suites | PASS, offline | `bash tests/sidecar/run_checks.sh`; prior evidence was restored after the run |
| Sidecar golden and rejection matrix | PASS, 94 cases | `bash tests/sidecar/run_checks.sh`; golden bundle SHA-256 `9ec5e44616e197dfa0b3d16a5f9b0f280b523883be2c1cddf4f363126e8f79d4` |
| Host #104 durable floor, owner/TBS/generation fencing and confirmed uninstall clearing | NOT_RUN | Host branch was read-only semantic reference; this task did not execute the cross-repository matrix |
| App #27 live producer and joint live freshness gate | NOT_RUN | Producer is not delivered; no Realtime connection is claimed |
| v4 signed package, device install, camera operation and production storage | NOT_RUN | No v4 packager or device/production operation was run |

## F5-F7 comparison

- F5: v4 uses NFC4 and strict 32-byte headers. ENABLE_SET accepts only type 5 with the exact 48-byte ENB1 payload. Its type 3 receipt is 48-byte ENR1; the state revision is repeated in the header and payload. v3 continues to reject type 5 and NFC4.
- F6: Enable, CONFIG_APPLY, COUNTERS_RESET and schema3 state flushes share the App revision CAS path. APPLIED follows exact blob and revision readback. Pause clears partial window and tracker continuity, keeps cumulative counts and report sequence, and does not submit a partial report. The v4 snapshot exposes Enable and video freshness; live freshness reports `not_connected`.
- F7: App-side tests exercise malformed NFC3/NFC4 envelopes, reserved fields, request replay and conflict, session change, stale generations and revisions, CAS conflict, IO, unknown storage, torn writes and receipt loss. Host floor admission, identity rotation, cleanup and cross-repository interleavings remain NOT_RUN.
