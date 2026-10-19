# Line Crossing Enable control evidence

## Candidate and build

- Base: `1f48bdd5a78e789e2a2bd62a3ce460eda9292a10`
- v4 ELF build: `make -C apps/line-crossing/app elf-v4`
- Build result: PASS; `arm-none-eabi-gcc` linked `lc-line-crossing-v4.elf`.
- ELF SHA-256: `f8cc3913a963d69d595e8b713e4eff7d1a160866635a9a337927a60a53b40022`
- Linker emitted an RWX LOAD segment warning. The ELF was not packaged or installed.
- Golden command and receipt: [golden-enable-wire.hex](golden-enable-wire.hex)
- SHA-256 of the concatenated 96-byte golden pair: `6e266fba558364bb72ae73e20e0f4cd71a134aa4c1f8086b52f4c6cbf27b8009`

## Acceptance summary

- [x] AC1 App state: schema3 stores Enable, configuration, counters and sequence with CRC and revision CAS; schema1/2 migrate once to Enabled; untrusted storage fails closed to UNKNOWN/restricted.
- [x] AC2 App control: NFC4 type5 ENB1 is accepted only from the latched v4 session; ENABLE_SET, CONFIG_APPLY and COUNTERS_RESET share verified revision CAS; APPLIED follows exact readback.
- [x] AC3 Pause/resume: FRAME and idle paths stop business counting, window close and report submission; partial window/tracker continuity is cleared while totals, report sequence and queued history remain.
- [x] App-side AC4 tests: real bus, controller, state blob and v4 entry are covered, with legacy, rollback, failure and regression suites recorded below. Full cross-owner production control remains separately gated below.
- Host #104 floor/identity lifecycle, app live producer and joint live gate remain NOT_RUN as listed below.

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
| Host #104 floor/install/session C behavior | PASS, 77 checks in `app_native_vnext`; source-pinned joint results below | Host source extracted read-only at the exact commit shown below |
| Host #104 production floor-to-ENABLE_SET control path | NOT_RUN | Exact production seam gaps and the post-merge A-owned gate request are recorded below |
| App #27 live producer and joint live freshness gate | NOT_RUN | Producer is not delivered; no Realtime connection is claimed |
| v4 signed package, device install, camera operation and production storage | NOT_RUN | No v4 packager or device/production operation was run |

## F5-F7 comparison

- F5: v4 uses NFC4 and strict 32-byte headers. ENABLE_SET accepts only type 5 with the exact 48-byte ENB1 payload. Its type 3 receipt is 48-byte ENR1; the state revision is repeated in the header and payload. v3 continues to reject type 5 and NFC4.
- F6: Enable, CONFIG_APPLY, COUNTERS_RESET and schema3 state flushes share the App revision CAS path. APPLIED follows exact blob and revision readback. Pause clears partial window and tracker continuity, keeps cumulative counts and report sequence, and does not submit a partial report. The v4 snapshot exposes Enable and video freshness; live freshness reports `not_connected`.
- F7: App-side tests exercise malformed NFC3/NFC4 envelopes, reserved fields, request replay and conflict, session change, stale generations and revisions, CAS conflict, IO, unknown storage, torn writes and receipt loss. Host floor admission, identity rotation, cleanup and cross-repository interleavings remain NOT_RUN.

## AC4 cross-owner source-pinned matrix (r2)

### Source pins and build

- Host #104: `dc0948c1e12e954612fbfa9769434bf01e449c3c`.
- App source pin: the exact `APP_SHA` printed by `bash tests/line-crossing-enable/run_joint_matrix.sh`; the final delivery snapshot records the complete Candidate SHA.
- The runner archives Host from the pinned Git object into a temporary source snapshot, builds Host C tests there, then links Host `app_host_control.c`, Host installer/floor and state-store objects, and App #30 `lc_bus.c`, `lc_stateblob.c`, and `lc_ctrl.c` into `test_cross_owner_matrix`.
- The App test transport adapter only queues the command and captures the receipt. The floor algorithm, installer identity, state-store CAS and App codec/CAS/receipt code are the real pinned C implementations. The Host production control C entry is separately exercised and its current rejection is reported as a gap.
- The Host package vectors use the Host test suite's non-production test key. No production signing, package deployment, or hardware result is claimed.

### Matrix results

| Case | Component evidence | Full production-path status |
| --- | --- | --- |
| Current-session Paused | The combined C seam prepares and reads back the real Host floor before App write, matches owner/SPKI/TBS/package hashes and session/boot/request/config/expected revision, then verifies Host state-store readback against the App ENR1 APPLIED receipt. The observed floor SHA-256 is `8e1e9763ca62a5fdd77119d2d4ba6e1e438b36a513a2dee1a6ac0a0c9b0a6e67`; the schema3 state SHA-256 is `07bbc4b90412fee2a6196066e16c1895ff976f1b83823391f69348ea04a68c44`; session 17, boot 9001, request 401, config generation 1, expected revision 1, receipt revision 2. | NOT_RUN: the test adapter supplies the control delivery because Host #104 production control cannot admit this command or receipt. |
| Host precommit failure / UNKNOWN | Characterization: real Host floor raise returns `APP_INSTALL_ERR_STORAGE_STATE_UNKNOWN` (`-10`); no floor is stored; `app_native_vnext_floor_check(..., major=3)` returns `APP_INSTALL_OK` (`0`). | GAP: the first failed floor write leaves no conservative marker and old major 3 is admitted. No production Host-to-App command gate exists to prove command withholding. |
| App CAS conflict / torn / UNKNOWN / lost receipt | Combined real Host state-store race returns App receipt status 5/effective UNKNOWN, keeps App revision at 2 while Host is at 3, clears partial window, preserves report_seq 12, and submits no report. The 204-assertion App suite separately covers torn/IO/UNKNOWN readback and lost-receipt retry. | Component PASS; no optimistic APPLIED is observed. |
| Changed signer/TBS/generation, old v3 and retirement | Pinned Host installer/session suites exercise owner, key/TBS, major-floor and confirmed uninstall behavior; App v3 and Sidecar regression suites are listed in Verification matrix. | Component PASS where listed; lifecycle against the missing production ENABLE_SET seam remains NOT_RUN. |

The current Host #104 source gap is precise: `app_native_vnext_floor_raise` is defined in `Custom/Services/AppHost/app_sidecar_lifecycle.c` but has no production caller under `Custom/Services/AppHost`; `app_host_control_session_open` rejects v4 `ENABLE_CONTROL` (`0x100`); `app_host_control_register` rejects type 5; and `app_host_control_receipt` accepts exactly the 32-byte header, so it cannot verify the 48-byte ENR1 receipt. The source-pinned C test prints these observations and exits successfully only for its characterization assertions; they are not an AC4 PASS.

**Request to A:** classify the remaining complete Host-to-App Enable interlock as a post-merge A-owned integration gate, to be closed when the Host runtime/control seam is delivered. That gate must add a production caller which durably prepares and reads back the Host-owned floor before `control_next`, keep old-major admission fail-closed when floor precommit is UNKNOWN, and verify the 48-byte ENR1 against the same owner/session/config/revision and exact Host state-store readback. Do not count the primitive-sequence PASS above as the complete production positive case.

### Reproduction

```bash
APP_SHA=<exact App commit under test> bash tests/line-crossing-enable/run_joint_matrix.sh
```

Expected decisive output:

```text
HOST_PRECOMMIT_FAILURE=GAP raise=-10 floor_present=0 major3_check=0
HOST_CONTROL_SEAM=GAP bit8=-3 type5=-2 receipt48=-1
CROSS_PAUSE=PASS ... expected_revision=1 receipt_revision=2
APP_HOST_CAS_CONFLICT=PASS host_revision=3 app_revision=2 status=5 effective=3 partial_window=0 reports=0 report_seq=12
cross_owner_matrix: 67 checks, 0 failures
MATRIX_TESTS=PASS; FULL_AC4_PRODUCTION_GATE=NOT_RUN
```
