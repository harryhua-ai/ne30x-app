# AC3 App/Host signed-package interoperability

Status: PASS for the offline cross-repository parser matrix.

- App signer/independent verifier source: `71f1850063f022b86f3b027e27eaabb992de60b0`
- App candidate at evidence run: `76cf1fccd49e8911f4fa385e90e582a44bdd2b29`
- Host parser/verifier source: `f6a851a3c1c116f85d9a2609c9d8b63b1d0a66f1`
- Host source was archived from that exact commit into a temporary directory; the Host repository was not modified.
- Reproduction: `bash tests/package-vnext/run.sh` or `python3 tests/package-vnext/joint_interop.py`.
- Complete commands and stdout: [`joint-interop.log`](joint-interop.log).
- Structured report includes exact package bytes as hex: [`joint-interop.json`](joint-interop.json).

## Exact App-signed packages

The App baseline packer generated each signed package, and the script required full-byte equality with both the archived golden and the Host fixture before invoking the Host C parser.

| Profile | Binary | Bytes | Package SHA-256 | SHA-256(TBS) | Image SHA-256 | Publisher / SPKI SHA-256 | Required caps | Signature | Quotas |
| --- | --- | ---: | --- | --- | --- | --- | --- | ---: | --- |
| live-only | [`live-only.neapp.v4`](spec/app-pr37/live-only.neapp.v4) | 394 | `ba64faefea77a1569a2b96f86a4ac356d34f27cbd7e90808af21b7a9b38ae2b2` | `5c61a2522b566af23f46d56cdb6ba82db11a663a2ff6bde7c86fc5981e78111c` | `845e09288e0f1d876832dcda553580c6aa64ef17f08b9e529550aefa4db12cd1` | `dev-publisher` / `dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba` | `0x223` | 70 B DER | event_max=0, state_quota=0, report_max=0, control_max=0, snapshot_max=0, live_publish_max=9008, live_track_max=64 |
| enable | [`enable.neapp.v4`](spec/app-pr37/enable.neapp.v4) | 395 | `1d6356272535efc854eb968ea23f694144b111ab1830137a81d7dad7461c75a7` | `26df9606642ae23fe14ca570e8ad5c3b88097a1e8d88a18008dae7e0b40127f4` | `845e09288e0f1d876832dcda553580c6aa64ef17f08b9e529550aefa4db12cd1` | `dev-publisher` / `dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba` | `0x173` | 71 B DER | event_max=0, state_quota=4096, report_max=0, control_max=256, snapshot_max=0, live_publish_max=0, live_track_max=0 |

The live-only profile is caps `0x223` (bits 0, 1, 5, 9), with no bit 6 and zero control/snapshot quotas; its 9008-byte publish and 64-track closure passes. The Enable profile is caps `0x173` (bits 0, 1, 4, 5, 6, 8), with `state_quota=4096` and `control_max=256` for ENB1 control.

Both package byte strings and SPKI DER byte strings are preserved under [`spec/app-pr37/`](spec/app-pr37/). Their exact bytes are also embedded in `joint-interop.json`.

## Same-byte App verifier / Host C parser matrix

Each row feeds the same package file to the App v4 verifier and the compiled `app_admission_verify_package` C implementation from the pinned Host source. The table reports the full package SHA-256 so the compared input is unambiguous.

| Case | App result | Host C result | Expected category | Same category | Package SHA-256 |
| --- | --- | --- | --- | --- | --- |
| live-only | `PASS` | `PASS` | `PASS` | PASS | `ba64faefea77a1569a2b96f86a4ac356d34f27cbd7e90808af21b7a9b38ae2b2` |
| enable | `PASS` | `PASS` | `PASS` | PASS | `1d6356272535efc854eb968ea23f694144b111ab1830137a81d7dad7461c75a7` |
| tbs-tamper | `SIGNATURE_INVALID` | `SIGNATURE_INVALID` | `SIGNATURE_INVALID` | PASS | `665aac288b3cd472c8927026c840880e15e0f6fb98bc1151b9551307a6962bc3` |
| signature-tamper | `SIGNATURE_INVALID` | `SIGNATURE_INVALID` | `SIGNATURE_INVALID` | PASS | `de9ceea38eeb8843fec521703e927a8d34552b7bbe2eefaaa4af48797c21890d` |
| unsigned | `BAD_PACKAGE` | `BAD_PACKAGE` | `BAD_PACKAGE` | PASS | `5c61a2522b566af23f46d56cdb6ba82db11a663a2ff6bde7c86fc5981e78111c` |
| cross-major | `BAD_PACKAGE` | `BAD_PACKAGE` | `BAD_PACKAGE` | PASS | `75fdf7dd79453c589798c6c1201b54ae7241ba04bcb1036eaf40643474140e81` |
| wrong-spki | `PUBLISHER_UNTRUSTED` | `PUBLISHER_UNTRUSTED` | `PUBLISHER_UNTRUSTED` | PASS | `ba64faefea77a1569a2b96f86a4ac356d34f27cbd7e90808af21b7a9b38ae2b2` |
| wrong-owner | `PUBLISHER_UNTRUSTED` | `PUBLISHER_UNTRUSTED` | `PUBLISHER_UNTRUSTED` | PASS | `ba64faefea77a1569a2b96f86a4ac356d34f27cbd7e90808af21b7a9b38ae2b2` |
| enable-missing-bit6 | `BAD_PACKAGE` | `BAD_PACKAGE` | `BAD_PACKAGE` | PASS | `68a51c75de2c09cb27a64bfa248fe9888be23ed5d8c958fe1eae18d4188fe1a4` |
| live-closure | `RESOURCE_LIMIT` | `RESOURCE_LIMIT` | `RESOURCE_LIMIT` | PASS | `4e9884953165d2eb17387796e708f6e596faf65301c6112242f6a4e9502a4a47` |
| host-live-capability-denied | `ABI_INCOMPATIBLE` | `ABI_INCOMPATIBLE` | `ABI_INCOMPATIBLE` | PASS | `ba64faefea77a1569a2b96f86a4ac356d34f27cbd7e90808af21b7a9b38ae2b2` |
| exec-region-floor | `RESOURCE_LIMIT` | `RESOURCE_LIMIT` | `RESOURCE_LIMIT` | PASS | `ba64faefea77a1569a2b96f86a4ac356d34f27cbd7e90808af21b7a9b38ae2b2` |

The negatives exercise TBS/signature mutation, unsigned input, unknown major generation, wrong SPKI and publisher owner, missing Enable dependency bit 6, live closure overrun, unsupported live capability, and execution-region floor. Each was constructed so the tested parser rule fires; signed semantic negatives were re-signed with the public d=2 test scalar.

## Host integration and runtime boundary

- `app_native_vnext`: 77 checks, 0 failures.
- `app_host_session`: 592 checks, 0 failures.
- Live runtime authorization: `APP_SESSION_ERR_UNAVAILABLE; Host #91 producer-ingest is not implemented`. Shape verification PASS does not grant live runtime access; Host #91 producer-ingest remains unavailable.
- NE301 firmware ARM target build, device install/execute, production signing keys, and production/device behavior: NOT_RUN.
- The separate required package-v3 legacy regression cross-compiled only its synthetic hello-app fixtures with `arm-none-eabi-gcc`; it did not build NE301 firmware.
