# .neapp v2 candidate spec — offline vector evidence

- Spec: `docs/app-package-protocol-v2-draft.md` (Issue #12 candidate, NOT integrated)
- Suite: `python3 tests/spec-v2/run_all_tests.py` (stdlib-only; OpenSSL used as independent verifier)
- Vectors: **56/56 PASS**

## Golden v2 package (spec §10.1)
- `golden.neapp.v2` — 314B, SHA-256 `3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e`
- `golden-tbs.bin` — 244B, SHA-256 `e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278`
- `golden-sig.der` — 70B (pinned strict DER)
- `test-publisher.spki.der` — 91B, SHA-256 `5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3`
- key: public non-production P-256 scalar d=1 — MUST NOT be used as a production trust anchor

## Independent OpenSSL cross-proof
- `$ openssl dgst -sha256 -verify pub.pem -signature golden-sig.der golden-tbs.bin`
- exit **0**, output: `Verified OK`

## Negative reference artifacts
- `negative-archive-1024-4096.neapp.v2` — 314B, SHA-256 `f05ca613d7ea2e74f61cdd5cc2bbc9f44a4406eca216366fee81894b6b664e24` (spec §8 M7 resource-insufficient negative; never a business-positive sample)
- `v1-golden.neapp` — 284B, SHA-256 `9a212324132c0f26e2878384904f1af4abd3090a6ae5806ef32da2d3b4c80679` (frozen v1 §2.5 golden, rebuilt byte-for-byte; interop input only)

## Vector results
| # | vector | expected | status |
| --- | --- | --- | --- |
| 1 | `golden_tbs_length` | 244B | PASS |
| 2 | `golden_tbs_digest_pinned` | e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278 | PASS |
| 3 | `golden_pkg_length` | 314B | PASS |
| 4 | `golden_pkg_digest_pinned` | 3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e | PASS |
| 5 | `golden_structural_manifest_native_policy` | full acceptance | PASS |
| 6 | `golden_crypto_pure_python` | ECDSA valid | PASS |
| 7 | `golden_spki_digest_pinned` | 5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3 | PASS |
| 8 | `golden_crypto_openssl` | Verified OK, exit 0 | PASS |
| 9 | `archive_tbs_digest_pinned` | 60e708cb083a3be066420874da75eeaefcec5ec8106844456b922fc1d9bf8226 | PASS |
| 10 | `archive_pkg_digest_pinned` | f05ca613d7ea2e74f61cdd5cc2bbc9f44a4406eca216366fee81894b6b664e24 | PASS |
| 11 | `archive_signature_math_valid` | signature valid | PASS |
| 12 | `archive_quota_1024_4096_resource_limit` | reject RESOURCE_LIMIT | PASS |
| 13 | `caps_unknown_bit6` | reject BAD_PACKAGE | PASS |
| 14 | `caps_unknown_bit6_signature_valid` | signature valid | PASS |
| 15 | `reserved_176_nonzero` | reject BAD_PACKAGE | PASS |
| 16 | `reserved_58_59_nonzero` | reject BAD_PACKAGE | PASS |
| 17 | `unknown_run_profile` | reject BAD_PACKAGE | PASS |
| 18 | `profile1_without_bit5` | reject BAD_PACKAGE | PASS |
| 19 | `ai_events_zero_event_max` | reject BAD_PACKAGE | PASS |
| 20 | `v2_container_v1_abi` | reject BAD_PACKAGE | PASS |
| 21 | `native_header_abi_v1_mismatch` | reject BAD_PACKAGE | PASS |
| 22 | `native_reserved0_nonzero` | reject BAD_PACKAGE | PASS |
| 23 | `manifest_native_len_mismatch` | reject BAD_PACKAGE | PASS |
| 24 | `der_trailing_byte` | reject BAD_PACKAGE | PASS |
| 25 | `der_truncated` | reject BAD_PACKAGE | PASS |
| 26 | `manifest_len_160_in_v2` | reject BAD_PACKAGE | PASS |
| 27 | `v1_magic_on_v2_container` | reject BAD_PACKAGE | PASS |
| 28 | `v2_package_on_v1_host` | reject BAD_PACKAGE | PASS |
| 29 | `nmf1_magic_in_v2` | reject BAD_PACKAGE | PASS |
| 30 | `payload_tamper_detected` | SIGNATURE_INVALID | PASS |
| 31 | `payload_tamper_openssl_rejects` | non-zero exit | PASS |
| 32 | `manifest_tamper_detected` | SIGNATURE_INVALID | PASS |
| 33 | `v1_golden_digest` | 9a212324132c0f26e2878384904f1af4abd3090a6ae5806ef32da2d3b4c80679 | PASS |
| 34 | `v1_golden_structural` | v1 gate PASS | PASS |
| 35 | `v1_golden_signature_valid` | signature valid | PASS |
| 36 | `v1_on_v2_host_caps_limited` | only v1 16B table semantics (M3) | PASS |
| 37 | `v1_golden_openssl` | Verified OK, exit 0 | PASS |
| 38 | `frame64_length_1576` | 1576B | PASS |
| 39 | `frame64_roundtrip` | kind=1 count=64 | PASS |
| 40 | `frame0_is_40b` | 40B FRAME(count=0) | PASS |
| 41 | `kind_model_changed_encodes` | 40B valid | PASS |
| 42 | `kind_gap_encodes` | 40B valid | PASS |
| 43 | `kind_stopping_encodes` | 40B valid | PASS |
| 44 | `event_unknown_kind` | reject BAD_EVENT | PASS |
| 45 | `event_unknown_flag_bit` | reject BAD_EVENT | PASS |
| 46 | `event_flag1_without_sentinel` | reject BAD_EVENT | PASS |
| 47 | `event_sentinel_without_flag1` | reject BAD_EVENT | PASS |
| 48 | `event_65_detections_encode` | reject BAD_EVENT | PASS |
| 49 | `event_65_detections_wire` | reject BAD_EVENT | PASS |
| 50 | `event_total_len_mismatch` | reject BAD_EVENT | PASS |
| 51 | `event_nonfinite_confidence` | reject BAD_EVENT | PASS |
| 52 | `event_class_index_oob` | reject BAD_EVENT | PASS |
| 53 | `model_meta_layout` | 128B, PP_TYPE_OD, fields ok | PASS |
| 54 | `model_meta_wrong_type_incompatible` | INCOMPATIBLE | PASS |
| 55 | `report_oversize_rejected` | QUOTA_EXCEEDED | PASS |
| 56 | `report_capacity_aligns_lc_dq` | 6144B | PASS |

## Boundary (spec §12)
This evidence proves host-side byte/math/policy behavior of the candidate vectors only. No PASS is claimed or implied for: real v2 parsers, STM32 target builds/static asserts, device mbedTLS/PKA verification, sustained AI event delivery, cooperative-stop reclaim, storage atomicity/power-loss, or actual host resource capacities.