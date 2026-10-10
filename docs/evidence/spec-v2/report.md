# .neapp v2 candidate spec — offline vector evidence

- Spec: `docs/app-package-protocol-v2-draft.md` (Issue #12 candidate, NOT integrated)
- Suite: `python3 tests/spec-v2/run_all_tests.py` (stdlib-only; OpenSSL used as independent verifier)
- Vectors: **73/73 PASS**

## Golden v2 package (spec §10.1)
- `golden.neapp.v2` — 314B, SHA-256 `3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e`
- `golden-tbs.bin` — 244B, SHA-256 `e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278`
- `golden-sig.der` — 70B (pinned strict DER)
- `test-publisher.spki.der` — 91B, SHA-256 `5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3`
- key: public non-production P-256 scalar d=1 — MUST NOT be used as a production trust anchor

## Independent OpenSSL cross-proof
- `$ openssl dgst -sha256 -verify pub.pem -signature golden-sig.der golden-tbs.bin`
- exit **0**, output: `Verified OK`

## Rev 3 corrections (A self-audit review of d3dab54, AC2/AC4/AC3)
1. **AC2 publisher trust mapping**: `full_accept` resolves the issuer key from the Host-LOCAL `trusted_publishers` store keyed by the signed `publisher_id` and compares the manifest fingerprint against that store before verifying (spec §2.3 step 3/§3.1, fail-closed `PUBLISHER_UNTRUSTED`). Negatives `unknown_publisher_id` and `publisher_key_fingerprint_mismatch` are validly re-signed with attributable detail.
2. **AC2 host loader/region admission**: the simulated Host now carries its own `loader_base`/`loader_size`/`exec_region_bytes`; policy checks `native_target_addr` against the independently known loader range and `required_exec_region_bytes` against the actual exec region (spec §3.3, v1 §2.3). Negatives `target_outside_host_loader_range` and `exec_region_exceeds_host_actual` are validly re-signed. No production physical memory proof is claimed.
3. **AC4 strict model_meta wire**: `validate_model_meta` requires a NUL terminator, all-zero right padding, valid UTF-8 and zero reserved; malformed-wire negatives `model_name_no_nul`, `model_name_junk_after_nul`, `model_version_no_nul`, `model_meta_trailing_reserved_nonzero` added (INCOMPATIBLE).
4. **AC3 tick_ms semantics** (A decision issuecomment-6093724900): documented in spec §6.3/§6.4 as the sole exception to the negative-error-code channel — raw mod-2^32 time bits, progress measured by uint32 difference. Vectors: 0x7fffffff->0x80000000 and 0xffffffff->0x00000000 both advance +1; the signed-int32 misreading trap is documented. 48B table, C signatures and v1 code unchanged.

## Rev 2 corrections (A review of 7564c22, AC2/AC4 blockers)
1. **AC2 caps subset**: `policy_check_v2_host` now fail-closed rejects KNOWN capability bits the current Host does not provide (`ABI_INCOMPATIBLE`); negatives `caps_subset_host_missing_report_submit` + `caps_subset_negative_signature_valid` added.
2. **AC4 verify order + true payload tamper**: `full_accept` follows spec §2.3 order (bounded structure/manifest encoding -> ECDSA over raw TBS -> native cross-checks -> policy). `payload_tamper_detected` flips a dynamically computed TRUE payload byte (golden TBS true payload = [240,244); DER byte-identical) and asserts exactly `SIGNATURE_INVALID`; DER-region corruption moved to its own correctly labeled vector `der_region_tamper_detected`.
3. **AC4 ABI negative attribution**: `native_header_abi_mismatch_vs_manifest` keeps manifest `required_host_abi=0x00020000`, flips ONLY the native header ABI to `0x00010000` (manifest native SHA updated), re-signs, and requires the rejection detail to name the native<->manifest cross mismatch. The v2-container-declares-v1-ABI case (`v2_container_v1_abi`) remains a separate independent test. Rejection-attribution detail matching (`detail_contains`) also added to the archive negative.

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
| 21 | `caps_subset_negative_signature_valid` | signature valid | PASS |
| 22 | `caps_subset_host_missing_report_submit` | reject ABI_INCOMPATIBLE | PASS |
| 23 | `unknown_publisher_id` | reject PUBLISHER_UNTRUSTED | PASS |
| 24 | `publisher_negative_signature_valid` | signature valid | PASS |
| 25 | `publisher_key_fingerprint_mismatch` | reject PUBLISHER_UNTRUSTED | PASS |
| 26 | `target_outside_host_loader_range` | reject RESOURCE_LIMIT | PASS |
| 27 | `exec_region_exceeds_host_actual` | reject RESOURCE_LIMIT | PASS |
| 28 | `native_header_abi_mismatch_vs_manifest` | reject BAD_PACKAGE | PASS |
| 29 | `native_reserved0_nonzero` | reject BAD_PACKAGE | PASS |
| 30 | `manifest_native_len_mismatch` | reject BAD_PACKAGE | PASS |
| 31 | `der_trailing_byte` | reject BAD_PACKAGE | PASS |
| 32 | `der_truncated` | reject BAD_PACKAGE | PASS |
| 33 | `manifest_len_160_in_v2` | reject BAD_PACKAGE | PASS |
| 34 | `v1_magic_on_v2_container` | reject BAD_PACKAGE | PASS |
| 35 | `v2_package_on_v1_host` | reject BAD_PACKAGE | PASS |
| 36 | `nmf1_magic_in_v2` | reject BAD_PACKAGE | PASS |
| 37 | `payload_tamper_detected` | SIGNATURE_INVALID | PASS |
| 38 | `payload_tamper_openssl_rejects` | non-zero exit | PASS |
| 39 | `manifest_tamper_detected` | SIGNATURE_INVALID | PASS |
| 40 | `der_region_tamper_detected` | SIGNATURE_INVALID | PASS |
| 41 | `v1_golden_digest` | 9a212324132c0f26e2878384904f1af4abd3090a6ae5806ef32da2d3b4c80679 | PASS |
| 42 | `v1_golden_structural` | v1 gate PASS | PASS |
| 43 | `v1_golden_signature_valid` | signature valid | PASS |
| 44 | `v1_on_v2_host_caps_limited` | only v1 16B table semantics (M3) | PASS |
| 45 | `v1_golden_openssl` | Verified OK, exit 0 | PASS |
| 46 | `frame64_length_1576` | 1576B | PASS |
| 47 | `frame64_roundtrip` | kind=1 count=64 | PASS |
| 48 | `frame0_is_40b` | 40B FRAME(count=0) | PASS |
| 49 | `kind_model_changed_encodes` | 40B valid | PASS |
| 50 | `kind_gap_encodes` | 40B valid | PASS |
| 51 | `kind_stopping_encodes` | 40B valid | PASS |
| 52 | `event_unknown_kind` | reject BAD_EVENT | PASS |
| 53 | `event_unknown_flag_bit` | reject BAD_EVENT | PASS |
| 54 | `event_flag1_without_sentinel` | reject BAD_EVENT | PASS |
| 55 | `event_sentinel_without_flag1` | reject BAD_EVENT | PASS |
| 56 | `event_65_detections_encode` | reject BAD_EVENT | PASS |
| 57 | `event_65_detections_wire` | reject BAD_EVENT | PASS |
| 58 | `event_total_len_mismatch` | reject BAD_EVENT | PASS |
| 59 | `event_nonfinite_confidence` | reject BAD_EVENT | PASS |
| 60 | `event_class_index_oob` | reject BAD_EVENT | PASS |
| 61 | `model_meta_layout` | 128B, PP_TYPE_OD, fields ok | PASS |
| 62 | `model_meta_wrong_type_incompatible` | INCOMPATIBLE | PASS |
| 63 | `report_oversize_rejected` | QUOTA_EXCEEDED | PASS |
| 64 | `report_capacity_aligns_lc_dq` | 6144B | PASS |
| 65 | `model_name_no_nul` | reject INCOMPATIBLE | PASS |
| 66 | `model_name_junk_after_nul` | reject INCOMPATIBLE | PASS |
| 67 | `model_version_no_nul` | reject INCOMPATIBLE | PASS |
| 68 | `model_meta_trailing_reserved_nonzero` | reject INCOMPATIBLE | PASS |
| 69 | `tick_positive_small_delta` | delta 50 | PASS |
| 70 | `tick_wrap_7fffffff_to_80000000` | delta 1 (legal progress, not an error) | PASS |
| 71 | `tick_int32_trap_guard_80000000` | trap documented and guarded | PASS |
| 72 | `tick_wrap_ffffffff_to_00000000` | delta 1 (legal progress, not an error) | PASS |
| 73 | `tick_bits_out_of_range` | reject INVALID_ARGUMENT | PASS |

## Boundary (spec §12)
This evidence proves host-side byte/math/policy behavior of the candidate vectors only. No PASS is claimed or implied for: real v2 parsers, STM32 target builds/static asserts, device mbedTLS/PKA verification, sustained AI event delivery, cooperative-stop reclaim, storage atomicity/power-loss, or actual host resource capacities.