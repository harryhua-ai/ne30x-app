# NEUI Sidecar v1 offline pack/verify — evidence report (Issue #26)

- Protocol authority: ne301 issue #79 §12 (frozen Sidecar v1 wire, 2026-10-15)
- Source commit: `28a515408c803ad304cffe3fc8dbc71f968a9995`
- Toolchain: python 3.14.4, cryptography 48.0.0, OpenSSL 3.6.2 7 Apr 2026 (Library: OpenSSL 3.6.2 7 Apr 2026)
- Cases: 90 total — 13 positive/predicate, 63 verifier rejection, 14 packer refusal

## Golden vector (deterministic, PUBLIC d=1 test signer)

| quantity | value |
| --- | --- |
| bundle / tbs / der bytes | 968 / 896 / 72 |
| `ui_tbs_sha256` | `aa8130ea20737d457bb6ace49871daa82e85338c7b2e2da656edcc9b7f3fe02f` |
| bundle `sha256` | `9ec5e44616e197dfa0b3d16a5f9b0f280b523883be2c1cddf4f363126e8f79d4` |
| signer SPKI `sha256` | `5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3` |
| `native_tbs_sha256` binding | `d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e` (from docs/evidence/spec-v3/golden.neapp.v3, offline-verified before packing) |
| fixture files | 4 (base fixture; sha256 pinned in report.json) |

Repack idempotency: the same fixture + metadata + key reproduce the identical TBS and (RFC-6979) identical bundle bytes; a low-S DER re-encoding over the same TBS keeps the same `ui_tbs_sha256` (no low-S assumption).

## Boundary

OFFLINE packaging evidence only; NOT NE301 Host verification/admission/install, NOT device LittleFS free space, RAM, dual-artifact transaction, camera H264, browser trusted loading, or User product acceptance; the §12.2 caps are maximum accepted bundle-INPUT limits, not a device installability promise; signing identities are NON-PRODUCTION test roots (the PUBLIC spec d=1 key and ephemeral test keys) and never device production trust roots

## Case detail

Every verifier rejection asserts its expected error class AND a detail-substring attribution; full case list with observed details is in `report.json` (`case_suite.cases`).
