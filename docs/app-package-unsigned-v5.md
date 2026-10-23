# Unsigned `.neapp` v5 package format

Authority: ne301 issue #136 (cross-repo single behavior change). The byte-level
authority for this repository is `package/unsigned/neapp_v5_format.py`; this
document describes exactly those bytes. The Host side (ne301
`Custom/Services/AppHost`) implements the same container independently. All
integers are unsigned little-endian.

The format is the production NEPK v1.1 two-member container (header + signed
native v4 member + signed NEUI v1 member + domain/seq/signature) with every
trust and signature element removed. No private key, SPKI, signature value,
release sequence, ledger, or remote signing step participates anywhere in
packing or verification. Container magic: v1/v2/v3 exist
(`4e45415050010000`/`020000`/`030000`) and v4 (`4e45415050040000`) is the
frozen signed native vNext container still in production use as the NEPK native
member, so the unsigned format takes the next free container major:
**`4e45415050050000`** ("NEAPP" + LE32(5)).

## Container

```
offset  len  field
0       8    magic = 4e 45 41 50 50 05 00 00
8       4    native_member_len  (u32, 241..2097360)
12      4    ui_member_len      (u32, 184..2113552)
16      N    native member (N = native_member_len)
16+N    U    ui member (U = ui_member_len), EOF exactly at 16+N+U
```

Total package length must equal `16 + native_member_len + ui_member_len`
exactly (u64-checked arithmetic; package cap 4,210,928 bytes). There is no
trailer: no pair signature, no `NEPAIR1\0` domain separator, no release
sequence.

## Native member (NMF5 manifest + native image)

The 208-byte manifest reuses the frozen NMF4 layout with the two trust slots
emptied (required all-zero) and the magic replaced by `NMF5`; every other field
keeps its NMF4 offset and semantics (required_host_abi pinned `0x00040000`,
run_profile pinned 3, caps within `0x000003FF`, quota rules, live-quota
closure):

```
manifest offset  len  field
0                4    magic = 4e 4d 46 35 ("NMF5")
4                16   publisher_id slot: REQUIRED all zero (trust removed)
20               32   app_id ([a-z0-9-], starts lowercase letter, NUL padded)
52               2    version_major (>= 1)
54               2    version_minor
56               2    version_patch
58               2    reserved: REQUIRED zero
60               4    target_board_id (0x00003010)
64               4    required_psram_mib (64)
68               4    required_host_abi (0x00040000)
72               4    required_host_caps (<= 0x000003FF)
76               4    required_exec_region_bytes (>= native_image_size)
80               4    native_file_len (= 32 + native_image_size = N - 208)
84               4    native_image_size
88               4    native_entry_offset (even, < native_image_size)
92               4    native_target_addr (0x93E00000)
96               32   native_file_sha256 = SHA-256(native image bytes)
128              32   publisher_key_sha256 slot: REQUIRED all zero (trust removed)
160              4    run_profile (3)
164              4    event_max
168              4    state_quota
172              4    report_max
176              4    control_max (>= 32 with capability bit6)
180              4    snapshot_max
184              4    live_publish_max
188              4    live_track_max
192              16   reserved: REQUIRED all zero
```

The native image at manifest offset 208 is the unchanged v4 native image: 32B
NEA1 header (format_version 1, header_size 32, reserved0 0, abi_version
`0x00040000`, target_addr, image_size, entry_offset, CRC-32 of payload) plus
payload, cross-checked against the manifest fields. The packer derives it from
the real ARM ELF via `package/vnext/neapp_v4_image.py` and refuses an ELF that
does not embed the marker `<app-id>-app <MAJOR.MINOR.PATCH>: v4 session entry`.

## UI member (unsigned NEUI v5)

The member reuses the NEUI v1 sidecar wire with the version bump aligned to the
container major (`4e45554905000000` = "NEUI" + LE32(5)), the two trust slots
emptied, the native binding slot carrying the SHA-256 of the whole native
member, and no trailing signature:

```
offset  len  field
0       8    magic = 4e 45 55 49 05 00 00 00
8       4    manifest_len (u32, 167..16384)
12      4    asset_payload_len (u32, 1..2097152, = sum of record file_len)
16      M    manifest (M = manifest_len)
16+M    A    asset payload bytes in record order, EOF exactly at 16+M+A
```

Manifest fixed block (128 bytes):

```
offset  len  field
0       16   publisher_id slot: REQUIRED all zero (trust removed)
16      32   app_id (must equal the native manifest app_id)
48      32   publisher_key_sha256 slot: REQUIRED all zero (trust removed)
80      32   native_member_sha256 = SHA-256(entire native member bytes)
112     2    ui version_major (>= 1)
114     2    ui version_minor
116     2    ui version_patch
118     2    file_count (1..64)
120     4    host_ui_abi (1)
124     4    reserved: REQUIRED zero
128     ..   records, in strict ascending raw-ASCII path order
```

Each record: `path_len u16 (1..160), file_len u32 (1..1048576), sha256[32],
path bytes`. Path rules are the frozen NEUI v1 rules (relative, ASCII,
`[A-Za-z0-9._-]` segments, no `..`/`.`/backslash/percent/colon/query/fragment,
no case-fold collisions, exactly one root `index.html`). Every asset's
SHA-256 is checked against its record at verification.

## Verification semantics

`verify_package_v5` (and CLI `neapp_verify_v5.py`) accepts only the magic
above, enforces every bound/reserved/cross-check field, validates the v4
manifest policy shape (unknown capability bits, bit8/bit9 prerequisites,
quota/capability consistency, live-quota closure), checks the native image
NEA1 header/CRC-32/SHA-256, the UI record digests and payload sum, the
native/UI member binding (`native_member_sha256`), and the app_id agreement
between both members. An optional target-Host admission tier (mirroring the
frozen v4 DevicePolicy fields: board, PSRAM, ABI, host caps, quotas, live
capacity, loader geometry) can be enabled with `--host-policy`.

Legacy signed inputs are identified, never parsed as v5: files starting with
the neapp v1/v2/v3/v4 magics, the NEUI v1 sidecar magic, or the `NEPK` prefix
are rejected with `LEGACY_SIGNED_FORMAT` and an explicit "unsupported legacy
signed format" detail. Unknown magics are rejected as `BAD_PACKAGE`.

## Integrity and trust boundary

SHA-256 here is consistency checking (detect transfer/storage corruption and
member mismatches) and nothing more: it cannot prove origin because anyone
allowed to modify the package can recompute every digest. Runtime semantics
(explicit run, no autostart, Native+UI binding, install transaction) are
carried by the manifest policy fields above exactly as in the frozen v4
conventions; their enforcement remains a Host administrator-gated concern.

## Reproduction

```sh
make -C apps/line-crossing/app elf-v4 V4_APP_VERSION=4.0.0
(cd tests/line-crossing-ui && pnpm install && npm ci --prefix browser-runner && node browser-runner/build.mjs)
make -C apps/line-crossing/app neapp-v5 V4_APP_VERSION=4.0.0
```

The output is `apps/line-crossing/app/build/pkg/line-crossing-4.0.0.neapp`
(real ELF + production UI, verified in CI and locally). A fully deterministic
committed sample plus a real-build sample live in `tests/fixtures/`:

- `line-crossing-4.0.0.neapp` (716 B,
  sha256 `0b35833f7fc052de85b99ba7138f2f5db3f9356e2e56e1172cf6675806dc5356`)
  is byte-reproducible from `tests/unsigned/support.py` inputs and is
  re-checked by `tests/unsigned/test_pack.py`.
- `line-crossing-4.0.0-real.neapp` (474,854 B,
  sha256 `18f206e78114730dda99df9ea236a01fd2b5f3cc3e8c433bb5e200a1bc1988c7`)
  is the real-ELF + production-UI build sample for cross-repo parsing.
