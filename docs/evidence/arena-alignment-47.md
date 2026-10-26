# Arena alignment fix evidence (Issue #47, NE301 #48 defect 8)

## Device evidence chain

Fifth device round (NE301 #48, v4.3.1.182 host): `UFSR.UNALIGNED` (CFSR=0x01000000), PC=0x93e04bfa = `ldrd r2,r4,[r0]` at the scan-loop head of `lcapp_alloc`, r0=0x93e0b8bd (odd). Native ELF symbol table: `lc_arena_pool` at 0x93e0b8bd. `.bss` in `lc_app.ld` aligns only the section start; `uint8_t[96KiB]` has natural alignment 1, and the three preceding statics occupied 9 bytes, leaving the pool at an odd address. Block headers are `lc_block_t` (uint64_t member, 8B alignment requirement) accessed via `ldrd`, which faults on non-word-aligned operands on Cortex-M55.

## Fix

`apps/line-crossing/app/lc_arena.c`: `static _Alignas(8) uint8_t lc_arena_pool[LC_ARENA_SIZE];` (one line). Syntax-checked with clang and arm-none-eabi-gcc (-std=gnu11, -mcpu=cortex-m55).

## Symbol layout, before/after (real ARM v4 ELF, arm-none-eabi-nm)

| symbol | before (4.1.1) | after (4.1.2 candidate) |
| --- | --- | --- |
| lc_arena_high | 0x93e0b8b4 | 0x93e0b8ac |
| lc_arena_used_now | 0x93e0b8b8 | 0x93e0b8b0 |
| lc_arena_ready | 0x93e0b8bc | 0x93e0b8b4 |
| lc_arena_pool | 0x93e0b8bd (odd) | **0x93e0b8b8 (%8==0)** |

Static invariant: LC_ARENA_SIZE=98304≡0 (mod 8), sizeof(lc_block_t)=8, LC_ARENA_ALIGN=8, so every split/coalesce step advances by 8-multiples from an 8-aligned base; all block headers and returned pointers remain 8-aligned.

## Bounded audit of the same defect class (apps/line-crossing/app/**)

| site | pattern | verdict |
| --- | --- | --- |
| lc_arena.c (4 casts) | lc_block_t* onto byte arena | fixed by pool alignment |
| lc_app_event_buf (v2/v3/v4 entries) | host fills via api->event_next; app parses via lc_rd_u32(ev + 4*k) byte reads | alignment-independent |
| lc_ctrl_cmd_buf / lc_ctrl_snapshot_buf / stack header r[] | lc_wr_u32/lc_rd_u32 byte codec | alignment-independent |
| lc_cfgcodec buffers | wr_u16/rd_u32 byte codec | alignment-independent |
| src/lc_tracker.c (read-only, outside writable scope) | state kept in structs, no uint8_t-backed struct casts onto odd-capable storage | no instance found |

No other uint8_t buffer is cast to a higher-alignment type in the app native sources.

## Regression tests (tests/unsigned/test_arena_alignment.py)

- `test_pool_symbol_8_byte_aligned_in_real_arm_elf`: builds the real v4 ELF via `make elf-v4` and asserts `lc_arena_pool % 8 == 0` from `arm-none-eabi-nm`. Reverse proof: with the fix reverted the test fails at exactly `0x93e0b8bd`; with the fix it passes (pool at 0x93e0b8b8). This test runs in the existing CI verify job (unittest discover -s tests/unsigned runs after the real ELF build step).
- `test_allocator_functional_on_host`: compiles lc_arena.c natively (cc -std=gnu11) and covers first allocation, pointer alignment, split, free-list reuse, coalesce-to-full (96K-16 reallocatable after freeing all), arena_used==0, and exhaustion returning NULL.

## 4.1.2 candidate package (offline, official path)

Built from the candidate tree with `make clean-v4` then `make neapp-v5 V4_APP_VERSION=4.1.2` (packaging params come from the merged #46 Makefile: caps 0x3ff, event 1576, state 512, report 6144, control 256, snapshot 1024, live_publish 9008, live_track 64; packer defaults untouched).

- Package: `line-crossing-4.1.2.neapp`, 474,866 B, SHA256 `0991cd1471c08e8df1963ad1fa4493008fe052617a1708e3632ab212f905173e`
- `neapp_verify_v5 --compact`: result PASS, required_host_caps=0x3ff, all seven quotas present, native_version 4.1.2, ui_version 1.1.1, run_profile 3, target_board_id 0x3010, required_host_abi 0x00040000
- UI assets: all 7 file SHA256s identical to the device-validated 4.1.1 package (37ca34e7…, caa915f0…, 450a3f70…, 87b8dac8…, 0f07f17e…, 9987a618…, d46f6db9…); ui_member_sha256 differs only by the manifest's native binding version (4.1.1 -> 4.1.2), by design
- Provenance: `build/pkg/line-crossing-4.1.2.neapp.provenance.json` includes the host_policy block

## Boundary

All evidence above is offline. Nothing here claims device execution, #48 AC2/AC3/AC5, state persistence on hardware, or release readiness. CI green on this PR is necessary, not sufficient.
