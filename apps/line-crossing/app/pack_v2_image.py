#!/usr/bin/env python3
"""pack_v2_image — pack the built Line Crossing App ELF into a NEA1 native
image with the v2 Host ABI (abi_version 0x00020000).

Mirrors tools/pack_app_image.py (P3, Issue #6) field-for-field except that
the ABI version is PINNED to 0x00020000 (v2 spec §3.3: manifest
required_host_abi must equal the native header abi_version; a v1-ABI image
can never be presented as a v2 app).  The 32B NEA1 header layout, CRC-32
over the payload and entry_offset resolution via arm-none-eabi-nm are the
same frozen format.

OFFLINE tooling: producing this image means nothing was installed or run on
a device (v2 spec §12).
"""

from __future__ import annotations

import argparse
import struct
import subprocess
import sys
import zlib
from pathlib import Path

ABI_V2 = 0x00020000
NATIVE_HDR = struct.Struct("<IHHIIIIII")
DEFAULT_EXEC_BASE = 0x93E00000
DEFAULT_REGION_SIZE = 0x200000


def parse_int(v: str) -> int:
    return int(v, 0)


def resolve_entry_offset(elf: Path, nm: str, exec_base: int, payload_size: int) -> int:
    out = subprocess.check_output([nm, "-g", str(elf)], text=True)
    addrs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "app_entry":
            addrs.append(int(parts[0], 16))
    if not addrs:
        raise ValueError("app_entry symbol not found in ELF (must be global)")
    if len(addrs) > 1:
        raise ValueError(f"app_entry defined more than once: {[hex(a) for a in addrs]}")
    off = addrs[0] - exec_base
    if off < 0:
        raise ValueError(f"app_entry {addrs[0]:#x} below exec base {exec_base:#x}")
    if off % 2 != 0:
        raise ValueError(f"entry offset {off:#x} is not even")
    if off >= payload_size:
        raise ValueError(f"entry offset {off:#x} outside payload size {payload_size}")
    return off


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--elf", required=True, type=Path)
    p.add_argument("--payload", required=True, type=Path, help="flat payload bin (objcopy)")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--exec-base", type=parse_int, default=DEFAULT_EXEC_BASE)
    p.add_argument("--region-size", type=parse_int, default=DEFAULT_REGION_SIZE)
    p.add_argument("--nm", default="arm-none-eabi-nm")
    args = p.parse_args()

    payload = args.payload.read_bytes()
    if not payload:
        print("ERROR: payload is empty", file=sys.stderr)
        return 2
    if len(payload) > args.region_size:
        print(f"ERROR: payload {len(payload)} exceeds region {args.region_size}", file=sys.stderr)
        return 2
    entry = resolve_entry_offset(args.elf, args.nm, args.exec_base, len(payload))
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    header = NATIVE_HDR.pack(
        0x3141454E,      # "NEA1"
        32,              # header_size
        1,               # format_version
        ABI_V2,          # pinned v2 ABI
        args.exec_base,
        len(payload),
        entry,
        0,               # reserved0
        crc,
    )
    assert len(header) == 32
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(header + payload)
    print(
        f"packed {args.out}: 32B NEA1 v2 header + {len(payload)}B payload = {32 + len(payload)}B, "
        f"entry_offset {entry:#x}, crc32 {crc:#010x}, abi {ABI_V2:#010x}, target {args.exec_base:#010x}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
