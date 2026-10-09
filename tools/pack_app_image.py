#!/usr/bin/env python3
"""Pack a built hello-app ELF into a NE301 app-host loadable image.

Layout is dictated solely by the pinned public ABI header (fetched by
tools/fetch_abi_header.sh): magic, format version, ABI version and header
size are read from that header, never hardcoded here.

Image = header + payload, where payload is the flat binary of the ELF and
entry_offset is resolved from the ELF symbol table (arm-none-eabi-nm) as
(app_entry - exec_base). Semantics follow the pinned reference packer
ne301 experiment/app-host-poc@a5b4bf3 tests/app_host/testapp/pack_image.py.
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path

DEFAULT_EXEC_BASE = 0x93E00000
DEFAULT_REGION_SIZE = 0x200000  # 2 MB app-host execution region


def parse_integer(value: str) -> int:
    return int(value, 0)


def read_define(header_text: str, name: str) -> int:
    pattern = rf"^\s*#define\s+{re.escape(name)}\s+(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\s*$"
    match = re.search(pattern, header_text, re.MULTILINE)
    if not match:
        raise ValueError(f"ABI header is missing numeric define {name}")
    return int(match.group(1), 0)


def resolve_entry_offset(elf: Path, nm: str, exec_base: int, payload_size: int) -> int:
    out = subprocess.check_output([nm, "-g", str(elf)], text=True)
    addresses = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "app_entry":
            addresses.append(int(parts[0], 16))
    if not addresses:
        raise ValueError("app_entry symbol not found in ELF (must be global)")
    if len(addresses) > 1:
        raise ValueError(f"app_entry defined more than once: {[hex(a) for a in addresses]}")
    offset = addresses[0] - exec_base
    if offset < 0:
        raise ValueError(f"app_entry {addresses[0]:#x} below exec base {exec_base:#x}")
    if offset % 2 != 0:
        raise ValueError(f"entry offset {offset:#x} is not even")
    if offset >= payload_size:
        raise ValueError(f"entry offset {offset:#x} outside payload size {payload_size}")
    return offset


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path, help="linked app ELF")
    parser.add_argument("--out", required=True, type=Path, help="output image path")
    parser.add_argument("--abi-header", required=True, type=Path,
                        help="pinned app_host_abi.h (single authority for magic/version/size)")
    parser.add_argument("--payload", type=Path,
                        help="flat payload bin; derived from --elf via objcopy when omitted")
    parser.add_argument("--exec-base", type=parse_integer, default=DEFAULT_EXEC_BASE,
                        help=f"app execution base address (default {DEFAULT_EXEC_BASE:#x})")
    parser.add_argument("--region-size", type=parse_integer, default=DEFAULT_REGION_SIZE,
                        help=f"execution region size in bytes (default {DEFAULT_REGION_SIZE:#x})")
    parser.add_argument("--nm", default="arm-none-eabi-nm")
    parser.add_argument("--objcopy", default="arm-none-eabi-objcopy")
    args = parser.parse_args()

    abi_text = args.abi_header.read_text(encoding="utf-8")
    magic = read_define(abi_text, "APP_HOST_IMAGE_MAGIC")
    format_version = read_define(abi_text, "APP_HOST_IMAGE_FORMAT_VERSION")
    abi_version = read_define(abi_text, "APP_HOST_ABI_VERSION")
    header_size = read_define(abi_text, "APP_HOST_IMAGE_HEADER_SIZE")
    if header_size != 32:
        raise ValueError(f"pinned header size {header_size} != 32; v1 packer needs an update")

    payload_path = args.payload
    if payload_path is None:
        payload_path = args.out.with_suffix(".payload.bin")
        subprocess.check_call([args.objcopy, "-O", "binary", str(args.elf), str(payload_path)])
    payload = payload_path.read_bytes()
    if not payload:
        raise ValueError("payload is empty")

    if len(payload) > args.region_size:
        raise ValueError(f"payload {len(payload)} exceeds execution region {args.region_size}")

    entry_offset = resolve_entry_offset(args.elf, args.nm, args.exec_base, len(payload))
    crc = zlib.crc32(payload) & 0xFFFFFFFF

    header = struct.pack(
        "<IHHIIIIII",
        magic,
        header_size,
        format_version,
        abi_version,
        args.exec_base,
        len(payload),
        entry_offset,
        0,
        crc,
    )
    assert len(header) == header_size, "packed header size mismatch"

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("wb") as f:
        f.write(header)
        f.write(payload)

    print(
        f"packed {args.out}: header {header_size} B + payload {len(payload)} B = "
        f"{header_size + len(payload)} B, entry_offset {entry_offset:#x}, crc32 {crc:#010x}, "
        f"abi {abi_version:#010x}, target {args.exec_base:#010x}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
