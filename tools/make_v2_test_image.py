#!/usr/bin/env python3
"""make_v2_test_image — deterministic controlled NEA1 native test image with
the v2 Host ABI (for .neapp v2 packaging tests, Issue #13 AC1).

The image is a pure host-side artifact: a 32B NEA1 header (magic "NEA1",
header_size 32, format_version 1, abi_version 0x00020000, reserved0 0) plus a
caller-supplied payload, with the reflected-IEEE CRC-32 over the payload
written into the header.  The default payload `00207047` is a minimal
well-formed Thumb-2 function (`movs r0, #0; bx lr` — return 0); no business
algorithm, no device build and no apps/hello-app source is involved.

Deterministic: identical arguments produce identical bytes, so the default
invocation reproduces the #12 spec §10.1 golden native image byte-for-byte
(the last 36 bytes of docs/evidence/spec-v2/golden-tbs.bin).

abi_version is pinned to 0x00020000 (spec §3.3); the tool refuses any other
value so a v1-ABI image can never be passed off as a v2 test image here.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path

ABI_V2 = 0x00020000
NATIVE_HDR = struct.Struct("<IHHIIIIII")  # tools/pack_app_image.py layout


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", required=True, type=Path, help="output image path")
    parser.add_argument("--payload-hex", default="00207047",
                        help="payload hex (default 00207047: Thumb 'movs r0,#0; bx lr')")
    parser.add_argument("--target-addr", type=parse_int, default=0x93E00000,
                        help="native target address (default: experiment Host exec base)")
    parser.add_argument("--entry-offset", type=parse_int, default=0,
                        help="entry offset inside the payload (even, < payload size)")
    parser.add_argument("--abi-version", type=parse_int, default=ABI_V2,
                        help=f"pinned v2 ABI {ABI_V2:#010x}; other values are refused")
    parser.add_argument("--reserved0", type=parse_int, default=0,
                        help="reserved0 field (must stay 0; nonzero refused)")
    parser.add_argument("--expect-sha256", default=None,
                        help="assert the produced image has this SHA-256")
    args = parser.parse_args()

    try:
        payload = bytes.fromhex(args.payload_hex.replace(" ", ""))
    except ValueError:
        print(f"ERROR: --payload-hex is not valid hex: {args.payload_hex!r}", file=sys.stderr)
        return 2
    if not payload:
        print("ERROR: payload must not be empty", file=sys.stderr)
        return 2
    if args.abi_version != ABI_V2:
        print(f"ERROR: this tool only makes v2-ABI images ({ABI_V2:#010x}); got "
              f"{args.abi_version:#010x}", file=sys.stderr)
        return 2
    if args.reserved0 != 0:
        print("ERROR: reserved0 must stay 0 (spec §3.3)", file=sys.stderr)
        return 2
    if args.entry_offset >= len(payload) or args.entry_offset % 2 != 0:
        print("ERROR: entry_offset must be even and inside the payload", file=sys.stderr)
        return 2

    crc = zlib.crc32(payload) & 0xFFFFFFFF
    header = NATIVE_HDR.pack(
        0x3141454E,      # "NEA1" little-endian
        32,              # header_size
        1,               # format_version
        args.abi_version,
        args.target_addr,
        len(payload),
        args.entry_offset,
        args.reserved0,
        crc,
    )
    image = header + payload
    digest = hashlib.sha256(image).hexdigest()

    if args.expect_sha256 is not None and digest != args.expect_sha256.lower():
        print(f"ERROR: image sha256 {digest} != expected {args.expect_sha256}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(image)
    print(f"v2 test image -> {args.out}")
    print(f"  bytes    {len(image)} (32B NEA1 header + {len(payload)}B payload)")
    print(f"  abi      {args.abi_version:#010x}  target {args.target_addr:#010x}  "
          f"entry {args.entry_offset:#x}  crc32 {crc:#010x}")
    print(f"  sha256   {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
