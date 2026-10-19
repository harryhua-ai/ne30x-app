#!/usr/bin/env python3
"""make_v4_test_image — deterministic controlled NEA1 native test image with
the v4 Host ABI (for .neapp v4 packaging tests, App #36).

Host-side artifact only: a 32B NEA1 header (magic "NEA1", header_size 32,
format_version 1, abi_version pinned 0x00040000, reserved0 0) plus a
deterministic payload with the reflected-IEEE CRC-32 written into the
header.  The default payload is the frozen 64B v4 function table
(table_size 64, abi_version 0x00040000, 14 Thumb-tagged SIMULATION
pointers) followed by the minimal Thumb-2 stub `00207047`
(`movs r0,#0; bx lr`); the entry offset defaults to the stub.  The
pointer values are SIMULATION evidence values, not a real firmware build;
the target-build static asserts required by Host #104 F3 remain a
device/software build concern (NOT_RUN offline).

No business algorithm, no device build, no apps/** source is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "package" / "vnext"))

import neapp_v4_format as fmt4

ABI_V4 = 0x00040000
NATIVE_HDR = struct.Struct("<IHHIIIIII")
THUMB_STUB_HEX = "00207047"
SIM_POINTER_BASE = 0x93E00001


def parse_int(value: str) -> int:
    return int(value, 0)


def default_payload() -> bytes:
    pointers = [SIM_POINTER_BASE + 4 * i for i in range(len(fmt4.V4_FUNCTION_NAMES))]
    return fmt4.build_function_table_v4(pointers) + bytes.fromhex(THUMB_STUB_HEX)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", required=True, type=Path, help="output image path")
    parser.add_argument("--payload-hex", default=None,
                        help="payload hex override (default: 64B v4 function table + Thumb stub)")
    parser.add_argument("--target-addr", type=parse_int, default=fmt4.EXEC_BASE_V4,
                        help=f"native target address (default: experiment Host exec base "
                             f"{fmt4.EXEC_BASE_V4:#010x})")
    parser.add_argument("--entry-offset", type=parse_int, default=None,
                        help="entry offset inside the payload (even, < payload size; "
                             "default: just past the embedded function table)")
    parser.add_argument("--abi-version", type=parse_int, default=ABI_V4,
                        help=f"pinned v4 ABI {ABI_V4:#010x}; other values are refused")
    parser.add_argument("--reserved0", type=parse_int, default=0,
                        help="reserved0 field (must stay 0; nonzero refused)")
    parser.add_argument("--expect-sha256", default=None,
                        help="assert the produced image has this SHA-256")
    args = parser.parse_args()

    payload = (bytes.fromhex(args.payload_hex.replace(" ", ""))
               if args.payload_hex else default_payload())
    table_bytes = 0 if args.payload_hex is not None else fmt4.V4_TABLE_SIZE
    entry_offset = (args.entry_offset if args.entry_offset is not None else table_bytes)

    if not payload:
        print("ERROR: payload must not be empty", file=sys.stderr)
        return 2
    if args.abi_version != ABI_V4:
        print(f"ERROR: this tool only makes v4-ABI images ({ABI_V4:#010x}); got "
              f"{args.abi_version:#010x}", file=sys.stderr)
        return 2
    if args.reserved0 != 0:
        print("ERROR: reserved0 must stay 0", file=sys.stderr)
        return 2
    if entry_offset >= len(payload) or entry_offset % 2 != 0:
        print("ERROR: entry_offset must be even and inside the payload", file=sys.stderr)
        return 2
    if len(payload) > fmt4.MAX_NATIVE_FILE_LEN:
        print("ERROR: payload exceeds the v4 native file cap", file=sys.stderr)
        return 2

    crc = zlib.crc32(payload) & 0xFFFFFFFF
    header = NATIVE_HDR.pack(
        0x3141454E,
        32,
        1,
        args.abi_version,
        args.target_addr,
        len(payload),
        entry_offset,
        args.reserved0,
        crc,
    )
    image = header + payload
    if args.expect_sha256:
        actual = hashlib.sha256(image).hexdigest()
        if actual != args.expect_sha256:
            print(f"ERROR: image sha256 {actual} != expected {args.expect_sha256}",
                  file=sys.stderr)
            return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(image)
    print(f"wrote {args.out}: {len(image)} B (payload {len(payload)} B, crc32 {crc:#010x}), "
          f"sha256 {hashlib.sha256(image).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
