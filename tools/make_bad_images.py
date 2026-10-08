#!/usr/bin/env python3
"""Generate deliberately corrupt app-host images for rejection-path testing.

Takes a known-good image and rewrites single header fields (or payload bytes)
so the pinned experiment Host validator must reject each variant. The output
filenames encode the expected rejection reason (tools/validate_app_image.py
reason codes), so test runners can derive the expectation from the name:

    bad-magic.bin            -> magic
    bad-header-size.bin      -> header-size
    bad-format-version.bin   -> format-version
    bad-abi-version.bin      -> abi-version
    bad-target-address.bin   -> target-address
    bad-image-size.bin       -> image-size
    bad-entry-offset.bin     -> entry-offset
    bad-crc32.bin            -> crc32

Field mutations keep the payload CRC intact: the host checks the mutated field
before reaching the CRC check, so each fixture fails at exactly one gate.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

HEADER = struct.Struct("<IHHIIIIII")

FIELDS = (
    "magic",
    "header_size",
    "format_version",
    "abi_version",
    "target_addr",
    "image_size",
    "entry_offset",
    "reserved0",
    "crc32",
)


def unpack(image: bytes) -> list[int]:
    return list(HEADER.unpack_from(image))


def repack(fields: list[int], payload: bytes) -> bytes:
    return HEADER.pack(*fields) + payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--good", required=True, type=Path,
                        help="known-good packed image")
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    image = args.good.read_bytes()
    if len(image) < HEADER.size + 1:
        raise ValueError(f"{args.good} is too small to mutate")

    fields = unpack(image)
    payload = image[HEADER.size:]

    variants: dict[str, list[int]] = {}

    bad = unpack(image)
    bad[FIELDS.index("magic")] ^= 0xFFFFFFFF
    variants["bad-magic.bin"] = bad

    bad = unpack(image)
    bad[FIELDS.index("header_size")] = 16  # below APP_HOST_IMAGE_HEADER_SIZE
    variants["bad-header-size.bin"] = bad

    bad = unpack(image)
    bad[FIELDS.index("format_version")] += 1
    variants["bad-format-version.bin"] = bad

    bad = unpack(image)
    bad[FIELDS.index("abi_version")] += 1  # exact-match rule: minor bump still rejected
    variants["bad-abi-version.bin"] = bad

    bad = unpack(image)
    bad[FIELDS.index("target_addr")] += 4
    variants["bad-target-address.bin"] = bad

    bad = unpack(image)
    bad[FIELDS.index("image_size")] = 0
    variants["bad-image-size.bin"] = bad

    bad = unpack(image)
    bad[FIELDS.index("entry_offset")] |= 1  # odd offset fails the Thumb-alignment rule
    variants["bad-entry-offset.bin"] = bad

    bad_payload = bytearray(payload)
    bad_payload[-1] ^= 0xFF
    variants["bad-crc32.bin"] = fields

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, header_fields in variants.items():
        body = bytes(bad_payload) if name == "bad-crc32.bin" else payload
        out_path = args.out_dir / name
        out_path.write_bytes(repack(header_fields, body))
        reason = name[len("bad-"):].replace(".bin", "")
        print(f"wrote {out_path} (expect rejection: {reason}, crc32 {zlib.crc32(body) & 0xFFFFFFFF:#010x})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
