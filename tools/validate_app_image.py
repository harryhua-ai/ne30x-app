#!/usr/bin/env python3
"""Validate a NE301 app-host image against the pinned public ABI header.

Reject checks and their order deliberately mirror the pinned experiment Host
loader (ne301 experiment/app-host-poc@a5b4bf3
Custom/Services/AppHost/app_host_validate.c + app_host.c read_file):

    oversize         whole file exceeds the execution region (host read_file -3)
    truncated        file smaller than the 32-byte header
    magic            APP_HOST_IMAGE_MAGIC mismatch
    header-size      header_size < APP_HOST_IMAGE_HEADER_SIZE
    format-version   APP_HOST_IMAGE_FORMAT_VERSION mismatch
    abi-version      APP_HOST_ABI_VERSION mismatch (exact, no minor tolerance)
    target-address   target_addr != expected execution base
    image-size       image_size zero / beyond region / header+payload beyond file
    entry-offset     entry_offset >= image_size or odd
    crc32            zlib CRC-32 of the payload (header excluded) mismatch

A file carrying trailing bytes beyond header+payload prints a WARNING but is
VALID: the host loader reads the whole file yet consumes only image_size bytes.

This tool absorbs and replaces the draft tests/validate-app-image.py.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
import zlib
from pathlib import Path

HEADER = struct.Struct("<IHHIIIIII")

# reason -> pinned host app_host_check_str() wording (device-log correlation)
HOST_REJECT_MESSAGES = {
    "truncated": "image smaller than header",
    "magic": "bad magic",
    "header-size": "header size invalid",
    "format-version": "format version unsupported",
    "abi-version": "abi version mismatch",
    "target-address": "target address mismatch",
    "image-size": "image size out of bounds",
    "entry-offset": "entry offset invalid",
    "crc32": "crc mismatch",
}
FAILURE_REASONS = ("oversize",) + tuple(HOST_REJECT_MESSAGES)


def parse_integer(value: str) -> int:
    return int(value, 0)


def read_define(header_text: str, name: str) -> int:
    pattern = rf"^\s*#define\s+{re.escape(name)}\s+(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\s*$"
    match = re.search(pattern, header_text, re.MULTILINE)
    if not match:
        raise ValueError(f"ABI header is missing numeric define {name}")
    return int(match.group(1), 0)


def validate_image(
    image: bytes,
    *,
    abi_header: str,
    target_address: int,
    region_size: int,
) -> tuple[str | None, dict[str, int], list[str]]:
    """Return (reason-or-None, parsed header fields, warnings)."""
    expected_magic = read_define(abi_header, "APP_HOST_IMAGE_MAGIC")
    expected_format = read_define(abi_header, "APP_HOST_IMAGE_FORMAT_VERSION")
    expected_abi = read_define(abi_header, "APP_HOST_ABI_VERSION")
    expected_header_size = read_define(abi_header, "APP_HOST_IMAGE_HEADER_SIZE")

    if HEADER.size != expected_header_size:
        raise ValueError(
            f"local v1 decoder is {HEADER.size} bytes but pinned ABI says {expected_header_size}"
        )

    warnings: list[str] = []

    if len(image) > region_size:
        return "oversize", {}, warnings
    if len(image) < expected_header_size:
        return "truncated", {}, warnings

    (
        magic,
        header_size,
        format_version,
        abi_version,
        image_target,
        image_size,
        entry_offset,
        _reserved0,
        crc32,
    ) = HEADER.unpack_from(image)

    fields = {
        "header_size": header_size,
        "format_version": format_version,
        "abi_version": abi_version,
        "target_address": image_target,
        "image_size": image_size,
        "entry_offset": entry_offset,
        "crc32": crc32,
    }

    if magic != expected_magic:
        return "magic", fields, warnings
    if header_size < expected_header_size:
        return "header-size", fields, warnings
    if format_version != expected_format:
        return "format-version", fields, warnings
    if abi_version != expected_abi:
        return "abi-version", fields, warnings
    if image_target != target_address:
        return "target-address", fields, warnings
    if image_size == 0 or image_size > region_size:
        return "image-size", fields, warnings
    if header_size + image_size > len(image):
        return "image-size", fields, warnings
    if entry_offset >= image_size or (entry_offset & 1):
        return "entry-offset", fields, warnings
    if zlib.crc32(image[header_size:header_size + image_size]) & 0xFFFFFFFF != crc32:
        return "crc32", fields, warnings
    if header_size + image_size != len(image):
        warnings.append(
            f"trailing data: file has {len(image)} bytes, header+payload is "
            f"{header_size + image_size}; host tolerates and ignores the excess"
        )
    return None, fields, warnings


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--abi-header", required=True, type=Path)
    parser.add_argument("--target-address", type=parse_integer, default=0x93E00000,
                        help="expected execution base (default 0x93E00000)")
    parser.add_argument("--region-size", type=parse_integer, default=0x200000,
                        help="execution region size (default 0x200000)")
    parser.add_argument("--expect-failure", choices=FAILURE_REASONS,
                        help="assert the image is rejected for exactly this reason")
    args = parser.parse_args()

    try:
        data = args.image.read_bytes()
        abi_text = args.abi_header.read_text(encoding="utf-8")
        failure, fields, warnings = validate_image(
            data,
            abi_header=abi_text,
            target_address=args.target_address,
            region_size=args.region_size,
        )
    except (OSError, ValueError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.expect_failure:
        if failure != args.expect_failure:
            print(
                f"FAIL: expected {args.expect_failure}, got {failure or 'valid'} "
                f"({args.image})",
                file=sys.stderr,
            )
            return 1
        print(
            f"REJECTED as expected: {failure} "
            f"({HOST_REJECT_MESSAGES.get(failure, 'rejected before read_file')}) "
            f"— {args.image}"
        )
        return 0

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    if failure:
        print(
            f"INVALID: {failure} "
            f"({HOST_REJECT_MESSAGES.get(failure, 'rejected before read_file')}) "
            f"— {args.image}",
            file=sys.stderr,
        )
        return 1

    print(
        f"VALID: file={len(data)} payload={fields['image_size']} "
        f"target=0x{fields['target_address']:08x} "
        f"entry_offset=0x{fields['entry_offset']:x} "
        f"abi=0x{fields['abi_version']:08x} crc32=0x{fields['crc32']:08x}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
