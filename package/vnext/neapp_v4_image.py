from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

import neapp_v4_format as fmt4

ELF_HEADER = struct.Struct("<16sHHIIIIIHHHHHH")
ELF_PROGRAM_HEADER = struct.Struct("<IIIIIIII")
PT_LOAD = 1
PF_X = 1
EM_ARM = 40


class ElfImageError(ValueError):
    pass


def image_from_elf(elf: bytes, expected_base: int = fmt4.EXEC_BASE_V4) -> tuple[bytes, dict]:
    if len(elf) < ELF_HEADER.size:
        raise ElfImageError("ELF header is truncated")
    fields = ELF_HEADER.unpack_from(elf)
    ident = fields[0]
    elf_type, machine, version, entry, phoff = fields[1:6]
    ehsize, phentsize, phnum = fields[8:11]
    if ident[:4] != b"\x7fELF" or ident[4:7] != b"\x01\x01\x01":
        raise ElfImageError("input must be ELF32 little-endian version 1")
    if elf_type != 2 or machine != EM_ARM or version != 1:
        raise ElfImageError("input must be an ARM ELF32 executable")
    if ehsize != ELF_HEADER.size or phentsize != ELF_PROGRAM_HEADER.size or phnum == 0:
        raise ElfImageError("ELF program header layout is unsupported")
    table_end = phoff + phentsize * phnum
    if phoff < ehsize or table_end > len(elf):
        raise ElfImageError("ELF program header table is outside the file")
    segments = []
    memory_ends = []
    for index in range(phnum):
        header = ELF_PROGRAM_HEADER.unpack_from(elf, phoff + index * phentsize)
        kind, offset, vaddr, paddr, filesz, memsz, flags, alignment = header
        if kind != PT_LOAD:
            continue
        if filesz > memsz or offset + filesz > len(elf):
            raise ElfImageError(f"PT_LOAD segment {index} has invalid file or memory bounds")
        if paddr != vaddr:
            raise ElfImageError(f"PT_LOAD segment {index} has different physical and virtual addresses")
        if paddr + memsz > 0xFFFFFFFF:
            raise ElfImageError(f"PT_LOAD segment {index} address range overflows u32")
        memory_ends.append(paddr + memsz)
        if filesz:
            segments.append((paddr, paddr + filesz, flags, elf[offset:offset + filesz]))
    if not segments:
        raise ElfImageError("ELF has no file-backed PT_LOAD segment")
    base = min(segment[0] for segment in segments)
    end = max(segment[1] for segment in segments)
    memory_end = max(memory_ends)
    if base != expected_base:
        raise ElfImageError(f"ELF load base {base:#010x} != expected {expected_base:#010x}")
    if memory_end > expected_base + fmt4.EXEC_REGION_BYTES_V4:
        raise ElfImageError("ELF load range exceeds the v4 execution region")
    if not base <= (entry & ~1) < end:
        raise ElfImageError("ELF entry point is outside the file-backed load range")
    executable_entry = any(
        flags & PF_X and start <= (entry & ~1) < file_end
        for start, file_end, flags, _ in segments
    )
    if not executable_entry:
        raise ElfImageError("ELF entry point is not inside an executable PT_LOAD segment")
    payload = bytearray(end - base)
    occupied = bytearray(end - base)
    for start, file_end, _, chunk in segments:
        offset = start - base
        for index, value in enumerate(chunk):
            if occupied[offset + index]:
                raise ElfImageError("ELF file-backed PT_LOAD segments overlap")
            occupied[offset + index] = 1
            payload[offset + index] = value
    payload = bytes(payload)
    if not payload or len(payload) + fmt4.NATIVE_HEADER_SIZE > fmt4.MAX_NATIVE_FILE_LEN:
        raise ElfImageError("ELF payload is empty or exceeds the v4 native file cap")
    entry_offset = (entry & ~1) - base
    header = fmt4.NATIVE_HDR.pack(
        int.from_bytes(fmt4.NATIVE_MAGIC, "little"),
        fmt4.NATIVE_HEADER_SIZE,
        fmt4.NATIVE_FORMAT_VERSION,
        fmt4.HOST_ABI_V4,
        base,
        len(payload),
        entry_offset,
        0,
        zlib.crc32(payload) & 0xFFFFFFFF,
    )
    image = header + payload
    return image, {
        "elf_sha256": hashlib.sha256(elf).hexdigest(),
        "elf_entry": entry,
        "target_addr": base,
        "entry_offset": entry_offset,
        "payload_len": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_len": len(image),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expected-base", type=lambda value: int(value, 0), default=fmt4.EXEC_BASE_V4)
    args = parser.parse_args()
    try:
        image, report = image_from_elf(args.elf.read_bytes(), args.expected_base)
    except (OSError, ElfImageError) as error:
        print(json.dumps({"result": "REJECTED", "detail": str(error)}, sort_keys=True))
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(image)
    print(json.dumps({"result": "PASS", **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
