from __future__ import annotations

import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package" / "vnext"))

import neapp_v4_format as v4
from neapp_v4_image import ELF_HEADER, ELF_PROGRAM_HEADER, ElfImageError, image_from_elf


def elf_fixture(payload=b"ABCD", entry_offset=0, base=v4.EXEC_BASE_V4, extra_segment=False):
    phnum = 2 if extra_segment else 1
    headers_end = ELF_HEADER.size + phnum * ELF_PROGRAM_HEADER.size
    first_offset = (headers_end + 15) & ~15
    second_offset = first_offset + len(payload)
    file_len = second_offset + len(payload) if extra_segment else first_offset + len(payload)
    out = bytearray(file_len)
    ident = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    ELF_HEADER.pack_into(out, 0, ident, 2, 40, 1, base + entry_offset + 1, ELF_HEADER.size, 0, 0,
                         ELF_HEADER.size, ELF_PROGRAM_HEADER.size, phnum, 0, 0, 0)
    ELF_PROGRAM_HEADER.pack_into(out, ELF_HEADER.size, 1, first_offset, base, base, len(payload),
                                 len(payload), 5, 4)
    out[first_offset:first_offset + len(payload)] = payload
    if extra_segment:
        ELF_PROGRAM_HEADER.pack_into(out, ELF_HEADER.size + ELF_PROGRAM_HEADER.size,
                                     1, second_offset, base + 8, base + 8, len(payload),
                                     len(payload), 4, 4)
        out[second_offset:second_offset + len(payload)] = payload
    return bytes(out)


class ElfImageTests(unittest.TestCase):
    def test_real_elf_segments_form_a_crc_checked_nea1_v4_image(self):
        image, report = image_from_elf(elf_fixture())
        native = v4.parse_native_header_v4(image)
        self.assertEqual(native.magic, b"NEA1")
        self.assertEqual(native.header_size, 32)
        self.assertEqual(native.format_version, 1)
        self.assertEqual(native.abi_version, v4.HOST_ABI_V4)
        self.assertEqual(native.target_addr, v4.EXEC_BASE_V4)
        self.assertEqual(native.image_size, 4)
        self.assertEqual(native.entry_offset, 0)
        self.assertEqual(v4.native_payload_crc32_v4(image, native.image_size), native.crc32)
        self.assertEqual(report["payload_sha256"], hashlib.sha256(b"ABCD").hexdigest())

    def test_file_backed_segments_keep_address_gaps_zero_filled(self):
        image, _ = image_from_elf(elf_fixture(extra_segment=True))
        self.assertEqual(image[32:], b"ABCD\x00\x00\x00\x00ABCD")

    def test_non_arm_malformed_bounds_wrong_base_and_non_executable_entry_fail(self):
        data = bytearray(elf_fixture())
        wrong_machine = bytearray(data)
        struct.pack_into("<H", wrong_machine, 18, 3)
        outside_file = bytearray(data)
        struct.pack_into("<I", outside_file, ELF_HEADER.size + 4, len(data) + 1)
        non_exec = bytearray(data)
        struct.pack_into("<I", non_exec, ELF_HEADER.size + 24, 4)
        for invalid in (b"not elf", bytes(wrong_machine), bytes(outside_file), bytes(non_exec)):
            with self.subTest(invalid=invalid[:12]):
                with self.assertRaises(ElfImageError):
                    image_from_elf(invalid)
        with self.assertRaises(ElfImageError):
            image_from_elf(bytes(data), expected_base=v4.EXEC_BASE_V4 + 0x1000)

    def test_bss_only_pt_load_cannot_extend_beyond_the_execution_region(self):
        data = bytearray(elf_fixture(extra_segment=True))
        bss_header = ELF_HEADER.size + ELF_PROGRAM_HEADER.size
        bss_base = v4.EXEC_BASE_V4 + v4.EXEC_REGION_BYTES_V4 - 4
        struct.pack_into("<IIIIIIII", data, bss_header, 1, len(data), bss_base, bss_base, 0, 8, 4, 4)
        with self.assertRaises(ElfImageError):
            image_from_elf(bytes(data))


if __name__ == "__main__":
    unittest.main()
