from __future__ import annotations

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))
sys.path.insert(0, str(ROOT / "package" / "unsigned"))
sys.path.insert(0, str(ROOT / "package" / "vnext"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import neapp_v4_format as v4
import neapp_v5_format as v5
from support import FIXTURE_MARKER, fixture_elf, pack_fixture, write_fixture_ui_tree


def build_fixture_package(directory: Path) -> bytes:
    elf_path = directory / "fixture.elf"
    elf_path.write_bytes(fixture_elf())
    ui_root = write_fixture_ui_tree(directory / "ui")
    out = directory / "line-crossing-4.0.0.neapp"
    pack_fixture(elf_path, ui_root, out)
    return out.read_bytes()


class V5FormatPositiveTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="neapp-v5-fmt-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.package = build_fixture_package(self.root)

    def test_unsigned_package_passes_independent_verification(self):
        report, error = v5.verify_package_v5(self.package)
        self.assertIsNone(error)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["format"], "neapp-v5-unsigned")
        self.assertEqual(report["app_id"], "line-crossing")
        self.assertEqual(report["native_version"], "4.0.0")
        self.assertEqual(report["ui_version"], "1.1.1")
        self.assertEqual(report["ui_native_version"], "4.0.0")
        self.assertEqual(report["package_len"], len(self.package))
        self.assertEqual(report["package_sha256"], hashlib.sha256(self.package).hexdigest())
        self.assertEqual(report["ui_file_count"], 3)
        self.assertIn("index.html", [entry["path"] for entry in report["ui_files"]])

    def test_container_header_carries_exact_member_boundaries(self):
        native_len, ui_len = struct.unpack_from("<II", self.package, 8)
        self.assertEqual(self.package[0:8], v5.CONTAINER_MAGIC)
        self.assertEqual(v5.HEADER_LEN + native_len + ui_len, len(self.package))
        native = self.package[16:16 + native_len]
        self.assertEqual(native[0:8], v5.NATIVE_MEMBER_MAGIC)
        self.assertEqual(struct.unpack_from("<II", native, 8),
                         (v5.MANIFEST_LEN, native_len - v5.NATIVE_MEMBER_HEADER_LEN - v5.MANIFEST_LEN))
        self.assertEqual(native[16:20], v5.MANIFEST_MAGIC)
        self.assertEqual(native[16 + 4:16 + 20], b"\x00" * 16)
        self.assertEqual(native[16 + 128:16 + 160], b"\x00" * 32)
        ui_member = self.package[16 + native_len:]
        self.assertEqual(ui_member[0:8], v5.UI_MEMBER_MAGIC)
        self.assertEqual(ui_member[16 + 48:16 + 80], b"\x00" * 32)
        self.assertEqual(ui_member[16 + 80:16 + 112], hashlib.sha256(native).digest())
        self.assertEqual(ui_member[16 + 124:16 + 130], struct.pack("<HHH", 4, 0, 0))
        self.assertEqual(ui_member[16 + 130:16 + 136], b"\x00" * 6)

    def test_policy_fields_follow_the_frozen_v4_conventions(self):
        report, _ = v5.verify_package_v5(self.package)
        self.assertEqual(report["required_host_abi"], f"{v4.HOST_ABI_V4:#010x}")
        self.assertEqual(report["run_profile"], v4.RUN_PROFILE_V4)
        self.assertEqual(report["required_host_caps"], "0x63")
        self.assertEqual(report["control_max"], 256)


class V5FormatNegativeTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="neapp-v5-neg-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.package = bytearray(build_fixture_package(self.root))
        self.report, _ = v5.verify_package_v5(bytes(self.package))
        self.native_len, self.ui_len = struct.unpack_from("<II", self.package, 8)

    def test_truncated_package_is_rejected(self):
        for cut in (1, 8, 15, self.ui_len // 2, len(self.package) - 1):
            with self.subTest(cut=cut):
                _, error = v5.verify_package_v5(bytes(self.package[:-cut]))
                self.assertIsNotNone(error)
                self.assertEqual(error.code, "BAD_PACKAGE")

    def test_declared_length_overflow_is_rejected(self):
        for field, offset, value in (
            ("native_member_len", 8, 0xFFFFFFFF),
            ("native_member_len", 8, v5.MAX_NATIVE_MEMBER_LEN + 1),
            ("ui_member_len", 12, 0xFFFFFFFF),
            ("ui_member_len", 12, v5.MAX_UI_MEMBER_LEN + 1),
            ("native_member_len", 8, 0),
            ("ui_member_len", 12, 0),
        ):
            with self.subTest(field=field, value=value):
                data = bytearray(self.package)
                struct.pack_into("<I", data, offset, value)
                _, error = v5.verify_package_v5(bytes(data))
                self.assertIsNotNone(error)
                self.assertEqual(error.code, "BAD_PACKAGE")

    def test_trailing_bytes_are_rejected(self):
        _, error = v5.verify_package_v5(bytes(self.package) + b"\x00")
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "BAD_PACKAGE")

    def test_native_content_tamper_is_rejected(self):
        data = bytearray(self.package)
        data[16 + v5.NATIVE_MEMBER_HEADER_LEN + v5.MANIFEST_LEN + v4.NATIVE_HEADER_SIZE] ^= 1
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "BAD_PACKAGE")

    def test_ui_asset_tamper_is_rejected(self):
        data = bytearray(self.package)
        data[-1] ^= 1
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "BAD_PACKAGE")

    def test_native_ui_binding_mismatch_is_rejected(self):
        data = bytearray(self.package)
        binding_off = 16 + self.native_len + 16 + v5.UI_NATIVE_BINDING_OFF
        data[binding_off] ^= 1
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "MEMBER_MISMATCH")

    def test_app_id_mismatch_between_members_is_rejected(self):
        data = bytearray(self.package)
        app_off = 16 + self.native_len + 16 + 16
        data[app_off] = ord("x") if data[app_off] != ord("x") else ord("y")
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertIn(error.code, ("MEMBER_MISMATCH", "BAD_PACKAGE"))

    def test_nonzero_trust_slot_is_rejected(self):
        for slot_off, slot_len in ((v5.PUBLISHER_SLOT_OFF, v5.PUBLISHER_SLOT_LEN),
                                   (v5.PUBLISHER_KEY_SLOT_OFF, v5.PUBLISHER_KEY_SLOT_LEN)):
            with self.subTest(slot_off=slot_off):
                data = bytearray(self.package)
                data[16 + v5.NATIVE_MEMBER_HEADER_LEN + slot_off] = 1
                _, error = v5.verify_package_v5(bytes(data))
                self.assertIsNotNone(error)
                self.assertEqual(error.code, "BAD_PACKAGE")
                self.assertIn("must be all zero", error.detail)

    def test_ui_member_trust_slot_is_rejected_when_nonzero(self):
        data = bytearray(self.package)
        data[16 + self.native_len + v5.UI_HEADER_LEN + v5.UI_PUBLISHER_KEY_SLOT_OFF] = 1
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "BAD_PACKAGE")

    def test_ui_native_version_mismatch_is_rejected(self):
        data = bytearray(self.package)
        data[16 + self.native_len + v5.UI_HEADER_LEN + v5.UI_NATIVE_VERSION_OFF] ^= 1
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "MEMBER_MISMATCH")

    def test_ui_reserved_tail_nonzero_is_rejected(self):
        data = bytearray(self.package)
        data[16 + self.native_len + v5.UI_HEADER_LEN + v5.UI_RESERVED_TAIL_OFF] = 1
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "BAD_PACKAGE")

    def test_ui_member_magic_swap_to_legacy_neui_is_rejected(self):
        data = bytearray(self.package)
        data[16 + self.native_len:16 + self.native_len + 8] = bytes.fromhex("4e45554901000000")
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "BAD_PACKAGE")

    def test_unknown_capability_bits_are_rejected(self):
        data = bytearray(self.package)
        struct.pack_into("<I", data, 16 + v5.NATIVE_MEMBER_HEADER_LEN + 72, 0x00000463)
        _, error = v5.verify_package_v5(bytes(data))
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "BAD_PACKAGE")

    def test_host_admission_rejects_incompatible_policy(self):
        policy = v4.DevicePolicyV4(psram_mib=32)
        _, error = v5.verify_package_v5(bytes(self.package), policy=policy)
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "TARGET_INCOMPATIBLE")

    def test_intrinsic_tier_skips_admission_checks(self):
        policy = v4.DevicePolicyV4(psram_mib=32)
        report, error = v5.verify_package_v5(bytes(self.package), policy=policy, host_admission=False)
        self.assertIsNone(error)
        self.assertEqual(report["result"], "PASS")


class LegacySignedFormatTests(unittest.TestCase):
    def test_committed_signed_v3_package_is_reported_as_legacy(self):
        golden = (ROOT / "docs" / "evidence" / "spec-v3" / "golden.neapp.v3").read_bytes()
        _, error = v5.verify_package_v5(golden)
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "LEGACY_SIGNED_FORMAT")
        self.assertIn("neapp v3", error.detail)
        self.assertIn("unsupported legacy signed format", error.detail)

    def test_committed_signed_neui_sidecar_is_reported_as_legacy(self):
        bundle = (ROOT / "docs" / "evidence" / "line-crossing-ui" / "line-crossing.neui").read_bytes()
        _, error = v5.verify_package_v5(bundle)
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "LEGACY_SIGNED_FORMAT")
        self.assertIn("neui sidecar v1", error.detail)

    def test_all_legacy_signed_magics_are_detected_and_never_parsed(self):
        crafted = {
            "neapp v1": bytes.fromhex("4e45415050010000") + b"\x00" * 24,
            "neapp v2": bytes.fromhex("4e45415050020000") + b"\x00" * 24,
            "neapp v3": bytes.fromhex("4e45415050030000") + b"\x00" * 24,
            "neapp v4": bytes.fromhex("4e45415050040000") + b"\x00" * 24,
            "neui sidecar v1": bytes.fromhex("4e45554901000000") + b"\x00" * 24,
            "nepk v1.1": b"NEPK" + b"\x00" * 28,
        }
        for name, data in crafted.items():
            with self.subTest(legacy=name):
                self.assertEqual(v5.detect_legacy_signed(data), name)
                _, error = v5.verify_package_v5(data)
                self.assertIsNotNone(error)
                self.assertEqual(error.code, "LEGACY_SIGNED_FORMAT")
                self.assertIn(name, error.detail)

    def test_short_legacy_prefix_is_detected(self):
        data = bytes.fromhex("4e45415050040000") + b"\x00"
        _, error = v5.verify_package_v5(data)
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "LEGACY_SIGNED_FORMAT")

    def test_empty_and_unknown_magics_are_bad_package_not_legacy(self):
        for data in (b"", b"\x00" * 15, b"NOTANEAPP" + b"\x00" * 16,
                     bytes.fromhex("4e45415050060000") + b"\x00" * 24):
            with self.subTest(data=data[:8]):
                _, error = v5.verify_package_v5(data)
                self.assertIsNotNone(error)
                self.assertEqual(error.code, "BAD_PACKAGE")


if __name__ == "__main__":
    unittest.main()
