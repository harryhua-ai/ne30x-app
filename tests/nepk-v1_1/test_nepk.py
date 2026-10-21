from __future__ import annotations

import hashlib
import struct
import sys
import unittest
import zlib
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package" / "vnext"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))
sys.path.insert(0, str(ROOT / "package"))

import neapp_format as v1
import neapp_v4_format as v4
import neui_sidecar_format as ui
from nepk_v1_1_verify import NePKError, history_from_report, verify_nepk


PUBLISHER = "ne301-exp-pub"
APP = "line-crossing"
DOMAIN = b"NEPAIR1\x00"


def spki_for(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign(data, key):
    return key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))


def member_tbs_len(data):
    manifest_len, image_len = struct.unpack_from("<II", data, 8)
    return 16 + manifest_len + image_len


def native_member(key, version=(4, 0, 1), app_id=APP, publisher_id=PUBLISHER,
                  payload=b"\x10\x20\x30\x40", psram_mib=64,
                  required_caps=None):
    if required_caps is None:
        required_caps = v4.CAP_LOG | v4.CAP_TICK_MS | v4.CAP_SESSION_LIFECYCLE | v4.CAP_CONTROL_RECEIVE
    image = v4.NATIVE_HDR.pack(
        int.from_bytes(v4.NATIVE_MAGIC, "little"),
        v4.NATIVE_HEADER_SIZE,
        v4.NATIVE_FORMAT_VERSION,
        v4.HOST_ABI_V4,
        v4.EXEC_BASE_V4,
        len(payload),
        0,
        0,
        zlib.crc32(payload) & 0xFFFFFFFF,
    ) + payload
    spki = spki_for(key)
    manifest = v4.build_manifest_v4(v4.ManifestV4(
        publisher_id=publisher_id,
        app_id=app_id,
        version_major=version[0],
        version_minor=version[1],
        version_patch=version[2],
        target_board_id=v4.TARGET_BOARD_ID_V4,
        required_psram_mib=psram_mib,
        required_host_abi=v4.HOST_ABI_V4,
        required_host_caps=required_caps,
        required_exec_region_bytes=v4.EXEC_REGION_BYTES_V4,
        native_file_len=len(image),
        native_image_size=len(payload),
        native_entry_offset=0,
        native_target_addr=v4.EXEC_BASE_V4,
        native_file_sha256=hashlib.sha256(image).digest(),
        publisher_key_sha256=hashlib.sha256(spki).digest(),
        run_profile=v4.RUN_PROFILE_V4,
        event_max=0,
        state_quota=0,
        report_max=0,
        control_max=256,
        snapshot_max=0,
        live_publish_max=0,
        live_track_max=0,
    ))
    tbs = v4.build_container_prefix_v4(manifest, image)
    return tbs + sign(tbs, key)


def ui_member(key, native, version=(1, 0, 1), app_id=APP, publisher_id=PUBLISHER,
              asset=b"<!doctype html><title>line crossing</title>", ui_abi=1):
    native_tbs = native[:member_tbs_len(native)]
    spki = spki_for(key)
    manifest = ui.build_manifest(ui.SidecarManifest(
        publisher_id=publisher_id,
        app_id=app_id,
        publisher_key_sha256=hashlib.sha256(spki).digest(),
        native_tbs_sha256=hashlib.sha256(native_tbs).digest(),
        version_major=version[0],
        version_minor=version[1],
        version_patch=version[2],
        file_count=1,
        host_ui_abi=ui_abi,
        records=(ui.AssetRecord("index.html", len(asset), hashlib.sha256(asset).digest()),),
    ))
    tbs = ui.build_container_prefix(manifest, asset)
    return tbs + sign(tbs, key)


def pair_member(native, ui_data, sequence, key, version=(1, 1)):
    header = b"NEPK" + struct.pack("<HHII", version[0], version[1], len(native), len(ui_data))
    tbs = header + native + ui_data + DOMAIN + struct.pack("<Q", sequence)
    return tbs + sign(tbs, key)


class NePKVerifierTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.other_key = ec.generate_private_key(ec.SECP256R1())
        self.spki = spki_for(self.key)
        self.trust = {PUBLISHER: self.spki}
        self.native = native_member(self.key)
        self.ui = ui_member(self.key, self.native)
        self.package = pair_member(self.native, self.ui, 7, self.key)

    def verify(self, package=None, **kwargs):
        return verify_nepk(
            self.package if package is None else package,
            self.trust,
            expected_publisher_id=PUBLISHER,
            expected_app_id=APP,
            **kwargs,
        )

    def expect_reject(self, package, code=None, **kwargs):
        with self.assertRaises(NePKError) as raised:
            self.verify(package, **kwargs)
        if code:
            self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_valid_three_signature_package_reports_pair_identity(self):
        report = self.verify()
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["format"], "nepk-v1.1")
        self.assertEqual(report["release_seq"], 7)
        self.assertEqual(report["publisher_id"], PUBLISHER)
        self.assertEqual(report["app_id"], APP)
        self.assertEqual(report["native_tbs_sha256"], hashlib.sha256(self.native[:member_tbs_len(self.native)]).hexdigest())
        self.assertEqual(report["ui_tbs_sha256"], hashlib.sha256(self.ui[:member_tbs_len(self.ui)]).hexdigest())
        pair_tbs_len = 32 + len(self.native) + len(self.ui)
        self.assertEqual(report["pair_tbs_sha256"], hashlib.sha256(self.package[:pair_tbs_len]).hexdigest())
        self.assertEqual(report["history"]["pair_tbs_sha256"], report["pair_tbs_sha256"])
        self.assertEqual(report["transition"], "FRESH_INSTALL")
        self.assertTrue(report["native_signature_sha256"])
        self.assertTrue(report["ui_signature_sha256"])
        self.assertTrue(report["pair_signature_sha256"])

    def test_truncation_unknown_version_and_oversized_members_are_rejected(self):
        invalid = [b"", self.package[:15], self.package[:-1], self.package + b"\x00"]
        wrong_magic = bytearray(self.package)
        wrong_magic[0] ^= 1
        invalid.append(bytes(wrong_magic))
        old_v10 = bytearray(self.package)
        struct.pack_into("<H", old_v10, 6, 0)
        invalid.append(bytes(old_v10))
        future = bytearray(self.package)
        struct.pack_into("<H", future, 4, 2)
        invalid.append(bytes(future))
        too_big_native = bytearray(self.package)
        struct.pack_into("<I", too_big_native, 8, v4.MAX_PACKAGE_LEN + 1)
        invalid.append(bytes(too_big_native))
        too_big_ui = bytearray(self.package)
        struct.pack_into("<I", too_big_ui, 12, 2_113_625)
        invalid.append(bytes(too_big_ui))
        zero_native = bytearray(self.package)
        struct.pack_into("<I", zero_native, 8, 0)
        invalid.append(bytes(zero_native))
        zero_ui = bytearray(self.package)
        struct.pack_into("<I", zero_ui, 12, 0)
        invalid.append(bytes(zero_ui))
        pair_tbs_len = 32 + len(self.native) + len(self.ui)
        oversized_signature = self.package[:pair_tbs_len] + self.package[pair_tbs_len:]
        oversized_signature += b"\x00" * (73 - (len(oversized_signature) - pair_tbs_len))
        invalid.append(oversized_signature)
        for data in invalid:
            with self.subTest(length=len(data)):
                self.expect_reject(data)

    def test_pair_domain_release_sequence_and_pair_signature_are_covered(self):
        for offset, value in ((16 + len(self.native) + len(self.ui), ord("X")),
                              (16 + len(self.native) + len(self.ui) + 8, 1)):
            changed = bytearray(self.package)
            changed[offset] ^= value
            self.expect_reject(bytes(changed))
        zero_seq = bytearray(self.package)
        sequence_offset = 24 + len(self.native) + len(self.ui)
        zero_seq[sequence_offset:sequence_offset + 8] = b"\x00" * 8
        resigned = bytes(zero_seq[:32 + len(self.native) + len(self.ui)])
        self.expect_reject(resigned + sign(resigned, self.key))
        self.expect_reject(self.package[:-1] + bytes([self.package[-1] ^ 1]))

    def test_valid_member_replacement_breaks_pair_authorization(self):
        replacement_native = native_member(self.key, version=(4, 0, 2), payload=b"ABCD")
        replacement_ui = ui_member(self.key, self.native, version=(1, 0, 2))
        replacement_ui_for_native = ui_member(self.key, replacement_native, version=(1, 0, 2))
        old_pair_signature = self.package[32 + len(self.native) + len(self.ui):]
        native_replaced_tbs = (
            b"NEPK" + struct.pack("<HHII", 1, 1, len(replacement_native), len(replacement_ui_for_native))
            + replacement_native + replacement_ui_for_native + DOMAIN + struct.pack("<Q", 7)
        )
        ui_replaced_tbs = (
            b"NEPK" + struct.pack("<HHII", 1, 1, len(self.native), len(replacement_ui))
            + self.native + replacement_ui + DOMAIN + struct.pack("<Q", 7)
        )
        native_replaced = native_replaced_tbs + old_pair_signature
        ui_replaced = ui_replaced_tbs + old_pair_signature
        self.expect_reject(native_replaced, "SIGNATURE_INVALID")
        self.expect_reject(ui_replaced, "SIGNATURE_INVALID")

    def test_native_ui_and_pair_signatures_are_independently_checked(self):
        bad_native = bytearray(self.native)
        bad_native[224 + v4.NATIVE_HEADER_SIZE] ^= 1
        package = pair_member(bytes(bad_native), self.ui, 8, self.key)
        self.expect_reject(package, "SIGNATURE_INVALID")
        bad_ui = bytearray(self.ui)
        bad_ui[member_tbs_len(self.ui) - 1] ^= 1
        package = pair_member(self.native, bytes(bad_ui), 8, self.key)
        self.expect_reject(package, "SIGNATURE_INVALID")
        pair_tbs_len = 32 + len(self.native) + len(self.ui)
        wrong_pair_signature = self.package[:pair_tbs_len] + sign(self.package[:pair_tbs_len], self.other_key)
        self.expect_reject(wrong_pair_signature, "SIGNATURE_INVALID")

    def test_wrong_trust_anchor_publisher_and_expected_app_are_rejected(self):
        wrong_signer_native = native_member(self.other_key)
        wrong_signer_ui = ui_member(self.other_key, wrong_signer_native)
        wrong_signer_pair = pair_member(wrong_signer_native, wrong_signer_ui, 8, self.other_key)
        self.expect_reject(wrong_signer_pair, "PUBLISHER_UNTRUSTED")
        other_publisher_native = native_member(self.key, publisher_id="other-publisher")
        other_publisher_ui = ui_member(self.key, other_publisher_native, publisher_id="other-publisher")
        other_publisher = pair_member(other_publisher_native, other_publisher_ui, 8, self.key)
        self.expect_reject(other_publisher, "PUBLISHER_UNTRUSTED")
        other_trusted = {PUBLISHER: self.spki, "other-publisher": self.spki}
        with self.assertRaises(NePKError) as raised:
            verify_nepk(other_publisher, other_trusted, PUBLISHER, APP)
        self.assertEqual(raised.exception.code, "PUBLISHER_MISMATCH")
        with self.assertRaises(NePKError) as raised:
            verify_nepk(self.package, self.trust, expected_publisher_id=PUBLISHER, expected_app_id="other-app")
        self.assertEqual(raised.exception.code, "APP_MISMATCH")

    def test_ui_native_tbs_mismatch_and_ui_abi_mismatch_are_rejected(self):
        other_native = native_member(self.key, version=(4, 0, 2), payload=b"WXYZ")
        wrong_binding_ui = ui_member(self.key, other_native)
        wrong_binding = pair_member(self.native, wrong_binding_ui, 8, self.key)
        self.expect_reject(wrong_binding, "NATIVE_BINDING_MISMATCH")
        altered_ui = bytearray(self.ui)
        manifest_len = struct.unpack_from("<I", altered_ui, 8)[0]
        altered_ui[16 + 120:16 + 124] = struct.pack("<I", 2)
        ui_tbs_len = 16 + manifest_len + struct.unpack_from("<I", altered_ui, 12)[0]
        changed_ui_tbs = bytes(altered_ui[:ui_tbs_len])
        incompatible_ui = changed_ui_tbs + sign(changed_ui_tbs, self.key)
        self.expect_reject(pair_member(self.native, incompatible_ui, 8, self.key), "BAD_PACKAGE")

    def test_native_host_capability_policy_is_enforced(self):
        with self.assertRaises(NePKError) as raised:
            self.verify(native_policy=v4.DevicePolicyV4(host_caps=v4.CAP_LOG | v4.CAP_TICK_MS))
        self.assertEqual(raised.exception.code, "ABI_INCOMPATIBLE")

    def test_trusted_history_schema_is_validated_before_policy_comparison(self):
        report = self.verify()
        history = history_from_report(report)
        self.assertEqual(history.pair_tbs_sha256, report["pair_tbs_sha256"])
        with self.assertRaises(NePKError) as raised:
            self.verify(trusted_history=replace(history, release_seq=0))
        self.assertEqual(raised.exception.code, "BAD_HISTORY")
        with self.assertRaises(NePKError) as raised:
            self.verify(trusted_history=replace(history, release_seq=True))
        self.assertEqual(raised.exception.code, "BAD_HISTORY")
        with self.assertRaises(NePKError) as raised:
            self.verify(trusted_history=replace(history, native_tbs_sha256=" " + history.native_tbs_sha256))
        self.assertEqual(raised.exception.code, "BAD_HISTORY")
        with self.assertRaises(NePKError) as raised:
            self.verify(trusted_history=replace(history, pair_tbs_sha256=" " + history.pair_tbs_sha256))
        self.assertEqual(raised.exception.code, "BAD_HISTORY")
        self.assertEqual(self.verify(trusted_history=replace(history, native_version=list(history.native_version)))
                         ["transition"], "IDEMPOTENT")

    def test_release_history_rejects_replay_conflict_and_version_downgrade(self):
        previous = history_from_report(self.verify())
        replay = self.verify(trusted_history=previous)
        self.assertEqual(replay["transition"], "IDEMPOTENT")
        other_ui = ui_member(self.key, self.native, version=(1, 0, 2), asset=b"different ui")
        same_seq_pair = pair_member(self.native, other_ui, 7, self.key)
        self.expect_reject(same_seq_pair, "CONTENT_CONFLICT", trusted_history=previous)
        lower_seq = pair_member(self.native, self.ui, 6, self.key)
        self.expect_reject(lower_seq, "DOWNGRADE", trusted_history=previous)
        higher_seq = pair_member(self.native, self.ui, 8, self.key)
        self.assertEqual(self.verify(higher_seq, trusted_history=previous)["transition"], "UPGRADE")
        lower_native = native_member(self.key, version=(3, 9, 9), payload=b"LOWR")
        lower_ui = ui_member(self.key, lower_native, version=(1, 0, 1))
        self.expect_reject(pair_member(lower_native, lower_ui, 8, self.key), "NATIVE_VERSION_DOWNGRADE", trusted_history=previous)

    def test_same_release_sequence_rejects_different_resigned_member_der(self):
        previous_report = self.verify()
        previous = history_from_report(previous_report)
        native_tbs = self.native[:member_tbs_len(self.native)]
        ui_tbs = self.ui[:member_tbs_len(self.ui)]
        resigned_native = native_tbs + self.key.sign(native_tbs, ec.ECDSA(hashes.SHA256()))
        resigned_ui = ui_tbs + self.key.sign(ui_tbs, ec.ECDSA(hashes.SHA256()))
        self.assertNotEqual(resigned_native, self.native)
        self.assertNotEqual(resigned_ui, self.ui)
        candidate = pair_member(resigned_native, resigned_ui, 7, self.key)
        candidate_report = self.verify(candidate)
        self.assertEqual(candidate_report["native_tbs_sha256"], previous_report["native_tbs_sha256"])
        self.assertEqual(candidate_report["ui_tbs_sha256"], previous_report["ui_tbs_sha256"])
        self.assertEqual(candidate_report["release_seq"], previous_report["release_seq"])
        self.assertEqual(candidate_report["native_version"], previous_report["native_version"])
        self.assertEqual(candidate_report["ui_version"], previous_report["ui_version"])
        self.assertNotEqual(candidate_report["pair_tbs_sha256"], previous_report["pair_tbs_sha256"])
        self.expect_reject(candidate, "CONTENT_CONFLICT", trusted_history=previous)

    def test_cross_native_ui_floor_and_same_version_content_conflicts(self):
        previous = history_from_report(self.verify())
        higher_native = native_member(self.key, version=(4, 1, 0), payload=b"NEWN")
        lower_ui = ui_member(self.key, higher_native, version=(0 + 1, 0, 0), asset=b"old ui")
        self.expect_reject(pair_member(higher_native, lower_ui, 8, self.key), "UI_VERSION_DOWNGRADE", trusted_history=previous)
        higher_ui_same_version = ui_member(self.key, higher_native, version=(1, 0, 1), asset=b"rebound ui")
        valid_rebind = pair_member(higher_native, higher_ui_same_version, 8, self.key)
        self.assertEqual(self.verify(valid_rebind, trusted_history=previous)["transition"], "UPGRADE")
        same_version_native = native_member(self.key, version=(4, 0, 1), payload=b"DIFF")
        same_version_ui = ui_member(self.key, same_version_native, version=(1, 0, 2))
        self.expect_reject(pair_member(same_version_native, same_version_ui, 8, self.key), "NATIVE_CONTENT_CONFLICT", trusted_history=previous)
        same_native_diff_ui = ui_member(self.key, self.native, version=(1, 0, 1), asset=b"same version changed")
        self.expect_reject(pair_member(self.native, same_native_diff_ui, 8, self.key), "UI_CONTENT_CONFLICT", trusted_history=previous)


if __name__ == "__main__":
    unittest.main()
