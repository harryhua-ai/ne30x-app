from __future__ import annotations

import hashlib
import json
import os
import subprocess
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

import neapp_v5_format as v5
from neapp_pack_v5 import PackError, build_v5
from support import (
    FIXTURE_APP_ID,
    FIXTURE_MARKER,
    FIXTURE_NATIVE_VERSION,
    FIXTURE_PACKAGE_PATH,
    FIXTURE_UI_VERSION,
    fixture_elf,
    fixture_package_sha256,
    write_fixture_ui_tree,
)

PACKER = ROOT / "package" / "unsigned" / "neapp_pack_v5.py"
VERIFIER = ROOT / "package" / "unsigned" / "neapp_verify_v5.py"
GOLDEN_V3 = ROOT / "docs" / "evidence" / "spec-v3" / "golden.neapp.v3"


def run_cli(script: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(script), *args],
                          capture_output=True, text=True)


class PackerTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="neapp-v5-pack-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.elf_path = self.root / "fixture.elf"
        self.elf_path.write_bytes(fixture_elf())
        self.ui_root = write_fixture_ui_tree(self.root / "ui")
        self.out = self.root / "line-crossing-4.0.0.neapp"

    def test_packer_output_is_deterministic_and_independently_verified(self):
        first = build_v5(
            self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
            FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
            0, 0, 0, 256, 0, 0, 0, None,
        )
        second_out = self.root / "line-crossing-4.0.0.again.neapp"
        build_v5(
            self.elf_path, self.ui_root, second_out, FIXTURE_APP_ID,
            FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
            0, 0, 0, 256, 0, 0, 0, None,
        )
        self.assertEqual(self.out.read_bytes(), second_out.read_bytes())
        self.assertEqual(first["package"]["sha256"], hashlib.sha256(self.out.read_bytes()).hexdigest())
        report, error = v5.verify_package_v5(self.out.read_bytes())
        self.assertIsNone(error)
        self.assertEqual(report["result"], "PASS")

    def test_committed_fixture_is_byte_reproducible(self):
        build_v5(
            self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
            FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
            0, 0, 0, 256, 0, 0, 0, None,
        )
        self.assertTrue(FIXTURE_PACKAGE_PATH.is_file())
        self.assertEqual(self.out.read_bytes(), FIXTURE_PACKAGE_PATH.read_bytes())

    def test_provenance_has_no_signing_inputs(self):
        provenance = self.root / "line-crossing-4.0.0.neapp.provenance.json"
        build_v5(
            self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
            FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
            0, 0, 0, 256, 0, 0, 0, None,
            provenance_path=provenance,
        )
        metadata = json.loads(provenance.read_text(encoding="utf-8"))
        self.assertEqual(metadata["artifact_type"], "unsigned NEAPP v5 package")
        self.assertIn("none: no private key", metadata["signing_dependencies"])
        for forbidden in ("signature", "signer_spki_sha256", "release_seq", "publisher"):
            self.assertNotIn(forbidden, metadata)
            self.assertNotIn(forbidden, metadata["native_build"])
            self.assertNotIn(forbidden, metadata["ui_build"])

    def test_elf_version_marker_mismatch_is_refused(self):
        self.elf_path.write_bytes(fixture_elf(marker=b"line-crossing-app 4.0.1: v4 session entry"))
        with self.assertRaises(PackError):
            build_v5(
                self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
                FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
                0, 0, 0, 256, 0, 0, 0, None,
            )

    def test_ui_tree_without_index_html_is_refused(self):
        (self.ui_root / "index.html").unlink()
        with self.assertRaises(PackError):
            build_v5(
                self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
                FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
                0, 0, 0, 256, 0, 0, 0, None,
            )

    def test_ui_tree_with_symlink_is_refused(self):
        link = self.ui_root / "app.js"
        link.unlink()
        link.symlink_to(self.elf_path)
        with self.assertRaises(PackError):
            build_v5(
                self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
                FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
                0, 0, 0, 256, 0, 0, 0, None,
            )

    def test_invalid_policy_declaration_is_refused_at_pack_time(self):
        with self.assertRaises(PackError):
            build_v5(
                self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
                FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x1000,
                0, 0, 0, 256, 0, 0, 0, None,
            )
        with self.assertRaises(PackError):
            build_v5(
                self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
                FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
                0, 0, 0, 16, 0, 0, 0, None,
            )


class CliTests(unittest.TestCase):
    def test_packer_and_verifier_cli_round_trip(self):
        with tempfile.TemporaryDirectory(prefix="neapp-v5-cli-") as raw:
            root = Path(raw)
            elf_path = root / "fixture.elf"
            elf_path.write_bytes(fixture_elf())
            ui_root = write_fixture_ui_tree(root / "ui")
            out = root / "line-crossing-4.0.0.neapp"
            pack = run_cli(PACKER, "--elf", str(elf_path), "--ui-assets", str(ui_root),
                           "--out", str(out), "--app-id", "line-crossing",
                           "--native-version", "4.0.0", "--ui-version", "1.0.0")
            self.assertEqual(pack.returncode, 0, pack.stderr)
            payload = json.loads(pack.stdout)
            self.assertEqual(payload["result"], "PASS")
            self.assertEqual(payload["package"]["sha256"],
                             hashlib.sha256(out.read_bytes()).hexdigest())
            verify = run_cli(VERIFIER, "--package", str(out), "--compact")
            self.assertEqual(verify.returncode, 0, verify.stderr)
            report = json.loads(verify.stdout)
            self.assertEqual(report["result"], "PASS")
            self.assertEqual(report["app_id"], "line-crossing")

    def test_verifier_cli_rejects_legacy_signed_package_explicitly(self):
        verify = run_cli(VERIFIER, "--package", str(GOLDEN_V3), "--compact")
        self.assertEqual(verify.returncode, 1)
        report = json.loads(verify.stdout)
        self.assertEqual(report["result"], "LEGACY_SIGNED_FORMAT")
        self.assertIn("unsupported legacy signed format", report["detail"])

    def test_verifier_cli_rejects_truncated_unsigned_package(self):
        with tempfile.TemporaryDirectory(prefix="neapp-v5-cli-neg-") as raw:
            root = Path(raw)
            data = bytearray(FIXTURE_PACKAGE_PATH.read_bytes())
            truncated = root / "truncated.neapp"
            truncated.write_bytes(bytes(data[:-3]))
            verify = run_cli(VERIFIER, "--package", str(truncated), "--compact")
            self.assertEqual(verify.returncode, 1)
            report = json.loads(verify.stdout)
            self.assertEqual(report["result"], "BAD_PACKAGE")

    def test_verifier_cli_supports_host_policy_admission(self):
        with tempfile.TemporaryDirectory(prefix="neapp-v5-cli-pol-") as raw:
            root = Path(raw)
            policy = root / "policy.json"
            policy.write_text(json.dumps({"psram_mib": 32}), encoding="utf-8")
            verify = run_cli(VERIFIER, "--package", str(FIXTURE_PACKAGE_PATH),
                             "--host-policy", str(policy), "--compact")
            self.assertEqual(verify.returncode, 1)
            report = json.loads(verify.stdout)
            self.assertEqual(report["result"], "TARGET_INCOMPATIBLE")


class FixtureArtifactTests(unittest.TestCase):
    def test_committed_fixture_passes_verification(self):
        self.assertTrue(FIXTURE_PACKAGE_PATH.is_file())
        report, error = v5.verify_package_v5(FIXTURE_PACKAGE_PATH.read_bytes())
        self.assertIsNone(error)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["package_sha256"], fixture_package_sha256())


if __name__ == "__main__":
    unittest.main()
