from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package"))
sys.path.insert(0, str(ROOT / "package" / "unsigned"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import neapp_v5_native as v4
import neapp_v5_product_version as product
import neapp_v5_format as v5
from neapp_pack_v5 import PackError, build_v5
from support import (
    FIXTURE_APP_ID,
    FIXTURE_NATIVE_VERSION,
    FIXTURE_UI_VERSION,
    FIXTURE_PACKAGE_PATH,
    fixture_elf,
    write_fixture_ui_tree,
)

PACKER = ROOT / "package" / "unsigned" / "neapp_pack_v5.py"
VERIFIER = ROOT / "package" / "unsigned" / "neapp_verify_v5.py"
PRODUCT_CAPS = v4.HOST_CAPS_VOCABULARY_MASK  # 0x7ff: product-version-capable Host
OLD_HOST_CAPS = v4.HOST_CAPS_KNOWN_MASK      # 0x3ff: Hosts without product metadata
CANONICAL = b'{"product_version":"1.0.3"}'


def run_cli(script: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(script), *args],
                          capture_output=True, text=True)


class CarrierSchemaTests(unittest.TestCase):
    def test_canonical_bytes_parse(self):
        self.assertEqual(product.parse_product_version_asset(CANONICAL), "1.0.3")

    def test_declared_version_validation(self):
        self.assertEqual(product.parse_product_version("1.0.3"), "1.0.3")
        self.assertEqual(product.parse_product_version("10.20.30"), "10.20.30")
        self.assertEqual(product.parse_product_version("1.0.0"), "1.0.0")
        self.assertEqual(product.parse_product_version("1.10.1"), "1.10.1")
        for bad in ("v1.0.2", "01.0.2", "1.0", "1.0.2.0", "0.9.9", "1..0",
                    "1.0.x", "", "1.0.2 ", " 1.0.2", 1.01, None,
                    "1.01.1", "1.0.01"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                product.parse_product_version(bad)
        for bad_asset in (b'{"product_version":"1.01.1"}',
                          b'{"product_version":"1.0.01"}'):
            with self.assertRaises(v4.BadPackage):
                product.parse_product_version_asset(bad_asset)

    def test_asset_schema_negatives(self):
        cases = {
            "not json": b"product_version",
            "not an object": b'"1.0.2"',
            "array": b'[{"product_version":"1.0.2"}]',
            "missing key": b'{"version":"1.0.2"}',
            "extra field": b'{"product_version":"1.0.2","channel":"stable"}',
            "non-string": b'{"product_version":1.01}',
            "v prefix": b'{"product_version":"v1.0.2"}',
            "zero major": b'{"product_version":"0.1.0"}',
            "leading zero": b'{"product_version":"01.0.2"}',
            "whitespace": b'{"product_version": "1.0.2"}',
            "trailing newline": CANONICAL + b"\n",
            "duplicate key": b'{"product_version":"1.0.2","product_version":"1.0.3"}',
            "nan constant": b'{"product_version":"1.0.2","x":NaN}',
            "empty": b"",
            "too long": b'{"product_version":"' + b"1" * 200 + b'"}',
            "invalid utf-8": b'{"product_version":"1.0.\xff"}',
        }
        for name, blob in cases.items():
            with self.assertRaises(v4.BadPackage, msg=name):
                product.parse_product_version_asset(blob)


class LineCrossingDefaultsTests(unittest.TestCase):
    def test_packaging_defaults_match_the_candidate_versions(self):
        app_dir = ROOT / "apps" / "line-crossing" / "app"
        result = subprocess.run(
            ["make", "-s", "-C", str(app_dir), "print-v4_app_version",
             "print-v5_ui_version", "print-v5_product_version"],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout.splitlines(), ["4.2.14", "1.2.17", "1.0.3"])


class ProductPackageTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="neapp-product-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.elf_path = self.root / "fixture.elf"
        self.elf_path.write_bytes(fixture_elf())
        self.ui_root = write_fixture_ui_tree(self.root / "ui")
        self.out = self.root / "line-crossing-1.0.3.neapp"

    def pack_product(self, product_version="1.0.3", carrier=CANONICAL,
                     native_version=FIXTURE_NATIVE_VERSION,
                     ui_version=FIXTURE_UI_VERSION):
        (self.ui_root / product.PRODUCT_VERSION_ASSET_PATH).write_bytes(carrier)
        return build_v5(
            self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
            native_version, ui_version, 0x63,
            0, 0, 0, 256, 0, 0, 0,
            product_version=product_version,
        )

    def test_product_package_carries_the_asset_in_the_hash_chain(self):
        metadata = self.pack_product()
        self.assertEqual(metadata["product_version"], "1.0.3")
        self.assertEqual(metadata["host_policy"]["host_caps"], 0x63 | v4.CAP_PRODUCT_VERSION)
        carrier_records = [entry for entry in metadata["ui_build"]["asset_records"]
                           if entry["path"] == product.PRODUCT_VERSION_ASSET_PATH]
        self.assertEqual(len(carrier_records), 1)
        self.assertEqual(carrier_records[0]["sha256"], hashlib.sha256(CANONICAL).hexdigest())
        data = self.out.read_bytes()
        self.assertEqual(data[:8], bytes.fromhex("4e45415050050000"))
        native_len, ui_len = struct.unpack_from("<II", data, 8)
        self.assertEqual(v5.HEADER_LEN + native_len + ui_len, len(data))
        report, error = v5.verify_package_v5(data, policy=v4.DevicePolicyV4(host_caps=PRODUCT_CAPS))
        self.assertIsNone(error)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["product_version"], "1.0.3")
        self.assertEqual(report["required_host_caps"], f"{0x63 | v4.CAP_PRODUCT_VERSION:#x}")
        # The carrier asset rides collect_assets(): it is an ordinary record
        # in the verified UI manifest hash chain.
        self.assertIn(product.PRODUCT_VERSION_ASSET_PATH,
                      [entry["path"] for entry in report["ui_files"]])

    def test_old_host_gate_refuses_before_install_simulation(self):
        self.pack_product()
        report, error = v5.verify_package_v5(self.out.read_bytes())
        self.assertIsNone(report)
        self.assertIsInstance(error, v4.AbiIncompatible)
        self.assertIn(f"{v4.CAP_PRODUCT_VERSION:#x}", error.detail)

    def test_native_and_ui_component_versions_stay_untouched(self):
        metadata = self.pack_product()
        self.assertEqual(metadata["native_version"], list(FIXTURE_NATIVE_VERSION))
        self.assertEqual(metadata["ui_version"], list(FIXTURE_UI_VERSION))
        report, error = v5.verify_package_v5(
            self.out.read_bytes(), policy=v4.DevicePolicyV4(host_caps=PRODUCT_CAPS))
        self.assertIsNone(error)
        self.assertEqual(report["native_version"],
                         ".".join(str(x) for x in FIXTURE_NATIVE_VERSION))
        self.assertEqual(report["ui_version"],
                         ".".join(str(x) for x in FIXTURE_UI_VERSION))
        # The product version is never aliased onto the UI component tuple.
        self.assertNotEqual(report["ui_version"], report["product_version"])

    def test_tampered_carrier_breaks_the_existing_hash_chain(self):
        self.pack_product()
        data = bytearray(self.out.read_bytes())
        index = data.find(CANONICAL)
        self.assertGreaterEqual(index, 0)
        data[index + len(CANONICAL) - 3] = ord("2")
        report, error = v5.verify_package_v5(
            bytes(data), policy=v4.DevicePolicyV4(host_caps=PRODUCT_CAPS))
        self.assertIsNone(report)
        self.assertIsNotNone(error)
        self.assertIn("sha256 does not match", error.detail)

    def test_pack_refuses_missing_carrier_asset(self):
        # No carrier file in the UI tree at all.
        with self.assertRaises(PackError):
            build_v5(
                self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
                FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
                0, 0, 0, 256, 0, 0, 0,
                product_version="1.0.3",
            )
        self.assertFalse(self.out.exists())

    def test_pack_refuses_carrier_declared_mismatch(self):
        self.pack_product()  # writes 1.0.3 carrier
        with self.assertRaises(PackError):
            build_v5(
                self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
                FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
                0, 0, 0, 256, 0, 0, 0,
                product_version="1.0.2",
            )

    def test_pack_refuses_non_canonical_carrier(self):
        with self.assertRaises(PackError):
            self.pack_product(carrier=b'{"product_version": "1.0.2"}\n')

    def test_pack_refuses_invalid_declared_version(self):
        for bad in ("v1.0.2", "01.2.3", "0.1.0", "1.0"):
            with self.assertRaises(PackError, msg=bad):
                self.pack_product(product_version=bad)

    def test_bit_gate_is_implied_by_metadata(self):
        metadata = self.pack_product()
        # Even a caller that passes only base caps gets the gate bit: a
        # product-version package without the 0x400 requirement is impossible.
        self.assertEqual(metadata["host_policy"]["host_caps"] & v4.CAP_PRODUCT_VERSION,
                         v4.CAP_PRODUCT_VERSION)

    def test_verifier_refuses_gate_bit_without_carrier(self):
        # Forge a package that claims the 0x400 gate bit but carries no
        # product-version.json: patch the manifest caps, then repair the
        # Native/UI member binding so only the product check can reject it.
        # The plain fixture tree has no carrier asset to remove.
        build_v5(
            self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
            FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
            0, 0, 0, 256, 0, 0, 0,
        )
        data = bytearray(self.out.read_bytes())
        native_len = int.from_bytes(data[8:12], "little")
        manifest_off = 16 + 16  # container header + native member header
        struct.pack_into("<I", data, manifest_off + 72, 0x63 | v4.CAP_PRODUCT_VERSION)
        binding_off = 16 + native_len + 16 + 80  # ui member header + binding offset
        data[binding_off:binding_off + 32] = hashlib.sha256(
            bytes(data[16:16 + native_len])).digest()
        report, error = v5.verify_package_v5(
            bytes(data), policy=v4.DevicePolicyV4(host_caps=PRODUCT_CAPS))
        self.assertIsNone(report)
        self.assertIsInstance(error, v4.BadPackage)
        self.assertIn("0x400", error.detail)

    def test_package_without_bit_but_with_asset_keeps_legacy_behavior(self):
        # A package that does NOT require the gate bit must keep the exact
        # historical verification behavior: the same-named asset is an
        # ordinary hashed resource, and no product_version is reported.
        (self.ui_root / product.PRODUCT_VERSION_ASSET_PATH).write_bytes(CANONICAL)
        build_v5(
            self.elf_path, self.ui_root, self.out, FIXTURE_APP_ID,
            FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION, 0x63,
            0, 0, 0, 256, 0, 0, 0,
        )
        report, error = v5.verify_package_v5(self.out.read_bytes())
        self.assertIsNone(error)
        self.assertEqual(report["result"], "PASS")
        self.assertNotIn("product_version", report)

    def test_committed_fixture_is_unaffected(self):
        report, error = v5.verify_package_v5(FIXTURE_PACKAGE_PATH.read_bytes())
        self.assertIsNone(error)
        self.assertEqual(report["result"], "PASS")
        self.assertNotIn("product_version", report)
        self.assertEqual(report["required_host_caps"], "0x63")


class ProductCliTests(unittest.TestCase):
    def test_packer_and_verifier_cli_round_trip(self):
        with tempfile.TemporaryDirectory(prefix="neapp-product-cli-") as raw:
            root = Path(raw)
            elf_path = root / "fixture.elf"
            elf_path.write_bytes(fixture_elf())
            ui_root = write_fixture_ui_tree(root / "ui")
            (ui_root / product.PRODUCT_VERSION_ASSET_PATH).write_bytes(CANONICAL)
            out = root / "line-crossing-1.0.3.neapp"
            pack = run_cli(PACKER, "--elf", str(elf_path), "--ui-assets", str(ui_root),
                           "--out", str(out), "--app-id", "line-crossing",
                           "--native-version", "4.0.0", "--ui-version", "1.1.1",
                           "--product-version", "1.0.3")
            self.assertEqual(pack.returncode, 0, pack.stderr)
            payload = json.loads(pack.stdout)
            self.assertEqual(payload["result"], "PASS")

            provenance = json.loads(Path(str(out) + ".provenance.json").read_text(encoding="utf-8"))
            self.assertEqual(provenance["product_version"], "1.0.3")
            self.assertEqual(provenance["native_version"], [4, 0, 0])
            self.assertEqual(provenance["ui_version"], [1, 1, 1])

            # Default simulated Host (0x3ff) refuses: old-Host fail-closed.
            refused = run_cli(VERIFIER, "--package", str(out), "--compact")
            self.assertEqual(refused.returncode, 1)
            report = json.loads(refused.stdout)
            self.assertEqual(report["result"], "ABI_INCOMPATIBLE")
            self.assertIn("0x400", report["detail"])

            # Product-version-capable Host admits and reports the version.
            admitted = run_cli(VERIFIER, "--package", str(out), "--compact",
                               "--host-caps-hex", hex(PRODUCT_CAPS))
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            admitted_report = json.loads(admitted.stdout)
            self.assertEqual(admitted_report["result"], "PASS")
            self.assertEqual(admitted_report["product_version"], "1.0.3")

    def test_packer_cli_refuses_bad_product_version_flag(self):
        with tempfile.TemporaryDirectory(prefix="neapp-product-cli-bad-") as raw:
            root = Path(raw)
            elf_path = root / "fixture.elf"
            elf_path.write_bytes(fixture_elf())
            ui_root = write_fixture_ui_tree(root / "ui")
            (ui_root / product.PRODUCT_VERSION_ASSET_PATH).write_bytes(CANONICAL)
            out = root / "line-crossing-1.0.3.neapp"
            pack = run_cli(PACKER, "--elf", str(elf_path), "--ui-assets", str(ui_root),
                           "--out", str(out), "--app-id", "line-crossing",
                           "--native-version", "4.0.0", "--ui-version", "1.1.1",
                           "--product-version", "01.0.2")
            self.assertNotEqual(pack.returncode, 0)
            self.assertFalse(out.exists())

    def test_verifier_cli_rejects_bad_host_caps_override(self):
        verify = run_cli(VERIFIER, "--package", str(FIXTURE_PACKAGE_PATH),
                         "--compact", "--host-caps-hex", "not-a-number")
        self.assertEqual(verify.returncode, 1)
        report = json.loads(verify.stdout)
        self.assertEqual(report["result"], "INPUT_ERROR")

    def test_verifier_cli_host_policy_and_caps_override_combine(self):
        with tempfile.TemporaryDirectory(prefix="neapp-product-cli-pol-") as raw:
            root = Path(raw)
            policy = root / "policy.json"
            policy.write_text(json.dumps({"psram_mib": 32}), encoding="utf-8")
            verify = run_cli(VERIFIER, "--package", str(FIXTURE_PACKAGE_PATH),
                             "--host-policy", str(policy), "--compact",
                             "--host-caps-hex", hex(PRODUCT_CAPS))
            self.assertEqual(verify.returncode, 1)
            report = json.loads(verify.stdout)
            # The caps override took effect (fixture needs no 0x400), so the
            # refusal must come from the policy mismatch, not the caps mask.
            self.assertEqual(report["result"], "TARGET_INCOMPATIBLE")


if __name__ == "__main__":
    unittest.main()
