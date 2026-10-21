from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package" / "vnext"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))
sys.path.insert(0, str(ROOT / "package"))

import neapp_v4_format as v4
from nepk_v1_1_pack import EXPECTED_TEST_SPKI_SHA256, PackError, build_nepk
from nepk_v1_1_verify import verify_nepk
from test_image import elf_fixture


class NePKPackerTests(unittest.TestCase):
    def test_test_identity_binding_produces_one_verified_package_and_provenance(self):
        key = ec.generate_private_key(ec.SECP256R1())
        spki = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(spki).hexdigest()
        with tempfile.TemporaryDirectory(prefix="nepk-packer-test-") as temp:
            root = Path(temp)
            key_path = root / "test-key.pem"
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            assets = root / "ui"
            assets.mkdir()
            (assets / "index.html").write_text("<!doctype html><title>fixture</title>", encoding="utf-8")
            elf = root / "real-input.elf"
            elf.write_bytes(elf_fixture(payload=b"line-crossing-app 4.0.1: v4 session entry"))
            output = root / "line-crossing.neapp"
            provenance = root / "line-crossing.provenance.json"
            metadata = build_nepk(
                elf, assets, key_path, output, "ne301-exp-pub", "line-crossing",
                (4, 0, 1), (1, 0, 1), 17, "candidate-source-sha", provenance,
                expected_spki_sha256=fingerprint,
            )
            self.assertEqual(metadata["artifact_type"], "TEST ONLY NEPK v1.1; not a production trust root or release")
            self.assertFalse(metadata["private_key_included"])
            self.assertTrue(output.is_file())
            self.assertTrue(provenance.is_file())
            self.assertEqual(metadata["package"]["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            report = verify_nepk(output.read_bytes(), {"ne301-exp-pub": spki}, "ne301-exp-pub", "line-crossing")
            self.assertEqual(report["result"], "PASS")
            self.assertEqual(report["release_seq"], 17)
            self.assertEqual(metadata["source"]["commit"], "candidate-source-sha")
            self.assertEqual(metadata["publisher_spki_sha256"], fingerprint)
            self.assertEqual(metadata["native_build"]["elf_sha256"], hashlib.sha256(elf.read_bytes()).hexdigest())

    def test_test_signing_key_must_match_the_pinned_test_spki(self):
        key = ec.generate_private_key(ec.SECP256R1())
        spki = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(spki).hexdigest()
        self.assertNotEqual(fingerprint, EXPECTED_TEST_SPKI_SHA256)
        with tempfile.TemporaryDirectory(prefix="nepk-wrong-key-") as temp:
            root = Path(temp)
            key_path = root / "key.pem"
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            assets = root / "ui"
            assets.mkdir()
            (assets / "index.html").write_text("x", encoding="ascii")
            elf = root / "app.elf"
            elf.write_bytes(elf_fixture(payload=b"line-crossing-app 4.0.1: v4 session entry"))
            with self.assertRaises(PackError):
                build_nepk(elf, assets, key_path, root / "bad.neapp", "ne301-exp-pub",
                           "line-crossing", (4, 0, 1), (1, 0, 1), 1)


if __name__ == "__main__":
    unittest.main()
