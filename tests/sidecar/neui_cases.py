#!/usr/bin/env python3
"""neui_cases — Issue #26 offline positive/negative/rejection-matrix suite
for NEUI UI-Sidecar v1 bundles produced by the package/sidecar tooling.

Runs the REAL CLIs (package/sidecar/neui_verify_v1.py,
package/sidecar/neui_pack_v1.py, package/neapp_verify_v3.py,
package/neapp_pack_v3.py, tests/package-v3/make_v3_test_image.py,
tools/sidecar/make_neui_fixture.py) and layers the committed golden
sidecar artifacts (docs/evidence/sidecar-v1/) plus the committed #19
native v3 golden (docs/evidence/spec-v3/golden.neapp.v3) through the
independent verifier, so the pinned ui_tbs_sha256 identity, the
byte-identical golden reproduction, the native-TBS binding, the install
transition classification and the full structural/signature/trust/path
rejection matrix are re-proven against the frozen ne301 #79 §12 wire.

Every rejection case asserts the expected error class AND a
detail-substring attribution, so a pass cannot come from a checkpoint
that happens to run earlier.  Forged bundles are re-signed with the
PUBLIC NON-PRODUCTION spec d=1 test scalar (or an ephemeral test key) to
prove "valid signature" never upgrades an invalid bundle.  Every case is
offline packaging-layer evidence, never a device or Host claim.

Exit code 0 only if every expectation (class + detail attribution) matches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "package"))
sys.path.insert(0, str(REPO / "package" / "sidecar"))
import neapp_format as fmt
import neui_sidecar_format as sc

VERIFY = REPO / "package" / "sidecar" / "neui_verify_v1.py"
PACK = REPO / "package" / "sidecar" / "neui_pack_v1.py"
VERIFY_V3 = REPO / "package" / "neapp_verify_v3.py"
PACK_V3 = REPO / "package" / "neapp_pack_v3.py"
MAKE_V3_IMAGE = REPO / "tests" / "package-v3" / "make_v3_test_image.py"
FIXTURE_TOOL = REPO / "tools" / "sidecar" / "make_neui_fixture.py"
NATIVE_GOLDEN = REPO / "docs" / "evidence" / "spec-v3" / "golden.neapp.v3"
NATIVE_SPKI = REPO / "docs" / "evidence" / "spec-v3" / "test-publisher.spki.der"

SPKI_SHA256 = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
NATIVE_TBS_SHA256 = "d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e"
GOLDEN_UI_TBS_SHA256 = "aa8130ea20737d457bb6ace49871daa82e85338c7b2e2da656edcc9b7f3fe02f"
GOLDEN_BUNDLE_SHA256 = "9ec5e44616e197dfa0b3d16a5f9b0f280b523883be2c1cddf4f363126e8f79d4"
GOLDEN_DER_HEX = (
    "3046022100c6e9b567e1e33db227f7ed17b2fff38d98acc9577f688b43b9d7d9747e5038ae"
    "02210089412530ee5653dcf127e8c56968505f3a6aaa87b414a8528fbf5e412751fae9"
)
FIXTURE_SHA256 = {
    "assets/data.txt": "0425d207cfc5a2d2803468154454a886bb61c4d77e4f315bd3f192722fe79613",
    "css/style.css": "11e342847acb42e55786baccd45fb98ff096b1907994731693eb69d87159cadd",
    "index.html": "6d3ffad90906331b584082c8d72761f7761e9c18fafd383aaa4a79e8e8bafc68",
    "js/app.js": "8e429026a9b1a783359d418892700aec53d5c715dbeddfc7e2b76078d9470846",
}

PUBLISHER = "test-publisher"
APP_ID = "line-crossing"

results: list[dict] = []


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def run_verifier(bundle: Path, trust: Path, expect: str,
                 native_package: Path | None = None,
                 native_trust: Path | None = None) -> dict:
    cmd = [sys.executable, str(VERIFY), "--bundle", str(bundle),
           "--trust", str(trust), "--expect", expect, "--compact"]
    if native_package is not None:
        cmd += ["--native-package", str(native_package)]
    if native_trust is not None:
        cmd += ["--native-trust", str(native_trust)]
    proc = run_cmd(cmd)
    if proc.returncode != 0:
        raise AssertionError(
            f"sidecar verifier did not produce expected {expect} for {bundle.name}:\n"
            f"{proc.stdout}{proc.stderr}")
    return json.loads(proc.stdout.strip().splitlines()[0])


def verify_bytes(name: str, data: bytes, case_dir: Path, trust: Path, expect: str,
                 detail_contains: str | None = None, note: str = "",
                 native_package: Path | None = None,
                 native_trust: Path | None = None,
                 extra: dict | None = None) -> dict:
    path = case_dir / f"{name}.neui"
    path.write_bytes(data)
    report = run_verifier(path, trust, expect, native_package, native_trust)
    detail = report.get("detail")
    if detail_contains is not None and expect != "PASS":
        if detail is None or detail_contains not in detail:
            raise AssertionError(
                f"{name}: expected detail containing {detail_contains!r}, got {detail!r}")
    entry = {
        "case": name,
        "category": "sidecar",
        "expected": expect,
        "observed": report.get("result", expect),
        "bundle_sha256": sha256_hex(data),
        "detail": detail,
        "note": note,
    }
    if extra:
        entry.update(extra)
    results.append(entry)
    print(f"  ok {name}: {expect}" + (f" [{detail_contains}]" if detail_contains else ""))
    return report


def record_predicate(name: str, note: str, predicate: bool, extra: dict | None = None) -> None:
    if not predicate:
        raise AssertionError(f"{name}: predicate failed")
    entry = {"case": name, "category": "sidecar", "expected": "PASS",
             "observed": "PASS", "note": note}
    if extra:
        entry.update(extra)
    results.append(entry)
    print(f"  ok {name}: predicate")


class Signer:
    def __init__(self, key_pem: bytes, publisher_id: str):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self.key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(self.key, ec.EllipticCurvePrivateKey):
            raise ValueError("expected an EC private key")
        self.publisher_id = publisher_id
        self.spki = fmt.spki_der_from_public_key(self.key.public_key())
        self.fingerprint = hashlib.sha256(self.spki).digest()

    def sign(self, tbs: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        try:
            algorithm = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        except TypeError:
            algorithm = ec.ECDSA(hashes.SHA256())
        return self.key.sign(tbs, algorithm)


def fixed_block(pub: bytes = PUBLISHER.encode(), app: bytes = APP_ID.encode(),
                fp: bytes | None = None, native_tbs: bytes | None = None,
                ver: tuple[int, int, int] = (1, 0, 0), count: int = 4,
                abi: int = 1, reserved: int = 0) -> bytes:
    out = bytearray(128)
    out[0:16] = pub.ljust(16, b"\x00")
    out[16:48] = app.ljust(32, b"\x00")
    out[48:80] = fp if fp is not None else bytes(32)
    out[80:112] = native_tbs if native_tbs is not None else bytes(32)
    struct.pack_into("<HHH", out, 112, *ver)
    struct.pack_into("<H", out, 118, count)
    struct.pack_into("<I", out, 120, abi)
    struct.pack_into("<I", out, 124, reserved)
    return bytes(out)


def forge_record(path: bytes, file_len: int, sha: bytes) -> bytes:
    return struct.pack("<HI", len(path), file_len) + sha + path


def build_forged(fixed: bytes, records: list[bytes], payload: bytes,
                 signer: Signer, asset_len: int | None = None,
                 manifest_tail: bytes = b"") -> bytes:
    manifest = fixed + b"".join(records) + manifest_tail
    header = sc.CONTAINER_MAGIC + struct.pack("<II", len(manifest),
                                              len(payload) if asset_len is None else asset_len)
    tbs = header + manifest + payload
    return tbs + signer.sign(tbs)


def split_bundle(bundle: bytes) -> tuple[bytes, bytes]:
    manifest_len, asset_len = struct.unpack_from("<II", bundle, 8)
    return bundle[16:16 + manifest_len], bundle[:16 + manifest_len + asset_len]


def relength(bundle: bytes, manifest_len: int | None = None,
             asset_len: int | None = None) -> bytes:
    out = bytearray(bundle)
    if manifest_len is not None:
        out[8:12] = struct.pack("<I", manifest_len)
    if asset_len is not None:
        out[12:16] = struct.pack("<I", asset_len)
    return bytes(out)


def to_low_s_der(sig: bytes) -> bytes:
    r, s = fmt.parse_strict_ecdsa_der(sig)
    s2 = fmt.P256_ORDER - s

    def enc_int(v: int) -> bytes:
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return bytes([0x02, len(b)]) + b

    body = enc_int(r) + enc_int(s2)
    return bytes([0x30, len(body)]) + body


def pack_sidecar(work: Path, fixture: Path, out: Path, signer_pem: Path,
                 version: str = "1.0.0", publisher: str = PUBLISHER,
                 app: str = APP_ID, native: Path | None = None,
                 extra: list[str] | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PACK),
           "--asset-root", str(fixture), "--out", str(out),
           "--key", str(signer_pem), "--publisher-id", publisher,
           "--app-id", app, "--version", version,
           "--native-package", str(native if native else work / "native-golden-replica.neapp.v3"),
           "--native-trust", str(work / "trust-d1.json"), "--sidecar", "none"]
    if extra:
        cmd += extra
    return run_cmd(cmd)


def expect_pack_refusal(name: str, work: Path, fixture: Path, out: Path,
                        version: str = "1.0.0", publisher: str = PUBLISHER,
                        app: str = APP_ID, native: Path | None = None,
                        extra: list[str] | None = None,
                        stderr_contains: str = "") -> None:
    proc = pack_sidecar(work, fixture, out, work / "keys" / "d1-test-signer.pem",
                        version=version, publisher=publisher, app=app,
                        native=native, extra=extra)
    if proc.returncode == 0:
        raise AssertionError(f"{name}: packer accepted an illegal input (rc=0)")
    if proc.returncode != 2:
        raise AssertionError(f"{name}: expected packer exit 2, got {proc.returncode}: "
                             f"{proc.stdout}{proc.stderr}")
    if stderr_contains and stderr_contains not in (proc.stderr or ""):
        raise AssertionError(f"{name}: expected stderr containing {stderr_contains!r}, "
                             f"got {proc.stderr!r}")
    if out.exists():
        raise AssertionError(f"{name}: refused pack must not emit the bundle file")
    results.append({
        "case": name,
        "category": "packer-refusal",
        "expected": "packer exit 2 (fail-closed, no bundle emitted)",
        "observed": "packer exit 2",
        "detail": (proc.stderr or "").strip().splitlines()[0] if proc.stderr else "",
        "note": name,
    })
    print(f"  ok {name}: refused")


def make_tree(root: Path, files: dict[str, bytes]) -> Path:
    if root.exists():
        shutil.rmtree(root)
    for rel, blob in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--golden-dir", required=True, type=Path,
                        help="committed sidecar golden evidence dir "
                             "(docs/evidence/sidecar-v1)")
    args = parser.parse_args()

    work = args.work_dir
    case_dir = work / "cases"
    case_dir.mkdir(parents=True, exist_ok=True)
    golden_dir = args.golden_dir

    print("[neui-cases] setup: d=1 identity, native replicas, fixtures")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    d1 = ec.derive_private_key(1, ec.SECP256R1())
    spki_d1 = d1.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if sha256_hex(spki_d1) != SPKI_SHA256:
        raise AssertionError("d=1 SPKI digest drifted from the pinned spec value")
    if NATIVE_SPKI.read_bytes() != spki_d1:
        raise AssertionError("committed #19 test-publisher SPKI != generated d=1 SPKI")
    keys = work / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    d1_pem = keys / "d1-test-signer.pem"
    d1_pem.write_text(d1.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode(), encoding="ascii")
    trust_d1 = work / "trust-d1.json"
    trust_d1.write_text(json.dumps({
        "version": 1,
        "comment": ("NON-PRODUCTION offline test trust store for the PUBLIC spec "
                    "d=1 test key; never a production trust anchor"),
        "publishers": {PUBLISHER: {"spki_der_hex": spki_d1.hex(),
                                   "spki_sha256": SPKI_SHA256}},
    }, indent=2) + "\n", encoding="utf-8")
    signer = Signer(d1_pem.read_bytes(), PUBLISHER)

    image_golden = work / "lc-v3-test-image.bin"
    proc = run_cmd([sys.executable, str(MAKE_V3_IMAGE), "--out", str(image_golden),
                    "--expect-sha256",
                    "aa8c3ef6e4082656c76255807bee5a7c562ad212a0c3e2a4f009a62129cdee69"])
    if proc.returncode != 0:
        raise AssertionError(f"make_v3_test_image failed: {proc.stderr}")
    native_golden_replica = work / "native-golden-replica.neapp.v3"
    proc = run_cmd([sys.executable, str(PACK_V3), "--image", str(image_golden),
                    "--out", str(native_golden_replica),
                    "--key", str(d1_pem), "--publisher-id", PUBLISHER,
                    "--app-id", APP_ID, "--version", "3.0.0",
                    "--host-caps", "0xff", "--event-max", "2048",
                    "--state-quota", "4096", "--report-max", "6144",
                    "--control-max", "256", "--snapshot-max", "1024",
                    "--sidecar", "none"])
    if proc.returncode != 0:
        raise AssertionError(f"native v3 replica pack failed: {proc.stderr}")
    if sha256_hex(native_golden_replica.read_bytes()) != \
            sha256_hex(NATIVE_GOLDEN.read_bytes()):
        raise AssertionError("native v3 replica != committed #19 golden package")
    image_alt = work / "lc-v3-alt-image.bin"
    proc = run_cmd([sys.executable, str(MAKE_V3_IMAGE), "--out", str(image_alt),
                    "--payload-hex", "00207048"])
    if proc.returncode != 0:
        raise AssertionError(f"make_v3_test_image alt failed: {proc.stderr}")
    native_alt = work / "native-alt.neapp.v3"
    proc = run_cmd([sys.executable, str(PACK_V3), "--image", str(image_alt),
                    "--out", str(native_alt),
                    "--key", str(d1_pem), "--publisher-id", PUBLISHER,
                    "--app-id", APP_ID, "--version", "3.0.1",
                    "--host-caps", "0x63", "--control-max", "256",
                    "--sidecar", "none"])
    if proc.returncode != 0:
        raise AssertionError(f"alt native v3 pack failed: {proc.stderr}")
    native_tbs_alt = sha256_hex(native_alt.read_bytes()[:16 + 192 + 36])
    if native_tbs_alt == NATIVE_TBS_SHA256:
        raise AssertionError("alt native TBS equals the golden native TBS")

    proc = run_cmd([sys.executable, str(FIXTURE_TOOL), "--out-dir", str(work / "fixtures"),
                    "--variant", "base"])
    if proc.returncode != 0:
        raise AssertionError(f"fixture base failed: {proc.stderr}")
    proc = run_cmd([sys.executable, str(FIXTURE_TOOL), "--out-dir", str(work / "fixtures"),
                    "--variant", "alt"])
    if proc.returncode != 0:
        raise AssertionError(f"fixture alt failed: {proc.stderr}")
    fixture_base = work / "fixtures" / "base"
    fixture_alt = work / "fixtures" / "alt"
    for rel, digest in FIXTURE_SHA256.items():
        actual = sha256_hex((fixture_base / rel).read_bytes())
        if actual != digest:
            raise AssertionError(f"fixture {rel} sha256 {actual} != pinned {digest}")
    record_predicate(
        "fixture_digest_pins",
        "generated base fixture files match the pinned per-file SHA-256 values "
        "(deterministic non-production fixture; not the real counting UI)",
        True, extra={"files": FIXTURE_SHA256})

    print("[neui-cases] positives: AC1 pack, golden reproduction, idempotency (AC3)")
    golden_replica = work / "golden-replica.neui"
    proc = pack_sidecar(work, fixture_base, golden_replica, d1_pem)
    if proc.returncode != 0:
        raise AssertionError(f"golden replica pack failed: {proc.stderr}")
    replica = golden_replica.read_bytes()
    golden_bundle = (golden_dir / "golden.neui").read_bytes()
    golden_tbs = (golden_dir / "golden-tbs.bin").read_bytes()
    golden_der = (golden_dir / "golden-sig.der").read_bytes()
    record_predicate(
        "golden_replica_byte_identical",
        "neui_pack_v1 with the PUBLIC d=1 identity over the deterministic base fixture "
        "reproduces the committed sidecar golden byte-for-byte: TBS == golden-tbs.bin, "
        "DER == golden-sig.der, bundle == golden.neui",
        replica == golden_bundle and replica[:len(golden_tbs)] == golden_tbs
        and replica[len(golden_tbs):] == golden_der,
        extra={"pinned_ui_tbs_sha256": GOLDEN_UI_TBS_SHA256,
               "observed_ui_tbs_sha256": sha256_hex(replica[:len(golden_tbs)]),
               "pinned_bundle_sha256": GOLDEN_BUNDLE_SHA256,
               "observed_bundle_sha256": sha256_hex(replica),
               "bundle_len": len(replica)})
    verify_bytes("golden_bundle_accept", golden_bundle, case_dir, trust_d1,
                 "PASS", note="committed sidecar golden through the independent verifier")
    rep_native = run_verifier(golden_dir / "golden.neui", trust_d1, "PASS",
                              native_package=NATIVE_GOLDEN, native_trust=trust_d1)
    record_predicate(
        "golden_native_binding_accept",
        "committed golden bundle verifies PASS with the native-binding cross-check against "
        "the committed #19 native v3 golden: publisher_id/app_id/publisher_key_sha256/"
        "native_tbs_sha256 all match the verified native TBS "
        + NATIVE_TBS_SHA256,
        rep_native["native_binding_checked"] is True
        and rep_native["native_tbs_sha256"] == NATIVE_TBS_SHA256
        and rep_native["publisher_key_sha256"] == SPKI_SHA256
        and rep_native["file_count"] == 4
        and rep_native["ui_tbs_sha256"] == GOLDEN_UI_TBS_SHA256,
        extra={"native_tbs_sha256": rep_native["native_tbs_sha256"],
               "publisher_key_sha256": rep_native["publisher_key_sha256"],
               "file_count": rep_native["file_count"],
               "sidecar_version": rep_native["sidecar_version"],
               "asset_payload_len": rep_native["asset_payload_len"],
               "manifest_len": rep_native["manifest_len"],
               "signature_len": rep_native["signature_len"]})

    golden_repack = work / "golden-repack.neui"
    proc = pack_sidecar(work, fixture_base, golden_repack, d1_pem)
    if proc.returncode != 0:
        raise AssertionError(f"repack failed: {proc.stderr}")
    repack = golden_repack.read_bytes()
    record_predicate(
        "idempotent_repack_same_identity",
        "packing the same fixture + metadata twice reproduces the identical TBS and, "
        "under RFC-6979, the identical bundle bytes: idempotent content identity "
        "(ui_tbs_sha256 stable, legal DER nondeterminism tolerated by design)",
        sha256_hex(repack[:len(golden_tbs)]) == sha256_hex(golden_tbs)
        and repack == golden_bundle,
        extra={"ui_tbs_sha256": sha256_hex(repack[:len(golden_tbs)])})

    tbs_len = 16 + 327 + 553
    low_s = to_low_s_der(golden_der)
    verify_bytes("low_s_variant_same_identity", golden_tbs + low_s, case_dir, trust_d1,
                 "PASS",
                 note="same golden TBS with re-encoded low-S DER: different valid DER, same "
                      "ui_tbs_sha256 content identity (no low-S assumption)",
                 extra={"der_len_original": len(golden_der), "der_len_low_s": len(low_s)})

    print("[neui-cases] install transition classification (§12.1/§12.3)")
    upg_bundle = work / "alt-1.1.0.neui"
    proc = pack_sidecar(work, fixture_alt, upg_bundle, d1_pem, version="1.1.0")
    if proc.returncode != 0:
        raise AssertionError(f"alt 1.1.0 pack failed: {proc.stderr}")
    upg = upg_bundle.read_bytes()
    conflict_bundle = work / "alt-1.0.0.neui"
    proc = pack_sidecar(work, fixture_alt, conflict_bundle, d1_pem, version="1.0.0")
    if proc.returncode != 0:
        raise AssertionError(f"alt 1.0.0 pack failed: {proc.stderr}")
    conflict = conflict_bundle.read_bytes()
    rebind_bundle = work / "rebind-1.0.0.neui"
    proc = pack_sidecar(work, fixture_base, rebind_bundle, d1_pem, native=native_alt)
    if proc.returncode != 0:
        raise AssertionError(f"rebind pack failed: {proc.stderr}")
    rebind = rebind_bundle.read_bytes()

    m_golden_raw, tbs_golden_bytes = split_bundle(golden_bundle)
    m_golden = sc.parse_manifest(m_golden_raw)
    m_upg = sc.parse_manifest(split_bundle(upg)[0])
    m_conflict = sc.parse_manifest(split_bundle(conflict)[0])
    m_rebind = sc.parse_manifest(split_bundle(rebind)[0])
    tbs_golden = sha256_hex(tbs_golden_bytes)
    tbs_upg = sha256_hex(split_bundle(upg)[1])
    tbs_conflict = sha256_hex(split_bundle(conflict)[1])
    tbs_rebind = sha256_hex(split_bundle(rebind)[1])
    record_predicate(
        "classify_idempotent",
        "same native identity + same ui_tbs (low-S DER variant) classifies IDEMPOTENT: "
        "a different valid DER is not a new content version",
        sc.classify_install_transition(m_golden, tbs_golden, m_golden, tbs_golden)
        == "IDEMPOTENT")
    record_predicate(
        "classify_upgrade",
        "same native identity, higher semantic version, different ui_tbs classifies UPGRADE",
        sc.classify_install_transition(m_golden, tbs_golden, m_upg, tbs_upg) == "UPGRADE",
        extra={"installed_version": "1.0.0", "candidate_version": "1.1.0"})
    record_predicate(
        "classify_content_conflict",
        "same native identity, same semantic version, different ui_tbs classifies "
        "CONTENT_CONFLICT (§12.1: same-version different-content is a reject)",
        sc.classify_install_transition(m_golden, tbs_golden, m_conflict, tbs_conflict)
        == "CONTENT_CONFLICT",
        extra={"ui_tbs_1.0.0_base": tbs_golden, "ui_tbs_1.0.0_alt": tbs_conflict})
    record_predicate(
        "classify_downgrade",
        "same native identity, lower semantic version classifies DOWNGRADE (not an "
        "ordinary update; authorized crash rollback is separate #83 behavior)",
        sc.classify_install_transition(m_upg, tbs_upg, m_golden, tbs_golden) == "DOWNGRADE",
        extra={"installed_version": "1.1.0", "candidate_version": "1.0.0"})
    record_predicate(
        "classify_native_rebind",
        "a new native TBS never inherits the old Sidecar: classifies NATIVE_REBIND and "
        "requires separate admission for the new native identity",
        sc.classify_install_transition(m_golden, tbs_golden, m_rebind, tbs_rebind)
        == "NATIVE_REBIND",
        extra={"native_tbs_golden": NATIVE_TBS_SHA256, "native_tbs_alt": native_tbs_alt})
    record_predicate(
        "classify_fresh_install",
        "no installed predecessor classifies FRESH_INSTALL",
        sc.classify_install_transition(None, None, m_golden, tbs_golden) == "FRESH_INSTALL")

    print("[neui-cases] native binding negatives (--native-package)")
    verify_bytes("wrong_native_identity", golden_bundle, case_dir, trust_d1,
                 "BAD_PACKAGE", detail_contains="native_tbs_sha256",
                 note="bundle bound to the golden native TBS, cross-checked against a "
                      "different valid native package",
                 native_package=native_alt, native_trust=trust_d1)

    golden_manifest_raw = golden_bundle[16:16 + 327]
    golden_payload = golden_bundle[16 + 327:tbs_len]
    other_key = ec.generate_private_key(ec.SECP256R1())
    other_spki = fmt.spki_der_from_public_key(other_key.public_key())
    other_fp = hashlib.sha256(other_spki).digest()

    def try_alg(key):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        try:
            return ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        except TypeError:
            return ec.ECDSA(hashes.SHA256())

    cross_app = bytearray(golden_manifest_raw)
    cross_app[16:48] = b"other-app".ljust(32, b"\x00")
    header = sc.CONTAINER_MAGIC + struct.pack("<II", 327, 553)
    tbs = header + bytes(cross_app) + golden_payload
    verify_bytes("cross_app_app_id_mismatch", tbs + signer.sign(tbs), case_dir, trust_d1,
                 "BAD_PACKAGE", detail_contains="cross-App",
                 note="sidecar app_id != native app_id (re-signed, signature valid) is a "
                      "cross-App binding reject under the native cross-check",
                 native_package=NATIVE_GOLDEN, native_trust=trust_d1)

    print("[neui-cases] signature coverage (tamper / wrong key / DER)")
    tampered = bytearray(golden_bundle)
    tampered[16 + 327 + 100] ^= 0x01
    verify_bytes("tamper_payload_byte", bytes(tampered), case_dir, trust_d1,
                 "SIGNATURE_INVALID", detail_contains="verification failed",
                 note="one asset byte flipped inside the signed region; DER untouched")
    ver_tampered = bytearray(golden_bundle)
    ver_tampered[16 + 114] ^= 0x01
    verify_bytes("tamper_manifest_version", bytes(ver_tampered), case_dir, trust_d1,
                 "SIGNATURE_INVALID", detail_contains="verification failed",
                 note="signed sidecar version_minor flipped in place (the version_major "
                      "field is structurally checked before signature, so the flip there "
                      "is BAD_PACKAGE by design: tamper_manifest_major_structural)")
    ver_major_tampered = bytearray(golden_bundle)
    ver_major_tampered[16 + 112] ^= 0x01
    verify_bytes("tamper_manifest_major_structural", bytes(ver_major_tampered),
                 case_dir, trust_d1, "BAD_PACKAGE",
                 detail_contains="sidecar_version_major",
                 note="version_major flipped to 0 in place: the structural manifest check "
                      "fires before signature verification (normative order)")
    native_tampered = bytearray(golden_bundle)
    native_tampered[16 + 80] ^= 0x01
    verify_bytes("tamper_manifest_native_tbs", bytes(native_tampered), case_dir, trust_d1,
                 "SIGNATURE_INVALID", detail_contains="verification failed",
                 note="signed native_tbs_sha256 flipped in place: the native binding cannot "
                      "be re-pointed without invalidating the signature")
    der_tampered = bytearray(golden_bundle)
    der_tampered[tbs_len + 8] ^= 0x01
    verify_bytes("tamper_der_byte", bytes(der_tampered), case_dir, trust_d1,
                 "SIGNATURE_INVALID", detail_contains="verification failed",
                 note="DER byte corrupted (TBS untouched)")
    verify_bytes("wrong_signer_key", golden_bundle[:tbs_len]
                 + other_key.sign(golden_bundle[:tbs_len], try_alg(other_key)),
                 case_dir, trust_d1, "SIGNATURE_INVALID",
                 detail_contains="verification failed",
                 note="TBS signed by an ephemeral non-trusted key; manifest fingerprint "
                      "still names the trusted d=1 key")

    print("[neui-cases] publisher trust mapping (re-signed)")
    verify_bytes("unknown_publisher",
                 build_forged(fixed_block(pub=b"other-pub", fp=other_fp,
                                          native_tbs=bytes.fromhex(NATIVE_TBS_SHA256),
                                          count=1),
                              [forge_record(b"index.html", len(golden_payload),
                                            hashlib.sha256(golden_payload).digest())],
                              golden_payload, Signer(_pem_for(other_key), "other-pub")),
                 case_dir, trust_d1, "PUBLISHER_UNTRUSTED",
                 detail_contains="not in the local trust mapping",
                 note="publisher_id absent from the Host trust mapping; the bundle-carried "
                      "fingerprint cannot self-trust")
    verify_bytes("publisher_fingerprint_mismatch",
                 build_forged(fixed_block(fp=other_fp,
                                          native_tbs=bytes.fromhex(NATIVE_TBS_SHA256),
                                          count=1),
                              [forge_record(b"index.html", len(golden_payload),
                                            hashlib.sha256(golden_payload).digest())],
                              golden_payload, signer),
                 case_dir, trust_d1, "PUBLISHER_UNTRUSTED",
                 detail_contains="does not match the trusted key",
                 note="manifest publisher_key_sha256 no longer matches the trusted store "
                      "entry (re-signed)")

    print("[neui-cases] header structure negatives")
    magic2 = bytearray(golden_bundle)
    magic2[5] = 0x02
    verify_bytes("magic_major2", bytes(magic2), case_dir, trust_d1, "BAD_PACKAGE",
                 detail_contains="container magic",
                 note="container major downgraded to 2 (unknown version)")
    magic_bad = bytearray(golden_bundle)
    magic_bad[2] = 0x42
    verify_bytes("magic_corrupt", bytes(magic_bad), case_dir, trust_d1, "BAD_PACKAGE",
                 detail_contains="container magic",
                 note="magic ASCII corrupted")
    for name, value, contains in (
            ("manifest_len_zero", 0, "manifest_len"),
            ("manifest_len_127", 127, "manifest_len"),
            ("manifest_len_16385", 16385, "manifest_len"),
            ("manifest_len_u32max", 0xFFFFFFFF, "manifest_len")):
        verify_bytes(name, relength(golden_bundle, manifest_len=value), case_dir,
                     trust_d1, "BAD_PACKAGE", detail_contains=contains,
                     note=f"manifest_len field = {value} (overflow-safe bounded parse)")
    for name, value, contains in (
            ("asset_len_zero", 0, "asset_payload_len"),
            ("asset_len_2097153", 2_097_153, "asset_payload_len"),
            ("asset_len_u32max", 0xFFFFFFFF, "asset_payload_len")):
        verify_bytes(name, relength(golden_bundle, asset_len=value), case_dir,
                     trust_d1, "BAD_PACKAGE", detail_contains=contains,
                     note=f"asset_payload_len field = {value}")
    verify_bytes("truncate_header", golden_bundle[:10], case_dir, trust_d1, "BAD_PACKAGE",
                 detail_contains="shorter than",
                 note="file shorter than the 16-byte container header")
    verify_bytes("truncate_body", golden_bundle[:tbs_len - 1], case_dir, trust_d1,
                 "BAD_PACKAGE", detail_contains="truncated",
                 note="file truncated below the claimed signed region")
    verify_bytes("truncate_der", golden_bundle[:-1], case_dir, trust_d1, "BAD_PACKAGE",
                 detail_contains="DER", note="DER truncated by one byte")
    verify_bytes("der_trailing_byte", golden_bundle + b"\xff", case_dir, trust_d1,
                 "BAD_PACKAGE", detail_contains="DER",
                 note="valid DER + one trailing byte (tail must be fully consumed)")
    verify_bytes("der_second_object", golden_bundle + b"\x05\x00", case_dir, trust_d1,
                 "BAD_PACKAGE", detail_contains="DER",
                 note="second DER object appended")
    verify_bytes("der_r_zero", golden_bundle[:tbs_len]
                 + bytes.fromhex("3006020100020101"), case_dir, trust_d1, "BAD_PACKAGE",
                 detail_contains="r outside P-256 range",
                 note="DER with r=0 (outside P-256 range)")

    v3_report = run_cmd([sys.executable, str(VERIFY), "--bundle", str(NATIVE_GOLDEN),
                         "--trust", str(trust_d1), "--expect", "BAD_PACKAGE", "--compact"])
    if v3_report.returncode != 0 or "not NEUI v1" not in v3_report.stdout:
        raise AssertionError(f"domain separation failed: {v3_report.stdout}{v3_report.stderr}")
    results.append({
        "case": "native_v3_package_on_sidecar_verifier",
        "category": "domain-separation",
        "expected": "BAD_PACKAGE",
        "observed": "BAD_PACKAGE",
        "detail": json.loads(v3_report.stdout.strip().splitlines()[0])["detail"],
        "note": "the committed #19 native v3 golden never parses as a sidecar; the NEUI "
                "signature domain is disjoint from the NEAPP domains",
    })
    print("  ok native_v3_package_on_sidecar_verifier: BAD_PACKAGE")
    v3_side = run_cmd([sys.executable, str(VERIFY_V3), "--package",
                       str(golden_dir / "golden.neui"), "--trust", str(trust_d1),
                       "--expect", "BAD_PACKAGE", "--compact"])
    if v3_side.returncode != 0 or "not NEAPP v3" not in v3_side.stdout:
        raise AssertionError(f"reverse domain separation failed: {v3_side.stdout}{v3_side.stderr}")
    results.append({
        "case": "sidecar_bundle_on_v3_verifier",
        "category": "domain-separation",
        "expected": "BAD_PACKAGE",
        "observed": "BAD_PACKAGE",
        "detail": json.loads(v3_side.stdout.strip().splitlines()[0])["detail"],
        "note": "the sidecar golden never parses as a native .neapp v3 package; the "
                "frozen v3 verifier is untouched and rejects the foreign magic",
    })
    print("  ok sidecar_bundle_on_v3_verifier: BAD_PACKAGE")

    print("[neui-cases] manifest field negatives (re-signed, valid signatures)")
    idx_rec = forge_record(b"index.html", len(golden_payload),
                           hashlib.sha256(golden_payload).digest())
    fp_d1 = signer.fingerprint
    native_tbs_raw = bytes.fromhex(NATIVE_TBS_SHA256)

    def manifest_case(name, fixed_kwargs=None, records=None, payload=None,
                      asset_len=None, contains=None, note="", signer_key=signer,
                      manifest_tail=b""):
        kwargs = {"count": 1, "fp": signer.fingerprint, **(fixed_kwargs or {})}
        f = fixed_block(native_tbs=native_tbs_raw, **kwargs)
        recs = records if records is not None else [idx_rec]
        pay = golden_payload if payload is None else payload
        verify_bytes(name,
                     build_forged(f, recs, pay, signer_key, asset_len=asset_len,
                                  manifest_tail=manifest_tail),
                     case_dir, trust_d1, "BAD_PACKAGE", detail_contains=contains,
                     note=note)

    manifest_case("host_ui_abi_2", fixed_kwargs={"abi": 2}, contains="host_ui_abi",
                  note="host_ui_abi=2 (re-signed): only 1 is legal in v1")
    manifest_case("reserved_nonzero", fixed_kwargs={"reserved": 1}, contains="reserved",
                  note="reserved_u32 nonzero (re-signed)")
    manifest_case("version_major_zero", fixed_kwargs={"ver": (0, 9, 9)},
                  contains="sidecar_version_major",
                  note="sidecar_version_major=0 below the frozen minimum 1 (re-signed)")
    manifest_case("file_count_zero", fixed_kwargs={"count": 0}, records=[],
                  manifest_tail=bytes(39),
                  contains="file_count", note="file_count=0 (re-signed)")
    manifest_case("publisher_uppercase", fixed_kwargs={"pub": b"Test-Publisher"},
                  contains="publisher_id",
                  note="publisher_id outside the v3 lower-ASCII identifier charset "
                       "(re-signed)")
    manifest_case("app_id_bad_padding",
                  fixed_kwargs={"app": b"line-crossing-padded!"},
                  contains="app_id",
                  note="app_id outside the v3 identifier charset (re-signed)")
    manifest_case("file_count_65",
                  fixed_kwargs={"count": 65},
                  records=[forge_record(f"f{i:03d}.txt".encode(), 1,
                                        hashlib.sha256(bytes([i])).digest())
                           for i in range(65)],
                  payload=bytes(range(65)),
                  contains="file_count",
                  note="file_count=65 above the 1..64 cap (re-signed)")
    manifest_case("path_len_zero",
                  records=[struct.pack("<HI", 0, 1) + hashlib.sha256(b"x").digest()],
                  payload=b"x", contains="path_len",
                  note="record path_len=0 (re-signed)", manifest_tail=b"\x00")
    manifest_case("path_len_161",
                  records=[forge_record(b"a" * 161, 1, hashlib.sha256(b"x").digest())],
                  payload=b"x", contains="path_len",
                  note="record path_len=161 above the 160-byte cap (re-signed)")
    manifest_case("file_len_zero",
                  records=[forge_record(b"index.html", 0, hashlib.sha256(b"").digest())],
                  payload=b"x", contains="file_len",
                  note="record file_len=0 below the frozen minimum 1 (re-signed)")
    big_blob = bytes(1_048_577)
    manifest_case("file_len_over_cap",
                  records=[forge_record(b"index.html", len(big_blob),
                                        hashlib.sha256(big_blob).digest())],
                  payload=big_blob, contains="file_len",
                  note="single file above the 1,048,576-byte cap (re-signed)")
    manifest_case("record_sha_mismatch",
                  records=[forge_record(b"index.html", len(golden_payload), bytes(32))],
                  payload=golden_payload, contains="does not match the manifest record",
                  note="record sha256 zeroed (re-signed): per-asset digest must match")
    rec_a = forge_record(b"a.txt", 4, hashlib.sha256(b"aaaa").digest())
    rec_b = forge_record(b"b.txt", 4, hashlib.sha256(b"bbbb").digest())
    manifest_case("records_unsorted",
                  fixed_kwargs={"count": 2}, records=[rec_b, rec_a],
                  payload=b"aaaabbbb", contains="ascending",
                  note="records in descending order (re-signed)")
    manifest_case("duplicate_paths",
                  fixed_kwargs={"count": 2}, records=[rec_a, rec_a],
                  payload=b"aaaa", contains="duplicate asset path",
                  note="two records with the same path (re-signed)")
    rec_fold1 = forge_record(b"AAA.txt", 4, hashlib.sha256(b"aaaa").digest())
    rec_fold2 = forge_record(b"aaa.txt", 4, hashlib.sha256(b"bbbb").digest())
    manifest_case("casefold_collision",
                  fixed_kwargs={"count": 2}, records=[rec_fold1, rec_fold2],
                  payload=b"aaaabbbb", contains="case folding",
                  note="paths colliding under ASCII case folding (re-signed)")
    manifest_case("missing_index",
                  records=[rec_a], payload=b"aaaa", contains="exactly one",
                  note="no index.html entry (re-signed)")
    nested_only = forge_record(b"foo/index.html", 4, hashlib.sha256(b"aaaa").digest())
    manifest_case("nested_index_only",
                  records=[nested_only], payload=b"aaaa", contains="exactly one",
                  note="only a nested foo/index.html and no root index.html (re-signed)")
    manifest_case("nested_second_index",
                  fixed_kwargs={"count": 2}, records=[nested_only, idx_rec],
                  payload=b"aaaa" + golden_payload, contains="nested",
                  note="root index.html plus a nested foo/index.html (re-signed)")
    manifest_case("manifest_extra_bytes",
                  fixed_kwargs={"count": 1}, records=[idx_rec],
                  payload=golden_payload, contains="extra bytes after the last record",
                  note="manifest longer than its records consume (re-signed)",
                  manifest_tail=b"\x00")
    manifest_case("manifest_truncated_record",
                  fixed_kwargs={"count": 2}, records=[rec_a],
                  payload=b"aaaa", contains="truncated inside record",
                  note="file_count=2 with only one record present (re-signed)")

    def path_case(name, path_bytes, contains, note):
        manifest_case(name,
                      records=[forge_record(path_bytes, 4,
                                            hashlib.sha256(b"aaaa").digest())],
                      payload=b"aaaa", contains=contains, note=note)

    path_case("path_leading_slash", b"/index.html", "absolute",
              "absolute path (re-signed)")
    path_case("path_trailing_slash", b"docs/", "ends with '/'",
              "trailing slash path (re-signed)")
    path_case("path_dotdot_segment", b"../index.html", "dot segment",
              "parent-directory traversal (re-signed)")
    path_case("path_dot_segment", b"./index.html", "dot segment",
              "dot segment fails the canonical path rules (re-signed)")
    path_case("path_backslash", b"js\\app.js", "backslash", "backslash separator")
    path_case("path_percent", b"js%2fapp.js", "percent escape", "percent escape")
    path_case("path_colon", b"c:app.js", "colon", "colon in path")
    path_case("path_query", b"index.html?x=1", "query separator", "query suffix")
    path_case("path_fragment", b"index.html#top", "fragment separator", "fragment suffix")
    path_case("path_non_ascii", b"ind\xe9x.html", "non-ASCII", "non-ASCII byte in path")
    path_case("path_empty_segment", b"js//app.js", "empty segment", "double slash")
    path_case("path_hidden_dotfile", b".hidden.html", "does not start with",
              "dotfile fails the segment charset (re-signed)")
    path_case("path_nul", b"index\x00.html", "NUL", "NUL byte in path (re-signed)")

    print("[neui-cases] payload framing negatives (re-signed)")
    manifest_case("payload_sum_mismatch",
                  payload=golden_payload[:552], asset_len=552,
                  contains="sum of record file_len",
                  note="asset_payload_len one byte below the record sum (re-signed)")
    manifest_case("payload_wrong_order",
                  fixed_kwargs={"count": 3},
                  records=[rec_a, rec_b, forge_record(b"index.html",
                                                      len(golden_payload),
                                                      hashlib.sha256(golden_payload).digest())],
                  payload=b"bbbbaaaa" + golden_payload,
                  contains="does not match the manifest record",
                  note="payload bytes not in record order: sorted records, swapped content")

    print("[neui-cases] oversize totals (re-signed)")
    mib = bytes(1_048_576)
    manifest_case("total_payload_over_cap",
                  fixed_kwargs={"count": 3},
                  records=[forge_record(b"one.bin", 1_048_576,
                                        hashlib.sha256(mib).digest()),
                           forge_record(b"two.bin", 1_048_576,
                                        hashlib.sha256(mib).digest()),
                           forge_record(b"three.bin", 1_048_575,
                                        hashlib.sha256(mib[:-1]).digest())],
                  payload=mib + mib, contains="sum to more than",
                  note="record file_len sum 3,145,727 above the 2,097,152-byte payload cap "
                       "(re-signed)")

    print("[neui-cases] packer fail-closed refusals (AC1/AC2)")
    trees = work / "trees"
    expect_pack_refusal("pack_refusal_missing_index", work,
                        make_tree(trees / "no-index", {"css/style.css": b"body{}\n",
                                                       "js/app.js": b";\n"}),
                        case_dir / "no-index.neui",
                        stderr_contains="exactly one root 'index.html'")
    expect_pack_refusal("pack_refusal_second_index", work,
                        make_tree(trees / "two-index", {"index.html": b"<h1>x</h1>\n",
                                                        "sub/index.html": b"<h1>y</h1>\n"}),
                        case_dir / "two-index.neui",
                        stderr_contains="nested")
    expect_pack_refusal("pack_refusal_empty_file", work,
                        make_tree(trees / "empty", {"index.html": b""}),
                        case_dir / "empty.neui",
                        stderr_contains="outside 1..1048576")
    expect_pack_refusal("pack_refusal_oversize_file", work,
                        make_tree(trees / "oversize", {"index.html": bytes(1_048_577)}),
                        case_dir / "oversize.neui",
                        stderr_contains="outside 1..1048576")
    expect_pack_refusal("pack_refusal_total_over_cap", work,
                        make_tree(trees / "total-over",
                                  {"index.html": b"x",
                                   "a.bin": bytes(1_048_576),
                                   "b.bin": bytes(1_048_576)}),
                        case_dir / "total-over.neui",
                        stderr_contains="payload cap")
    many = {f"f{i:03d}.txt": b"x" for i in range(65)}
    expect_pack_refusal("pack_refusal_too_many_files", work,
                        make_tree(trees / "many", many),
                        case_dir / "many.neui",
                        stderr_contains="file_count cap")
    sym_tree = make_tree(trees / "symlink-file",
                         {"index.html": b"<h1>x</h1>\n", "real.txt": b"real\n"})
    os.symlink(sym_tree / "real.txt", sym_tree / "link.txt")
    expect_pack_refusal("pack_refusal_symlink_file", work, sym_tree,
                        case_dir / "symlink-file.neui",
                        stderr_contains="symbolic-link asset")
    outside = work / "outside-root"
    outside.mkdir(exist_ok=True)
    (outside / "secret.txt").write_bytes(b"secret\n")
    esc_tree = make_tree(trees / "symlink-dir", {"index.html": b"<h1>x</h1>\n"})
    os.symlink(outside, esc_tree / "escape")
    expect_pack_refusal("pack_refusal_symlink_dir_escape", work, esc_tree,
                        case_dir / "symlink-dir.neui",
                        stderr_contains="symbolic-link directory")
    fifo_tree = make_tree(trees / "fifo", {"index.html": b"<h1>x</h1>\n"})
    os.mkfifo(fifo_tree / "pipe")
    expect_pack_refusal("pack_refusal_fifo", work, fifo_tree,
                        case_dir / "fifo.neui",
                        stderr_contains="non-regular asset")
    expect_pack_refusal("pack_refusal_version_major_zero", work, fixture_base,
                        case_dir / "major0.neui", version="0.1.0",
                        stderr_contains="sidecar_version_major must be >= 1")
    expect_pack_refusal("pack_refusal_native_not_v3", work, fixture_base,
                        case_dir / "native-v2.neui",
                        native=REPO / "docs" / "evidence" / "spec-v2" / "golden.neapp.v2",
                        stderr_contains="native package rejected")
    tampered_native = work / "native-tampered.neapp.v3"
    tn = bytearray(NATIVE_GOLDEN.read_bytes())
    tn[16 + 192 + 35] ^= 0x01
    tampered_native.write_bytes(bytes(tn))
    expect_pack_refusal("pack_refusal_native_signature_invalid", work, fixture_base,
                        case_dir / "native-bad.neui", native=tampered_native,
                        stderr_contains="failed offline v3 verification")
    expect_pack_refusal("pack_refusal_publisher_mismatch", work, fixture_base,
                        case_dir / "pub-mismatch.neui", publisher="dev-publisher",
                        stderr_contains="publisher_id")
    expect_pack_refusal("pack_refusal_app_mismatch", work, fixture_base,
                        case_dir / "app-mismatch.neui", app="other-app",
                        stderr_contains="app_id")

    print("[neui-cases] provenance traceability (AC1)")
    prov_bundle = work / "prov.neui"
    proc = pack_sidecar(work, fixture_base, prov_bundle, d1_pem,
                        extra=["--sidecar", str(work / "prov.provenance.json")])
    if proc.returncode != 0:
        raise AssertionError(f"provenance pack failed: {proc.stderr}")
    prov = json.loads((work / "prov.provenance.json").read_text())
    record_predicate(
        "pack_provenance_traceable",
        "provenance sidecar records the format authority, NON-PRODUCTION trust-root "
        "notice, generator, source commit, ui_tbs_sha256, signer SPKI fingerprint, the "
        "native binding (verified native TBS; whole-file native digest labelled "
        "traceability-only) and the full per-file digest list",
        prov["format"] == "neui-sidecar-v1"
        and "ne301 issue #79" in prov["spec_authority"]
        and "NON-PRODUCTION" in prov["non_production_trust_root"]
        and prov["ui_tbs_sha256"] == GOLDEN_UI_TBS_SHA256
        and prov["signer_spki_sha256"] == SPKI_SHA256
        and prov["native_binding"]["native_tbs_sha256"] == NATIVE_TBS_SHA256
        and prov["native_binding"]["native_offline_verified"] is True
        and "traceability only" in prov["native_binding"]["native_package_sha256_note"]
        and prov["manifest"]["sidecar_version"] == "1.0.0"
        and prov["manifest"]["file_count"] == 4
        and len(prov["files"]) == 4,
        extra={"generator": prov["generator"], "source_commit": prov["source_commit"]})

    summary = work / "neui-cases-results.json"
    summary.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")

    import platform

    toolchain = {
        "python": sys.version.split()[0],
        "python_cryptography": subprocess.run(
            [sys.executable, "-c", "import cryptography; print(cryptography.__version__)"],
            capture_output=True, text=True).stdout.strip(),
        "openssl": subprocess.run(["openssl", "version"], capture_output=True,
                                  text=True).stdout.strip(),
        "platform": platform.platform(),
    }
    try:
        source_commit = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                                       capture_output=True, text=True,
                                       check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        source_commit = "unknown"
    report = {
        "issue": "harryhua-ai/ne30x-app#26 (sidecar v1 offline pack/verify/golden)",
        "protocol_authority": "ne301 issue #79 §12 (frozen Sidecar v1 wire, 2026-10-15)",
        "boundary": ("OFFLINE packaging evidence only; NOT NE301 Host verification/"
                     "admission/install, NOT device LittleFS free space, RAM, dual-artifact "
                     "transaction, camera H264, browser trusted loading, or User product "
                     "acceptance; the §12.2 caps are maximum accepted bundle-INPUT limits, "
                     "not a device installability promise; signing identities are "
                     "NON-PRODUCTION test roots (the PUBLIC spec d=1 key and ephemeral "
                     "test keys) and never device production trust roots"),
        "source_commit": source_commit,
        "toolchain": toolchain,
        "golden_consistency": {
            "pinned_ui_tbs_sha256": GOLDEN_UI_TBS_SHA256,
            "observed_ui_tbs_sha256": sha256_hex(replica[:len(golden_tbs)]),
            "pinned_bundle_sha256": GOLDEN_BUNDLE_SHA256,
            "observed_bundle_sha256": sha256_hex(replica),
            "bundle_len": len(replica),
            "tbs_len": len(golden_tbs),
            "der_len": len(golden_der),
            "byte_identical": replica == golden_bundle,
            "der_note": ("the packer signs with cryptography RFC-6979 deterministic "
                         "signing; the committed golden DER is reproducible with the "
                         "pinned toolchain and any other valid DER over the same TBS "
                         "keeps the same ui_tbs_sha256 identity"),
            "spki_sha256": SPKI_SHA256,
            "native_binding": {
                "native_package": "docs/evidence/spec-v3/golden.neapp.v3",
                "native_tbs_sha256": NATIVE_TBS_SHA256,
                "native_publisher_id": PUBLISHER,
                "native_app_id": APP_ID,
                "native_offline_verified_before_binding": True,
            },
            "fixture_files": FIXTURE_SHA256,
        },
        "case_suite": {
            "cases_total": len(results),
            "by_expected": {
                code: sum(1 for r in results if r["expected"] == code)
                for code in sorted({r["expected"] for r in results})
            },
            "cases": results,
        },
        "key_discipline": {
            "private_keys_committed": False,
            "private_key_locations": [
                "tests/sidecar/work/keys/d1-test-signer.pem (PUBLIC spec §12 scalar, "
                "gitignored)",
                "ephemeral negative-test keys (in-memory only)",
            ],
            "trust_roots": ("NON-PRODUCTION test identities only; no production key "
                            "material; the d=1 identity is the PUBLIC spec test scalar "
                            "and never a device production trust root"),
        },
    }
    golden_dir_report = golden_dir / "report.json"
    golden_dir_report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8")

    neg = [r for r in results if r["expected"] not in ("PASS",) and not
           r["expected"].startswith("packer")]
    pos = [r for r in results if r["expected"] == "PASS"]
    ref = [r for r in results if r["expected"].startswith("packer")]
    lines = [
        "# NEUI Sidecar v1 offline pack/verify — evidence report (Issue #26)",
        "",
        f"- Protocol authority: {report['protocol_authority']}",
        f"- Source commit: `{source_commit}`",
        f"- Toolchain: python {toolchain['python']}, cryptography "
        f"{toolchain['python_cryptography']}, {toolchain['openssl']}",
        f"- Cases: {len(results)} total — {len(pos)} positive/predicate, "
        f"{len(neg)} verifier rejection, {len(ref)} packer refusal",
        "",
        "## Golden vector (deterministic, PUBLIC d=1 test signer)",
        "",
        "| quantity | value |",
        "| --- | --- |",
        f"| bundle / tbs / der bytes | {len(replica)} / {len(golden_tbs)} / "
        f"{len(golden_der)} |",
        f"| `ui_tbs_sha256` | `{GOLDEN_UI_TBS_SHA256}` |",
        f"| bundle `sha256` | `{GOLDEN_BUNDLE_SHA256}` |",
        f"| signer SPKI `sha256` | `{SPKI_SHA256}` |",
        f"| `native_tbs_sha256` binding | `{NATIVE_TBS_SHA256}` "
        "(from docs/evidence/spec-v3/golden.neapp.v3, offline-verified before packing) |",
        f"| fixture files | 4 (base fixture; sha256 pinned in report.json) |",
        "",
        "Repack idempotency: the same fixture + metadata + key reproduce the identical "
        "TBS and (RFC-6979) identical bundle bytes; a low-S DER re-encoding over the same "
        "TBS keeps the same `ui_tbs_sha256` (no low-S assumption).",
        "",
        "## Boundary",
        "",
        report["boundary"],
        "",
        "## Case detail",
        "",
        "Every verifier rejection asserts its expected error class AND a detail-substring "
        "attribution; full case list with observed details is in `report.json` "
        "(`case_suite.cases`).",
    ]
    (golden_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"neui case suite: {len(results)} entries, all expectations matched")
    print(f"results -> {summary}")
    print(f"report  -> {golden_dir_report}")
    return 0


def _pem_for(key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"NEUI CASE FAILURE: {exc}", file=sys.stderr)
        raise SystemExit(1)
