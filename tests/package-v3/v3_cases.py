#!/usr/bin/env python3
"""v3_cases — Issue #20 offline positive/negative/rejection-matrix suite for
.neapp v3 packages produced by the package/ tooling.

Runs the REAL CLIs (package/neapp_verify_v3.py, package/neapp_verify_v2.py,
package/neapp_verify.py, package/neapp_pack_v3.py) and layers the #19
committed golden artifacts (docs/evidence/spec-v3/) plus the frozen #12/#6
v1/v2 golden artifacts (docs/evidence/spec-v2/) through the independent
cryptography-based verifier, so the pinned SHA-256(TBS) identities, the
byte-identical golden package reproduction, and the structural/policy
rejections are re-proven against the integrated spec vectors (AC3).

Every rejection case asserts the expected §11 error class AND a
detail-substring attribution, so a pass cannot come from a checkpoint that
happens to run earlier.  All signing uses NON-PRODUCTION identities only:
the per-round dev key and the PUBLIC spec d=1 test scalar; neither is ever
a device production trust root.  Every case is offline packaging-layer
evidence, never a device claim.

v1/v2 golden artifacts are consumed read-only from docs/evidence/spec-v2/
(source documented in docs/p6-packaging.md §v3); they are never rewritten.

Exit code 0 only if every expectation (class + detail attribution) matches.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "package"))
fmt = importlib.import_module("neapp_format")
fmt2 = importlib.import_module("neapp_v2_format")
fmt3 = importlib.import_module("neapp_v3_format")

VERIFY_V3 = REPO / "package" / "neapp_verify_v3.py"
VERIFY_V2 = REPO / "package" / "neapp_verify_v2.py"
VERIFY_V1 = REPO / "package" / "neapp_verify.py"
PACK_V3 = REPO / "package" / "neapp_pack_v3.py"
SPEC_V3_EVIDENCE = REPO / "docs" / "evidence" / "spec-v3"
SPEC_V2_EVIDENCE = REPO / "docs" / "evidence" / "spec-v2"

GOLDEN_TBS_SHA256 = "d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e"
GOLDEN_PKG_SHA256 = "c74f7e468a9b63403bbaa8d36816bfd5250ffd68f66ebffc7d994440f1e22342"
GOLDEN_NATIVE_SHA256 = "aa8c3ef6e4082656c76255807bee5a7c562ad212a0c3e2a4f009a62129cdee69"
GOLDEN_DER_HEX = (
    "304402204646fc74c70bbbefcabc29afb8228bc121ad8b432104254d0b3f09"
    "819e9b6de50220251fd81c3f8976906785871c0016bad865f5e3c7f460b67"
    "b76e6fc1cce5bab50"
)
SPKI_SHA256 = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
V2_GOLDEN_PKG_SHA256 = "3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e"
V1_GOLDEN_PKG_SHA256 = "9a212324132c0f26e2878384904f1af4abd3090a6ae5806ef32da2d3b4c80679"
HELLO_V1_IMAGE_SHA256 = "d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03"

OFF_PUB, OFF_APP = 4, 20
OFF_VERSION = 52
OFF_ABI, OFF_CAPS, OFF_EXEC, OFF_BOARD, OFF_PSRAM = 68, 72, 76, 60, 64
OFF_FILE_LEN, OFF_IMAGE_SIZE, OFF_ENTRY, OFF_TARGET = 80, 84, 88, 92
OFF_NATIVE_SHA, OFF_KEY_FP = 96, 128
OFF_PROFILE, OFF_EVENT_MAX, OFF_STATE_QUOTA, OFF_REPORT_MAX = 160, 164, 168, 172
OFF_CONTROL_MAX, OFF_SNAPSHOT_MAX = 176, 180

results: list[dict] = []


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_v3_verifier(package_path: Path, trust: Path, expect: str,
                    policy: Path | None = None) -> dict:
    cmd = [sys.executable, str(VERIFY_V3), "--package", str(package_path),
           "--trust", str(trust), "--expect", expect, "--compact"]
    if policy is not None:
        cmd += ["--policy", str(policy)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(
            f"v3 verifier did not produce expected {expect} for {package_path.name}:\n"
            f"{proc.stdout}{proc.stderr}"
        )
    return json.loads(proc.stdout.strip().splitlines()[0])


def run_legacy_verifier(verifier: Path, package_path: Path, trust: Path,
                        expect: str) -> dict:
    proc = subprocess.run([sys.executable, str(verifier), "--package", str(package_path),
                           "--trust", str(trust), "--expect", expect, "--compact"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(
            f"{verifier.name} did not produce expected {expect} for {package_path.name}:\n"
            f"{proc.stdout}{proc.stderr}"
        )
    return json.loads(proc.stdout.strip().splitlines()[0])


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


def build_package(manifest_raw: bytes, image: bytes, signer: Signer) -> bytes:
    tbs = fmt3.build_container_prefix_v3(manifest_raw, image)
    return tbs + signer.sign(tbs)


def openssl_verify(spki_der: bytes, tbs: bytes, sig_der: bytes) -> tuple[int, str]:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        pem = Path(td) / "pub.pem"
        kf = Path(td) / "pub.spki.der"
        tf = Path(td) / "tbs.bin"
        sf = Path(td) / "sig.der"
        kf.write_bytes(spki_der)
        tf.write_bytes(tbs)
        sf.write_bytes(sig_der)
        r = subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(kf),
                            "-out", str(pem)], capture_output=True, text=True)
        if r.returncode != 0:
            return r.returncode, "pkey: " + (r.stderr or r.stdout)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pem),
                            "-signature", str(sf), str(tf)], capture_output=True, text=True)
        return r.returncode, (r.stdout + r.stderr).strip()


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path,
                        help="controlled v3-ABI native test image (make_v3_test_image.py)")
    parser.add_argument("--alt-image", required=True, type=Path,
                        help="second controlled v3 image with different payload")
    parser.add_argument("--golden-replica-package", required=True, type=Path,
                        help="d=1-packed byte replica of the #19 golden v3 package")
    parser.add_argument("--dev-package", required=True, type=Path,
                        help="dev-key-packed v3 package @1.0.0 (caps 0xff, 2048/4096/6144/256/1024)")
    parser.add_argument("--dev-package-2-0-0", required=True, type=Path,
                        help="dev-key-packed v3 package @2.0.0 (upgrade path)")
    parser.add_argument("--alt-image-package", required=True, type=Path,
                        help="dev-key-packed v3 package of the alt image @1.0.0 (conflict path)")
    parser.add_argument("--hello-image", type=Path, default=None,
                        help="optional prebuilt hello-app V1 image (extra input, never rebuilt)")
    args = parser.parse_args()

    work = args.work_dir
    case_dir = work / "v3-cases"
    case_dir.mkdir(parents=True, exist_ok=True)
    trust_dev = work / "trust-dev.json"
    trust_d1 = work / "trust-d1.json"
    dev_signer = Signer((work / "keys" / "dev-signer.pem").read_bytes(), "dev-publisher")

    for name, digest in (("golden.neapp.v3", GOLDEN_PKG_SHA256),
                         ("golden-tbs.bin", GOLDEN_TBS_SHA256),
                         ("golden-sig.der", None),
                         ("test-publisher.spki.der", SPKI_SHA256)):
        path = SPEC_V3_EVIDENCE / name
        if not path.is_file():
            raise AssertionError(f"missing committed #19 evidence artifact: {path}")
        if digest is not None and sha256_hex(path.read_bytes()) != digest:
            raise AssertionError(f"#19 evidence artifact hash drifted: {path}")
    for name, digest in (("golden.neapp.v2", V2_GOLDEN_PKG_SHA256),
                         ("v1-golden.neapp", V1_GOLDEN_PKG_SHA256)):
        path = SPEC_V2_EVIDENCE / name
        if not path.is_file() or sha256_hex(path.read_bytes()) != digest:
            raise AssertionError(f"frozen #12/#6 evidence artifact missing or drifted: {path}")
    golden_pkg = (SPEC_V3_EVIDENCE / "golden.neapp.v3").read_bytes()
    golden_tbs = (SPEC_V3_EVIDENCE / "golden-tbs.bin").read_bytes()
    golden_der = (SPEC_V3_EVIDENCE / "golden-sig.der").read_bytes()
    spki_d1 = (SPEC_V3_EVIDENCE / "test-publisher.spki.der").read_bytes()
    v2_golden = (SPEC_V2_EVIDENCE / "golden.neapp.v2").read_bytes()
    v1_golden = (SPEC_V2_EVIDENCE / "v1-golden.neapp").read_bytes()
    if golden_der.hex() != GOLDEN_DER_HEX:
        raise AssertionError("committed golden-sig.der is not the pinned §12.1 DER")
    golden_native = golden_tbs[-36:]
    if sha256_hex(golden_native) != GOLDEN_NATIVE_SHA256:
        raise AssertionError("golden native image digest drifted")

    image = args.image.read_bytes()
    alt_image = args.alt_image.read_bytes()
    golden_replica = args.golden_replica_package.read_bytes()
    dev_pkg = args.dev_package.read_bytes()
    dev_pkg_200 = args.dev_package_2_0_0.read_bytes()
    alt_pkg = args.alt_image_package.read_bytes()
    if sha256_hex(image) != GOLDEN_NATIVE_SHA256:
        raise AssertionError("controlled v3 test image is not the golden native image bytes")

    dev_image_len = struct.unpack_from("<I", dev_pkg, 12)[0]
    dev_signed_len = 16 + 192 + dev_image_len
    dev_sig = dev_pkg[dev_signed_len:]
    base_manifest = bytearray(dev_pkg[16:16 + 192])
    base_image = bytes(dev_pkg[16 + 192:16 + 192 + dev_image_len])

    def record(name: str, note: str, expect: str, package: bytes,
               trust_file: Path = trust_dev, policy: Path | None = None,
               detail_contains: str | None = None, extra: dict | None = None) -> None:
        path = case_dir / f"{name}.neapp.v3"
        path.write_bytes(package)
        report = run_v3_verifier(path, trust_file, expect, policy)
        detail = report.get("detail")
        if detail_contains is not None and expect != "PASS":
            if detail is None or detail_contains not in detail:
                raise AssertionError(
                    f"{name}: expected detail containing {detail_contains!r}, got {detail!r}"
                )
        entry = {
            "case": name,
            "category": "v3",
            "expected": expect,
            "observed": report.get("result", expect),
            "package_sha256": sha256_hex(package),
            "content_identity_sha256": report.get("content_identity_sha256"),
            "detail": detail,
            "note": note,
        }
        if extra:
            entry.update(extra)
        results.append(entry)
        print(f"  ok {name}: {expect}" + (f" [{detail_contains}]" if detail_contains else ""))

    def record_predicate(name: str, note: str, predicate: bool, extra: dict | None = None) -> None:
        if not predicate:
            raise AssertionError(f"{name}: predicate failed")
        entry = {
            "case": name,
            "category": "v3",
            "expected": "PASS",
            "observed": "PASS",
            "note": note,
        }
        if extra:
            entry.update(extra)
        results.append(entry)
        print(f"  ok {name}: predicate")

    def policy_file(name: str, data: dict) -> Path:
        pdir = case_dir / "policies"
        pdir.mkdir(exist_ok=True)
        p = pdir / f"{name}.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    print("[v3-cases] positives: AC1 controlled-image package + #19 golden reproduction (AC3)")
    rep_dev = run_v3_verifier(args.dev_package, trust_dev, "PASS")
    results.append({
        "case": "dev_v3_accept",
        "category": "v3",
        "expected": "PASS",
        "observed": "PASS",
        "package_sha256": rep_dev["package_sha256"],
        "content_identity_sha256": rep_dev["content_identity_sha256"],
        "detail": ("controlled v3-ABI test image, dev-key signed; caps 0xff, quotas "
                   "2048/4096/6144/256/1024, run_profile 2, abi 0x00030000"),
        "note": "Issue #20 AC1: 受控测试原生镜像 -> 签名 v3 包 -> 离线验真通过",
    })
    print("  ok dev_v3_accept: PASS")

    replica_tbs = golden_replica[:244]
    record_predicate(
        "golden_replica_byte_identical",
        "pack_v3 with the PUBLIC d=1 identity reproduces the #19 golden: TBS byte-identical "
        "to golden-tbs.bin, whole 314B package byte-identical to golden.neapp.v3 "
        "(SHA-256(TBS) d793a455…, SHA-256(package) c74f7e46…)",
        replica_tbs == golden_tbs and golden_replica == golden_pkg
        and rep_dev is not None
        and run_v3_verifier(args.golden_replica_package, trust_d1, "PASS")
        ["content_identity_sha256"] == GOLDEN_TBS_SHA256,
        extra={"pinned_tbs_sha256": GOLDEN_TBS_SHA256,
               "observed_tbs_sha256": sha256_hex(replica_tbs),
               "pinned_package_sha256": GOLDEN_PKG_SHA256,
               "observed_package_sha256": sha256_hex(golden_replica),
               "package_byte_identical": golden_replica == golden_pkg},
    )

    record("golden_artifact_accept", "committed #19 golden.neapp.v3 through the independent "
           "cryptography-based v3 verifier", "PASS", golden_pkg, trust_file=trust_d1)

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    d1_pub = fmt.parse_spki_p256(spki_d1)
    try:
        d1_pub.verify(golden_der, golden_tbs, ec.ECDSA(hashes.SHA256()))
        crypto_ok = True
    except InvalidSignature:
        crypto_ok = False
    code, out = openssl_verify(spki_d1, golden_tbs, golden_der)
    record_predicate(
        "golden_der_independent_cross",
        "pinned #19 golden DER independently verified over golden-tbs.bin by "
        "`cryptography` AND the OpenSSL CLI (independent of the #19 pure-Python prover)",
        crypto_ok and code == 0,
        extra={"openssl_exit": code, "openssl_output": out},
    )

    low_s = to_low_s_der(golden_der)
    record("golden_low_s_variant_same_identity",
           "same #19 golden TBS with re-encoded low-S DER: different valid DER, same "
           "SHA-256(TBS) content identity (§2.2)", "PASS", golden_tbs + low_s,
           trust_file=trust_d1,
           extra={"predicate": "SHA-256(TBS) unchanged by DER re-encoding",
                  "der_len_original": len(golden_der), "der_len_low_s": len(low_s)})

    prov = json.loads(Path(str(args.dev_package) + ".provenance.json").read_text())
    record_predicate(
        "dev_provenance_traceable",
        "provenance sidecar carries source/target/publisher/app identity, version, "
        "capabilities/quotas/profile, native digest and TBS identity (AC1 traceability)",
        prov["format"] == "neapp-v3"
        and prov["tbs_sha256"] == rep_dev["content_identity_sha256"]
        and prov["manifest"]["required_host_caps"] == "0xff"
        and prov["manifest"]["run_profile"] == 2
        and prov["manifest"]["event_max"] == 2048
        and prov["manifest"]["state_quota"] == 4096
        and prov["manifest"]["report_max"] == 6144
        and prov["manifest"]["control_max"] == 256
        and prov["manifest"]["snapshot_max"] == 1024
        and prov["manifest"]["required_host_abi"] == "0x00030000"
        and "NON-PRODUCTION" in prov["non_production_trust_root"]
        and prov["signer_spki_sha256"] == sha256_hex(dev_signer.spki),
        extra={"generator": prov["generator"], "source_commit": prov["source_commit"]},
    )

    print("[v3-cases] packer admission semantics: generic profile 2 default pack + "
          "explicit target-Host policy separation (Issue #20 fix)")
    generic_pkg_path = case_dir / "pack-generic-profile2.neapp.v3"
    generic_pack = subprocess.run(
        [sys.executable, str(PACK_V3), "--image", str(args.image),
         "--out", str(generic_pkg_path), "--key", str(work / "keys" / "dev-signer.pem"),
         "--publisher-id", "dev-publisher", "--app-id", "lc-test-app",
         "--version", "1.0.0", "--sidecar", "none"],
        capture_output=True, text=True)
    if generic_pack.returncode != 0:
        raise AssertionError(
            f"packer DEFAULT command failed on a legal generic v3 profile 2 input:\n"
            f"{generic_pack.stderr}")
    generic_pkg = generic_pkg_path.read_bytes()
    m_generic = fmt3.parse_manifest_v3(generic_pkg[16:208])
    record_predicate(
        "pack_default_generic_profile2_shape",
        "the packer DEFAULT command (no capability/quota flags) emits a legal GENERIC "
        "v3 run_profile 2 package: caps 0x63 "
        "(log|tick_ms|session_lifecycle|control_receive), control_max 256, no "
        "bit2/3/4/7 quotas; the packer no longer imposes the simulated "
        "line-crossing-64 business or its quotas as built-in pack-time admission",
        m_generic.required_host_caps == 0x63
        and m_generic.control_max == 256
        and m_generic.event_max == 0
        and m_generic.state_quota == 0
        and m_generic.report_max == 0
        and m_generic.snapshot_max == 0
        and m_generic.run_profile == 2,
        extra={"caps": f"{m_generic.required_host_caps:#x}",
               "control_max": m_generic.control_max},
    )
    generic_host = policy_file("generic-host", {"business": None})
    record("pack_default_generic_profile2_verifier_pass",
           "the default-packed generic profile 2 package verifies PASS under a matching "
           "generic Host policy (business none): legal per frozen v3 §4.1 without any "
           "Line Crossing specific bits",
           "PASS", generic_pkg, policy=generic_host)
    lc_host = policy_file("line-crossing-host", {"business": "line-crossing-64"})
    record("generic_profile2_vs_line_crossing_host",
           "the SAME legal generic package under a line-crossing-64 Host policy is "
           "rejected by HOST business admission (missing bits2/3/4/7): admission is "
           "target-Host-policy dependent, not a packer-emitted rule",
           "BAD_PACKAGE", generic_pkg, policy=lc_host,
           detail_contains="line-crossing-64 requires capability bits")

    large_out = case_dir / "pack-large-quota-512-2048.neapp.v3"
    large_common = ["--image", str(args.image),
                    "--key", str(work / "keys" / "dev-signer.pem"),
                    "--publisher-id", "dev-publisher", "--app-id", "lc-test-app",
                    "--version", "1.0.0", "--host-caps", "0xff",
                    "--event-max", "2048", "--state-quota", "4096", "--report-max", "6144",
                    "--control-max", "512", "--snapshot-max", "2048", "--sidecar", "none"]
    sufficient = policy_file("host-sufficient-512-2048",
                             {"business": "line-crossing-64",
                              "control_msg_bytes": 512, "snapshot_ram_bytes": 2048})
    large_pack = subprocess.run(
        [sys.executable, str(PACK_V3), "--out", str(large_out), *large_common,
         "--host-policy", str(sufficient)],
        capture_output=True, text=True)
    if large_pack.returncode != 0:
        raise AssertionError(
            f"packer refused a large-quota declaration under its explicitly declared "
            f"sufficient target-Host policy:\n{large_pack.stderr}")
    large_pkg = large_out.read_bytes()
    m_large = fmt3.parse_manifest_v3(large_pkg[16:208])
    if (m_large.control_max, m_large.snapshot_max) != (512, 2048):
        raise AssertionError("large-quota package does not carry control_max 512 / "
                             "snapshot_max 2048")
    record("pack_large_quota_with_sufficient_host_policy",
           "signed control_max 512 / snapshot_max 2048 — beyond the golden SIMULATED "
           "256/1024B reference values (§13.10/§14) — packs and verifies PASS when a "
           "sufficient target-Host policy is passed EXPLICITLY via --host-policy",
           "PASS", large_pkg, policy=sufficient)
    insufficient = policy_file("host-insufficient-simulated-default", {})
    record("large_quota_pkg_vs_insufficient_host",
           "the SAME large-quota package against the default simulated Host capacity "
           "(256/1024B): RESOURCE_LIMIT — the golden simulated values are a reviewable "
           "verification policy, not pack-time law",
           "RESOURCE_LIMIT", large_pkg, policy=insufficient,
           detail_contains="exceeds the Host control message capacity")
    refused_out = case_dir / "pack-large-quota-refused.neapp.v3"
    if refused_out.exists():
        refused_out.unlink()
    refused_pack = subprocess.run(
        [sys.executable, str(PACK_V3), "--out", str(refused_out), *large_common,
         "--host-policy", str(insufficient)],
        capture_output=True, text=True)
    if refused_pack.returncode == 0 or "RESOURCE_LIMIT" not in (refused_pack.stderr or ""):
        raise AssertionError(
            f"packer must refuse the large-quota declaration under the insufficient "
            f"target-Host policy with a RESOURCE_LIMIT attribution "
            f"(rc={refused_pack.returncode})")
    if refused_out.exists():
        raise AssertionError("refused pack must not emit the package file")
    results.append({
        "case": "pack_large_quota_insufficient_host_refusal",
        "category": "v3",
        "expected": "packer exit 2 (RESOURCE_LIMIT under --host-policy 256/1024B)",
        "observed": "packer exit 2",
        "detail": (refused_pack.stderr or "").strip().splitlines()[0],
        "note": "the identical signed declaration packs under the sufficient policy and "
                "is refused under the insufficient one: target-Host admission is "
                "explicit, reviewable policy input, never an implied packer default",
    })
    print("  ok pack_large_quota_insufficient_host_refusal: refused")

    print("[v3-cases] rejection matrix: structure / DER / manifest encoding")
    magic2 = bytearray(dev_pkg)
    magic2[5] = 0x02
    record("magic_v2_on_v3", "container major downgraded to 2 (unknown version, §1.3/§10)",
           "BAD_PACKAGE", bytes(magic2), detail_contains="container magic")
    magic1 = bytearray(dev_pkg)
    magic1[5] = 0x01
    record("magic_v1_on_v3", "container major downgraded to 1 (unknown version, §1.3/§10)",
           "BAD_PACKAGE", bytes(magic1), detail_contains="container magic")

    def relength(package: bytes, manifest_len: int | None = None,
                 image_len: int | None = None) -> bytes:
        out = bytearray(package)
        if manifest_len is not None:
            out[8:12] = struct.pack("<I", manifest_len)
        if image_len is not None:
            out[12:16] = struct.pack("<I", image_len)
        return bytes(out)

    record("manifest_len_160_in_v3", "manifest_len field = 160 (v1 value) in a v3 header",
           "BAD_PACKAGE", relength(dev_pkg, manifest_len=160), detail_contains="manifest_len")
    record("manifest_len_193_in_v3", "manifest_len field = 193 in a v3 header",
           "BAD_PACKAGE", relength(dev_pkg, manifest_len=193), detail_contains="manifest_len")
    record("image_len_below_header", "image_len 31 cannot hold the 32B native header",
           "BAD_PACKAGE", relength(dev_pkg, image_len=31), detail_contains="cannot hold")
    record("image_len_overflow", "image_len 0xFFFFFFFF (overflow-safe rejection)",
           "BAD_PACKAGE", relength(dev_pkg, image_len=0xFFFFFFFF),
           detail_contains="exceeds the v3 native file cap")
    record("truncate_whole_package", "package truncated below the minimum v3 length",
           "BAD_PACKAGE", dev_pkg[:10], detail_contains="shorter than the minimum")
    record("truncate_signature", "DER signature truncated by one byte",
           "BAD_PACKAGE", dev_pkg[:-1], detail_contains="DER")
    record("der_tail_byte", "valid DER + one trailing byte (tail must be fully consumed)",
           "BAD_PACKAGE", dev_pkg + b"\xff", detail_contains="DER")
    record("der_second_object", "second DER object appended (70B DER + 2B)",
           "BAD_PACKAGE", dev_pkg + b"\x05\x00", detail_contains="DER")
    record("der_r_zero", "DER with r=0 (outside P-256 range)",
           "BAD_PACKAGE", dev_pkg[:dev_signed_len] + bytes.fromhex("3006020100020101"),
           detail_contains="r outside P-256 range")

    r_len = dev_sig[3]
    r_bytes = dev_sig[4:4 + r_len]
    new_int = bytes([0x02, 0x81, r_len]) + r_bytes
    crafted = (bytes([0x30, len(new_int) + (len(dev_sig) - (4 + r_len))])
               + new_int + dev_sig[4 + r_len:])
    record("der_nonminimal_length", "DER non-minimal long-form length encoding",
           "BAD_PACKAGE", dev_pkg[:dev_signed_len] + crafted, detail_contains="DER")

    def raw_manifest_case(name: str, note: str, mutate_raw, expect: str,
                          detail_contains: str | None = None,
                          img: bytes | None = None,
                          post_stamp=None) -> None:
        m = bytearray(base_manifest)
        mutate_raw(m)
        m[OFF_KEY_FP:OFF_KEY_FP + 32] = dev_signer.fingerprint
        if post_stamp is not None:
            post_stamp(m)
        record(name, note, expect,
               build_package(bytes(m), base_image if img is None else img, dev_signer),
               detail_contains=detail_contains)

    raw_manifest_case("nmf2_magic_in_v3", "manifest magic NMF2 inside a v3 container "
                      "(re-signed, §10 M6 flavor)", lambda m: m.__setitem__(3, 0x32),
                      "BAD_PACKAGE", "manifest magic")
    raw_manifest_case("reserved_58_nonzero", "manifest reserved[58..59] nonzero "
                      "(v1-inherited invariant, re-signed)",
                      lambda m: m.__setitem__(58, 0x01), "BAD_PACKAGE",
                      "reserved bytes (58..59)")
    raw_manifest_case("reserved_184_nonzero", "manifest reserved[184..191] nonzero "
                      "(v3 invariant, re-signed, §10 M9)",
                      lambda m: struct.pack_into("<I", m, 184, 1), "BAD_PACKAGE",
                      "reserved bytes (184..191)")
    raw_manifest_case("abi_v2_value_in_nmf3_m6",
                      "M6: v3 container declaring required_host_abi=0x00020000 (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_ABI, 0x00020000),
                      "BAD_PACKAGE", "required_host_abi must be 0x00030000")

    print("[v3-cases] rejection matrix: signature coverage (tamper native/manifest/DER)")
    payload_off = 16 + 192 + fmt.NATIVE_HEADER_SIZE
    payload_len = dev_image_len - fmt.NATIVE_HEADER_SIZE
    tamper_off = payload_off + payload_len // 2
    assert payload_off <= tamper_off < dev_signed_len

    tampered = bytearray(dev_pkg)
    tampered[tamper_off] ^= 0x01
    if tampered[dev_signed_len:] != dev_pkg[dev_signed_len:]:
        raise AssertionError("DER must remain byte-identical for the payload tamper case")
    record("tamper_native_payload", "one true native payload byte flipped inside the signed "
           "region; DER untouched", "SIGNATURE_INVALID", bytes(tampered),
           detail_contains="verification failed",
           extra={"tamper_offset": tamper_off, "signed_len": dev_signed_len,
                  "payload_region": f"[{payload_off}, {payload_off + payload_len})"})
    caps_tampered = bytearray(dev_pkg)
    caps_tampered[16 + OFF_CAPS] ^= 0x01
    record("tamper_manifest_caps_escalation", "signed capability mask flipped in place: "
           "permissions cannot be escalated without invalidating the signature",
           "SIGNATURE_INVALID", bytes(caps_tampered), detail_contains="verification failed")
    ctrl_tampered = bytearray(dev_pkg)
    ctrl_tampered[16 + OFF_CONTROL_MAX] ^= 0x01
    record("tamper_manifest_control_max", "signed control_max quota flipped in place",
           "SIGNATURE_INVALID", bytes(ctrl_tampered), detail_contains="verification failed")
    ver_tampered = bytearray(dev_pkg)
    ver_tampered[16 + OFF_VERSION] ^= 0x01
    record("tamper_manifest_version", "signed version metadata flipped in place",
           "SIGNATURE_INVALID", bytes(ver_tampered), detail_contains="verification failed")
    der_tampered = bytearray(dev_pkg)
    der_tampered[dev_signed_len + 6] ^= 0x01
    record("tamper_der_region", "DER signature byte corrupted (TBS untouched) — proves "
           "corrupted signatures fail, not payload coverage", "SIGNATURE_INVALID",
           bytes(der_tampered), detail_contains="verification failed")

    wrong_key = ec.generate_private_key(ec.SECP256R1())
    dev_tbs = dev_pkg[:dev_signed_len]
    try:
        alg = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    except TypeError:
        alg = ec.ECDSA(hashes.SHA256())
    record("wrong_signer_key", "TBS signed by an ephemeral non-trusted key; manifest "
           "fingerprint still names the trusted dev key", "SIGNATURE_INVALID",
           dev_tbs + wrong_key.sign(dev_tbs, alg), detail_contains="verification failed")

    print("[v3-cases] rejection matrix: publisher trust mapping (re-signed)")

    def set_pub(m, text):
        m[OFF_PUB:OFF_PUB + 16] = text.encode("ascii").ljust(16, b"\x00")

    raw_manifest_case("unknown_publisher", "publisher_id absent from the Host trust mapping "
                      "(re-signed; the package-carried fingerprint cannot self-trust, §2.3)",
                      lambda m: set_pub(m, "other-pub"), "PUBLISHER_UNTRUSTED",
                      "not in the local trust mapping")
    raw_manifest_case("publisher_fingerprint_mismatch", "manifest publisher_key_sha256 no "
                      "longer matches the trusted store entry (re-signed)",
                      lambda m: None, "PUBLISHER_UNTRUSTED", "does not match the trusted key",
                      post_stamp=lambda m: m.__setitem__(OFF_KEY_FP, m[OFF_KEY_FP] ^ 0x01))

    print("[v3-cases] rejection matrix: native cross-checks (re-signed, digest-consistent)")

    def fix_native_sha(m, img):
        m[OFF_NATIVE_SHA:OFF_NATIVE_SHA + 32] = hashlib.sha256(img).digest()

    def native_abi_flip_v2(img: bytes) -> bytes:
        b = bytearray(img)
        struct.pack_into("<I", b, 8, 0x00020000)
        return bytes(b)

    bad_native = native_abi_flip_v2(base_image)
    raw_manifest_case("native_header_abi_v2_mismatch",
                      "ONLY the native header abi_version flipped to 0x00020000, manifest "
                      "keeps 0x00030000, native SHA updated, re-signed (§3.3/§10 M6)",
                      lambda m: fix_native_sha(m, bad_native), "BAD_PACKAGE", "abi_version",
                      img=bad_native)

    def reserved0_flip(img: bytes) -> bytes:
        b = bytearray(img)
        struct.pack_into("<I", b, 24, 1)
        return bytes(b)

    bad_native = reserved0_flip(base_image)
    raw_manifest_case("native_reserved0_nonzero", "native header reserved0=1 with matching "
                      "digest, re-signed (v1-inherited rule)",
                      lambda m: fix_native_sha(m, bad_native), "BAD_PACKAGE", "reserved0",
                      img=bad_native)

    def crc_stale(img: bytes) -> bytes:
        b = bytearray(img)
        b[fmt.NATIVE_HEADER_SIZE] ^= 0x01
        return bytes(b)

    bad_native = crc_stale(base_image)
    raw_manifest_case("resigned_payload_crc_stale", "payload flipped + valid re-sign, native "
                      "header CRC not synchronized", lambda m: fix_native_sha(m, bad_native),
                      "BAD_PACKAGE", "CRC-32", img=bad_native)

    def digest_stale(img: bytes) -> bytes:
        b = bytearray(img)
        b[fmt.NATIVE_HEADER_SIZE] ^= 0x01
        crc = fmt.native_payload_crc32(bytes(b), len(b) - 32)
        struct.pack_into("<I", b, 28, crc)
        return bytes(b)

    bad_native = digest_stale(base_image)
    raw_manifest_case("resigned_payload_digest_stale", "payload flipped + CRC synchronized + "
                      "valid re-sign, manifest native_file_sha256 left stale",
                      lambda m: m, "BAD_PACKAGE", "native_file_sha256", img=bad_native)

    raw_manifest_case("manifest_native_len_mismatch", "manifest native_file_len = +1 (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_FILE_LEN, len(base_image) + 1),
                      "BAD_PACKAGE", "native_file_len")

    def entry_odd(img: bytes) -> bytes:
        b = bytearray(img)
        struct.pack_into("<I", b, 20, 0x51)
        return bytes(b)

    bad_native = entry_odd(base_image)
    raw_manifest_case("entry_odd_signed", "odd Thumb entry offset (0x51, outside the 4B test "
                      "payload), native+manifest consistent, re-signed",
                      lambda m: (fix_native_sha(m, bad_native),
                                 struct.pack_into("<I", m, OFF_ENTRY, 0x51)),
                      "BAD_PACKAGE", "entry_offset", img=bad_native)

    print("[v3-cases] rejection matrix: v3 policy after valid signature (re-signed)")
    raw_manifest_case("caps_unknown_bit8_m8", "capability bit8 set (unknown, §4.1/§10 M8) — "
                      "re-signed", lambda m: struct.pack_into("<I", m, OFF_CAPS, 0x1FF),
                      "BAD_PACKAGE", "unknown bits")
    raw_manifest_case("profile1_in_v3_m9", "run_profile 1 (the v2 value) is not a legal v3 "
                      "value (re-signed, §10 M9)",
                      lambda m: struct.pack_into("<I", m, OFF_PROFILE, 1),
                      "BAD_PACKAGE", "unknown run_profile")
    raw_manifest_case("profile2_missing_bit5", "run_profile 2 without session_lifecycle bit5 "
                      "(re-signed)", lambda m: struct.pack_into("<I", m, OFF_CAPS, 0xDF),
                      "BAD_PACKAGE", "session_lifecycle")
    raw_manifest_case("profile2_missing_bit6", "run_profile 2 without control_receive bit6 "
                      "(re-signed)", lambda m: struct.pack_into("<I", m, OFF_CAPS, 0xBF),
                      "BAD_PACKAGE", "control_receive")
    raw_manifest_case("cap_bit6_without_control_max", "control_receive bit6 kept with "
                      "control_max=0 (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_CONTROL_MAX, 0),
                      "BAD_PACKAGE", "requires a nonzero control_max")
    raw_manifest_case("snapshot_max_without_bit7", "snapshot_max kept nonzero while "
                      "business_snapshot bit7 cleared (no silent reservation, re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_CAPS, 0x7F),
                      "BAD_PACKAGE", "without the business_snapshot")
    raw_manifest_case("control_max_below_wire_min_m11",
                      "M11: control_max=16 below the generic 32B control-wire minimum "
                      "(re-signed)", lambda m: struct.pack_into("<I", m, OFF_CONTROL_MAX, 16),
                      "RESOURCE_LIMIT", "below the generic 32B control-wire minimum")
    raw_manifest_case("control_max_above_host_m11",
                      "M11: control_max=512 exceeds the Host control message capacity 256 "
                      "(re-signed)", lambda m: struct.pack_into("<I", m, OFF_CONTROL_MAX, 512),
                      "RESOURCE_LIMIT", "exceeds the Host control message capacity")
    raw_manifest_case("snapshot_max_above_host_m11",
                      "M11: snapshot_max=2048 exceeds the Host snapshot RAM 1024 (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_SNAPSHOT_MAX, 2048),
                      "RESOURCE_LIMIT", "exceeds the Host snapshot RAM")
    raw_manifest_case("event_max_under_business_floor",
                      "M11 flavor: ai_events with event_max=1024 < the 64-detection minimum "
                      "1576 (re-signed)", lambda m: struct.pack_into("<I", m, OFF_EVENT_MAX, 1024),
                      "RESOURCE_LIMIT", "below the 64-detection")
    raw_manifest_case("report_max_under_business_floor",
                      "M11 flavor: report_submit with report_max=4096 < the 6144B "
                      "line_counting report minimum (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_REPORT_MAX, 4096),
                      "RESOURCE_LIMIT", "below the line_counting report minimum")
    raw_manifest_case("event_max_over_host_buffer",
                      "event_max=3072 exceeds the Host event buffer 2048 (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_EVENT_MAX, 3072),
                      "RESOURCE_LIMIT", "exceeds the Host event buffer")
    raw_manifest_case("state_quota_over_host",
                      "state_quota=8192 exceeds the Host state quota 4096 (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_STATE_QUOTA, 8192),
                      "RESOURCE_LIMIT", "exceeds the Host state quota")
    raw_manifest_case("board_mismatch", "target_board_id 0x3011 (re-signed, signature valid "
                      "must not bypass policy)",
                      lambda m: struct.pack_into("<I", m, OFF_BOARD, 0x3011),
                      "TARGET_INCOMPATIBLE", "target_board_id")
    raw_manifest_case("psram_mismatch", "required_psram_mib=128 unsupported (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_PSRAM, 128),
                      "TARGET_INCOMPATIBLE", "required_psram_mib")
    raw_manifest_case("exec_region_over_host_actual",
                      "required_exec_region_bytes=3MiB exceeds the Host actual 2MiB region "
                      "(re-signed)", lambda m: struct.pack_into("<I", m, OFF_EXEC, 3 * 1024 * 1024),
                      "RESOURCE_LIMIT", "exceeds the Host actual execution region")

    def move_target(img: bytes) -> bytes:
        b = bytearray(img)
        struct.pack_into("<I", b, 12, 0x94E00000)
        return bytes(b)

    bad_native = move_target(base_image)
    raw_manifest_case("target_outside_host_loader_range",
                      "self-consistent target 0x94E00000 (native+manifest agree, digest "
                      "updated, re-signed) outside the Host-independently-known loader range",
                      lambda m: (fix_native_sha(m, bad_native),
                                 struct.pack_into("<I", m, OFF_TARGET, 0x94E00000)),
                      "RESOURCE_LIMIT", "outside the Host loader range", img=bad_native)

    small_load = policy_file("load-region-32", {"load_region_bytes": 32})
    record("native_file_overrides_small_load_region",
           "native_file_len=36 exceeds a 32B Host load region even though the declared "
           "residency is 4B (load transient vs residency, v1 §2.3 rule)",
           "RESOURCE_LIMIT", dev_pkg, policy=small_load, detail_contains="Host load region")

    no_bit7_policy = policy_file("host-caps-no-bit7", {"host_caps": "0x7f"})
    record("host_missing_bit7_m10",
           "M10: all capability bits known, but this Host does not provide "
           "business_snapshot bit7 (golden package, signature valid)",
           "ABI_INCOMPATIBLE", golden_pkg, trust_file=trust_d1, policy=no_bit7_policy,
           detail_contains="does not provide capability bits")

    print("[v3-cases] cross-version discrimination (§10 M2/M3/M4/M5, no v2-reserved escalation)")
    v2_report = run_legacy_verifier(VERIFY_V2, SPEC_V3_EVIDENCE / "golden.neapp.v3",
                                    trust_dev, "BAD_PACKAGE")
    if "not NEAPP v2" not in v2_report["detail"]:
        raise AssertionError(f"M2 attribution missing: {v2_report['detail']!r}")
    results.append({
        "case": "v3_golden_on_v2_verifier_m2",
        "category": "v3",
        "expected": "BAD_PACKAGE",
        "observed": "BAD_PACKAGE",
        "package_sha256": sha256_hex(golden_pkg),
        "detail": v2_report["detail"],
        "note": "§10 M2: the unmodified v2 verifier rejects the v3 container magic; it never "
                "parses the 192B manifest as v2 (v2 tooling untouched)",
    })
    print("  ok v3_golden_on_v2_verifier_m2: BAD_PACKAGE")

    v1_report = run_legacy_verifier(VERIFY_V1, SPEC_V3_EVIDENCE / "golden.neapp.v3",
                                    trust_dev, "BAD_PACKAGE")
    if "not NEAPP v1" not in v1_report["detail"]:
        raise AssertionError(f"M3 attribution missing: {v1_report['detail']!r}")
    results.append({
        "case": "v3_golden_on_v1_verifier_m3",
        "category": "v3",
        "expected": "BAD_PACKAGE",
        "observed": "BAD_PACKAGE",
        "package_sha256": sha256_hex(golden_pkg),
        "detail": v1_report["detail"],
        "note": "§10 M3: the unmodified v1 verifier rejects the v3 container magic",
    })
    print("  ok v3_golden_on_v1_verifier_m3: BAD_PACKAGE")

    record("v2_golden_on_v3_verifier_m4",
           "M4: frozen #12 v2 golden package fed to the v3 verifier (unknown container magic; "
           "v2 packages keep v2 rules and can never gain bit6/bit7 from v2 reserved bytes)",
           "BAD_PACKAGE", v2_golden, trust_file=trust_dev, detail_contains="container magic")
    record("v1_golden_on_v3_verifier_m5",
           "M5: frozen #6 v1 golden package fed to the v3 verifier (unknown container magic)",
           "BAD_PACKAGE", v1_golden, trust_file=trust_dev, detail_contains="container magic")

    m_v2 = fmt2.parse_manifest_v2(v2_golden[16:16 + 192])
    record_predicate(
        "v2_reserved_bits_no_v3_upgrade_m4",
        "M4 semantics: the v2 golden declares abi 0x00020000, run_profile 1 and caps ⊆ bits "
        "0..5 with its [176..191] reserved bytes all zero; a v3 Host would serve only the "
        "frozen 48B table — control_receive/business_snapshot are never inferred from v2 "
        "reserved bytes (no privilege upgrade)",
        m_v2.required_host_abi == 0x00020000
        and m_v2.run_profile == 1
        and m_v2.required_host_caps & ~0x3F == 0,
        extra={"v2_abi": f"{m_v2.required_host_abi:#010x}",
               "v2_caps": f"{m_v2.required_host_caps:#x}",
               "v2_profile": m_v2.run_profile},
    )

    m_dev = fmt3.parse_manifest_v3(dev_pkg[16:208])
    m_dev_200 = fmt3.parse_manifest_v3(dev_pkg_200[16:208])
    m_alt = fmt3.parse_manifest_v3(alt_pkg[16:208])
    tbs_dev = dev_pkg[:16 + 192 + struct.unpack_from("<I", dev_pkg, 12)[0]]
    tbs_dev_200 = dev_pkg_200[:16 + 192 + struct.unpack_from("<I", dev_pkg_200, 12)[0]]
    tbs_alt = alt_pkg[:16 + 192 + struct.unpack_from("<I", alt_pkg, 12)[0]]
    record_predicate(
        "downgrade_discriminator",
        "same publisher/app identity at 2.0.0 and 1.0.0: the signed version triple and "
        "distinct SHA-256(TBS) identities are exactly the inputs a device needs to classify "
        "DOWNGRADE_FORBIDDEN (v1 §3/§5.1 semantics inherited by v3 §10)",
        (m_dev.publisher_id, m_dev.app_id) == (m_dev_200.publisher_id, m_dev_200.app_id)
        and (m_dev_200.version_major, m_dev_200.version_minor, m_dev_200.version_patch) == (2, 0, 0)
        and (m_dev.version_major, m_dev.version_minor, m_dev.version_patch) == (1, 0, 0)
        and tbs_dev != tbs_dev_200,
        extra={"identity_2_0_0": sha256_hex(tbs_dev_200),
               "identity_1_0_0": sha256_hex(tbs_dev)},
    )
    record_predicate(
        "content_conflict_discriminator",
        "same publisher/app/version, different native content: two different SHA-256(TBS) "
        "identities — the offline discriminator input for VERSION_CONTENT_CONFLICT",
        (m_dev.publisher_id, m_dev.app_id) == (m_alt.publisher_id, m_alt.app_id)
        and (m_dev.version_major, m_dev.version_minor, m_dev.version_patch)
        == (m_alt.version_major, m_alt.version_minor, m_alt.version_patch)
        and sha256_hex(tbs_dev) != sha256_hex(tbs_alt)
        and m_dev.native_file_sha256 != m_alt.native_file_sha256,
        extra={"identity_main": sha256_hex(tbs_dev), "identity_alt": sha256_hex(tbs_alt)},
    )

    repack_path = case_dir / "repack-identical.neapp.v3"
    repack = subprocess.run(
        [sys.executable, str(PACK_V3), "--image", str(args.image),
         "--out", str(repack_path), "--key", str(work / "keys" / "dev-signer.pem"),
         "--publisher-id", "dev-publisher", "--app-id", "lc-test-app",
         "--version", "1.0.0", "--host-caps", "0xff", "--event-max", "2048",
         "--state-quota", "4096", "--report-max", "6144",
         "--control-max", "256", "--snapshot-max", "1024", "--sidecar", "none"],
        capture_output=True, text=True)
    if repack.returncode != 0:
        raise AssertionError(f"repack failed:\n{repack.stderr}")
    repack_pkg = repack_path.read_bytes()
    tbs_repack = repack_pkg[:16 + 192 + struct.unpack_from("<I", repack_pkg, 12)[0]]
    record_predicate(
        "idempotent_repack_same_identity",
        "repacking identical image+metadata through the packer CLI reproduces the identical "
        "TBS and, under RFC-6979, the identical package bytes: idempotent content identity "
        "(§2.2)",
        tbs_repack == tbs_dev and repack_pkg == dev_pkg,
        extra={"identity": sha256_hex(tbs_dev)},
    )

    if args.hello_image is not None:
        hello = args.hello_image.read_bytes()
        record_predicate(
            "helloapp_v1_image_pinned",
            "hello-app V1 regression image is the pinned historical build "
            "(SHA-256 d6eec431…, reproduced byte-for-byte by the UNCHANGED v1 regression)",
            sha256_hex(hello) == HELLO_V1_IMAGE_SHA256,
            extra={"hello_app_v1_sha256": sha256_hex(hello)},
        )
        hello_native = fmt.parse_native_header(hello)

        def hello_manifest(m):
            m[OFF_APP:OFF_APP + 32] = b"hello-app".ljust(32, b"\x00")
            struct.pack_into("<I", m, OFF_EXEC, hello_native.image_size)
            struct.pack_into("<I", m, OFF_FILE_LEN, len(hello))
            struct.pack_into("<I", m, OFF_IMAGE_SIZE, hello_native.image_size)
            struct.pack_into("<I", m, OFF_ENTRY, hello_native.entry_offset)
            struct.pack_into("<I", m, OFF_TARGET, hello_native.target_addr)
            fix_native_sha(m, hello)

        raw_manifest_case("helloapp_v1_image_in_v3_container",
                          "hello-app V1 image (sha256 d6eec431…, abi_version 0x00010000) used "
                          "as an additional v3 input WITHOUT rebuild: v1-ABI native inside a "
                          "v3 container must fail the ABI cross-check",
                          hello_manifest, "BAD_PACKAGE", "abi_version", img=hello)

        for label, img_path in (("helloapp_v1", args.hello_image),):
            pack_proc = subprocess.run(
                [sys.executable, str(PACK_V3), "--image", str(img_path),
                 "--out", str(case_dir / f"{label}-should-not-pack.neapp.v3"),
                 "--key", str(work / "keys" / "dev-signer.pem"),
                 "--publisher-id", "dev-publisher", "--app-id", "hello-app",
                 "--version", "1.0.0", "--control-max", "256"],
                capture_output=True, text=True)
            if pack_proc.returncode == 0 or "abi_version" not in (pack_proc.stderr or ""):
                raise AssertionError(
                    f"packer must refuse a v1-ABI image with an abi attribution "
                    f"(rc={pack_proc.returncode})"
                )
            results.append({
                "case": f"{label}_image_pack_refusal",
                "category": "v3",
                "expected": "packer exit 2 (native ABI != 0x00030000 refused)",
                "observed": "packer exit 2",
                "detail": (pack_proc.stderr or "").strip().splitlines()[0],
                "note": "hello-app V1 image as extra v3 input: the packer refuses it before signing",
            })
            print(f"  ok {label}_image_pack_refusal: refused")

        v2abi_image = case_dir / "v2-abi-image.bin"
        v2abi_image.write_bytes(native_abi_flip_v2(base_image))
        pack_proc = subprocess.run(
            [sys.executable, str(PACK_V3), "--image", str(v2abi_image),
             "--out", str(case_dir / "v2abi-should-not-pack.neapp.v3"),
             "--key", str(work / "keys" / "dev-signer.pem"),
             "--publisher-id", "dev-publisher", "--app-id", "lc-test-app",
             "--version", "1.0.0", "--control-max", "256"],
            capture_output=True, text=True)
        if pack_proc.returncode == 0 or "abi_version" not in (pack_proc.stderr or ""):
            raise AssertionError(
                f"packer must refuse a v2-ABI image with an abi attribution "
                f"(rc={pack_proc.returncode})"
            )
        results.append({
            "case": "v2abi_image_pack_refusal",
            "category": "v3",
            "expected": "packer exit 2 (native ABI 0x00020000 refused)",
            "observed": "packer exit 2",
            "detail": (pack_proc.stderr or "").strip().splitlines()[0],
            "note": "v2-ABI native image cannot be passed off as a v3 test image",
        })
        print("  ok v2abi_image_pack_refusal: refused")

    summary = case_dir / "v3-cases-results.json"
    summary.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"v3 case suite: {len(results)} entries, all expectations matched")
    print(f"results -> {summary}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"V3 CASE FAILURE: {exc}", file=sys.stderr)
        raise SystemExit(1)
