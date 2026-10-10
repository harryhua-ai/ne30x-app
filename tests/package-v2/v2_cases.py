#!/usr/bin/env python3
"""v2_cases — P6 (Issue #13) offline positive/negative/rejection-matrix suite
for .neapp v2 packages produced by the package/ tooling.

Runs the REAL CLIs (package/neapp_verify_v2.py, package/neapp_verify.py,
package/neapp_pack_v2.py) the way tests/package/generated_cases.py does for
v1, and layers the #12 pinned golden/negative artifacts
(docs/evidence/spec-v2/) through the independent cryptography-based verifier
so the SHA-256(TBS) identities and structural rejections are re-proven
against the integrated spec vectors (AC3).

Every rejection case asserts the expected §9 error class AND a
detail-substring attribution, so a pass cannot come from a checkpoint that
happens to run earlier.  All signing uses the NON-PRODUCTION dev/test
identity generated at test time (never committed); the d=1 scalar is the
spec §10.1 PUBLIC test key and is likewise non-production.  Nothing here is
a device claim: every case is offline packaging-layer evidence.

Exit code 0 only if every expectation (class + detail attribution) matches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "package"))
import neapp_format as fmt  # noqa: E402
import neapp_v2_format as fmt2  # noqa: E402

VERIFY_V2 = REPO / "package" / "neapp_verify_v2.py"
VERIFY_V1 = REPO / "package" / "neapp_verify.py"
PACK_V2 = REPO / "package" / "neapp_pack_v2.py"
SPEC_V2_EVIDENCE = REPO / "docs" / "evidence" / "spec-v2"

# #12 pinned values (spec §10.1/§10.2 and the committed evidence artifacts)
GOLDEN_TBS_SHA256 = "e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278"
GOLDEN_PKG_SHA256 = "3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e"
GOLDEN_DER_HEX = (
    "3044022011e9d2635e2036fb0bcbd1107a5e6d272c150473a8c1e029887604f9aa754"
    "73702205b6ca9206755a161913fcf9cdf57c789b363420bc16a74438bc439aeb80d11b0"
)
SPKI_SHA256 = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
ARCHIVE_PKG_SHA256 = "f05ca613d7ea2e74f61cdd5cc2bbc9f44a4406eca216366fee81894b6b664e24"
V1_GOLDEN_SHA256 = "9a212324132c0f26e2878384904f1af4abd3090a6ae5806ef32da2d3b4c80679"
HELLO_V1_IMAGE_SHA256 = "d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03"

# v2 manifest raw-byte offsets (spec §3; signed region = file[16:208])
OFF_PUB, OFF_APP = 4, 20
OFF_VERSION = 52
OFF_ABI, OFF_CAPS, OFF_EXEC = 68, 72, 76
OFF_FILE_LEN, OFF_IMAGE_SIZE, OFF_ENTRY, OFF_TARGET = 80, 84, 88, 92
OFF_NATIVE_SHA, OFF_KEY_FP = 96, 128
OFF_PROFILE, OFF_EVENT_MAX, OFF_STATE_QUOTA, OFF_REPORT_MAX = 160, 164, 168, 172

results: list[dict] = []


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_v2_verifier(package_path: Path, trust: Path, expect: str,
                    policy: Path | None = None) -> dict:
    cmd = [sys.executable, str(VERIFY_V2), "--package", str(package_path),
           "--trust", str(trust), "--expect", expect, "--compact"]
    if policy is not None:
        cmd += ["--policy", str(policy)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(
            f"v2 verifier did not produce expected {expect} for {package_path.name}:\n"
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
    tbs = fmt2.build_container_prefix_v2(manifest_raw, image)
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
    """Re-encode the same (r, n-s): a different but equally valid DER over the
    same TBS (spec §2.2 idempotent identity; mirrors the v1 §2.5 low-S vector)."""
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
                        help="controlled v2-ABI native test image (tools/make_v2_test_image.py)")
    parser.add_argument("--alt-image", required=True, type=Path,
                        help="second controlled image with different payload")
    parser.add_argument("--golden-replica-package", required=True, type=Path,
                        help="d=1-packed replica of the #12 golden v2 package")
    parser.add_argument("--dev-package", required=True, type=Path,
                        help="dev-key-packed v2 package @1.0.0 (caps 0x3f, 2048/4096/6144)")
    parser.add_argument("--dev-package-2-0-0", required=True, type=Path,
                        help="dev-key-packed v2 package @2.0.0 (upgrade path)")
    parser.add_argument("--alt-image-package", required=True, type=Path,
                        help="dev-key-packed v2 package of the alt image @1.0.0 (conflict path)")
    parser.add_argument("--hello-image", type=Path, default=None,
                        help="optional prebuilt hello-app V1 image (extra input, never rebuilt)")
    args = parser.parse_args()

    work = args.work_dir
    case_dir = work / "v2-cases"
    case_dir.mkdir(parents=True, exist_ok=True)
    trust_dev = work / "trust-dev.json"
    trust_d1 = work / "trust-d1.json"
    dev_signer = Signer((work / "keys" / "dev-signer.pem").read_bytes(), "dev-publisher")

    for name, digest in (("golden.neapp.v2", GOLDEN_PKG_SHA256),
                         ("golden-tbs.bin", GOLDEN_TBS_SHA256),
                         ("golden-sig.der", None),
                         ("test-publisher.spki.der", SPKI_SHA256),
                         ("negative-archive-1024-4096.neapp.v2", ARCHIVE_PKG_SHA256),
                         ("v1-golden.neapp", V1_GOLDEN_SHA256)):
        path = SPEC_V2_EVIDENCE / name
        if not path.is_file():
            raise AssertionError(f"missing committed #12 evidence artifact: {path}")
        if digest is not None and sha256_hex(path.read_bytes()) != digest:
            raise AssertionError(f"#12 evidence artifact hash drifted: {path}")
    golden_pkg = (SPEC_V2_EVIDENCE / "golden.neapp.v2").read_bytes()
    golden_tbs = (SPEC_V2_EVIDENCE / "golden-tbs.bin").read_bytes()
    golden_der = (SPEC_V2_EVIDENCE / "golden-sig.der").read_bytes()
    spki_d1 = (SPEC_V2_EVIDENCE / "test-publisher.spki.der").read_bytes()
    archive_pkg = (SPEC_V2_EVIDENCE / "negative-archive-1024-4096.neapp.v2").read_bytes()
    v1_golden = (SPEC_V2_EVIDENCE / "v1-golden.neapp").read_bytes()
    if golden_der.hex() != GOLDEN_DER_HEX:
        raise AssertionError("committed golden-sig.der is not the pinned §10.1 DER")

    image = args.image.read_bytes()
    alt_image = args.alt_image.read_bytes()
    golden_replica = args.golden_replica_package.read_bytes()
    dev_pkg = args.dev_package.read_bytes()
    dev_pkg_200 = args.dev_package_2_0_0.read_bytes()
    alt_pkg = args.alt_image_package.read_bytes()

    # Base material for crafted mutations: the dev-key package (trusted
    # framing — it was self-verified by the packer before being written).
    dev_image_len = struct.unpack_from("<I", dev_pkg, 12)[0]
    dev_signed_len = 16 + 192 + dev_image_len
    dev_sig = dev_pkg[dev_signed_len:]
    base_manifest = bytearray(dev_pkg[16:16 + 192])
    base_image = bytes(dev_pkg[16 + 192:16 + 192 + dev_image_len])

    def record(name: str, note: str, expect: str, package: bytes,
               trust_file: Path = trust_dev, policy: Path | None = None,
               detail_contains: str | None = None, extra: dict | None = None) -> None:
        path = case_dir / f"{name}.neapp.v2"
        path.write_bytes(package)
        report = run_v2_verifier(path, trust_file, expect, policy)
        detail = report.get("detail")
        if detail_contains is not None and expect != "PASS":
            if detail is None or detail_contains not in detail:
                raise AssertionError(
                    f"{name}: expected detail containing {detail_contains!r}, got {detail!r}"
                )
        entry = {
            "case": name,
            "category": "v2",
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
            "category": "v2",
            "expected": "PASS",
            "observed": "PASS",
            "note": note,
        }
        if extra:
            entry.update(extra)
        results.append(entry)
        print(f"  ok {name}: predicate")

    def mutated(mutator, signer: Signer = dev_signer, img: bytes | None = None) -> bytes:
        m = bytearray(base_manifest)
        mutator(m)
        used_image = base_image if img is None else img
        m[OFF_KEY_FP:OFF_KEY_FP + 32] = signer.fingerprint
        return build_package(bytes(m), used_image, signer)

    def policy_file(name: str, data: dict) -> Path:
        pdir = case_dir / "policies"
        pdir.mkdir(exist_ok=True)
        p = pdir / f"{name}.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    # =====================================================================
    print("[v2-cases] positives: AC1 controlled-image package + #12 golden consistency (AC3)")
    rep_dev = run_v2_verifier(args.dev_package, trust_dev, "PASS")
    results.append({
        "case": "dev_v2_accept",
        "category": "v2",
        "expected": "PASS",
        "observed": "PASS",
        "package_sha256": rep_dev["package_sha256"],
        "content_identity_sha256": rep_dev["content_identity_sha256"],
        "detail": ("controlled v2-ABI test image, dev-key signed; caps 0x3f, quotas "
                   "2048/4096/6144, run_profile 1, abi 0x00020000"),
        "note": "Issue #13 AC1: 受控测试原生镜像 -> 签名 v2 包 -> 离线验真通过",
    })
    print("  ok dev_v2_accept: PASS")

    rep_gr = run_v2_verifier(args.golden_replica_package, trust_d1, "PASS")
    replica_tbs = golden_replica[:len(golden_replica) - rep_gr["signature_len"]]
    if replica_tbs != golden_tbs:
        raise AssertionError("golden replica TBS is not byte-identical to #12 golden-tbs.bin")
    if rep_gr["content_identity_sha256"] != GOLDEN_TBS_SHA256:
        raise AssertionError("golden replica SHA-256(TBS) != pinned §10.1 value")
    results.append({
        "case": "golden_replica_tbs_identity",
        "category": "v2",
        "expected": "PASS",
        "observed": "PASS",
        "package_sha256": rep_gr["package_sha256"],
        "content_identity_sha256": rep_gr["content_identity_sha256"],
        "detail": ("packer TBS is byte-identical to docs/evidence/spec-v2/golden-tbs.bin; "
                   "SHA-256(TBS) equals the pinned e14e2cce…; the DER is a DIFFERENT valid "
                   "signature (cryptography RFC-6979) over the same identity — §2.2 "
                   "idempotent content identity"),
        "note": "Issue #13 AC3: 独立复算 SHA-256(TBS) 与 #12 黄金一致",
    })
    print("  ok golden_replica_tbs_identity: PASS")

    record("golden_artifact_accept", "committed #12 golden.neapp.v2 through the independent "
           "cryptography-based v2 verifier", "PASS", golden_pkg, trust_file=trust_d1)

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
        "pinned #12 golden DER independently verified over golden-tbs.bin by "
        "`cryptography` AND the OpenSSL CLI (independent of the #12 pure-Python prover)",
        crypto_ok and code == 0,
        extra={"openssl_exit": code, "openssl_output": out},
    )

    record("archive_negative_resource_limit",
           "committed #12 archive negative (valid signature, event_max=1024 < 1576, "
           "report_max=4096 < 6144) -> RESOURCE_LIMIT, §8 M7", "RESOURCE_LIMIT",
           archive_pkg, trust_file=trust_d1, detail_contains="event_max 1024")

    low_s = to_low_s_der(golden_der)
    record("golden_low_s_variant_same_identity",
           "same #12 golden TBS with re-encoded low-S DER: different valid DER, same "
           "SHA-256(TBS) content identity (§2.2)", "PASS", golden_tbs + low_s,
           trust_file=trust_d1,
           extra={"predicate": "SHA-256(TBS) unchanged by DER re-encoding",
                  "der_len_original": len(golden_der), "der_len_low_s": len(low_s)})

    prov = json.loads(Path(str(args.dev_package) + ".provenance.json").read_text())
    record_predicate(
        "dev_provenance_traceable",
        "provenance sidecar carries source/target/publisher/app identity, version, "
        "capabilities/quotas/profile, native digest and TBS identity (AC1 traceability)",
        prov["format"] == "neapp-v2"
        and prov["tbs_sha256"] == rep_dev["content_identity_sha256"]
        and prov["manifest"]["required_host_caps"] == "0x3f"
        and prov["manifest"]["run_profile"] == 1
        and prov["manifest"]["event_max"] == 2048
        and prov["manifest"]["state_quota"] == 4096
        and prov["manifest"]["report_max"] == 6144
        and prov["manifest"]["required_host_abi"] == "0x00020000"
        and "NON-PRODUCTION" in prov["non_production_trust_root"]
        and prov["signer_spki_sha256"] == sha256_hex(dev_signer.spki),
        extra={"generator": prov["generator"], "source_commit": prov["source_commit"]},
    )

    # =====================================================================
    print("[v2-cases] rejection matrix: structure / DER / manifest encoding")
    magic3 = bytearray(dev_pkg)
    magic3[5] = 0x03
    record("magic_unknown_version", "container major bumped to 3 (unknown version, §1.3)",
           "BAD_PACKAGE", bytes(magic3), detail_contains="container magic")
    magic1 = bytearray(dev_pkg)
    magic1[5] = 0x01
    record("magic_v1_on_v2", "container magic downgraded to v1, body unchanged",
           "BAD_PACKAGE", bytes(magic1), detail_contains="container magic")

    def relength(package: bytes, manifest_len: int | None = None,
                 image_len: int | None = None) -> bytes:
        out = bytearray(package)
        if manifest_len is not None:
            out[8:12] = struct.pack("<I", manifest_len)
        if image_len is not None:
            out[12:16] = struct.pack("<I", image_len)
        return bytes(out)

    record("manifest_len_160_in_v2", "manifest_len field = 160 (v1 value) in a v2 header",
           "BAD_PACKAGE", relength(dev_pkg, manifest_len=160), detail_contains="manifest_len")
    record("manifest_len_193_in_v2", "manifest_len field = 193 in a v2 header",
           "BAD_PACKAGE", relength(dev_pkg, manifest_len=193), detail_contains="manifest_len")
    record("image_len_below_header", "image_len 31 cannot hold the 32B native header",
           "BAD_PACKAGE", relength(dev_pkg, image_len=31), detail_contains="cannot hold")
    record("image_len_overflow", "image_len 0xFFFFFFFF (overflow-safe rejection)",
           "BAD_PACKAGE", relength(dev_pkg, image_len=0xFFFFFFFF),
           detail_contains="exceeds the v2 native file cap")
    record("truncate_whole_package", "package truncated below the minimum v2 length",
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

    # non-minimal DER length inside the first INTEGER (same recipe as v1 suite)
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
            post_stamp(m)  # applied after the fingerprint stamp (e.g. fingerprint corruption)
        record(name, note, expect,
               build_package(bytes(m), base_image if img is None else img, dev_signer),
               detail_contains=detail_contains)

    raw_manifest_case("nmf1_magic_in_v2", "manifest magic NMF1 inside a v2 container (re-signed)",
                      lambda m: m.__setitem__(0, 0x31), "BAD_PACKAGE", "manifest magic")
    raw_manifest_case("reserved_58_nonzero", "manifest reserved[58..59] nonzero (v1-inherited "
                      "invariant, re-signed)", lambda m: m.__setitem__(58, 0x01),
                      "BAD_PACKAGE", "reserved bytes (58..59)")
    raw_manifest_case("reserved_176_nonzero", "manifest reserved[176..191] nonzero (re-signed)",
                      lambda m: m.__setitem__(176, 0x01), "BAD_PACKAGE",
                      "reserved bytes (176..191)")
    raw_manifest_case("v2_container_v1_abi_m4",
                      "M4: v2 container declaring required_host_abi=0x00010000 (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_ABI, 0x00010000),
                      "BAD_PACKAGE", "required_host_abi must be 0x00020000")

    print("[v2-cases] rejection matrix: signature coverage (tamper native/manifest/DER)")
    # locate the true payload region inside the signed TBS (no hardcoded offsets)
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

    print("[v2-cases] rejection matrix: publisher trust mapping (re-signed)")
    def set_pub(m, text):
        m[OFF_PUB:OFF_PUB + 16] = text.encode("ascii").ljust(16, b"\x00")
    raw_manifest_case("unknown_publisher", "publisher_id absent from the Host trust mapping "
                      "(re-signed; package fingerprint cannot self-trust)",
                      lambda m: set_pub(m, "other-pub"), "PUBLISHER_UNTRUSTED",
                      "not in the local trust mapping")

    raw_manifest_case("publisher_fingerprint_mismatch", "manifest publisher_key_sha256 no "
                      "longer matches the trusted store entry (re-signed)",
                      lambda m: None, "PUBLISHER_UNTRUSTED", "does not match the trusted key",
                      post_stamp=lambda m: m.__setitem__(OFF_KEY_FP, m[OFF_KEY_FP] ^ 0x01))

    print("[v2-cases] rejection matrix: native cross-checks (re-signed, digest-consistent)")

    def fix_native_sha(m, img):
        m[OFF_NATIVE_SHA:OFF_NATIVE_SHA + 32] = hashlib.sha256(img).digest()

    def native_abi_flip(img: bytes) -> bytes:
        b = bytearray(img)
        struct.pack_into("<I", b, 8, 0x00010000)  # native header abi_version only
        return bytes(b)

    bad_native = native_abi_flip(base_image)
    raw_manifest_case("native_header_abi_mismatch_m8",
                      "M8: ONLY the native header abi_version flipped to 0x00010000, manifest "
                      "keeps 0x00020000, native SHA updated, re-signed",
                      lambda m: fix_native_sha(m, bad_native), "BAD_PACKAGE", "abi_version",
                      img=bad_native)

    def reserved0_flip(img: bytes) -> bytes:
        b = bytearray(img)
        struct.pack_into("<I", b, 24, 1)
        return bytes(b)

    bad_native = reserved0_flip(base_image)
    raw_manifest_case("native_reserved0_nonzero", "native header reserved0=1 with matching "
                      "digest, re-signed (v1-inherited rule)", lambda m: fix_native_sha(m, bad_native),
                      "BAD_PACKAGE", "reserved0", img=bad_native)

    def crc_stale(img: bytes) -> bytes:
        b = bytearray(img)
        b[fmt.NATIVE_HEADER_SIZE] ^= 0x01  # payload flipped, header CRC left stale
        return bytes(b)

    bad_native = crc_stale(base_image)
    raw_manifest_case("resigned_payload_crc_stale", "payload flipped + valid re-sign, native "
                      "header CRC not synchronized", lambda m: fix_native_sha(m, bad_native),
                      "BAD_PACKAGE", "CRC-32", img=bad_native)

    def digest_stale(img: bytes) -> bytes:
        b = bytearray(img)
        b[fmt.NATIVE_HEADER_SIZE] ^= 0x01
        crc = fmt.native_payload_crc32(bytes(b), len(b) - 32)
        struct.pack_into("<I", b, 28, crc)  # CRC synchronized; manifest SHA left stale
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
        struct.pack_into("<I", b, 20, 0x51)  # odd entry offset in native header
        return bytes(b)

    bad_native = entry_odd(base_image)
    raw_manifest_case("entry_odd_signed", "odd Thumb entry offset (0x51, outside the 4B test "
                      "payload), native+manifest consistent, re-signed",
                      lambda m: (fix_native_sha(m, bad_native),
                                 struct.pack_into("<I", m, OFF_ENTRY, 0x51)),
                      "BAD_PACKAGE", "entry_offset", img=bad_native)

    if args.hello_image is not None:
        hello = args.hello_image.read_bytes()
        if sha256_hex(hello) != HELLO_V1_IMAGE_SHA256:
            raise AssertionError("hello-app V1 image is not the pinned historical bytes — "
                                 "refusing to use a rebuilt artifact")
        hello_native = fmt.parse_native_header(hello)

        def hello_manifest(m):
            m[OFF_APP:OFF_APP + 32] = b"hello-app".ljust(32, b"\x00")
            struct.pack_into("<I", m, OFF_EXEC, hello_native.image_size)
            struct.pack_into("<I", m, OFF_FILE_LEN, len(hello))
            struct.pack_into("<I", m, OFF_IMAGE_SIZE, hello_native.image_size)
            struct.pack_into("<I", m, OFF_ENTRY, hello_native.entry_offset)
            struct.pack_into("<I", m, OFF_TARGET, hello_native.target_addr)
            fix_native_sha(m, hello)
            # manifest abi deliberately stays 0x00020000; the hello-app V1 image
            # carries abi_version 0x00010000 -> native<->manifest cross must fail

        raw_manifest_case("helloapp_v1_image_in_v2_container",
                          "hello-app V1 image (sha256 d6eec431…, abi_version 0x00010000) used "
                          "as an additional v2 input WITHOUT rebuild: v1-ABI native inside a "
                          "v2 container must fail the ABI cross-check",
                          hello_manifest, "BAD_PACKAGE", "abi_version", img=hello)

        pack_proc = subprocess.run(
            [sys.executable, str(PACK_V2), "--image", str(args.hello_image),
             "--out", str(case_dir / "hello-should-not-pack.neapp.v2"),
             "--key", str(work / "keys" / "dev-signer.pem"),
             "--publisher-id", "dev-publisher", "--app-id", "hello-app", "--version", "1.0.0"],
            capture_output=True, text=True)
        if pack_proc.returncode == 0 or "abi_version" not in (pack_proc.stderr or ""):
            raise AssertionError(
                f"packer must refuse a v1-ABI image with an abi attribution (rc={pack_proc.returncode})"
            )
        results.append({
            "case": "helloapp_v1_image_pack_refusal",
            "category": "v2",
            "expected": "packer exit 2 (native ABI 0x00010000 refused)",
            "observed": "packer exit 2",
            "detail": (pack_proc.stderr or "").strip().splitlines()[0],
            "note": "hello-app V1 image as extra v2 input: the packer refuses it before signing",
        })
        print("  ok helloapp_v1_image_pack_refusal: refused")

    print("[v2-cases] rejection matrix: v2 policy after valid signature (re-signed)")
    raw_manifest_case("caps_unknown_bit6", "capability bit6 set (unknown, §4.1) — re-signed",
                      lambda m: struct.pack_into("<I", m, OFF_CAPS, 0x3F | (1 << 6)),
                      "BAD_PACKAGE", "unknown bits")
    raw_manifest_case("profile1_without_bit5", "run_profile 1 without session_lifecycle bit5 "
                      "(re-signed)", lambda m: struct.pack_into("<I", m, OFF_CAPS, 0x1F),
                      "BAD_PACKAGE", "session_lifecycle")
    raw_manifest_case("unknown_run_profile_2", "run_profile=2 is not a legal v2 value (re-signed)",
                      lambda m: struct.pack_into("<I", m, OFF_PROFILE, 2),
                      "BAD_PACKAGE", "unknown run_profile")
    raw_manifest_case("quota_without_cap", "event_max kept nonzero while ai_events bit2 cleared "
                      "(no silent reservation, re-signed; 0x3f & ~bit2 = 0x3b)",
                      lambda m: struct.pack_into("<I", m, OFF_CAPS, 0x3B),
                      "BAD_PACKAGE", "without the ai_events")
    raw_manifest_case("cap_without_quota", "ai_events bit2 kept with event_max=0 (re-signed)",
                      lambda m: (struct.pack_into("<I", m, OFF_CAPS, 0x3F),
                                 struct.pack_into("<I", m, OFF_EVENT_MAX, 0)),
                      "BAD_PACKAGE", "requires a nonzero event_max")
    raw_manifest_case("board_mismatch", "target_board_id 0x3011 (re-signed, signature valid "
                      "must not bypass policy)", lambda m: struct.pack_into("<I", m, 60, 0x3011),
                      "TARGET_INCOMPATIBLE", "target_board_id")
    raw_manifest_case("psram_mismatch", "required_psram_mib=128 unsupported (re-signed)",
                      lambda m: struct.pack_into("<I", m, 64, 128),
                      "TARGET_INCOMPATIBLE", "required_psram_mib")

    # M10: golden package is signature-valid with caps=0x3f (all bits known);
    # a Host lacking report_submit must fail closed as ABI_INCOMPATIBLE.
    no_report_policy = policy_file("host-caps-no-report", {"host_caps": "0x37"})
    record("caps_subset_host_missing_report_submit",
           "M10: all capability bits known, but this Host does not provide report_submit "
           "(golden package, signature valid)", "ABI_INCOMPATIBLE", golden_pkg,
           trust_file=trust_d1, policy=no_report_policy,
           detail_contains="does not provide capability bits")

    raw_manifest_case("event_max_under_business_floor",
                      "M7 flavor: ai_events with event_max=1024 < the 64-detection minimum 1576 "
                      "(re-signed)", lambda m: struct.pack_into("<I", m, OFF_EVENT_MAX, 1024),
                      "RESOURCE_LIMIT", "below the 64-detection")
    raw_manifest_case("report_max_under_business_floor",
                      "M7 flavor: report_submit with report_max=4096 < the 6144B line_counting "
                      "report minimum (re-signed)",
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
    raw_manifest_case("exec_region_over_host_actual",
                      "required_exec_region_bytes=3MiB exceeds the Host actual 2MiB region "
                      "(re-signed)", lambda m: struct.pack_into("<I", m, OFF_EXEC, 3 * 1024 * 1024),
                      "RESOURCE_LIMIT", "exceeds the Host actual execution region")

    def move_target(img: bytes) -> bytes:
        b = bytearray(img)
        struct.pack_into("<I", b, 12, 0x94E00000)  # native header target_addr
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

    print("[v2-cases] cross-version discrimination (§8 M2/M3, downgrade/conflict discriminators)")
    v1_proc = subprocess.run([sys.executable, str(VERIFY_V1), "--package",
                              str(SPEC_V2_EVIDENCE / "golden.neapp.v2"),
                              "--trust", str(trust_dev), "--expect", "BAD_PACKAGE",
                              "--compact"], capture_output=True, text=True)
    if v1_proc.returncode != 0:
        raise AssertionError(f"v1 verifier must reject a v2 package (M2):\n{v1_proc.stderr}")
    m2_detail = json.loads(v1_proc.stdout.strip().splitlines()[0])["detail"]
    if "not NEAPP v1" not in m2_detail:
        raise AssertionError(f"M2 attribution missing: {m2_detail!r}")
    results.append({
        "case": "v2_package_on_v1_verifier_m2",
        "category": "v2",
        "expected": "BAD_PACKAGE",
        "observed": "BAD_PACKAGE",
        "package_sha256": sha256_hex(golden_pkg),
        "detail": m2_detail,
        "note": "§8 M2: the unmodified v1 verifier rejects the v2 container magic; it never "
                "parses the 192B manifest (v1 tooling untouched)",
    })
    print("  ok v2_package_on_v1_verifier_m2: BAD_PACKAGE")

    record("v1_package_on_v2_verifier", "frozen v1 §2.5 golden package fed to the v2 verifier "
           "(unknown container magic; M3 keeps v1 packages on v1 rules)",
           "BAD_PACKAGE", v1_golden, trust_file=trust_dev, detail_contains="not NEAPP v2")

    v1_manifest = fmt.parse_manifest(v1_golden[16:16 + 160])
    record_predicate(
        "v1_caps_no_v2_upgrade_m3",
        "M3 semantics: the v1 golden declares abi 0x00010000 and caps ⊆ {log, tick_ms}; a v2 "
        "Host would serve only the frozen 16B table — no v2 capability is inferred from any "
        "v1 field (no privilege upgrade)",
        v1_manifest.required_host_abi == 0x00010000
        and v1_manifest.required_host_caps & ~0b11 == 0,
        extra={"v1_abi": f"{v1_manifest.required_host_abi:#010x}",
               "v1_caps": f"{v1_manifest.required_host_caps:#x}"},
    )

    m_dev = fmt2.parse_manifest_v2(dev_pkg[16:208])
    m_dev_200 = fmt2.parse_manifest_v2(dev_pkg_200[16:208])
    m_alt = fmt2.parse_manifest_v2(alt_pkg[16:208])
    tbs_dev = dev_pkg[:16 + 192 + struct.unpack_from("<I", dev_pkg, 12)[0]]
    tbs_dev_200 = dev_pkg_200[:16 + 192 + struct.unpack_from("<I", dev_pkg_200, 12)[0]]
    tbs_alt = alt_pkg[:16 + 192 + struct.unpack_from("<I", alt_pkg, 12)[0]]
    record_predicate(
        "downgrade_discriminator",
        "same publisher/app identity at 2.0.0 and 1.0.0: the signed version triple and "
        "distinct SHA-256(TBS) identities are exactly the inputs a device needs to classify "
        "DOWNGRADE_FORBIDDEN (v1 §3/§5.1 semantics inherited by v2 §8)",
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

    # idempotent identity: repack identical inputs through the real packer CLI
    # and require the identical TBS (and, under RFC-6979, identical bytes).
    repack_path = case_dir / "repack-identical.neapp.v2"
    repack = subprocess.run(
        [sys.executable, str(PACK_V2), "--image", str(args.image),
         "--out", str(repack_path), "--key", str(work / "keys" / "dev-signer.pem"),
         "--publisher-id", "dev-publisher", "--app-id", "lc-test-app",
         "--version", "1.0.0", "--host-caps", "0x3f", "--event-max", "2048",
         "--state-quota", "4096", "--report-max", "6144", "--sidecar", "none"],
        capture_output=True, text=True)
    if repack.returncode != 0:
        raise AssertionError(f"repack failed:\n{repack.stderr}")
    repack_pkg = repack_path.read_bytes()
    tbs_repack = repack_pkg[:16 + 192 + struct.unpack_from("<I", repack_pkg, 12)[0]]
    record_predicate(
        "idempotent_repack_same_identity",
        "repacking identical image+metadata through the packer CLI reproduces the identical "
        "TBS (and identical package bytes under RFC-6979): idempotent content identity (§2.2)",
        tbs_repack == tbs_dev and repack_pkg == dev_pkg,
        extra={"identity": sha256_hex(tbs_dev)},
    )

    summary = case_dir / "v2-cases-results.json"
    summary.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"v2 case suite: {len(results)} entries, all expectations matched")
    print(f"results -> {summary}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"V2 CASE FAILURE: {exc}", file=sys.stderr)
        raise SystemExit(1)
