#!/usr/bin/env python3
"""generated_cases — locally generated positive/negative .neapp v1 cases.

Complements tests/package/spec_vectors.py (which adopts the spec §2.5
frozen vectors verbatim).  The spec's own evidence table also lists cases
published only as SHA-256 values without bytes; those are covered here by
documented equivalents, plus additional structure/DER/policy negatives the
spec's §2.3/§7.1 check order requires (truncation, overflow lengths,
double DER, non-minimal encodings, out-of-range integers, re-signed
policy violations, resource limits).

All signing in this module uses the NON-PRODUCTION dev/test identity
generated at test time (never committed); one case deliberately creates an
ephemeral in-memory wrong key to prove wrong-signer rejection.  Nothing
here is a device claim: every case is offline packaging-layer evidence.
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

VERIFY = REPO / "package" / "neapp_verify.py"


def run_verifier(package_path: Path, trust: Path, expect: str, policy: Path | None = None) -> dict:
    cmd = [sys.executable, str(VERIFY), "--package", str(package_path), "--trust", str(trust),
           "--expect", expect, "--compact"]
    if policy is not None:
        cmd += ["--policy", str(policy)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(
            f"verifier did not produce expected {expect} for {package_path.name}:\n"
            f"{proc.stdout}{proc.stderr}"
        )
    return json.loads(proc.stdout.strip().splitlines()[0])


class Signer:
    def __init__(self, key_pem: bytes, publisher_id: str):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self.key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(self.key, ec.EllipticCurvePrivateKey):
            raise ValueError("dev key is not an EC private key")
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


def unpack(package: bytes):
    """Split one of OUR OWN structurally valid packages (trusted framing)."""
    manifest_len, image_len = struct.unpack_from("<II", package, 8)
    signed = fmt.HEADER_LEN + manifest_len + image_len
    return package[:signed], package[signed:]


def resign(package: bytes, signer: Signer,
           mutate_manifest=None, mutate_image=None) -> bytes:
    """Rebuild a package from an existing one, applying mutations, fixing the
    native-file digest like the spec's own negative recipes do, and
    re-signing with the dev identity (so failures isolate the intended
    policy/encoding rule, never a stale signature)."""
    prefix, _sig = unpack(package)
    manifest = fmt.parse_manifest(prefix[fmt.HEADER_LEN:fmt.HEADER_LEN + fmt.MANIFEST_LEN])
    image = bytearray(prefix[fmt.HEADER_LEN + fmt.MANIFEST_LEN:])
    if mutate_manifest is not None:
        manifest = mutate_manifest(manifest)
    if mutate_image is not None:
        image = bytearray(mutate_image(image))
    manifest.native_file_sha256 = hashlib.sha256(bytes(image)).digest()
    manifest.publisher_key_sha256 = signer.fingerprint
    tbs = fmt.build_container_prefix(fmt.build_manifest(manifest), bytes(image))
    return tbs + signer.sign(tbs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--v1-package", required=True, type=Path)
    parser.add_argument("--v2-package", required=True, type=Path)
    parser.add_argument("--v2-image-as-v1-package", required=True, type=Path,
                        help="V2 image packaged under version 1.0.0 (content-conflict evidence)")
    args = parser.parse_args()

    work = args.work_dir
    case_dir = work / "generated-cases"
    case_dir.mkdir(parents=True, exist_ok=True)
    trust = work / "trust-dev.json"
    trust_data = json.loads(trust.read_text(encoding="utf-8"))
    publisher_id = next(iter(trust_data["publishers"]))
    signer = Signer((work / "keys" / "dev-signer.pem").read_bytes(), publisher_id)

    v1 = args.v1_package.read_bytes()
    v2 = args.v2_package.read_bytes()
    v2_as_v1 = args.v2_image_as_v1_package.read_bytes()

    results: list[dict] = []

    def check(name: str, spec_ref: str, expect: str, package: bytes,
              policy: Path | None = None, trust_file: Path = trust) -> None:
        path = case_dir / f"{name}.neapp"
        path.write_bytes(package)
        report = run_verifier(path, trust_file, expect, policy)
        results.append({
            "case": name,
            "category": "generated",
            "expected": expect,
            "observed": report.get("result", expect),
            "package_sha256": hashlib.sha256(package).hexdigest(),
            "content_identity_sha256": report.get("content_identity_sha256"),
            "detail": report.get("detail"),
            "note": spec_ref,
        })
        print(f"  ok {name}: {expect}")

    # ---------------- positives ----------------
    print("[generated] positives")
    check("dev_v1_accept", "P3-built V1 package", "PASS", v1)
    check("dev_v2_accept", "P3-built V2 package", "PASS", v2)

    # Deterministic packaging / idempotent content identity: repacking the
    # same image+metadata yields the same TBS (and, with RFC-6979, the same
    # package bytes); two DIFFERENT valid signatures over one TBS stay one
    # content identity (spec §2.2 幂等身份).
    v1_tbs, _ = unpack(v1)
    resigned_same = resign(v1, signer)
    resigned_tbs, resigned_sig = unpack(resigned_same)
    if hashlib.sha256(v1_tbs).hexdigest() != hashlib.sha256(resigned_tbs).hexdigest():
        raise AssertionError("repack of identical inputs changed the TBS")
    results.append({
        "case": "repack_same_content_identity",
        "category": "generated",
        "expected": "PASS",
        "observed": "PASS",
        "predicate": "repacking identical inputs yields an identical SHA-256(TBS)",
        "package_sha256": hashlib.sha256(resigned_same).hexdigest(),
        "content_identity_sha256": hashlib.sha256(resigned_tbs).hexdigest(),
        "detail": "identical TBS; DER bytes identical under RFC-6979 deterministic signing",
        "note": "spec §2.2: 相同签名原文可有不同合法 DER，不得造成虚假版本冲突",
    })
    print("  ok repack_same_content_identity")

    # V1 → V2 replacement evidence (AC1/AC4): same publisher+app identity,
    # higher version, distinct content identities.
    rep_v1 = run_verifier(args.v1_package, trust, "PASS")
    rep_v2 = run_verifier(args.v2_package, trust, "PASS")
    if (rep_v1["publisher_id"], rep_v1["app_id"]) != (rep_v2["publisher_id"], rep_v2["app_id"]):
        raise AssertionError("V1/V2 identity mismatch")
    if rep_v2["app_version"] != "2.0.0" or rep_v1["app_version"] != "1.0.0":
        raise AssertionError("unexpected V1/V2 versions")
    if rep_v1["content_identity_sha256"] == rep_v2["content_identity_sha256"]:
        raise AssertionError("V1/V2 content identities must differ")
    results.append({
        "case": "v1_to_v2_traceable_replacement",
        "category": "generated",
        "expected": "PASS",
        "observed": "PASS",
        "predicate": "same publisher/app identity, version 1.0.0 -> 2.0.0, distinct content identities",
        "package_sha256": rep_v2["package_sha256"],
        "content_identity_sha256": rep_v2["content_identity_sha256"],
        "detail": (
            f"V1 identity {rep_v1['content_identity_sha256']} -> "
            f"V2 identity {rep_v2['content_identity_sha256']}; image sha256 "
            f"{rep_v1['native_file_sha256']} -> {rep_v2['native_file_sha256']}"
        ),
        "note": "Issue #6 AC1/AC4: V1/V2 在可追溯包层独立替换",
    })
    print("  ok v1_to_v2_traceable_replacement")

    # VERSION_CONTENT_CONFLICT discriminator evidence: same identity AND same
    # version, different content -> different SHA-256(TBS).  The offline
    # verifier does not hold install state; it supplies exactly the identity/
    # digest evidence a device policy needs to classify the conflict
    # (spec §3.1/§5.1).
    if rep_v1["content_identity_sha256"] == run_verifier(
            args.v2_image_as_v1_package, trust, "PASS")["content_identity_sha256"]:
        raise AssertionError("content-conflict discriminator failed")
    results.append({
        "case": "version_content_conflict_discriminator",
        "category": "generated",
        "expected": "PASS",
        "observed": "PASS",
        "predicate": "same publisher/app/version, different content identity (SHA-256(TBS))",
        "package_sha256": hashlib.sha256(v2_as_v1).hexdigest(),
        "content_identity_sha256": None,
        "detail": (
            f"V1@1.0.0 identity {rep_v1['content_identity_sha256']} vs "
            f"other-image@1.0.0 identity "
            f"{run_verifier(args.v2_image_as_v1_package, trust, 'PASS')['content_identity_sha256']}"
        ),
        "note": "spec §5.1: 同身份同版本不同摘要 -> VERSION_CONTENT_CONFLICT（设备侧分类）",
    })
    print("  ok version_content_conflict_discriminator")

    # ---------------- negatives: signature coverage ----------------
    print("[generated] signature coverage negatives")
    tampered = bytearray(v1)
    tampered[-1] ^= 0x01  # flip one payload byte inside the signed region
    check("tamper_payload", "spec §2.5 表：已签名内容被篡改（等价本地生成）",
          "SIGNATURE_INVALID", bytes(tampered))

    tampered_manifest = bytearray(v1)
    tampered_manifest[68] = 0x02  # manifest version_major 1 -> 2 (signed metadata)
    check("tamper_manifest_version", "篡改已签名 manifest 元数据（等价本地生成）",
          "SIGNATURE_INVALID", bytes(tampered_manifest))

    # Wrong-signer: manifest fingerprint still names the trusted dev key, but
    # the TBS is signed by an ephemeral in-memory key -> SIGNATURE_INVALID.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    wrong_key = ec.generate_private_key(ec.SECP256R1())  # never persisted
    tbs, _sig = unpack(v1)
    try:
        alg = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    except TypeError:
        alg = ec.ECDSA(hashes.SHA256())
    bad_sig_pkg = tbs + wrong_key.sign(tbs, alg)
    check("wrong_signer_key", "错误签名密钥（指纹仍指向可信钥）", "SIGNATURE_INVALID", bad_sig_pkg)

    # ---------------- negatives: container structure ----------------
    print("[generated] structure negatives")
    check("truncate_signature", "签名段截断（70B→69B，DER 越界）", "BAD_PACKAGE", v1[:-1])
    check("truncate_whole_package", "整包截断（短于 16B 容器头）", "BAD_PACKAGE", v1[:10])
    check("append_tail_byte", "签名段 73B 超上限", "BAD_PACKAGE", v1 + b"\x00")

    def relength(package: bytes, manifest_len: int | None = None,
                 image_len: int | None = None) -> bytes:
        out = bytearray(package)
        if manifest_len is not None:
            out[8:12] = struct.pack("<I", manifest_len)
        if image_len is not None:
            out[12:16] = struct.pack("<I", image_len)
        return bytes(out)

    check("manifest_len_159", "manifest_len != 160", "BAD_PACKAGE", relength(v1, manifest_len=159))
    check("manifest_len_zero", "manifest_len 为零（§2.2 必须正数）", "BAD_PACKAGE",
          relength(v1, manifest_len=0))
    check("image_len_below_header", "image_len < 32B 原生头", "BAD_PACKAGE",
          relength(v1, image_len=31))
    check("image_len_overflow", "image_len = 0xFFFFFFFF（溢出安全拒绝）", "BAD_PACKAGE",
          relength(v1, image_len=0xFFFFFFFF))
    check("magic_corrupted", "容器 magic 被改", "BAD_PACKAGE",
          b"\x00" + v1[1:])

    # ---------------- negatives: DER encoding ----------------
    print("[generated] DER encoding negatives")
    _, sig = unpack(v1)
    # double DER: valid signature followed by a second (empty) DER object
    check("der_second_object", "第二个 DER 对象（严格完整消费）", "BAD_PACKAGE", v1 + b"\x05\x00")
    # r=0 (out of P-256 range), 8-byte minimal signature segment
    check("der_r_zero", "DER r=0 越界", "BAD_PACKAGE",
          tbs + bytes.fromhex("3006020100020101"))
    # non-minimal DER length inside the first INTEGER (long form for short
    # content); integer value unchanged, so only the encoding rule fires
    r_pos = 2
    if sig[2] == 0x02:
        r_len = sig[3]
        r_bytes = sig[4:4 + r_len]
        new_int = bytes([0x02, 0x81, r_len]) + r_bytes  # 0x81 long form for <128
        crafted = bytes([0x30]) + bytes([len(new_int) + (len(sig) - (4 + r_len))]) + new_int + sig[4 + r_len:]
        check("der_nonminimal_length", "DER 非最短长度编码", "BAD_PACKAGE", tbs + crafted)
    else:  # defensive fallback (deterministic sigs make this unreachable)
        raise AssertionError("unexpected DER layout for the deterministic dev signature")

    # ---------------- negatives: manifest encoding (valid signature) --------
    print("[generated] manifest encoding negatives (re-signed)")
    image = v1[fmt.HEADER_LEN + fmt.MANIFEST_LEN:
               fmt.HEADER_LEN + fmt.MANIFEST_LEN + fmt.parse_manifest(
                   v1[fmt.HEADER_LEN:fmt.HEADER_LEN + fmt.MANIFEST_LEN]).native_file_len]

    def crafted_manifest_case(name: str, note: str, mutate_raw) -> None:
        raw_manifest = bytearray(v1[fmt.HEADER_LEN:fmt.HEADER_LEN + fmt.MANIFEST_LEN])
        mutate_raw(raw_manifest)
        tbs = fmt.build_container_prefix(bytes(raw_manifest), image)
        check(name, note, "BAD_PACKAGE", tbs + signer.sign(tbs))

    def pad_app_id(raw: bytearray) -> None:
        raw[29] = 0x01  # app_id text "hello-app" ends at manifest[28]; byte 29 is padding

    def nul_app_id(raw: bytearray) -> None:
        raw[24] = 0x00  # embed NUL inside "hello-app"

    crafted_manifest_case("app_id_nonzero_padding", "非零右填充（重签仍拒）", pad_app_id)
    crafted_manifest_case("app_id_embedded_nul", "标识内嵌 NUL（重签仍拒）", nul_app_id)

    # ---------------- negatives: re-signed policy violations ----------------
    print("[generated] re-signed policy negatives")

    def raw_manifest_case(name: str, note: str, mutate_raw, expect: str) -> None:
        """Mutate raw manifest bytes and re-sign: for negatives the packer
        itself refuses to emit (so only the verifier's rejection is tested)."""
        raw = bytearray(v1[fmt.HEADER_LEN:fmt.HEADER_LEN + fmt.MANIFEST_LEN])
        mutate_raw(raw)
        tbs = fmt.build_container_prefix(bytes(raw), image)
        check(name, note, expect, tbs + signer.sign(tbs))

    check("board_0x3011_signed",
          "§2.3 表：错误板型重签仍拒（本地等价 wrong_board_signed）",
          "TARGET_INCOMPATIBLE",
          resign(v1, signer, mutate_manifest=lambda m: replace_field(m, "target_board_id", 0x3011)))
    check("psram_32_signed", "32 MiB 无兼容性证据（重签仍拒）", "TARGET_INCOMPATIBLE",
          resign(v1, signer, mutate_manifest=lambda m: replace_field(m, "required_psram_mib", 32)))
    raw_manifest_case("caps_unknown_bit_signed", "未声明能力位（重签仍拒）",
                      lambda raw: struct.pack_into("<I", raw, 72, 0x5), "BAD_PACKAGE")
    raw_manifest_case("abi_manifest_header_mismatch_signed", "manifest ABI 与原生头不一致（重签仍拒）",
                      lambda raw: struct.pack_into("<I", raw, 68, 0x00020000), "BAD_PACKAGE")

    def wrong_abi_image(image: bytearray) -> bytearray:
        struct.pack_into("<I", image, 8, 0x00020000)  # native header abi_version
        return image

    check("abi_wrong_everywhere_signed",
          "§2.3 表：ABI 全量一致但非 v1 基线，重签验签通过仍须拒绝",
          "ABI_INCOMPATIBLE",
          resign(v1, signer,
                 mutate_manifest=lambda m: replace_field(m, "required_host_abi", 0x00020000),
                 mutate_image=wrong_abi_image))

    def odd_entry_image(image: bytearray) -> bytearray:
        struct.pack_into("<I", image, 20, 0x51)  # native header entry_offset -> odd
        return image

    check("entry_odd_signed", "奇数入口偏移（Thumb 约束，重签仍拒）", "BAD_PACKAGE",
          resign(v1, signer,
                 mutate_manifest=lambda m: replace_field(m, "native_entry_offset", 0x51),
                 mutate_image=odd_entry_image))

    check("exec_region_overcommit_signed", "运行驻留量超执行区（重签仍拒）", "RESOURCE_LIMIT",
          resign(v1, signer,
                 mutate_manifest=lambda m: replace_field(m, "required_exec_region_bytes", 0x300000)))

    check("unknown_publisher", "未知发行者（包内指纹无权自授信）", "PUBLISHER_UNTRUSTED",
          resign(v1, signer, mutate_manifest=lambda m: replace_field(m, "publisher_id", "other-pub")))

    # Load-transient vs residency: spec §2.3 requires native_file_len <= 可信
    # 执行区 in ADDITION to required_exec_region_bytes >= native_image_size.
    policy_dir = case_dir / "policies"
    policy_dir.mkdir(exist_ok=True)
    small_region = policy_dir / "exec-region-32.json"
    small_region.write_text(json.dumps({"exec_region_bytes": 32}), encoding="utf-8")
    check("native_file_overrides_small_region",
          "§2.3：装载临时量（native_file_len=36）超 32B 执行区，即使驻留声明=4B",
          "RESOURCE_LIMIT",
          (work / "vectors" / "golden.neapp").read_bytes(),
          policy=small_region, trust_file=work / "trust-spec.json")

    summary = case_dir / "generated-cases-results.json"
    summary.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"generated case suite: {len(results)} entries, all expectations matched")
    print(f"results -> {summary}")
    return 0


def replace_field(m: fmt.Manifest, field: str, value) -> fmt.Manifest:
    clone = fmt.Manifest(**vars(m))
    setattr(clone, field, value)
    return clone


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"GENERATED CASE FAILURE: {exc}", file=sys.stderr)
        raise SystemExit(1)
