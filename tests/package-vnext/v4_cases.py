#!/usr/bin/env python3
"""v4_cases — tooling-level positive/negative matrix for the .neapp v4
toolchain (App #36).

Drives the REAL packer/verifier CLIs (package/vnext/) against mutated and
crafted packages so every frozen rule fails closed in the shipped tools,
plus the cross-major matrix (v1/v2/v3 verifiers reject v4 packages; the
v4 verifier rejects committed v1/v2/v3 goldens).  Mutated packages are
re-signed with the PUBLIC d=1 test scalar so rejections come from the
rule under test, never from broken crypto.

All artifacts stay under the gitignored work dir.  Results JSON feeds the
run.sh evidence summary.  Offline; nothing here is device, Host-admission,
floor, or live-delivery evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKG_DIR = ROOT / "package" / "vnext"

GOLDEN_PUB = "test-publisher"
DEV_PUB = "dev-publisher"
GHOST_PUB = "ghost-publisher"
APP_ID = "line-crossing"


class CaseFailure(AssertionError):
    pass


RESULTS = []


def case(name, expected, ok, detail=""):
    RESULTS.append({"name": name, "expected": expected, "ok": bool(ok), "detail": detail})
    print(f"  {'PASS' if ok else 'FAIL'} {name}: {detail if not ok else ''}".rstrip())
    return bool(ok)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_verify(package: Path, trust: Path, expect: str):
    proc = subprocess.run(
        [sys.executable, str(PKG_DIR / "neapp_verify_v4.py"),
         "--package", str(package), "--trust", str(trust),
         "--expect", expect, "--compact"],
        capture_output=True, text=True)
    detail = proc.stdout.strip() or proc.stderr.strip()
    ok = proc.returncode == 0
    return ok, detail.splitlines()[-1] if detail else ""


def run_pack(extra_args, expect_fail_fragment=None):
    proc = subprocess.run(
        [sys.executable, str(PKG_DIR / "neapp_pack_v4.py"), *extra_args],
        capture_output=True, text=True)
    if expect_fail_fragment is not None:
        ok = proc.returncode == 2 and expect_fail_fragment in proc.stderr
        return ok, (proc.stderr.strip().splitlines() or [""])[-1]
    return proc.returncode == 0, proc.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--golden-replica", required=True, type=Path)
    parser.add_argument("--key-d1", required=True, type=Path)
    parser.add_argument("--key-d2", required=True, type=Path)
    parser.add_argument("--trust-d1", required=True, type=Path)
    parser.add_argument("--trust-both", required=True, type=Path)
    args = parser.parse_args()

    out_dir = args.work_dir / "v4-cases"
    out_dir.mkdir(parents=True, exist_ok=True)

    golden = args.golden_replica.read_bytes()
    HEADER = 16
    MANIFEST = 208
    native_len = struct.unpack_from("<I", golden, 12)[0]
    native_off = HEADER + MANIFEST
    tbs_len = 224 + native_len

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key_d1 = serialization.load_pem_private_key(Path(args.key_d1).read_bytes(), password=None)
    key_d2 = serialization.load_pem_private_key(Path(args.key_d2).read_bytes(), password=None)

    def sign_with(key, tbs: bytes) -> bytes:
        return key.sign(tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))

    def mutated_package(mutate, signer=key_d1):
        blob = bytearray(golden)
        mutate(blob)
        tbs = bytes(blob[:tbs_len])
        return tbs + sign_with(signer, tbs)

    def verify_case(name, blob: bytes, expected: str, trust=None, detail_contains=None):
        path = out_dir / f"{name.replace('.', '_')}.neapp.v4"
        path.write_bytes(blob)
        ok, detail = run_verify(path, trust or args.trust_d1, expected)
        if ok and detail_contains:
            ok = detail_contains in detail
        return case(name, expected, ok, detail)

    print("== container/length negatives")
    def m_v3_magic(blob):
        blob[0:8] = bytes.fromhex("4e45415050030000")
    verify_case("cross.v3_magic_rejected_by_v4_verifier",
                mutated_package(m_v3_magic), "BAD_PACKAGE")

    def m_manifest_len(blob):
        struct.pack_into("<I", blob, 8, 192)
    verify_case("container.manifest_len_192_rejected",
                mutated_package(m_manifest_len), "BAD_PACKAGE")

    def m_native_len_31(blob):
        struct.pack_into("<I", blob, 12, 31)
    verify_case("container.native_file_len_31_rejected",
                mutated_package(m_native_len_31), "BAD_PACKAGE")

    def m_native_len_over_cap(blob):
        struct.pack_into("<I", blob, 12, 2_097_153)
    verify_case("container.native_file_len_over_cap_rejected",
                mutated_package(m_native_len_over_cap), "BAD_PACKAGE")

    verify_case("container.truncated_rejected", golden[:-1], "BAD_PACKAGE")
    verify_case("container.trailing_byte_rejected", golden + b"\x00", "BAD_PACKAGE")

    print("== manifest negatives (re-signed so the rule under test fires)")
    def m_manifest(blob, offset, data):
        blob[HEADER + offset:HEADER + offset + len(data)] = data

    verify_case("manifest.magic_nmf3_rejected",
                mutated_package(lambda b: m_manifest(b, 0, b"NMF3")), "BAD_PACKAGE")
    verify_case("manifest.reserved_58_59_rejected",
                mutated_package(lambda b: m_manifest(b, 58, b"\x01\x00")), "BAD_PACKAGE")
    verify_case("manifest.reserved_192_207_rejected",
                mutated_package(lambda b: m_manifest(b, 207, b"\x01")), "BAD_PACKAGE")

    def m_abi_v3(blob):
        struct.pack_into("<I", blob, HEADER + 68, 0x00030000)
    verify_case("manifest.abi_0x00030000_rejected",
                mutated_package(m_abi_v3), "BAD_PACKAGE")

    def m_identifier_charset(blob):
        m_manifest(blob, 4, b"T")
    verify_case("manifest.identifier_charset_rejected",
                mutated_package(m_identifier_charset), "BAD_PACKAGE")

    def m_caps_bit10(blob):
        caps = struct.unpack_from("<I", blob, HEADER + 72)[0]
        struct.pack_into("<I", blob, HEADER + 72, caps | 0x400)
    verify_case("manifest.caps_bit10_unknown_rejected",
                mutated_package(m_caps_bit10), "BAD_PACKAGE")

    def m_bit8_missing_bit4(blob):
        caps = struct.unpack_from("<I", blob, HEADER + 72)[0]
        caps &= ~(0x10 | 0x80)
        caps |= 0x100
        struct.pack_into("<I", blob, HEADER + 72, caps)
        struct.pack_into("<I", blob, HEADER + 168, 0)
        struct.pack_into("<I", blob, HEADER + 180, 0)
    verify_case("manifest.bit8_without_bit4_rejected",
                mutated_package(m_bit8_missing_bit4), "BAD_PACKAGE",
                detail_contains="ENABLE_CONTROL")

    def m_live_max_311(blob):
        struct.pack_into("<I", blob, HEADER + 184, 311)
    verify_case("manifest.bit9_live_publish_max_311_rejected",
                mutated_package(m_live_max_311), "RESOURCE_LIMIT")

    def m_track_0(blob):
        struct.pack_into("<I", blob, HEADER + 188, 0)
    verify_case("manifest.bit9_live_track_max_0_rejected",
                mutated_package(m_track_0), "BAD_PACKAGE")

    def m_track_65(blob):
        struct.pack_into("<I", blob, HEADER + 188, 65)
    verify_case("manifest.bit9_live_track_max_65_rejected",
                mutated_package(m_track_65), "BAD_PACKAGE")

    def m_track64_live9007(blob):
        struct.pack_into("<I", blob, HEADER + 188, 64)
        struct.pack_into("<I", blob, HEADER + 184, 9007)
    verify_case("manifest.bit9_track64_below_9008_closure_rejected",
                mutated_package(m_track64_live9007), "RESOURCE_LIMIT",
                detail_contains="closure")

    def m_no_bit9_live312(blob):
        caps = struct.unpack_from("<I", blob, HEADER + 72)[0]
        struct.pack_into("<I", blob, HEADER + 72, caps & ~0x200)
    verify_case("manifest.no_bit9_with_live_publish_max_rejected",
                mutated_package(m_no_bit9_live312), "BAD_PACKAGE")

    def m_profile_2(blob):
        struct.pack_into("<I", blob, HEADER + 160, 2)
    verify_case("manifest.v3_profile_2_rejected",
                mutated_package(m_profile_2), "BAD_PACKAGE")

    def m_event_without_bit2(blob):
        caps = struct.unpack_from("<I", blob, HEADER + 72)[0]
        struct.pack_into("<I", blob, HEADER + 72, caps & ~0x4)
    verify_case("manifest.event_max_without_bit2_rejected",
                mutated_package(m_event_without_bit2), "BAD_PACKAGE")

    def m_control_31(blob):
        struct.pack_into("<I", blob, HEADER + 176, 31)
    verify_case("manifest.control_max_31_rejected",
                mutated_package(m_control_31), "RESOURCE_LIMIT")

    print("== native negatives")
    def m_native(blob, offset, data):
        blob[native_off + offset:native_off + offset + len(data)] = data

    def m_native_crc(blob):
        blob[tbs_len - 1] ^= 0x01
    verify_case("native.crc_mismatch_rejected",
                mutated_package(m_native_crc), "BAD_PACKAGE")

    def m_native_abi_v3(blob):
        struct.pack_into("<I", blob, native_off + 8, 0x00030000)
    verify_case("native.abi_0x00030000_rejected",
                mutated_package(m_native_abi_v3), "BAD_PACKAGE")

    def m_native_reserved(blob):
        struct.pack_into("<I", blob, native_off + 24, 1)
    verify_case("native.reserved0_nonzero_rejected",
                mutated_package(m_native_reserved), "BAD_PACKAGE")

    def m_native_format(blob):
        struct.pack_into("<H", blob, native_off + 6, 2)
    verify_case("native.format_version_2_rejected",
                mutated_package(m_native_format), "BAD_PACKAGE")

    def m_native_header_size(blob):
        struct.pack_into("<H", blob, native_off + 4, 31)
    verify_case("native.header_size_31_rejected",
                mutated_package(m_native_header_size), "BAD_PACKAGE")

    def m_odd_entry(blob):
        struct.pack_into("<I", blob, HEADER + 88, 65)
        struct.pack_into("<I", blob, native_off + 20, 65)
    verify_case("native.odd_thumb_entry_rejected",
                mutated_package(m_odd_entry), "BAD_PACKAGE")

    print("== trust and signature negatives")
    def m_fingerprint_to_d2(blob):
        from cryptography.hazmat.primitives import serialization
        d2_spki = key_d2.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        blob[HEADER + 128:HEADER + 160] = hashlib.sha256(d2_spki).digest()
    verify_case("trust.fingerprint_mismatch_rejected",
                mutated_package(m_fingerprint_to_d2, signer=key_d2), "PUBLISHER_UNTRUSTED",
                detail_contains="does not match the trusted key")

    def m_ghost(blob):
        blob[HEADER + 4:HEADER + 20] = GHOST_PUB.encode().ljust(16, b"\x00")
    ghost_pkg = mutated_package(m_ghost)
    verify_case("trust.unknown_publisher_rejected", ghost_pkg, "PUBLISHER_UNTRUSTED",
                trust=args.trust_both)
    ok, detail = run_verify(
        _write(out_dir, "trust.unknown_publisher_passes_with_local_trust.neapp.v4",
               ghost_pkg), _ghost_trust(out_dir, key_d1), "PASS")
    case("trust.local_trust_mapping_decides", "PASS", ok, detail)

    def m_tbs_no_resign(blob):
        blob[HEADER + 184] ^= 0x01
    flipped = bytearray(golden)
    flipped[HEADER + 184] ^= 0x01
    verify_case("sig.tbs_mutation_without_resign_rejected",
                bytes(flipped), "SIGNATURE_INVALID")

    verify_case("sig.signature_flip_rejected",
                golden[:-1] + bytes([golden[-1] ^ 0x01]), "SIGNATURE_INVALID")

    print("== packer fail-closed refusals")
    base_pack = ["--image", str(args.image), "--key", str(args.key_d1),
                 "--publisher-id", GOLDEN_PUB, "--app-id", APP_ID,
                 "--version", "9.9.9", "--sidecar", "none",
                 "--out", str(out_dir / "refused.neapp.v4")]

    refusals = (
        ("pack.caps_bit10_refused",
         base_pack + ["--host-caps", "0x400"], "unknown bits"),
        ("pack.bit8_without_bit4_refused",
         base_pack + ["--host-caps", "0x160", "--control-max", "256"], "ENABLE_CONTROL"),
        ("pack.bit9_without_bit5_refused",
         base_pack + ["--host-caps", "0x200", "--live-publish-max", "312",
                      "--live-track-max", "1"], "session_lifecycle"),
        ("pack.bit9_track64_below_closure_refused",
         base_pack + ["--host-caps", "0x220", "--control-max", "0",
                      "--live-track-max", "64",
                      "--live-publish-max", "9007"], "9008"),
        ("pack.live_quota_without_bit9_refused",
         base_pack + ["--host-caps", "0x63", "--live-publish-max", "312",
                      "--live-track-max", "1"], "must be 0"),
        ("pack.board_override_refused",
         base_pack + ["--host-caps", "0x63", "--target-board-id", "0x3011"], "board"),
        ("pack.psram_override_refused",
         base_pack + ["--host-caps", "0x63", "--psram-mib", "128"], "PSRAM"),
    )
    for name, pack_args, fragment in refusals:
        ok, detail = run_pack(pack_args, expect_fail_fragment=fragment)
        case(name, "refused rc=2", ok, detail)

    def craft_image(abi=0x00040000, target=0x93E00000, crc=None, payload=b"\x00\x20\x70\x47"):
        body = struct.pack("<IHHIIIIII", 0x3141454E, 32, 1, abi, target,
                           len(payload), 0, 0,
                           crc if crc is not None else _crc32(payload))
        return body + payload

    def _crc32(payload):
        import zlib
        return zlib.crc32(payload) & 0xFFFFFFFF

    bad_img = out_dir / "native-abi-v3.bin"
    bad_img.write_bytes(craft_image(abi=0x00030000))
    ok, detail = run_pack(base_pack + ["--image", str(bad_img)], expect_fail_fragment="0x00030000")
    case("pack.v3_abi_image_refused", "refused rc=2", ok, detail)

    bad_img = out_dir / "native-bad-target.bin"
    bad_img.write_bytes(craft_image(target=0x60000000))
    ok, detail = run_pack(base_pack + ["--image", str(bad_img)], expect_fail_fragment="target_addr")
    case("pack.wrong_target_image_refused", "refused rc=2", ok, detail)

    bad_img = out_dir / "native-bad-crc.bin"
    bad_img.write_bytes(craft_image(crc=0xDEADBEEF))
    ok, detail = run_pack(base_pack + ["--image", str(bad_img)], expect_fail_fragment="CRC-32")
    case("pack.broken_crc_image_refused", "refused rc=2", ok, detail)

    strict_policy = out_dir / "policy-no-bit9.json"
    strict_policy.write_text(json.dumps({"host_caps": 0x1FF}))
    ok, detail = run_pack(base_pack + ["--host-caps", "0x3FF",
                                       "--event-max", "2048", "--state-quota", "4096",
                                       "--report-max", "6144", "--control-max", "256",
                                       "--snapshot-max", "1024",
                                       "--live-publish-max", "1168",
                                       "--live-track-max", "8",
                                       "--host-policy", str(strict_policy)],
                          expect_fail_fragment="capability bits")
    case("admission.host_without_bit9_refuses_emit", "refused rc=2", ok, detail)

    tight_live = out_dir / "policy-tight-live.json"
    tight_live.write_text(json.dumps({"host_caps": 0x3FF, "live_capacity_bytes": 1000}))
    ok, detail = run_pack(base_pack + ["--host-caps", "0x3FF",
                                       "--event-max", "2048", "--state-quota", "4096",
                                       "--report-max", "6144", "--control-max", "256",
                                       "--snapshot-max", "1024",
                                       "--live-publish-max", "1168",
                                       "--live-track-max", "8",
                                       "--host-policy", str(tight_live)],
                          expect_fail_fragment="live")
    case("admission.live_capacity_below_declaration_refuses_emit", "refused rc=2", ok, detail)

    print("== cross-major matrix (unmodified old tools)")
    old_verifiers = (
        ("old.v1_verifier_rejects_v4_package", ROOT / "package" / "neapp_verify.py"),
        ("old.v2_verifier_rejects_v4_package", ROOT / "package" / "neapp_verify_v2.py"),
        ("old.v3_verifier_rejects_v4_package", ROOT / "package" / "neapp_verify_v3.py"),
    )
    for name, verifier in old_verifiers:
        proc = subprocess.run(
            [sys.executable, str(verifier), "--package", str(args.golden_replica),
             "--trust", str(args.trust_d1), "--expect", "BAD_PACKAGE", "--compact"],
            capture_output=True, text=True)
        case(name, "BAD_PACKAGE", proc.returncode == 0,
             proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else proc.stderr.strip())

    committed_old_goldens = (
        ("new.v4_verifier_rejects_committed_v3_golden",
         ROOT / "docs" / "evidence" / "spec-v3" / "golden.neapp.v3"),
        ("new.v4_verifier_rejects_committed_v2_golden",
         ROOT / "docs" / "evidence" / "spec-v2" / "golden.neapp.v2"),
        ("new.v4_verifier_rejects_committed_v1_golden",
         ROOT / "docs" / "evidence" / "spec-v2" / "v1-golden.neapp"),
    )
    for name, path in committed_old_goldens:
        ok, detail = run_verify(path, args.trust_d1, "BAD_PACKAGE")
        case(name, "BAD_PACKAGE", ok, detail)

    (out_dir / "v4-cases-results.json").write_text(
        json.dumps(RESULTS, indent=2) + "\n", encoding="utf-8")

    failed = [r for r in RESULTS if not r["ok"]]
    print(f"v4_cases: {len(RESULTS) - len(failed)}/{len(RESULTS)} cases passed")
    return 1 if failed else 0


def _write(path: Path, name: str, blob: bytes) -> Path:
    target = path / name
    target.write_bytes(blob)
    return target


def _ghost_trust(out_dir: Path, key_d1) -> Path:
    from cryptography.hazmat.primitives import serialization
    spki = key_d1.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    trust = {
        "version": 1,
        "comment": "NON-PRODUCTION local mapping proving trust is local configuration, "
                   "never package content",
        "publishers": {
            GHOST_PUB: {
                "spki_der_hex": spki.hex(),
                "spki_sha256": hashlib.sha256(spki).hexdigest(),
            },
        },
    }
    path = out_dir / "trust-ghost.json"
    path.write_text(json.dumps(trust, indent=2) + "\n", encoding="utf-8")
    return path


if __name__ == "__main__":
    raise SystemExit(main())
