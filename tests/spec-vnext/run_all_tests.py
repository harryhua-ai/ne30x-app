#!/usr/bin/env python3
"""run_all_tests — App #36 spec-vnext vector suite (offline, stdlib-only).

Independent positive/negative matrix for the A-frozen v4 byte contract
(Host #104 comments 6258534821 / 6258601629 / 6258637748), implemented in
v4lib.py from scratch.  Cross-checks the App #36 tooling output as an
independent consumer of the same bytes: the golden v4 package built here
must be byte-identical to the packer's d=1 replica (byte-identity is
asserted by tests/package-vnext/run.sh against the evidence written here).

Evidence is written deterministically to
docs/evidence/package-vnext/spec/.  Re-runs must leave it byte-identical.

BOUNDARY: PASS here is offline vector evidence only — not Host admission,
native runtime admission, device capacity, floor/Enable semantics, live
delivery, or ARM build proof.
"""

import hashlib
import json
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import v4lib as V

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EVIDENCE_DIR = os.path.join(ROOT, "docs", "evidence", "package-vnext", "spec")

D_GOLDEN = 1
D_OTHER = 2
SPKI_GOLDEN = V.spki_der_for_scalar(D_GOLDEN)
SPKI_OTHER = V.spki_der_for_scalar(D_OTHER)

SPKI_SHA_HEX = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
GOLDEN_NATIVE_SHA_HEX = "845e09288e0f1d876832dcda553580c6aa64ef17f08b9e529550aefa4db12cd1"
GOLDEN_NATIVE_CRC = 0x990997A2
GOLDEN_TBS_SHA_HEX = "581e3ae98afef313de0bdf7d8bc85c2a36585a7c28e609dea183a558e599e095"
GOLDEN_DER_HEX = ("3044022072d7b4a00660b66c7df38bff0c1dcab29c877462ed66d34ce18f7dda6a2f5d9"
                  "302205ef31b0cad9d64bbef71df47e53177de80f69218834e0971b496b8b1eb593aae")
GOLDEN_PKG_SHA_HEX = "e6a7fedc8cda9f3900311bc077de2a3ea79002d10b23241d1690c9e28ee46e0e"
GOLDEN_ENABLE_SET_SHA_HEX = "ce0976a6f3ce0ce0e3e55592b08d57c3b1e0701d43e31af00a539c8f87d49a98"
GOLDEN_ENABLE_RECEIPT_SHA_HEX = "63db6108b97b719f833cc55c76b8e4eff1a7ce929598823a2c57604f1bc341ed"
GOLDEN_LVN4_EVENT_BATCH_SHA_HEX = "555096fc4935d5cd89ebc5d81cee1a92a30f0312d9d86d7fa4b4a2ccbed360c3"
GOLDEN_LVN4_TRACKS_SHA_HEX = "85bb6baa722e4766b9b9c95e13fe90fbee79e673376a4cd97a90f2cc54ffc6d6"

P = V.GOLDEN_IMAGE_PARAMS

RESULTS = []


def vector(name, expected, ok, detail="", evidence=None):
    RESULTS.append({"name": name, "expected": expected, "ok": bool(ok),
                    "detail": detail, "evidence": evidence or {}})
    return bool(ok)


def expect_accept(name, fn, detail="", evidence=None):
    try:
        fn()
    except V.SpecViolation as e:
        return vector(name, "ACCEPT", False, f"rejected {e.reason}: {e.detail}", evidence)
    return vector(name, "ACCEPT", True, detail, evidence)


def expect_rejection(name, fn, expected_reason, detail="", detail_contains=None):
    try:
        fn()
    except V.SpecViolation as e:
        if e.reason != expected_reason:
            return vector(name, expected_reason, False,
                          f"rejected with {e.reason} instead: {e.detail}")
        if detail_contains and detail_contains not in e.detail:
            return vector(name, expected_reason, False,
                          f"rejected as {e.reason} but detail missing {detail_contains!r}: {e.detail}")
        return vector(name, expected_reason, True, detail or e.detail)
    return vector(name, expected_reason, False, "accepted, expected rejection")


def golden_native():
    return V.build_native_image_v4()


def golden_manifest(native, spki_sha256):
    return V.build_manifest_v4(
        publisher_id=P["publisher_id"], app_id=P["app_id"], version=P["version"],
        caps=P["caps"], event_max=P["event_max"], state_quota=P["state_quota"],
        report_max=P["report_max"], control_max=P["control_max"],
        snapshot_max=P["snapshot_max"], live_publish_max=P["live_publish_max"],
        live_track_max=P["live_track_max"], native=native, spki_sha256=spki_sha256)


def golden_tbs(native=None, spki_sha256=None):
    native = native if native is not None else golden_native()
    spki_sha256 = spki_sha256 if spki_sha256 is not None else V.sha256(SPKI_GOLDEN)
    manifest = golden_manifest(native, spki_sha256)
    return V.build_container_prefix_v4(manifest, native)


TRUST = {P["publisher_id"]: SPKI_GOLDEN}


def sha_hex(data):
    return hashlib.sha256(data).hexdigest()


def main():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    failures = 0

    native = golden_native()
    manifest = golden_manifest(native, V.sha256(SPKI_GOLDEN))
    tbs = V.build_container_prefix_v4(manifest, native)
    der = V.sign_der(D_GOLDEN, tbs)
    package = tbs + der

    vector("golden.spki_sha256", SPKI_SHA_HEX, sha_hex(SPKI_GOLDEN) == SPKI_SHA_HEX,
           "PUBLIC non-production d=1 test signer (same scalar as the v1/v2/v3 goldens)")
    vector("golden.native_sha256", GOLDEN_NATIVE_SHA_HEX,
           sha_hex(native) == GOLDEN_NATIVE_SHA_HEX,
           f"{len(native)}B controlled v4 image (64B function table + Thumb stub)")
    vector("golden.native_crc32", f"{GOLDEN_NATIVE_CRC:#010x}",
           f"{V.parse_native_header_v4(native)['crc32']:#010x}" == f"{GOLDEN_NATIVE_CRC:#010x}")
    vector("golden.tbs_sha256", GOLDEN_TBS_SHA_HEX, sha_hex(tbs) == GOLDEN_TBS_SHA_HEX,
           f"TBS = file[0:{len(tbs)}] (224 + native_file_len); key-independent")
    vector("golden.der", GOLDEN_DER_HEX, der.hex() == GOLDEN_DER_HEX,
           f"strict-DER RFC-6979 d=1 over SHA-256(TBS), {len(der)}B")
    vector("golden.package_sha256", GOLDEN_PKG_SHA_HEX, sha_hex(package) == GOLDEN_PKG_SHA_HEX,
           f"{len(package)}B = {len(tbs)}B TBS + {len(der)}B DER")
    report = V.verify_package_v4(package, TRUST)
    vector("golden.verify_accept", "ACCEPT", report is not None and report["result"] == "PASS")

    if V.openssl_available():
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            vector("golden.openssl_cross_verify", "Verified OK",
                   V.openssl_verify(SPKI_GOLDEN, tbs, der, td),
                   "OpenSSL CLI verifies the pure-Python RFC-6979 signature over the exact TBS")
    else:
        vector("golden.openssl_cross_verify", "Verified OK", True,
               "SKIP openssl CLI unavailable", {})

    cryptography_available = True
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.derive_private_key(D_GOLDEN, ec.SECP256R1())
        crypto_der = key.sign(tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        vector("cross.rfc6979_cryptography_der_identity", GOLDEN_DER_HEX,
               crypto_der.hex() == GOLDEN_DER_HEX,
               "the cryptography-library deterministic signer and the pure-Python RFC-6979 "
               "produce the same k and therefore byte-identical DER for d=1")
    except ImportError:
        cryptography_available = False
        vector("cross.rfc6979_cryptography_der_identity", GOLDEN_DER_HEX, True,
               "SKIP cryptography package unavailable (stdlib-only environment)")

    def tampered_tbs_sig():
        bad = bytearray(tbs)
        bad[-1] ^= 0x01
        if not V.ecdsa_verify(SPKI_GOLDEN, bytes(bad), der):
            raise V.SpecViolation("SIGNATURE_INVALID", "signature does not verify over a flipped TBS byte")
    expect_rejection("sig.tbs_flip_rejected", tampered_tbs_sig, "SIGNATURE_INVALID")

    def wrong_key_sig():
        wrong = V.sign_der(D_OTHER, tbs)
        V.verify_package_v4(tbs + wrong, TRUST)
    expect_rejection("sig.wrong_key_rejected", wrong_key_sig, "SIGNATURE_INVALID")

    container_cases = [
        ("container.v3_magic_rejected",
         V.CONTAINER_MAGIC_V3 + tbs[8:], "BAD_PACKAGE"),
        ("container.v2_magic_rejected",
         V.CONTAINER_MAGIC_V2 + tbs[8:], "BAD_PACKAGE"),
        ("container.v1_magic_rejected",
         V.CONTAINER_MAGIC_V1 + tbs[8:], "BAD_PACKAGE"),
        ("container.random_magic_rejected",
         bytes.fromhex("4e45415050090000") + tbs[8:], "BAD_PACKAGE"),
    ]
    for name, blob, reason in container_cases:
        expect_rejection(name, lambda b=blob: V.verify_package_v4(b, TRUST), reason)

    try:
        v3_golden_path = os.path.join(ROOT, "docs", "evidence", "spec-v3", "golden.neapp.v3")
        with open(v3_golden_path, "rb") as f:
            v3_golden = f.read()
        expect_rejection(
            "container.committed_v3_golden_rejected",
            lambda: V.verify_package_v4(v3_golden, TRUST), "BAD_PACKAGE",
            detail=f"committed #19 v3 golden ({len(v3_golden)}B) is foreign input to v4")
    except OSError:
        vector("container.committed_v3_golden_rejected", "BAD_PACKAGE", False,
               "committed v3 golden not found (unexpected in-repo)")

    def bad_manifest_len():
        blob = bytearray(tbs)
        struct.pack_into("<I", blob, 8, 192)
        V.verify_package_v4(bytes(blob) + der, TRUST)
    expect_rejection("container.manifest_len_192_rejected", bad_manifest_len, "BAD_PACKAGE")

    def nmf3_manifest_in_v4():
        blob = bytearray(tbs)
        blob[16:20] = b"NMF3"
        V.parse_manifest_v4(bytes(blob[16:16 + V.MANIFEST_LEN_V4]))
    expect_rejection("manifest.nmf3_in_v4_rejected", nmf3_manifest_in_v4, "BAD_PACKAGE")

    def reserved_58():
        raw = bytearray(manifest)
        raw[58] = 1
        V.parse_manifest_v4(bytes(raw))
    expect_rejection("manifest.reserved_58_59_rejected", reserved_58, "BAD_PACKAGE")

    def reserved_192():
        raw = bytearray(manifest)
        raw[207] = 1
        V.parse_manifest_v4(bytes(raw))
    expect_rejection("manifest.reserved_192_207_rejected", reserved_192, "BAD_PACKAGE")

    def abi_v3_in_manifest():
        raw = bytearray(manifest)
        struct.pack_into("<I", raw, 68, V.ABI_V3)
        V.parse_manifest_v4(bytes(raw))
    expect_rejection("manifest.abi_0x00030000_rejected", abi_v3_in_manifest, "ABI_INCOMPATIBLE")

    def bad_identifier():
        raw = bytearray(manifest)
        raw[4] = 0x41
        V.parse_manifest_v4(bytes(raw))
    expect_rejection("manifest.identifier_charset_rejected", bad_identifier, "BAD_PACKAGE")

    def embedded_nul():
        raw = bytearray(manifest)
        raw[20:28] = b"lineCro\x00" + manifest[28:52]
        V.parse_manifest_v4(bytes(raw))
    expect_rejection("manifest.identifier_embedded_nul_rejected", embedded_nul, "BAD_PACKAGE")

    def caps_bit10():
        m = golden_manifest(native, V.sha256(SPKI_GOLDEN))
        raw = bytearray(m)
        struct.pack_into("<I", raw, 72, 0x400)
        t = V.build_container_prefix_v4(bytes(raw), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("caps.bit10_unknown_rejected", caps_bit10, "BAD_PACKAGE")

    def caps_bit8_without_bit4():
        caps = (P["caps"] & ~V.CAP_APP_STATE & ~V.CAP_BUSINESS_SNAPSHOT) | V.CAP_ENABLE_CONTROL
        raw = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", raw, 72, caps)
        t = V.build_container_prefix_v4(bytes(raw), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("caps.bit8_without_bit4_rejected", caps_bit8_without_bit4, "BAD_PACKAGE")

    def caps_bit9_without_bit5():
        caps = (P["caps"] & ~V.CAP_SESSION_LIFECYCLE & ~V.CAP_CONTROL_RECEIVE
                & ~V.CAP_APP_STATE) | V.CAP_LIVE_PUBLISH
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 72, caps)
        struct.pack_into("<I", m, 164, 0)
        struct.pack_into("<I", m, 168, 0)
        struct.pack_into("<I", m, 176, 0)
        struct.pack_into("<I", m, 180, 0)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("caps.bit9_without_bit5_rejected", caps_bit9_without_bit5, "BAD_PACKAGE")

    def caps_bit9_live_max_311():
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 184, 311)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("caps.bit9_live_publish_max_311_rejected",
                     caps_bit9_live_max_311, "RESOURCE_LIMIT")

    def caps_bit9_track_max_0():
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 188, 0)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("caps.bit9_live_track_max_0_rejected", caps_bit9_track_max_0, "BAD_PACKAGE")

    def caps_bit9_track_max_65():
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 188, 65)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("caps.bit9_live_track_max_65_rejected", caps_bit9_track_max_65, "BAD_PACKAGE")

    def bit9_track64_closure_9007():
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 188, 64)
        struct.pack_into("<I", m, 184, 9007)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("caps.bit9_track64_needs_9008_rejected",
                     bit9_track64_closure_9007, "RESOURCE_LIMIT",
                     detail="live_track_max=64 requires live_publish_max >= 9008 (F9 closure)")

    def bit9_track64_closure_9008_accepted():
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 188, 64)
        struct.pack_into("<I", m, 184, 9008)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_accept("caps.bit9_track64_9008_accepted", bit9_track64_closure_9008_accepted,
                  detail="live_track_max=64 with exactly the 9008B closure bound passes")

    def no_bit9_live_quotas_nonzero():
        caps = P["caps"] & ~V.CAP_LIVE_PUBLISH
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 72, caps)
        struct.pack_into("<I", m, 184, 312)
        struct.pack_into("<I", m, 188, 4)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("caps.no_bit9_live_quotas_must_be_zero_rejected",
                     no_bit9_live_quotas_nonzero, "BAD_PACKAGE")

    def profile_2():
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 160, 2)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("profile.v3_profile_2_rejected", profile_2, "BAD_PACKAGE")

    def event_quota_without_bit2():
        caps = P["caps"] & ~V.CAP_AI_EVENTS
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 72, caps)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("quota.event_max_without_bit2_rejected",
                     event_quota_without_bit2, "BAD_PACKAGE")

    def control_wire_min():
        m = bytearray(golden_manifest(native, V.sha256(SPKI_GOLDEN)))
        struct.pack_into("<I", m, 176, 31)
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("quota.control_max_31_rejected", control_wire_min, "RESOURCE_LIMIT")

    def unknown_publisher():
        V.verify_package_v4(package, {})
    expect_rejection("trust.unknown_publisher_rejected", unknown_publisher, "PUBLISHER_UNTRUSTED")

    def mismatched_fingerprint():
        m = bytearray(golden_manifest(native, V.sha256(SPKI_OTHER)))
        t = V.build_container_prefix_v4(bytes(m), native)
        V.verify_package_v4(t + V.sign_der(D_GOLDEN, t), TRUST)
    expect_rejection("trust.fingerprint_mismatch_rejected",
                     mismatched_fingerprint, "PUBLISHER_UNTRUSTED",
                     detail="package-carried/foreign key never self-trusts via the manifest field")

    def der_trailing_byte():
        blob = tbs + der + b"\x00"
        V.verify_package_v4(blob, TRUST)
    expect_rejection("der.trailing_byte_rejected", der_trailing_byte, "BAD_PACKAGE")

    def der_truncated():
        blob = tbs + der[:-1]
        V.verify_package_v4(blob, TRUST)
    expect_rejection("der.truncated_rejected", der_truncated, "BAD_PACKAGE")

    def der_nonminimal_int():
        r, s = V.decode_strict_der_sig(der)
        body = b"\x02\x21\x00" + r.to_bytes(32, "big") + V._der_int_encode(s)
        bad_sig = b"\x30" + bytes([len(body)]) + body
        V.verify_package_v4(tbs + bad_sig, TRUST)
    expect_rejection("der.nonminimal_integer_rejected", der_nonminimal_int, "BAD_PACKAGE")

    def der_negative_int():
        bad = bytearray(der)
        bad[4] |= 0x80
        V.verify_package_v4(tbs + bytes(bad), TRUST)
    expect_rejection("der.negative_integer_rejected", der_negative_int, "BAD_PACKAGE")

    def native_short():
        blob = V.build_container_prefix_v4(manifest, native[:31])
        V.verify_package_v4(blob + V.sign_der(D_GOLDEN, blob), TRUST)
    expect_rejection("native.native_file_len_31_rejected", native_short, "BAD_PACKAGE")

    def native_over_cap():
        blob = bytearray(V.build_container_prefix_v4(manifest, native))
        struct.pack_into("<I", blob, 12, V.MAX_NATIVE_FILE_LEN + 1)
        V.verify_package_v4(bytes(blob) + der, TRUST)
    expect_rejection("native.native_file_len_over_cap_rejected",
                     native_over_cap, "RESOURCE_LIMIT")

    def native_crc_flip():
        bad_native = bytearray(native)
        bad_native[-1] ^= 0x01
        blob = V.build_container_prefix_v4(manifest, bytes(bad_native))
        V.verify_package_v4(blob + V.sign_der(D_GOLDEN, blob), TRUST)
    expect_rejection("native.crc_mismatch_rejected", native_crc_flip, "BAD_PACKAGE")

    def native_abi_v3():
        bad_native = bytearray(native)
        struct.pack_into("<I", bad_native, 8, V.ABI_V3)
        blob = V.build_container_prefix_v4(manifest, bytes(bad_native))
        V.verify_package_v4(blob + V.sign_der(D_GOLDEN, blob), TRUST)
    expect_rejection("native.abi_0x00030000_rejected", native_abi_v3, "ABI_INCOMPATIBLE")

    def native_odd_entry():
        bad_native = bytearray(native)
        struct.pack_into("<I", bad_native, 24, 65)
        blob = V.build_container_prefix_v4(manifest, bytes(bad_native))
        V.verify_package_v4(blob + V.sign_der(D_GOLDEN, blob), TRUST)
    expect_rejection("native.odd_entry_rejected", native_odd_entry, "BAD_PACKAGE")

    table = V.build_function_table_v4()
    vector("table.default_14_thumb_pointers", "ACCEPT",
           len(V.parse_function_table_v4(table)) == 14)

    def table_v3_size():
        v3_like = bytearray(table[:V.V3_TABLE_SIZE])
        struct.pack_into("<I", v3_like, 0, V.V3_TABLE_SIZE)
        struct.pack_into("<I", v3_like, 4, V.ABI_V3)
        V.parse_function_table_v4(bytes(v3_like))
    expect_rejection("table.v3_60B_table_rejected", table_v3_size, "ABI_INCOMPATIBLE",
                     detail="a 60B v3 table (or any non-64B table) is foreign input")

    def table_wrong_abi():
        raw = bytearray(table)
        struct.pack_into("<I", raw, 4, V.ABI_V3)
        V.parse_function_table_v4(bytes(raw))
    expect_rejection("table.abi_0x00030000_rejected", table_wrong_abi, "ABI_INCOMPATIBLE")

    def table_non_thumb():
        raw = bytearray(table)
        struct.pack_into("<I", raw, 60, 0x93E00064)
        V.parse_function_table_v4(bytes(raw))
    expect_rejection("table.non_thumb_live_publish_rejected", table_non_thumb, "ABI_INCOMPATIBLE")

    def table_null_pointer():
        raw = bytearray(table)
        struct.pack_into("<I", raw, 8, 0)
        V.parse_function_table_v4(bytes(raw))
    expect_rejection("table.null_pointer_rejected", table_null_pointer, "ABI_INCOMPATIBLE")

    policy_full = {"host_caps": V.CAPS_KNOWN_MASK_V4, "live_capacity_bytes": 16384,
                   "live_capacity_tracks": 64}
    report = V.verify_package_v4(package, TRUST, policy=policy_full)
    vector("admission.full_caps_accepted", "ACCEPT", report is not None)

    def admission_caps_missing_bit9():
        V.verify_package_v4(package, TRUST,
                            policy={**policy_full, "host_caps": 0x1FF})
    expect_rejection("admission.host_without_bit9_rejected", admission_caps_missing_bit9,
                     "ABI_INCOMPATIBLE",
                     detail="missing Host implementation means UNAVAILABLE, never downgraded")

    def admission_live_capacity():
        V.verify_package_v4(package, TRUST,
                            policy={**policy_full, "live_capacity_bytes": 1000})
    expect_rejection("admission.live_capacity_refused_whole", admission_live_capacity,
                     "RESOURCE_LIMIT")

    def admission_board():
        V.verify_package_v4(package, TRUST,
                            policy={**policy_full, "target_board_id": 0x00003011})
    expect_rejection("admission.board_mismatch_rejected", admission_board, "TARGET_INCOMPATIBLE")

    intrinsic = V.verify_package_v4(package, TRUST)
    vector("intrinsic.tier_no_policy_accepted", "ACCEPT", intrinsic is not None,
           "the intrinsic tier alone never claims Host admission")

    es = V.build_enable_set(7, 42, 9, 5, V.DESIRED_ENABLED)
    vector("nfc4.enable_set_sha256", GOLDEN_ENABLE_SET_SHA_HEX,
           sha_hex(es) == GOLDEN_ENABLE_SET_SHA_HEX,
           "48B ENABLE_SET: 32B NFC4 header + ENB1 payload (desired Enabled, expected rev 5)")
    parsed = V.parse_enable_set(es)
    vector("nfc4.enable_set_roundtrip", "ACCEPT",
           parsed["desired_state"] == V.DESIRED_ENABLED
           and parsed["expected_state_revision"] == 5)

    er = V.build_enable_receipt(7, 42, 9, 6, V.STATUS_APPLIED, V.EFFECTIVE_ENABLED, 6)
    vector("nfc4.enable_receipt_sha256", GOLDEN_ENABLE_RECEIPT_SHA_HEX,
           sha_hex(er) == GOLDEN_ENABLE_RECEIPT_SHA_HEX,
           "48B ENR1 receipt: status APPLIED, readback revision == header state_revision")
    parsed_r = V.parse_enable_receipt(er)
    vector("nfc4.enable_receipt_roundtrip", "ACCEPT",
           parsed_r["status"] == V.STATUS_APPLIED
           and parsed_r["effective_state"] == V.EFFECTIVE_ENABLED)

    expect_rejection("nfc4.nfc3_magic_rejected_in_v4_parser",
                     lambda: V.parse_nfc4_header(
                         bytes(V.build_nfc4_header(2, 32, 1, 1, 1, 0, 0)).replace(b"NFC4", b"NFC3")),
                     "BAD_PACKAGE",
                     detail="a v3 NFC3 message is foreign input and must never be reinterpreted as v4")

    def enable_set_wrong_len():
        bad = es[:-1]
        struct.pack_into("<I", bytearray(bad), 8, 47)
        V.parse_enable_set(bytes(bad))
    expect_rejection("nfc4.enable_set_47B_rejected", enable_set_wrong_len, "BAD_PACKAGE")

    def enable_set_zero_session():
        V.parse_enable_set(V.build_enable_set(0, 42, 9, 5, V.DESIRED_ENABLED))
    expect_rejection("nfc4.enable_set_zero_session_rejected",
                     enable_set_zero_session, "BAD_PACKAGE")

    def enable_set_zero_config_gen():
        V.parse_enable_set(V.build_enable_set(7, 42, 0, 5, V.DESIRED_ENABLED))
    expect_rejection("nfc4.enable_set_zero_config_generation_rejected",
                     enable_set_zero_config_gen, "BAD_PACKAGE")

    def enable_set_nonzero_state_revision():
        raw = bytearray(es)
        struct.pack_into("<I", raw, 24, 3)
        V.parse_enable_set(bytes(raw))
    expect_rejection("nfc4.enable_set_state_revision_nonzero_rejected",
                     enable_set_nonzero_state_revision, "BAD_PACKAGE")

    def enable_set_flags_nonzero():
        raw = bytearray(es)
        struct.pack_into("<I", raw, 28, 1)
        V.parse_enable_set(bytes(raw))
    expect_rejection("nfc4.enable_set_flags_nonzero_rejected",
                     enable_set_flags_nonzero, "BAD_PACKAGE")

    def enable_set_bad_payload_magic():
        raw = bytearray(es)
        raw[32:36] = b"ENB2"
        V.parse_enable_set(bytes(raw))
    expect_rejection("nfc4.enable_set_bad_enb1_rejected", enable_set_bad_payload_magic,
                     "BAD_PACKAGE")

    def enable_set_desired_0():
        V.build_enable_set(7, 42, 9, 5, 0)
    expect_rejection("nfc4.enable_set_desired_0_rejected", enable_set_desired_0, "BAD_PACKAGE")

    def enable_set_desired_3():
        V.build_enable_set(7, 42, 9, 5, 3)
    expect_rejection("nfc4.enable_set_desired_3_rejected", enable_set_desired_3, "BAD_PACKAGE")

    def enable_set_reserved_nonzero():
        raw = bytearray(es)
        struct.pack_into("<I", raw, 44, 1)
        V.parse_enable_set(bytes(raw))
    expect_rejection("nfc4.enable_set_reserved_nonzero_rejected",
                     enable_set_reserved_nonzero, "BAD_PACKAGE")

    def receipt_bad_enr1():
        raw = bytearray(er)
        raw[32:36] = b"ENR2"
        V.parse_enable_receipt(bytes(raw))
    expect_rejection("nfc4.receipt_bad_enr1_rejected", receipt_bad_enr1, "BAD_PACKAGE")

    def receipt_readback_mismatch():
        V.build_enable_receipt(7, 42, 9, 6, V.STATUS_APPLIED, V.EFFECTIVE_ENABLED, 5)
    expect_rejection("nfc4.receipt_readback_revision_mismatch_rejected",
                     receipt_readback_mismatch, "BAD_PACKAGE",
                     detail="readback_state_revision must equal the header state_revision (F5)")

    def receipt_effective_0():
        V.build_enable_receipt(7, 42, 9, 6, V.STATUS_APPLIED, 0, 6)
    expect_rejection("nfc4.receipt_effective_state_0_rejected",
                     receipt_effective_0, "BAD_PACKAGE")

    def receipt_status_8():
        V.build_enable_receipt(7, 42, 9, 6, 8, V.EFFECTIVE_ENABLED, 6)
    expect_rejection("nfc4.receipt_status_8_rejected", receipt_status_8, "BAD_PACKAGE")

    def receipt_48B_requires_enr1():
        blob = V.build_nfc4_header(V.MSG_CMD_REPLY, 48, 7, 42, 9, 6, 0) + b"\x00" * 16
        V.parse_enable_receipt(blob)
    expect_rejection("nfc4.48B_receipt_without_enr1_rejected",
                     receipt_48B_requires_enr1, "BAD_PACKAGE",
                     detail="non-enable receipts are exactly 32B; a 48B receipt must be a valid ENR1")

    cache = V.EnableCommandCache()
    vector("nfc4.dedup_first_execution", "EXECUTED", cache.feed(es) == "EXECUTED")
    vector("nfc4.dedup_identical_cached", "CACHED", cache.feed(es) == "CACHED")

    def dedup_conflict():
        cache.feed(V.build_enable_set(7, 42, 9, 6, V.DESIRED_ENABLED))
    expect_rejection("nfc4.dedup_same_id_different_payload_rejected",
                     dedup_conflict, "BAD_PACKAGE")

    events16 = [{"event_seq": i + 1, "track_id": 100 + i, "event_ts_ms": 1000 + 40 * i,
                 "direction": 1 if i % 2 == 0 else 2, "flags": 0,
                 "x_q8": 128, "y_q8": 64} for i in range(16)]
    eb = V.build_event_batch(events16, packet_seq=1, event_through_seq=16,
                             cumulative_event_total=16, cumulative_source_gap=0,
                             source_ts_ms=1000, config_generation=9)
    vector("lvn4.event_batch_16_sha256", GOLDEN_LVN4_EVENT_BATCH_SHA_HEX,
           sha_hex(eb) == GOLDEN_LVN4_EVENT_BATCH_SHA_HEX,
           f"max EVENT_BATCH: 48 + 16*16 = {len(eb)}B (within live_publish_min 312)")
    parsed_pkt = V.parse_live_packet(eb, live_publish_max=312, live_track_max=8)
    vector("lvn4.event_batch_roundtrip", "ACCEPT", len(parsed_pkt["events"]) == 16)

    tracks = [
        {"track_id": 7, "class_index": 0, "state": 1, "flags": 0, "confidence_q16": 0x9999,
         "points": [{"ts_ms": 1000 + k * 33, "x_q16": 0x2000 + k * 0x100,
                     "y_q16": 0x8000 - k * 0x80} for k in range(3)]},
        {"track_id": 11, "class_index": 0xFFFF, "state": 1, "flags": 0,
         "confidence_q16": 0x8000,
         "points": [{"ts_ms": 2000, "x_q16": 0xC000, "y_q16": 0x4000}]},
    ]
    tsnap = V.build_tracks_snapshot(tracks, packet_seq=2, event_through_seq=16,
                                    cumulative_event_total=16, cumulative_source_gap=0,
                                    source_ts_ms=2000, config_generation=9,
                                    live_track_max=8)
    vector("lvn4.tracks_snapshot_sha256", GOLDEN_LVN4_TRACKS_SHA_HEX,
           sha_hex(tsnap) == GOLDEN_LVN4_TRACKS_SHA_HEX,
           "ACTIVE_TRACKS_SNAPSHOT: 48 + (12+3*8) + (12+1*8) = 104B, exact closure")
    parsed_t = V.parse_live_packet(tsnap, live_publish_max=312, live_track_max=8)
    vector("lvn4.tracks_snapshot_roundtrip", "ACCEPT",
           [t["track_id"] for t in parsed_t["tracks"]] == [7, 11])

    def lvn_bad_magic():
        V.parse_live_packet(b"LVN3" + eb[4:])
    expect_rejection("lvn4.wrong_magic_rejected", lvn_bad_magic, "BAD_PACKAGE")

    def lvn_bad_kind():
        raw = bytearray(eb)
        struct.pack_into("<H", raw, 6, 3)
        V.parse_live_packet(bytes(raw))
    expect_rejection("lvn4.kind_3_rejected", lvn_bad_kind, "BAD_PACKAGE")

    def lvn_len_mismatch():
        raw = bytearray(eb)
        struct.pack_into("<I", raw, 8, len(eb) - 1)
        V.parse_live_packet(bytes(raw))
    expect_rejection("lvn4.total_len_mismatch_rejected", lvn_len_mismatch, "BAD_PACKAGE")

    def lvn_packet_seq_0():
        raw = bytearray(eb)
        struct.pack_into("<I", raw, 12, 0)
        V.parse_live_packet(bytes(raw))
    expect_rejection("lvn4.packet_seq_0_rejected", lvn_packet_seq_0, "BAD_PACKAGE")

    def lvn_reserved_nonzero():
        raw = bytearray(eb)
        struct.pack_into("<I", raw, 44, 1)
        V.parse_live_packet(bytes(raw))
    expect_rejection("lvn4.reserved_nonzero_rejected", lvn_reserved_nonzero, "BAD_PACKAGE")

    def lvn_flags_bit3():
        raw = bytearray(eb)
        struct.pack_into("<I", raw, 40, 8)
        V.parse_live_packet(bytes(raw))
    expect_rejection("lvn4.flags_bit3_rejected", lvn_flags_bit3, "BAD_PACKAGE")

    def lvn_17_events():
        ev = events16 + [{"event_seq": 17, "track_id": 1, "event_ts_ms": 1,
                          "direction": 1, "flags": 0, "x_q8": 0, "y_q8": 0}]
        V.build_event_batch(ev, packet_seq=1, event_through_seq=17,
                            cumulative_event_total=17, cumulative_source_gap=0,
                            source_ts_ms=1, config_generation=9)
    expect_rejection("lvn4.17_events_over_bound_rejected", lvn_17_events, "RESOURCE_LIMIT")

    def lvn_event_seq_not_increasing():
        ev = [{"event_seq": 5, "track_id": 1, "event_ts_ms": 1, "direction": 1,
               "flags": 0, "x_q8": 0, "y_q8": 0},
              {"event_seq": 5, "track_id": 1, "event_ts_ms": 1, "direction": 1,
               "flags": 0, "x_q8": 0, "y_q8": 0}]
        V.build_event_batch(ev, packet_seq=1, event_through_seq=5,
                            cumulative_event_total=2, cumulative_source_gap=0,
                            source_ts_ms=1, config_generation=9)
    expect_rejection("lvn4.event_seq_not_strictly_increasing_rejected",
                     lvn_event_seq_not_increasing, "BAD_PACKAGE")

    def lvn_event_seq_over_through():
        ev = [{"event_seq": 6, "track_id": 1, "event_ts_ms": 1, "direction": 1,
               "flags": 0, "x_q8": 0, "y_q8": 0}]
        pkt = V.build_event_batch(ev, packet_seq=1, event_through_seq=5,
                                  cumulative_event_total=1, cumulative_source_gap=0,
                                  source_ts_ms=1, config_generation=9)
        V.parse_live_packet(pkt)
    expect_rejection("lvn4.event_seq_over_through_seq_rejected",
                     lvn_event_seq_over_through, "BAD_PACKAGE")

    def lvn_direction_0():
        ev = [{"event_seq": 1, "track_id": 1, "event_ts_ms": 1, "direction": 0,
               "flags": 0, "x_q8": 0, "y_q8": 0}]
        V.build_event_batch(ev, packet_seq=1, event_through_seq=1,
                            cumulative_event_total=1, cumulative_source_gap=0,
                            source_ts_ms=1, config_generation=9)
    expect_rejection("lvn4.direction_0_rejected", lvn_direction_0, "BAD_PACKAGE")

    def lvn_direction_3():
        ev = [{"event_seq": 1, "track_id": 1, "event_ts_ms": 1, "direction": 3,
               "flags": 0, "x_q8": 0, "y_q8": 0}]
        V.build_event_batch(ev, packet_seq=1, event_through_seq=1,
                            cumulative_event_total=1, cumulative_source_gap=0,
                            source_ts_ms=1, config_generation=9)
    expect_rejection("lvn4.direction_3_rejected", lvn_direction_3, "BAD_PACKAGE")

    def lvn_event_flags_bit1():
        raw = bytearray(eb)
        raw[48 + 13] = 0x02
        V.parse_live_packet(bytes(raw))
    expect_rejection("lvn4.event_flags_reserved_rejected", lvn_event_flags_bit1, "BAD_PACKAGE")

    def lvn_over_publish_max():
        V.parse_live_packet(eb, live_publish_max=303)
    expect_rejection("lvn4.packet_over_live_publish_max_rejected",
                     lvn_over_publish_max, "RESOURCE_LIMIT")

    def lvn_track_dup():
        tr = [dict(tracks[0]), dict(tracks[0])]
        V.build_tracks_snapshot(tr, packet_seq=1, event_through_seq=0,
                                cumulative_event_total=0, cumulative_source_gap=0,
                                source_ts_ms=0, config_generation=9, live_track_max=8)
    expect_rejection("lvn4.duplicate_track_id_rejected", lvn_track_dup, "BAD_PACKAGE")

    def lvn_track_zero_id():
        tr = [dict(tracks[0])]
        tr[0]["track_id"] = 0
        V.build_tracks_snapshot(tr, packet_seq=1, event_through_seq=0,
                                cumulative_event_total=0, cumulative_source_gap=0,
                                source_ts_ms=0, config_generation=9, live_track_max=8)
    expect_rejection("lvn4.track_id_0_rejected", lvn_track_zero_id, "BAD_PACKAGE")

    def lvn_track_17_points():
        tr = [dict(tracks[0])]
        tr[0]["points"] = [{"ts_ms": k, "x_q16": 0, "y_q16": 0} for k in range(17)]
        V.build_tracks_snapshot(tr, packet_seq=1, event_through_seq=0,
                                cumulative_event_total=0, cumulative_source_gap=0,
                                source_ts_ms=0, config_generation=9, live_track_max=8)
    expect_rejection("lvn4.point_count_17_rejected", lvn_track_17_points, "BAD_PACKAGE")

    def lvn_track_state_2():
        raw = bytearray(tsnap)
        raw[48 + 8] = 2
        V.parse_live_packet(bytes(raw), live_track_max=8)
    expect_rejection("lvn4.track_state_2_rejected", lvn_track_state_2, "BAD_PACKAGE")

    def lvn_track_flags_nonzero():
        raw = bytearray(tsnap)
        raw[48 + 9] = 1
        V.parse_live_packet(bytes(raw), live_track_max=8)
    expect_rejection("lvn4.track_flags_nonzero_rejected", lvn_track_flags_nonzero, "BAD_PACKAGE")

    def lvn_trailing_byte():
        raw = bytearray(tsnap)
        struct.pack_into("<I", raw, 8, len(tsnap) + 1)
        V.parse_live_packet(bytes(raw) + b"\x00", live_track_max=8)
    expect_rejection("lvn4.trailing_byte_after_records_rejected",
                     lvn_trailing_byte, "BAD_PACKAGE",
                     detail="kind2 records must parse to exactly the packet tail")

    def lvn_tracks_over_max():
        V.parse_live_packet(tsnap, live_track_max=1)
    expect_rejection("lvn4.tracks_over_signed_max_rejected", lvn_tracks_over_max,
                     "RESOURCE_LIMIT")

    session = V.Lvn4SessionModel()
    p1 = V.build_event_batch([], packet_seq=1, event_through_seq=0,
                             cumulative_event_total=0, cumulative_source_gap=0,
                             source_ts_ms=0, config_generation=9)
    vector("lvn4.session_first_packet", "OK", session.feed(V.parse_live_packet(p1)) == "OK",
           "an empty batch still carries the watermarks (record_count=0 is not 'no loss')")

    def session_replay_rejected():
        session.feed(V.parse_live_packet(p1))
    expect_rejection("lvn4.session_packet_replay_rejected", session_replay_rejected,
                     "BAD_PACKAGE")

    def session_gap_jump_rejected():
        p3 = V.build_event_batch([], packet_seq=3, event_through_seq=0,
                                 cumulative_event_total=0, cumulative_source_gap=0,
                                 source_ts_ms=0, config_generation=9)
        session.feed(V.parse_live_packet(p3))
    expect_rejection("lvn4.session_packet_gap_rejected", session_gap_jump_rejected,
                     "BAD_PACKAGE")

    session2 = V.Lvn4SessionModel()
    gap1 = V.build_event_batch([], packet_seq=1, event_through_seq=2,
                               cumulative_event_total=3, cumulative_source_gap=1,
                               source_ts_ms=0, config_generation=9, flags=V.LIVE_FLAG_SOURCE_GAP_DELTA)
    session2.feed(V.parse_live_packet(gap1))
    gap2 = V.build_event_batch([], packet_seq=2, event_through_seq=2,
                               cumulative_event_total=5, cumulative_source_gap=3,
                               source_ts_ms=0, config_generation=9,
                               flags=V.LIVE_FLAG_SOURCE_GAP_DELTA | V.LIVE_FLAG_SOURCE_LOSS_UNKNOWN)
    vector("lvn4.session_gap_conservation", "OK",
           session2.feed(V.parse_live_packet(gap2)) == "OK",
           "cumulative_source_gap 1 -> 3 and event_total 3 -> 5 move forward monotonically")

    def session_wrap_rejected():
        s = V.Lvn4SessionModel()
        s.last_packet_seq = None
        s.through_seq = 0
        s.cumulative_event_total = 0xFFFFFFFE
        s.cumulative_source_gap = 0
        pkt = V.build_event_batch([], packet_seq=1, event_through_seq=0,
                                  cumulative_event_total=0xFFFFFFFF,
                                  cumulative_source_gap=0, source_ts_ms=0,
                                  config_generation=9)
        s.feed(V.parse_live_packet(pkt))
    expect_rejection("lvn4.u32_exhaustion_requires_resync_rejected",
                     session_wrap_rejected, "BAD_PACKAGE")

    def session_unknown_loss_as_precise_zero_rejected():
        s = V.Lvn4SessionModel()
        pkt = V.build_event_batch([], packet_seq=1, event_through_seq=0,
                                  cumulative_event_total=0, cumulative_source_gap=0,
                                  source_ts_ms=0, config_generation=9,
                                  flags=V.LIVE_FLAG_SOURCE_LOSS_UNKNOWN)
        s.feed(V.parse_live_packet(pkt))
        pkt2 = V.build_event_batch([], packet_seq=2, event_through_seq=0,
                                   cumulative_event_total=0, cumulative_source_gap=0,
                                   source_ts_ms=0, config_generation=9,
                                   flags=V.LIVE_FLAG_SOURCE_LOSS_UNKNOWN)
        s.feed(V.parse_live_packet(pkt2))
    expect_rejection("lvn4.unknown_loss_not_precise_gap_rejected",
                     session_unknown_loss_as_precise_zero_rejected, "BAD_PACKAGE",
                     detail="SOURCE_LOSS_UNKNOWN must never be presented as a precise unchanged gap")

    pinned_golden_files = {
        "golden-native.bin": (native, GOLDEN_NATIVE_SHA_HEX),
        "golden-tbs.bin": (tbs, GOLDEN_TBS_SHA_HEX),
        "golden-sig.der": (der, hashlib.sha256(bytes.fromhex(GOLDEN_DER_HEX)).hexdigest()),
        "golden.neapp.v4": (package, GOLDEN_PKG_SHA_HEX),
        "test-publisher.spki.der": (SPKI_GOLDEN, SPKI_SHA_HEX),
        "golden-nfc4-enable-set.bin": (es, GOLDEN_ENABLE_SET_SHA_HEX),
        "golden-nfc4-enable-receipt.bin": (er, GOLDEN_ENABLE_RECEIPT_SHA_HEX),
        "golden-lvn4-event-batch.bin": (eb, GOLDEN_LVN4_EVENT_BATCH_SHA_HEX),
        "golden-lvn4-tracks-snapshot.bin": (tsnap, GOLDEN_LVN4_TRACKS_SHA_HEX),
    }
    for name, (blob, pinned) in pinned_golden_files.items():
        with open(os.path.join(EVIDENCE_DIR, name), "wb") as f:
            f.write(blob)
        vector(f"evidence.{name}_pinned", pinned, sha_hex(blob) == pinned,
               f"{len(blob)}B committed artifact reproduces its pinned SHA-256")

    passed = sum(1 for r in RESULTS if r["ok"])
    total = len(RESULTS)
    report_json = {
        "suite": "tests/spec-vnext/run_all_tests.py",
        "issue": "harryhua-ai/ne30x-app#36",
        "spec_authority": [
            "harryhua-ai/ne301#104 comment 6258534821 (F1-F4)",
            "harryhua-ai/ne301#104 comment 6258601629 (F5-F7)",
            "harryhua-ai/ne301#104 comment 6258637748 (F8-F10)",
        ],
        "vectors_total": total,
        "vectors_passed": passed,
        "vectors_failed": total - passed,
        "independence": (
            "v4lib.py shares no code with package/ (v1/v2/v3/v4 tooling) or "
            "tests/spec-v2//tests/spec-v3/; P-256/RFC-6979/DER implemented from scratch"),
        "signer": {
            "scalar": "d=1 (PUBLIC non-production test key, never a production trust root)",
            "spki_sha256": SPKI_SHA_HEX,
        },
        "boundary": (
            "offline vector evidence only: NOT Host admission, native runtime admission, "
            "device capacity, floor/Enable semantics, live delivery, or ARM build proof"),
        "vectors": RESULTS,
    }
    with open(os.path.join(EVIDENCE_DIR, "report.json"), "w") as f:
        json.dump(report_json, f, indent=2, ensure_ascii=False)
        f.write("\n")

    lines = [
        "# spec-vnext report (App #36)",
        "",
        f"- vectors: {passed}/{total} passed",
        "- spec authority: Host #104 freeze comments 6258534821 (F1-F4),",
        "  6258601629 (F5-F7), 6258637748 (F8-F10)",
        f"- golden package: {len(package)}B, sha256 {GOLDEN_PKG_SHA_HEX}",
        f"- golden TBS sha256: {GOLDEN_TBS_SHA_HEX}",
        f"- golden signer: PUBLIC d=1 test scalar, SPKI sha256 {SPKI_SHA_HEX}",
        "- boundary: offline vector evidence only (see report.json)",
        "",
    ]
    for r in RESULTS:
        if not r["ok"]:
            lines.append(f"- FAIL {r['name']}: expected {r['expected']}, {r['detail']}")
    lines.append("")
    with open(os.path.join(EVIDENCE_DIR, "report.md"), "w") as f:
        f.write("\n".join(lines))

    print(f"spec-vnext: {passed}/{total} vectors passed")
    if passed != total:
        for r in RESULTS:
            if not r["ok"]:
                print(f"  FAIL {r['name']}: expected {r['expected']}, {r['detail']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
