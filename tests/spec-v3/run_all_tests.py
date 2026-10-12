import hashlib
import json
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import v3lib as V

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EVIDENCE_DIR = os.path.join(ROOT, "docs", "evidence", "spec-v3")

D_TEST = 1
SPKI_SHA_HEX = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"

GOLDEN_TBS_SHA_HEX = "d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e"
GOLDEN_DER_HEX = ("304402204646fc74c70bbbefcabc29afb8228bc121ad8b432104254d0b3f09"
                  "819e9b6de50220251fd81c3f8976906785871c0016bad865f5e3c7f460b67"
                  "b76e6fc1cce5bab50")
GOLDEN_PKG_SHA_HEX = "c74f7e468a9b63403bbaa8d36816bfd5250ffd68f66ebffc7d994440f1e22342"
GOLDEN_NATIVE_SHA_HEX = "aa8c3ef6e4082656c76255807bee5a7c562ad212a0c3e2a4f009a62129cdee69"
GOLDEN_NATIVE_CRC = 0xDE8E3439

GOLDEN_CMD_APPLY_SHA_HEX = "e6fafa1183d9fadd84ee17721994ce2f758b8b988970a7c5b8f5fb6d7ecec3ca"
GOLDEN_CMD_RESET_SHA_HEX = "5d0a37ef0587533cbb141da8ad08fadb43b0e88d4ed115bb52d1ab4aeb8f43fb"
GOLDEN_REPLY_APPLIED_SHA_HEX = "054b7356b81fb555d6bdbc05f6d666cedb0d84a98555476a06cb32df09d87eed"
GOLDEN_SNAPSHOT_SHA_HEX = "9e1031d07cb4b1217429a927bc3f69909c9cad84ef9036975fab99afa77403b5"

V1_GOLDEN_TBS_SHA_HEX = "5035e6512c0c003490b228b9ae0dc6351166a04b0dc96a3ff053bb7fe348fe91"
V2_GOLDEN_TBS_SHA_HEX = "e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278"
V2_GOLDEN_DER_HEX = ("3044022011e9d2635e2036fb0bcbd1107a5e6d272c150473a8c1e029887604f9aa754"
                     "73702205b6ca9206755a161913fcf9cdf57c789b363420bc16a74438bc439aeb80d11b0")
V2_GOLDEN_PKG_SHA_HEX = "3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e"

SNAPSHOT_JSON_GOLDEN = json.dumps({
    "active_config": {
        "conf_threshold_permille": 250,
        "counter_name": "客流统计",
        "heat_grid_enable": False,
        "k_confirm": 5,
        "line": {"x1_permille": 200, "x2_permille": 800,
                 "y1_permille": 500, "y2_permille": 500},
        "max_dist_permille": 250,
        "max_miss": 5,
        "outside": {"x_permille": 500, "y_permille": 200},
        "target_class_name": "car",
        "track_history_k": 8,
        "tracks_report_enable": True,
        "window_minutes": 5,
    },
    "app_state": "running",
    "config_generation": 7,
    "counters": {"in": 12, "out": 9},
    "cumulative": {"in": 3456, "out": 2890},
    "gap": {"active": False, "last_reason": None},
    "model": {"class_generation": 2, "generation": 3, "loaded": True,
              "target_class": "car", "valid": True},
    "quality": {"dropped_frames": 2},
    "report_seq": 88,
    "schema": "line-crossing/1",
    "state_revision": 5,
    "storage": {"fault": False},
}, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

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
    except Exception as e:
        return vector(name, "ACCEPT", False, f"error {e!r}", evidence)
    return vector(name, "ACCEPT", True, detail, evidence)


def expect_rejection(name, fn, expected_reason, detail="", detail_contains=None):
    try:
        fn()
    except V.SpecViolation as e:
        ok = e.reason == expected_reason and (
            detail_contains is None or detail_contains in (e.detail or ""))
        return vector(name, expected_reason, ok,
                      f"{e.reason}: {e.detail}" if not ok else e.detail)
    except Exception as e:
        return vector(name, expected_reason, False, f"error {e!r}")
    return vector(name, expected_reason, False, "accepted but expected rejection")


def openssl_available():
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


def openssl_verify(spki_der, tbs, sig_der):
    tmp = EVIDENCE_DIR
    key_pem = os.path.join(tmp, "cross-check-pub.pem")
    tbs_f = os.path.join(tmp, "cross-check-tbs.bin")
    sig_f = os.path.join(tmp, "cross-check-sig.bin")
    with open(key_pem, "wb") as f:
        subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER",
                        "-in", os.path.join(tmp, "test-publisher.spki.der"),
                        "-out", key_pem], check=True, capture_output=True)
    with open(tbs_f, "wb") as f:
        f.write(tbs)
    with open(sig_f, "wb") as f:
        f.write(sig_der)
    proc = subprocess.run(["openssl", "dgst", "-sha256", "-verify", key_pem,
                           "-signature", sig_f, tbs_f], capture_output=True)
    for p in (key_pem, tbs_f, sig_f):
        os.unlink(p)
    return proc.returncode == 0 and b"Verified OK" in proc.stdout


TEST_SPKI = V.spki_der_for_scalar(D_TEST)


def host_v3_full():
    host = dict(V.HOST_POLICY_V3)
    host["trusted_publishers"] = {"test-publisher": TEST_SPKI}
    host["session_caps"] = V.CAPS_KNOWN_MASK_V3
    host["session_publisher"] = "test-publisher"
    return host


def host_v3_no_new_caps():
    host = host_v3_full()
    host["caps_supported"] = V.CAPS_KNOWN_MASK_V2
    return host


def build_golden_native():
    return V.build_native(bytes.fromhex("00207047"), V.ABI_V3)


def build_golden_manifest(native):
    return V.build_manifest_v3(
        "test-publisher", "line-crossing", (3, 0, 0), 0x00003010, 64,
        0x000000FF, 4, native, bytes.fromhex(SPKI_SHA_HEX),
        V.PROFILE_V3_HOT_COMMAND_SESSION, 2048, 4096, 6144, 256, 1024)


def build_golden_tbs():
    native = build_golden_native()
    manifest = build_golden_manifest(native)
    header = V.CONTAINER_MAGIC_V3 + struct.pack("<II", 192, len(native))
    return header + manifest + native


def golden_package():
    tbs = build_golden_tbs()
    return tbs + bytes.fromhex(GOLDEN_DER_HEX)


def resign_manifest(mutate_manifest=None, mutate_native=None, native_override=None):
    native = native_override if native_override is not None else build_golden_native()
    if mutate_native is not None:
        native = mutate_native(bytearray(native))
    manifest = bytearray(build_golden_manifest(native))
    if mutate_manifest is not None:
        mutate_manifest(manifest)
    header = V.CONTAINER_MAGIC_V3 + struct.pack("<II", 192, len(native))
    tbs = header + bytes(manifest) + native
    return tbs + V.sign_der(D_TEST, tbs), tbs


def rebuild_v1_golden():
    native = V.build_native(bytes.fromhex("00207047"), V.ABI_V1)
    manifest = bytearray(V.build_manifest_v3(
        "test-publisher", "hello-app", (1, 0, 0), 0x00003010, 64,
        0x00000003, 4, native, bytes.fromhex(SPKI_SHA_HEX),
        V.PROFILE_V2_SINGLE_SESSION, 0, 0, 0, 0, 0))
    manifest[0:4] = V.MANIFEST_MAGIC_V1
    struct.pack_into("<I", manifest, 68, V.ABI_V1)
    struct.pack_into("<I", manifest, 160, 0)
    struct.pack_into("<I", manifest, 164, 0)
    struct.pack_into("<I", manifest, 168, 0)
    struct.pack_into("<I", manifest, 172, 0)
    struct.pack_into("<I", manifest, 176, 0)
    struct.pack_into("<I", manifest, 180, 0)
    manifest_v1 = bytes(manifest[:160])
    header = V.CONTAINER_MAGIC_V1 + struct.pack("<II", 160, len(native))
    tbs = header + manifest_v1 + native
    return tbs + V.sign_der(D_TEST, tbs), tbs


def rebuild_v2_golden():
    native = V.build_native(bytes.fromhex("00207047"), V.ABI_V2)
    manifest = bytearray(V.build_manifest_v3(
        "test-publisher", "hello-app", (1, 0, 0), 0x00003010, 64,
        0x0000003F, 4, native, bytes.fromhex(SPKI_SHA_HEX),
        V.PROFILE_V2_SINGLE_SESSION, 2048, 4096, 6144, 0, 0))
    manifest[0:4] = V.MANIFEST_MAGIC_V2
    struct.pack_into("<I", manifest, 68, V.ABI_V2)
    header = V.CONTAINER_MAGIC_V2 + struct.pack("<II", 192, len(native))
    tbs = header + bytes(manifest) + native
    return tbs + bytes.fromhex(V2_GOLDEN_DER_HEX), tbs


def group_golden():
    tbs = build_golden_tbs()
    vector("golden.tbs_length", "244", len(tbs) == 244, f"{len(tbs)}B")
    vector("golden.tbs_sha256", GOLDEN_TBS_SHA_HEX,
           V.sha256_hex(tbs) == GOLDEN_TBS_SHA_HEX, V.sha256_hex(tbs))
    native = build_golden_native()
    vector("golden.native_crc32", hex(GOLDEN_NATIVE_CRC),
           hex(struct.unpack_from("<I", native, 28)[0]) == hex(GOLDEN_NATIVE_CRC),
           hex(struct.unpack_from("<I", native, 28)[0]))
    vector("golden.native_sha256", GOLDEN_NATIVE_SHA_HEX,
           V.sha256_hex(native) == GOLDEN_NATIVE_SHA_HEX, V.sha256_hex(native))
    der1 = V.sign_der(D_TEST, tbs)
    der2 = V.sign_der(D_TEST, tbs)
    vector("golden.der_deterministic", GOLDEN_DER_HEX,
           der1 == der2 and der1.hex() == GOLDEN_DER_HEX, f"{len(der1)}B")
    pkg = golden_package()
    vector("golden.package_length", "314", len(pkg) == 314, f"{len(pkg)}B")
    vector("golden.package_sha256", GOLDEN_PKG_SHA_HEX,
           V.sha256_hex(pkg) == GOLDEN_PKG_SHA_HEX, V.sha256_hex(pkg))
    host = host_v3_full()
    expect_accept("golden.full_accept_v3", lambda: V.full_accept_v3(pkg, host),
                  detail="structure->trust->signature->policy order accepts golden v3 package")
    expect_rejection("golden.full_accept_without_trust_map",
                     lambda: V.full_accept_v3(pkg, dict(V.HOST_POLICY_V3)),
                     "PUBLISHER_UNTRUSTED")
    if openssl_available():
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        with open(os.path.join(EVIDENCE_DIR, "test-publisher.spki.der"), "wb") as f:
            f.write(TEST_SPKI)
        vector("golden.openssl_cross_verify", "Verified OK",
               openssl_verify(TEST_SPKI, tbs, der1))
    else:
        vector("golden.openssl_cross_verify", "Verified OK", True,
               detail="SKIP openssl CLI unavailable")


def group_resigned_policy_negatives():
    host = host_v3_full()

    def set_caps(value):
        def mutate(m):
            struct.pack_into("<I", m, 72, value)
        return mutate

    cases = [
        ("resign.unknown_capability_bit8",
         set_caps(0x000001FF), None, None, "BAD_PACKAGE", "unknown capability"),
        ("resign.control_max_zero_with_bit6",
         lambda m: struct.pack_into("<I", m, 176, 0), None, None, "BAD_PACKAGE", "control_max"),
        ("resign.snapshot_max_without_bit7",
         lambda m: (struct.pack_into("<I", m, 72, 0x0000007F),
                    struct.pack_into("<I", m, 180, 1024)), None, None,
         "BAD_PACKAGE", "snapshot_max"),
        ("resign.reserved_184_191_nonzero",
         lambda m: struct.pack_into("<I", m, 184, 1), None, None,
         "BAD_PACKAGE", "reserved[184..191]"),
        ("resign.run_profile_1_in_v3",
         lambda m: struct.pack_into("<I", m, 160, 1), None, None,
         "BAD_PACKAGE", "run_profile"),
        ("resign.profile2_missing_bit5",
         set_caps(0x000000CE), None, None, "BAD_PACKAGE", "session_lifecycle"),
        ("resign.profile2_missing_bit6",
         set_caps(0x000000BF), None, None, "BAD_PACKAGE", "control_receive"),
        ("resign.line_crossing_missing_bit3",
         set_caps(0x000000F7), None, None, "BAD_PACKAGE", "report_max"),
        ("resign.event_max_below_1576",
         lambda m: struct.pack_into("<I", m, 164, 1024), None, None,
         "RESOURCE_LIMIT", "event_max"),
        ("resign.report_max_below_6144",
         lambda m: struct.pack_into("<I", m, 172, 4096), None, None,
         "RESOURCE_LIMIT", "report_max"),
        ("resign.control_max_below_generic_wire_min",
         lambda m: struct.pack_into("<I", m, 176, 16), None, None,
         "RESOURCE_LIMIT", "control wire header"),
        ("resign.control_max_above_host",
         lambda m: struct.pack_into("<I", m, 176, 512), None, None,
         "RESOURCE_LIMIT", "control capacity"),
        ("resign.snapshot_max_above_host",
         lambda m: struct.pack_into("<I", m, 180, 2048), None, None,
         "RESOURCE_LIMIT", "snapshot RAM"),
        ("resign.quota_without_capability_bit",
         lambda m: struct.pack_into("<I", m, 164, 0), None, None,
         "BAD_PACKAGE", "event_max"),
        ("resign.reserved_58_59_nonzero",
         lambda m: struct.pack_into("<I", m, 58, 1), None, None,
         "BAD_PACKAGE", "reserved[58..59]"),
        ("resign.wrong_board",
         lambda m: struct.pack_into("<I", m, 60, 0x00003011), None, None,
         "TARGET_INCOMPATIBLE", "board"),
        ("resign.untrusted_key_fingerprint",
         lambda m: m.__setitem__(128, 0x5D), None, None,
         "PUBLISHER_UNTRUSTED", "publisher_key_sha256"),
        ("resign.abi_v2_value_in_nmf3",
         lambda m: struct.pack_into("<I", m, 68, V.ABI_V2), None, None,
         "BAD_PACKAGE", "required_host_abi"),
        ("resign.native_abi_v2_mismatch",
         None,
         lambda n: (struct.pack_into("<I", n, 8, V.ABI_V2), bytes(n))[1],
         None, "BAD_PACKAGE", "native abi"),
        ("resign.native_reserved0_nonzero",
         None,
         lambda n: (struct.pack_into("<I", n, 24, 1), bytes(n))[1],
         None, "BAD_PACKAGE", "reserved0"),
    ]
    for name, mm, mn, _x, reason, contains in cases:
        pkg, _tbs = resign_manifest(mutate_manifest=mm, mutate_native=mn)
        expect_rejection(name, lambda p=pkg: V.full_accept_v3(p, host), reason,
                         detail_contains=contains)

    def unknown_publisher():
        native = build_golden_native()
        manifest = bytearray(build_golden_manifest(native))
        manifest[4:20] = V._enc_identifier("other-publisher", 16)
        struct.pack_into("<I", manifest, 160, 2)
        header = V.CONTAINER_MAGIC_V3 + struct.pack("<II", 192, len(native))
        tbs = header + bytes(manifest) + native
        return tbs + V.sign_der(D_TEST, tbs)

    expect_rejection("resign.unknown_publisher_id", lambda: V.full_accept_v3(unknown_publisher(), host),
                     "PUBLISHER_UNTRUSTED")
    pkg_v2caps = golden_package()
    expect_rejection("resign.v3_new_caps_on_v2_caps_host",
                     lambda: V.full_accept_v3(pkg_v2caps, host_v3_no_new_caps()),
                     "ABI_INCOMPATIBLE", detail_contains="does not provide")


def group_tamper_and_der():
    host = host_v3_full()
    pkg = bytearray(golden_package())
    tbs_len = 244

    def tampered_payload():
        bad = bytearray(pkg)
        bad[tbs_len - 1] ^= 0xFF
        return bytes(bad)

    def tampered_manifest():
        bad = bytearray(pkg)
        bad[16 + 164] ^= 0xFF
        return bytes(bad)

    def tampered_der():
        bad = bytearray(pkg)
        bad[-1] ^= 0xFF
        return bytes(bad)

    expect_rejection("tamper.signed_payload_payload_byte",
                     lambda: V.full_accept_v3(tampered_payload(), host), "SIGNATURE_INVALID")
    expect_rejection("tamper.signed_manifest_byte",
                     lambda: V.full_accept_v3(tampered_manifest(), host), "SIGNATURE_INVALID")
    expect_rejection("tamper.der_byte",
                     lambda: V.full_accept_v3(tampered_der(), host), "SIGNATURE_INVALID")
    expect_rejection("der.trailing_byte",
                     lambda: V.full_accept_v3(bytes(pkg) + b"\x00", host), "BAD_PACKAGE")
    expect_rejection("der.truncated",
                     lambda: V.full_accept_v3(bytes(pkg[:-1]), host), "BAD_PACKAGE")
    expect_rejection("container.truncated_image",
                     lambda: V.full_accept_v3(bytes(pkg[:100]), host), "BAD_PACKAGE")


def group_interop_matrix():
    v1_pkg, v1_tbs = rebuild_v1_golden()
    vector("interop.v1_golden_tbs_rebuilt", V1_GOLDEN_TBS_SHA_HEX,
           V.sha256_hex(v1_tbs) == V1_GOLDEN_TBS_SHA_HEX, f"{len(v1_tbs)}B")
    trust = {"test-publisher": TEST_SPKI}
    expect_accept("interop.v1_pkg_on_v1_semantics_host",
                  lambda: V.v1_host_accept(v1_pkg, trust),
                  detail="v1 package accepted under frozen v1 rules only (16B table log/tick)")
    expect_rejection("interop.v1_pkg_on_v3_host",
                     lambda: V.full_accept_v3(v1_pkg, host_v3_full()), "BAD_PACKAGE")
    expect_rejection("interop.v1_pkg_on_v2_host",
                     lambda: V.v2_host_accept(v1_pkg, trust), "BAD_PACKAGE")

    v2_pkg, v2_tbs = rebuild_v2_golden()
    vector("interop.v2_golden_tbs_rebuilt", V2_GOLDEN_TBS_SHA_HEX,
           V.sha256_hex(v2_tbs) == V2_GOLDEN_TBS_SHA_HEX, f"{len(v2_tbs)}B")
    vector("interop.v2_golden_pkg_rebuilt", V2_GOLDEN_PKG_SHA_HEX,
           V.sha256_hex(v2_pkg) == V2_GOLDEN_PKG_SHA_HEX, f"{len(v2_pkg)}B")
    expect_accept("interop.v2_pkg_on_v2_semantics_host",
                  lambda: V.v2_host_accept(v2_pkg, trust),
                  detail="v2 package accepted under frozen v2 rules only (48B table, caps<=bit5)")
    expect_rejection("interop.v2_pkg_on_v3_host",
                     lambda: V.full_accept_v3(v2_pkg, host_v3_full()), "BAD_PACKAGE")
    expect_rejection("interop.v2_pkg_on_v1_host",
                     lambda: V.v1_host_accept(v2_pkg, trust), "BAD_PACKAGE")

    v3_pkg = golden_package()
    expect_accept("interop.v3_pkg_on_v3_host",
                  lambda: V.full_accept_v3(v3_pkg, host_v3_full()),
                  detail="v3 golden accepted under v3 rules (60B table, caps bits0..7)")

    def nmf2_inside_v3_container():
        native = build_golden_native()
        manifest = bytearray(build_golden_manifest(native))
        manifest[0:4] = V.MANIFEST_MAGIC_V2
        header = V.CONTAINER_MAGIC_V3 + struct.pack("<II", 192, len(native))
        tbs = header + bytes(manifest) + native
        return tbs + V.sign_der(D_TEST, tbs)

    expect_rejection("interop.nmf2_manifest_inside_v3_container",
                     lambda: V.full_accept_v3(nmf2_inside_v3_container(), host_v3_full()),
                     "BAD_PACKAGE")

    def nmf3_inside_v2_container():
        native = V.build_native(bytes.fromhex("00207047"), V.ABI_V2)
        manifest = bytearray(V.build_manifest_v3(
            "test-publisher", "hello-app", (1, 0, 0), 0x00003010, 64, 0x0000003F, 4,
            native, bytes.fromhex(SPKI_SHA_HEX), 1, 2048, 4096, 6144, 0, 0))
        manifest[0:4] = V.MANIFEST_MAGIC_V3
        header = V.CONTAINER_MAGIC_V2 + struct.pack("<II", 192, len(native))
        tbs = header + bytes(manifest) + native
        return tbs + V.sign_der(D_TEST, tbs)

    expect_rejection("interop.nmf3_manifest_inside_v2_container",
                     lambda: V.v2_host_accept(nmf3_inside_v2_container(), trust),
                     "BAD_PACKAGE")

    vector("interop.abi_table_sizes_distinct", "16/48/60",
           V.ABI_TABLE_SIZE_V1 == 16 and V.ABI_TABLE_SIZE_V2 == 48
           and V.ABI_TABLE_SIZE_V3 == 60)


def group_command_wire():
    opaque152 = bytes((i * 7 + 3) & 0xFF for i in range(152))
    cmd = V.build_command(V.MSG_CONFIG_APPLY, 7, 42, 6, 0, opaque152)
    vector("command.golden_config_apply_opaque_payload_184B", GOLDEN_CMD_APPLY_SHA_HEX,
           V.sha256_hex(cmd) == GOLDEN_CMD_APPLY_SHA_HEX,
           f"{len(cmd)}B opaque transport vector, not a real business config candidate")
    parsed = V.validate_command(cmd)
    vector("command.validate_config_apply", "ok",
           parsed["msg_type"] == V.MSG_CONFIG_APPLY and parsed["payload"] == opaque152
           and parsed["session_generation"] == 7 and parsed["request_id"] == 42
           and parsed["config_generation"] == 6)
    rst = V.build_command(V.MSG_COUNTERS_RESET, 7, 43, 7, V.FLAG_DESTRUCTIVE_CONFIRMED, b"")
    vector("command.golden_counters_reset_32B", GOLDEN_CMD_RESET_SHA_HEX,
           V.sha256_hex(rst) == GOLDEN_CMD_RESET_SHA_HEX, f"{len(rst)}B")
    expect_accept("command.validate_counters_reset", lambda: V.validate_command(rst))

    def mutated(offset, value):
        bad = bytearray(cmd)
        bad[offset] = value
        return bytes(bad)

    expect_rejection("command.negative.bad_proto_magic",
                     lambda: V.validate_command(mutated(0, 0x4D)), "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.header_version_2",
                     lambda: V.validate_command(mutated(4, 2)), "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.unknown_msg_type",
                     lambda: V.validate_command(mutated(6, 5)), "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.total_len_mismatch",
                     lambda: V.validate_command(mutated(8, 0xFF)), "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.session_generation_zero",
                     lambda: V.validate_command(mutated(12, 0)), "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.request_id_zero",
                     lambda: V.validate_command(mutated(16, 0)), "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.expected_generation_zero",
                     lambda: V.validate_command(mutated(20, 0)), "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.state_revision_nonzero",
                     lambda: V.validate_command(mutated(24, 1)), "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.unknown_flag_bit1",
                     lambda: V.validate_command(mutated(28, 2)), "BAD_CONTROL_WIRE")

    def apply_empty_payload():
        return V.validate_command(V.build_command(V.MSG_CONFIG_APPLY, 7, 42, 6, 0, b""))

    def reset_with_payload():
        return V.validate_command(V.build_command(V.MSG_COUNTERS_RESET, 7, 43, 7, 1, b"\x00"))

    expect_rejection("command.negative.config_apply_empty_payload",
                     apply_empty_payload, "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.counters_reset_with_payload",
                     reset_with_payload, "BAD_CONTROL_WIRE")
    expect_rejection("command.negative.reply_type_is_not_command",
                     lambda: V.validate_command(
                         V.build_reply(7, 42, V.RESULT_APPLIED, 7, 1)),
                     "BAD_CONTROL_WIRE")


def group_reply_wire():
    rep = V.build_reply(7, 42, V.RESULT_APPLIED, 7, 5)
    vector("reply.golden_applied_32B", GOLDEN_REPLY_APPLIED_SHA_HEX,
           V.sha256_hex(rep) == GOLDEN_REPLY_APPLIED_SHA_HEX, f"{len(rep)}B")
    parsed = V.validate_reply(rep)
    vector("reply.validate_applied", "ok",
           parsed["result_status"] == V.RESULT_APPLIED
           and parsed["new_config_generation"] == 7
           and parsed["state_revision"] == 5)
    expect_accept("reply.validate_rejected_stale", lambda: V.validate_reply(
        V.build_reply(7, 42, V.RESULT_REJECTED_STALE_CONFIG, 6, 4)))

    def status_unknown():
        return V.validate_reply(V.build_reply(7, 42, 8, 7, 5))

    expect_rejection("reply.negative.unknown_result_status", status_unknown, "BAD_CONTROL_WIRE")

    def applied_zero_gen():
        return V.build_reply(7, 42, V.RESULT_APPLIED, 0, 5)

    expect_rejection("reply.negative.applied_zero_generation",
                     applied_zero_gen, "BAD_CONTROL_WIRE")

    def reply_with_payload_bytes():
        return V.validate_reply(rep + b"\x00")

    expect_rejection("reply.negative.payload_not_allowed",
                     reply_with_payload_bytes, "BAD_CONTROL_WIRE")

    def gen_zero_any_status():
        return V.build_reply(7, 42, V.RESULT_REJECTED_INVALID, 0, 0)

    expect_rejection("reply.negative.zero_generation",
                     gen_zero_any_status, "BAD_CONTROL_WIRE")


def group_snapshot_wire():
    snap = V.build_snapshot(7, 5, SNAPSHOT_JSON_GOLDEN)
    vector("snapshot.golden_771B", GOLDEN_SNAPSHOT_SHA_HEX,
           V.sha256_hex(snap) == GOLDEN_SNAPSHOT_SHA_HEX, f"{len(snap)}B")
    parsed = V.validate_snapshot(snap, snapshot_max=1024)
    vector("snapshot.validate_golden", "ok",
           parsed["session_generation"] == 0 and parsed["request_id"] == 0
           and parsed["config_generation"] == 7 and parsed["state_revision"] == 5
           and parsed["json"]["schema"] == "line-crossing/1")

    def duplicate_key():
        return V.validate_snapshot(V.build_snapshot(7, 5, '{"a":1,"a":2}'))

    expect_rejection("snapshot.negative.duplicate_json_key", duplicate_key, "BAD_SNAPSHOT")

    def invalid_utf8():
        bad = bytearray(V.build_snapshot(7, 5, '{"a":"x"}'))
        bad[-2] = 0xFF
        return V.validate_snapshot(bytes(bad))

    expect_rejection("snapshot.negative.invalid_utf8", invalid_utf8, "BAD_SNAPSHOT")

    def trailing_data():
        return V.validate_snapshot(V.build_snapshot(7, 5, '{"a":1} trailing'))

    expect_rejection("snapshot.negative.trailing_data", trailing_data, "BAD_SNAPSHOT")

    def top_level_array():
        return V.validate_snapshot(V.build_snapshot(7, 5, "[1,2]"))

    expect_rejection("snapshot.negative.top_level_not_object", top_level_array, "BAD_SNAPSHOT")

    def nan_literal():
        return V.validate_snapshot(V.build_snapshot(7, 5, '{"a":NaN}'))

    expect_rejection("snapshot.negative.nan_constant", nan_literal, "BAD_SNAPSHOT")

    def app_fills_session_generation():
        bad = bytearray(V.build_snapshot(7, 5, '{"a":1}'))
        struct.pack_into("<I", bad, 12, 7)
        return V.validate_snapshot(bytes(bad))

    expect_rejection("snapshot.negative.app_filled_session_generation",
                     app_fills_session_generation, "BAD_CONTROL_WIRE")

    def app_fills_request_id():
        bad = bytearray(V.build_snapshot(7, 5, '{"a":1}'))
        struct.pack_into("<I", bad, 16, 42)
        return V.validate_snapshot(bytes(bad))

    expect_rejection("snapshot.negative.app_filled_request_id",
                     app_fills_request_id, "BAD_CONTROL_WIRE")

    def zero_generation():
        return V.build_snapshot(0, 5, '{"a":1}')

    expect_rejection("snapshot.negative.zero_config_generation",
                     zero_generation, "BAD_CONTROL_WIRE")

    def oversize():
        big = '{"a":"' + "x" * 2000 + '"}'
        return V.validate_snapshot(V.build_snapshot(7, 5, big), snapshot_max=1024)

    expect_rejection("snapshot.negative.oversize_quota", oversize, "QUOTA_EXCEEDED")


def new_host():
    host = V.HostV3(host_policy=host_v3_full())
    host.open_session()
    return host


def group_host_state_machine():
    host_closed = V.HostV3(host_policy=host_v3_full())
    vector("session.register_without_session", "UNAUTHORIZED",
           host_closed.register_command(V.MSG_CONFIG_APPLY, 1, 0, b"\x00")[0] == "UNAUTHORIZED")
    vector("session.control_next_without_session", "UNAUTHORIZED",
           host_closed.control_next(256)[0] == -3)
    vector("session.snapshot_without_session", "UNAUTHORIZED",
           host_closed.snapshot_publish(V.build_snapshot(1, 0, "{}")) == -3)

    host = new_host()
    app = V.AppV3(active_config_generation=1, state_revision=0)
    app.bind_session(host.session_generation)
    code, buf, actual = host.control_next(256)
    vector("session.control_next_no_event", "NO_EVENT=1", code == 1 and buf is None)

    opaque152 = bytes((i * 7 + 3) & 0xFF for i in range(152))
    outcome, _pending = host.register_command(V.MSG_CONFIG_APPLY, 1, 0, opaque152)
    vector("session.register_config_apply", "PENDING", outcome == "PENDING")
    code, buf, actual = host.control_next(64)
    vector("session.control_next_buffer_too_small_keeps_pending",
           "BUFFER_TOO_SMALL + pending kept",
           code == -2 and actual == 184 and host.pending is not None)
    outcome2, _p2 = host.register_command(V.MSG_COUNTERS_RESET, 1,
                                          V.FLAG_DESTRUCTIVE_CONFIRMED, b"")
    vector("session.second_pending_busy", "BUSY", outcome2 == "BUSY")
    code, buf, actual = host.control_next(256)
    vector("session.control_next_delivers_184B", "OK 184B",
           code == 0 and len(buf) == 184 and actual == 184 and host.pending is None)
    expected_cmd = V.build_command(V.MSG_CONFIG_APPLY, host.session_generation,
                                   1, 1, 0, opaque152)
    vector("session.delivered_bytes_exact", "match", buf == expected_cmd)
    vector("session.control_next_after_delivery_no_event", "NO_EVENT=1",
           host.control_next(256)[0] == 1)
    vector("session.reply_wrong_request_id", "INVALID_ARGUMENT",
           host.control_reply(V.build_reply(host.session_generation, 99,
                                            V.RESULT_APPLIED, 2, 1)) == -1)
    vector("session.reply_right_request_id", "OK",
           host.control_reply(V.build_reply(host.session_generation, 1,
                                            V.RESULT_APPLIED, 2, 1)) == 0)
    vector("session.known_generation_advanced_by_applied", "2",
           host.known_config_generation == 2)
    outcome3, cached = host.register_command(V.MSG_CONFIG_APPLY, 1, 0, opaque152, request_id=1)
    vector("session.dedup_same_id_same_semantics_cached", "CACHED",
           outcome3 == "CACHED" and cached["result_status"] == V.RESULT_APPLIED)
    outcome4, _c4 = host.register_command(V.MSG_CONFIG_APPLY, 1, 0, b"\x00" * 152, request_id=1)
    vector("session.dedup_same_id_different_payload_rejected", "DUPLICATE_ID_CONFLICT",
           outcome4 == "DUPLICATE_ID_CONFLICT")
    outcome5, _c5 = host.register_command(V.MSG_CONFIG_APPLY, 2, 0, b"\x01" * 152)
    vector("session.register_next_new_id", "PENDING", outcome5 == "PENDING")

    host2 = new_host()
    host2.snapshot_publish(V.build_snapshot(3, 9, '{"a":1}'))
    outcome6, _c6 = host2.register_command(V.MSG_CONFIG_APPLY, 2, 0, b"\x00" * 152)
    vector("session.stale_expected_generation_conflict", "CONFLICT", outcome6 == "CONFLICT")
    host2.known_config_generation = None
    outcome7, _c7 = host2.register_command(V.MSG_CONFIG_APPLY, 2, 0, b"\x00" * 152)
    vector("session.no_baseline_registration_allowed", "PENDING", outcome7 == "PENDING")

    host3 = new_host()
    outcome8, _c8 = host3.register_command(V.MSG_COUNTERS_RESET, 1, 0, b"")
    vector("session.counters_reset_unconfirmed_rejected", "UNCONFIRMED",
           outcome8 == "UNCONFIRMED")
    outcome9, _c9 = host3.register_command(V.MSG_CONFIG_APPLY, 1, 0, b"\x00" * 300)
    vector("session.oversize_command_quota", "QUOTA_EXCEEDED", outcome9 == "QUOTA_EXCEEDED")

    host4 = new_host()
    host4.snapshot_publish(V.build_snapshot(1, 0, "{}"), now_ms=0)
    vector("snapshot.fresh_at_5000ms", "current",
           host4.snapshot_observable(now_ms=5000)["state"] == "current")
    vector("snapshot.stale_at_10001ms", "stale",
           host4.snapshot_observable(now_ms=10001)["state"] == "stale")
    host4.snapshot_publish(V.build_snapshot(1, 0, "{}"), now_ms=10500)
    vector("snapshot.refresh_clears_stale", "current",
           host4.snapshot_observable(now_ms=10500)["state"] == "current")

    host5 = new_host()
    host5.snapshot_publish(V.build_snapshot(1, 0, "{}"), now_ms=0)
    vector("snapshot.version_increments", "2",
           (host5.snapshot_publish(V.build_snapshot(1, 0, "{}"), now_ms=1) == 0
            and host5.snapshot_observable()["snapshot_version"] == 2))

    host6 = new_host()
    host6.register_command(V.MSG_CONFIG_APPLY, 1, 0, b"\x00" * 152)
    host6.control_next(256)
    host6.close_session()
    vector("session.close_marks_delivered_unknown", "1 unknown",
           host6.closed_unknown_ids == [1])
    vector("session.snapshot_unavailable_after_close", "unavailable",
           host6.snapshot_observable()["state"] == "unavailable")
    host6.open_session()
    rec = host6.reconcile_unknown(1)
    vector("session.reconcile_before_snapshot_unknown", "UNKNOWN",
           rec["outcome"] == "UNKNOWN" and rec["evidence"] is None)
    host6.snapshot_publish(V.build_snapshot(1, 0, '{"gen":1}'))
    rec2 = host6.reconcile_unknown(1)
    vector("session.reconcile_after_snapshot_read_only", "RECONCILED",
           rec2["outcome"] == "RECONCILED_READ_ONLY"
           and rec2["evidence"]["active_config_generation"] == 1)
    vector("session.reconcile_does_not_replay", "no pending/delivered",
           host6.pending is None and host6.delivered is None)


def group_transaction():
    host = new_host()
    app = V.AppV3(active_config_generation=1, state_revision=0)
    app.bind_session(host.session_generation)
    host.snapshot_publish(app.snapshot_bytes())
    vector("txn.host_learns_baseline_from_snapshot", "1",
           host.known_config_generation == 1)
    opaque152 = b"\x11" * 152
    outcome, _ = host.register_command(V.MSG_CONFIG_APPLY, 1, 0, opaque152)
    vector("txn.register_accepted_pending_only", "PENDING", outcome == "PENDING")
    code, cmd, _n = host.control_next(256)
    vector("txn.delivered_to_app", "OK", code == 0)
    reply = app.handle_command(cmd)
    parsed = V.validate_reply(reply)
    vector("txn.applied_reply_new_generation", "APPLIED gen2 rev1",
           parsed["result_status"] == V.RESULT_APPLIED
           and parsed["new_config_generation"] == 2 and parsed["state_revision"] == 1)
    vector("txn.host_accepts_reply", "OK", host.control_reply(reply) == 0)
    vector("txn.known_generation_after_apply", "2", host.known_config_generation == 2)
    host.snapshot_publish(app.snapshot_bytes())
    vector("txn.snapshot_after_apply_matches", "gen2",
           host.snapshot["config_generation"] == 2)
    counters_after = app.blob["counters"]
    vector("txn.config_apply_preserves_counters", "kept",
           counters_after == {"in": 0, "out": 0} and app.blob["report_seq"] == 0)

    backfill_payload = bytes((i * 7 + 3) & 0xFF for i in range(132))
    backfill_payload += struct.pack("<5I", 999999, 888888, 777777, 666666, 4242)
    outcome_bf, _p = host.register_command(V.MSG_CONFIG_APPLY,
                                           host.known_config_generation, 0,
                                           backfill_payload)
    code, cmd_bf, _n = host.control_next(256)
    reply_bf = app.handle_command(cmd_bf)
    parsed_bf = V.validate_reply(reply_bf)
    vector("txn.candidate_cannot_backfill_persistent_state", "counters/report_seq unchanged",
           outcome_bf == "PENDING" and code == 0
           and parsed_bf["result_status"] == V.RESULT_APPLIED
           and app.blob["counters"] == {"in": 0, "out": 0}
           and app.blob["report_seq"] == 0)
    vector("txn.backfill_candidate_reply_cached", "OK",
           host.control_reply(reply_bf) == 0)

    code, cmd2, _n = host.control_next(256)
    vector("txn.no_event_when_no_pending", "NO_EVENT=1", code == 1)

    app_stale = V.AppV3(active_config_generation=2, state_revision=1)
    app_stale.bind_session(host.session_generation)
    stale_cmd = V.build_command(V.MSG_CONFIG_APPLY, host.session_generation, 9, 1, 0, opaque152)
    reply_stale = app_stale.handle_command(stale_cmd)
    vector("txn.stale_expected_generation_rejected_at_app", "REJECTED_STALE_CONFIG",
           V.validate_reply(reply_stale)["result_status"] == V.RESULT_REJECTED_STALE_CONFIG)
    vector("txn.stale_rejection_keeps_generation", "2", app_stale.active_config_generation == 2)

    app_conflict = V.AppV3(active_config_generation=2, state_revision=4)
    app_conflict.persisted_blob = {"config": "active", "counters": {"in": 5, "out": 3},
                                   "report_seq": 7}
    app_conflict.persisted_revision = 4
    app_conflict.commit_mode = "conflict"
    app_conflict.bind_session(host.session_generation)
    cmd_ok = V.build_command(V.MSG_CONFIG_APPLY, host.session_generation, 10, 2, 0, opaque152)
    reply_conflict = app_conflict.handle_command(cmd_ok)
    vector("txn.cas_conflict_fails_not_applied", "FAILED_STATE_CONFLICT",
           V.validate_reply(reply_conflict)["result_status"] == V.RESULT_FAILED_STATE_CONFLICT)
    vector("txn.cas_conflict_preserves_persisted", "kept",
           app_conflict.persisted_blob["counters"] == {"in": 5, "out": 3}
           and app_conflict.persisted_revision == 4)

    app_io = V.AppV3(active_config_generation=2, state_revision=4)
    app_io.commit_mode = "io"
    app_io.bind_session(host.session_generation)
    reply_io = app_io.handle_command(cmd_ok)
    vector("txn.io_error_fails_not_applied", "FAILED_STORAGE_IO",
           V.validate_reply(reply_io)["result_status"] == V.RESULT_FAILED_STORAGE_IO)

    app_unknown = V.AppV3(active_config_generation=2, state_revision=4)
    app_unknown.commit_mode = "unknown"
    app_unknown.bind_session(host.session_generation)
    reply_unknown = app_unknown.handle_command(cmd_ok)
    parsed_unknown = V.validate_reply(reply_unknown)
    vector("txn.storage_unknown_not_applied", "FAILED_STORAGE_UNKNOWN",
           parsed_unknown["result_status"] == V.RESULT_FAILED_STORAGE_UNKNOWN)
    vector("txn.storage_unknown_restriction_on", "restricted",
           app_unknown.restricted and app_unknown.snapshot_json().find('"app_state":"restricted"') >= 0)
    destructive_later = V.build_command(V.MSG_COUNTERS_RESET, host.session_generation, 11, 2,
                                        V.FLAG_DESTRUCTIVE_CONFIRMED, b"")
    reply_blocked = app_unknown.handle_command(destructive_later)
    vector("txn.restricted_app_blocks_destructive", "FAILED_STORAGE_UNKNOWN",
           V.validate_reply(reply_blocked)["result_status"] == V.RESULT_FAILED_STORAGE_UNKNOWN
           and app_unknown.state_revision == 4)
    app_unknown.recover_trusted_state()
    vector("txn.recovery_restores_operation", "restricted cleared", not app_unknown.restricted)

    host_reset = new_host()
    app_reset = V.AppV3(active_config_generation=3, state_revision=8)
    app_reset.blob["report_seq"] = 41
    app_reset.blob["counters"] = {"in": 100, "out": 90}
    app_reset.bind_session(host_reset.session_generation)
    reset_cmd = V.build_command(V.MSG_COUNTERS_RESET, host_reset.session_generation, 12, 3,
                                V.FLAG_DESTRUCTIVE_CONFIRMED, b"")
    reply_reset = app_reset.handle_command(reset_cmd)
    parsed_reset = V.validate_reply(reply_reset)
    vector("txn.counters_reset_applied", "APPLIED",
           parsed_reset["result_status"] == V.RESULT_APPLIED)
    vector("txn.counters_reset_keeps_config_generation", "gen unchanged 3",
           parsed_reset["new_config_generation"] == 3
           and app_reset.active_config_generation == 3)
    vector("txn.counters_reset_advances_state_revision", "rev 9",
           parsed_reset["state_revision"] == 9)
    vector("txn.counters_reset_zeroes_counters_keeps_report_seq", "0/0 seq41",
           app_reset.blob["counters"] == {"in": 0, "out": 0}
           and app_reset.blob["report_seq"] == 41)

    app_mig = V.migrate_v2_state(True, {"counters": {"in": 55, "out": 44}, "report_seq": 12})
    vector("migration.v2_same_identity_restores_state", "counters 55/44 gen1",
           app_mig.blob["counters"] == {"in": 55, "out": 44}
           and app_mig.active_config_generation == 1)
    try:
        V.migrate_v2_state(False, {"counters": {"in": 1, "out": 1}})
        vector("migration.cross_identity_refused", "FORBIDDEN", False, "accepted")
    except V.SpecViolation as e:
        vector("migration.cross_identity_refused", "FORBIDDEN", e.reason == "FORBIDDEN", e.reason)

    host_gen_wrap = V.HostV3(host_policy=host_v3_full())
    host_gen_wrap.session_generation = 0xFFFFFFFE
    host_gen_wrap.open_session()
    host_gen_wrap.close_session()
    try:
        host_gen_wrap.open_session()
        vector("session.generation_wrap_forbidden", "refused", False, "wrapped")
    except V.SpecViolation as e:
        vector("session.generation_wrap_forbidden", "refused",
               e.reason == "BAD_CONTROL_WIRE", e.reason)


def group_abi_table():
    table = V.encode_abi_table_v3()
    vector("abi.table_60B", "60", len(table) == 60, f"{len(table)}B")
    expect_accept("abi.validate_v3_table", lambda: V.validate_abi_table_v3(table))
    names = [V.ABI_TABLE_V3[o] for o in sorted(k for k in V.ABI_TABLE_V3
                                               if isinstance(k, int))]
    vector("abi.thirteen_callbacks", "13", len(names) == 13, ",".join(names))
    vector("abi.new_callbacks_at_48_52_56", "control_next/control_reply/snapshot_publish",
           V.ABI_TABLE_V3[48] == "control_next" and V.ABI_TABLE_V3[52] == "control_reply"
           and V.ABI_TABLE_V3[56] == "snapshot_publish")

    def wrong_size():
        bad = bytearray(table)
        struct.pack_into("<I", bad, 0, 48)
        return V.validate_abi_table_v3(bytes(bad))

    expect_rejection("abi.negative.table_size_48", wrong_size, "ABI_INCOMPATIBLE")

    def wrong_abi():
        bad = bytearray(table)
        struct.pack_into("<I", bad, 4, V.ABI_V2)
        return V.validate_abi_table_v3(bytes(bad))

    expect_rejection("abi.negative.abi_0x00020000", wrong_abi, "ABI_INCOMPATIBLE")

    def too_short():
        return V.validate_abi_table_v3(table[:48])

    expect_rejection("abi.negative.length_48_prefix", too_short, "ABI_INCOMPATIBLE")

    def null_pointer():
        bad = bytearray(table)
        struct.pack_into("<I", bad, 56, 0)
        return V.validate_abi_table_v3(bytes(bad))

    expect_rejection("abi.negative.null_pointer_offset_56", null_pointer, "ABI_INCOMPATIBLE")

    def no_event_constant():
        return V.control_next_no_event_code() == 1

    vector("abi.control_next_no_event_is_1", "1", no_event_constant())


def write_evidence():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    pkg = golden_package()
    tbs = build_golden_tbs()
    der = bytes.fromhex(GOLDEN_DER_HEX)
    opaque152 = bytes((i * 7 + 3) & 0xFF for i in range(152))
    cmd = V.build_command(V.MSG_CONFIG_APPLY, 7, 42, 6, 0, opaque152)
    rst = V.build_command(V.MSG_COUNTERS_RESET, 7, 43, 7, V.FLAG_DESTRUCTIVE_CONFIRMED, b"")
    rep = V.build_reply(7, 42, V.RESULT_APPLIED, 7, 5)
    snap = V.build_snapshot(7, 5, SNAPSHOT_JSON_GOLDEN)
    files = {
        "golden.neapp.v3": pkg,
        "golden-tbs.bin": tbs,
        "golden-sig.der": der,
        "test-publisher.spki.der": TEST_SPKI,
        "golden-command-config-apply.bin": cmd,
        "golden-command-counters-reset.bin": rst,
        "golden-reply-applied.bin": rep,
        "golden-snapshot.bin": snap,
    }
    for name, data in files.items():
        with open(os.path.join(EVIDENCE_DIR, name), "wb") as f:
            f.write(data)
    report = {
        "suite": "tests/spec-v3",
        "spec": "docs/app-package-protocol-v3.md",
        "scope": "host-side offline spec evidence only",
        "not_proven": ["real Host compilation", "target resource or device writes",
                       "Line Crossing Web", "device PKA", "sustained AI session",
                       "real business config candidate schema/availability "
                       "(App #21; NE301 #57 consumes its reviewed public schema)"],
        "vectors": RESULTS,
        "hashes": {
            "golden_tbs_sha256": V.sha256_hex(tbs),
            "golden_package_sha256": V.sha256_hex(pkg),
            "golden_der": der.hex(),
            "spki_sha256": SPKI_SHA_HEX,
            "command_config_apply_sha256": V.sha256_hex(cmd),
            "command_counters_reset_sha256": V.sha256_hex(rst),
            "reply_applied_sha256": V.sha256_hex(rep),
            "snapshot_sha256": V.sha256_hex(snap),
            "v1_golden_tbs_sha256": V1_GOLDEN_TBS_SHA_HEX,
            "v2_golden_tbs_sha256": V2_GOLDEN_TBS_SHA_HEX,
            "v2_golden_package_sha256": V2_GOLDEN_PKG_SHA_HEX,
        },
        "passed": sum(1 for r in RESULTS if r["ok"]),
        "failed": sum(1 for r in RESULTS if not r["ok"]),
    }
    with open(os.path.join(EVIDENCE_DIR, "report.json"), "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    lines = ["# .neapp v3 spec — offline vector evidence", "",
             "Host-side spec evidence only: no real Host compilation, no resource or",
             "device writes, no Line Crossing Web, no device PKA (spec §14).",
             "The CONFIG_APPLY golden is an opaque-payload transport vector: it proves",
             "control-wire framing/quota/session forwarding only, NOT real business",
             "config availability (candidate schema/validation and the full readable",
             "active-config projection belong to App #21; NE301 #57 consumes its",
             "reviewed public schema). App-owned persistent state (lc_stateblob.c 152B,",
             "counters/window/report_seq) is not a writable config candidate.", "",
             "| vector | expected | result | detail |", "| --- | --- | --- | --- |"]
    for r in RESULTS:
        lines.append(f"| {r['name']} | {r['expected']} | "
                     f"{'PASS' if r['ok'] else 'FAIL'} | {r['detail']} |")
    lines += ["", "## Pinned hashes", ""]
    for k, v in report["hashes"].items():
        lines.append(f"- {k}: `{v}`")
    with open(os.path.join(EVIDENCE_DIR, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def main():
    group_golden()
    group_resigned_policy_negatives()
    group_tamper_and_der()
    group_interop_matrix()
    group_command_wire()
    group_reply_wire()
    group_snapshot_wire()
    group_host_state_machine()
    group_transaction()
    group_abi_table()
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    write_evidence()
    passed = sum(1 for r in RESULTS if r["ok"])
    failed = sum(1 for r in RESULTS if not r["ok"])
    print(f".neapp v3 spec vector suite (evidence -> docs/evidence/spec-v3/)")
    print(f"vectors: {len(RESULTS)}  PASS: {passed}  FAIL: {failed}")
    for r in RESULTS:
        if not r["ok"]:
            print(f"  FAIL {r['name']}: expected {r['expected']} — {r['detail']}")
    print("hashes:")
    print(f"  SHA-256(TBS)      = {V.sha256_hex(build_golden_tbs())}")
    print(f"  SHA-256(package)  = {V.sha256_hex(golden_package())}")
    print(f"  cmd CONFIG_APPLY  = {V.sha256_hex(V.build_command(1, 7, 42, 6, 0, bytes((i * 7 + 3) & 0xFF for i in range(152))))}")
    print(f"  cmd COUNTERS_RST  = {V.sha256_hex(V.build_command(2, 7, 43, 7, 1, b''))}")
    print(f"  reply APPLIED     = {V.sha256_hex(V.build_reply(7, 42, 0, 7, 5))}")
    print(f"  snapshot          = {V.sha256_hex(V.build_snapshot(7, 5, SNAPSHOT_JSON_GOLDEN))}")
    if failed:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS. Host-side spec evidence only — no real Host compile, "
          "no device/resource writes, no Line Crossing Web (spec §14).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
