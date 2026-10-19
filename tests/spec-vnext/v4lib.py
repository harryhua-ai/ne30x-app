"""v4lib — independent stdlib-only implementation of the A-frozen v4
("signed native vNext") byte contract for vector testing (App #36).

The single specification authority is the Host #104 architecture freeze
(harryhua-ai/ne301#104): comments 6258534821 (F1-F4 container/manifest/
caps/table), 6258601629 (F5-F7 v4 control wire NFC4 / ENABLE_SET / Paused
receipt bytes) and 6258637748 (F8-F10 live producer payload LVN4 / GAP
conservation).  This module shares NO code with package/ (v1/v2/v3/v4
tooling) or tests/spec-v2//tests/spec-v3/: P-256, RFC-6979, strict DER,
the container/manifest/native/table rules and the NFC4/LVN4 codecs are
implemented here from scratch so the suite can cross-check the App #36
packer/verifier output as an independent consumer of the same bytes.

Scope: the F1-F4 signed package plus the FROZEN byte formats of F5/F8/F9
(NFC4 header, ENABLE_SET 48B, ENABLE receipt 48B, LVN4 header 48B and the
two record kinds) and their structural negative rules.  NOT implemented
here (NOT_RUN): Host admission/floor semantics, App state CAS, real live
queueing/read-back, device capacity, ARM static asserts — the freeze
itself marks those as future/Host-side or device work.
"""

import hashlib
import hmac
import json as jsonlib
import os
import struct
import subprocess
import zlib

CONTAINER_MAGIC_V4 = bytes.fromhex("4e45415050040000")
MANIFEST_MAGIC_V4 = b"NMF4"
MANIFEST_LEN_V4 = 208
HEADER_LEN = 16

CONTAINER_MAGIC_V3 = bytes.fromhex("4e45415050030000")
CONTAINER_MAGIC_V2 = bytes.fromhex("4e45415050020000")
CONTAINER_MAGIC_V1 = bytes.fromhex("4e45415050010000")
MANIFEST_MAGIC_V3 = b"NMF3"

NATIVE_MAGIC = b"NEA1"
NATIVE_HEADER_SIZE = 32
NATIVE_HDR = struct.Struct("<IHHIIIIII")

ABI_V4 = 0x00040000
ABI_V3 = 0x00030000
BOARD_ID = 0x00003010
PSRAM_MIB = 64
EXEC_BASE = 0x93E00000
EXEC_REGION_BYTES = 0x200000

MAX_NATIVE_FILE_LEN = 2_097_152
MAX_PACKAGE_LEN_V4 = 2_097_448
DER_SIG_MIN = 8
DER_SIG_MAX = 72

CAP_LOG = 1 << 0
CAP_TICK_MS = 1 << 1
CAP_AI_EVENTS = 1 << 2
CAP_REPORT_SUBMIT = 1 << 3
CAP_APP_STATE = 1 << 4
CAP_SESSION_LIFECYCLE = 1 << 5
CAP_CONTROL_RECEIVE = 1 << 6
CAP_BUSINESS_SNAPSHOT = 1 << 7
CAP_ENABLE_CONTROL = 1 << 8
CAP_LIVE_PUBLISH = 1 << 9
CAPS_KNOWN_MASK_V4 = 0x000003FF

RUN_PROFILE_V4 = 3

CONTROL_WIRE_MIN = 32

LIVE_HEADER_SIZE = 48
LIVE_EVENT_RECORD_SIZE = 16
LIVE_EVENT_MAX_RECORDS = 16
LIVE_TRACK_HEADER_SIZE = 12
LIVE_TRACK_POINT_SIZE = 8
LIVE_TRACK_MAX_POINTS = 16
LIVE_PUBLISH_MIN = 312
LIVE_TRACK_MAX_LIMIT = 64
LIVE_KIND_EVENT_BATCH = 1
LIVE_KIND_TRACKS_SNAPSHOT = 2
LIVE_FLAG_SOURCE_GAP_DELTA = 1 << 0
LIVE_FLAG_SOURCE_LOSS_UNKNOWN = 1 << 1
LIVE_FLAG_RESYNC_REQUIRED = 1 << 2
LIVE_FLAGS_KNOWN_MASK = 0x00000007
LIVE_EVENT_FLAG_SOURCE_UNCERTAIN = 1 << 0

NFC4_MAGIC = b"NFC4"
NFC3_MAGIC = b"NFC3"
CONTROL_HEADER_SIZE = 32
NFC_HEADER_VERSION = 1
MSG_CONFIG_APPLY = 1
MSG_COUNTERS_RESET = 2
MSG_CMD_REPLY = 3
MSG_SNAPSHOT = 4
MSG_ENABLE_SET = 5
ENABLE_SET_LEN = 48
ENABLE_RECEIPT_LEN = 48
ENABLE_MAGIC = b"ENB1"
ENABLE_RECEIPT_MAGIC = b"ENR1"
DESIRED_ENABLED = 1
DESIRED_PAUSED = 2
EFFECTIVE_ENABLED = 1
EFFECTIVE_PAUSED = 2
EFFECTIVE_UNKNOWN = 3
STATUS_APPLIED = 0
STATUS_STALE_CONFIG = 1
STATUS_INVALID = 2
STATUS_RESOURCE = 3
STATUS_UNCONFIRMED = 4
STATUS_STATE_CONFLICT = 5
STATUS_STORAGE_IO = 6
STATUS_STORAGE_UNKNOWN = 7
STATUS_KNOWN_MAX = 7

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
SPKI_P256_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200"
)

V4_FUNCTION_NAMES = (
    "log", "tick_ms", "event_next", "model_meta", "class_name",
    "report_submit", "report_status", "state_read", "state_commit",
    "should_stop", "control_next", "control_reply", "snapshot_publish",
    "live_publish",
)
V4_TABLE_SIZE = 64
V3_TABLE_SIZE = 60
V4_TABLE_POINTER_OFFSETS = tuple(range(8, 64, 4))
SIM_POINTER_BASE = 0x93E00001

THUMB_STUB = bytes.fromhex("00207047")

GOLDEN_IMAGE_PARAMS = {
    "publisher_id": "test-publisher",
    "app_id": "line-crossing",
    "version": (4, 0, 0),
    "caps": 0x3FF,
    "event_max": 2048,
    "state_quota": 4096,
    "report_max": 6144,
    "control_max": 256,
    "snapshot_max": 1024,
    "live_publish_max": 1168,
    "live_track_max": 8,
}


class SpecViolation(Exception):
    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _inv(x, m):
    return pow(x, -1, m)


def ec_add(pt1, pt2):
    if pt1 is None:
        return pt2
    if pt2 is None:
        return pt1
    x1, y1 = pt1
    x2, y2 = pt2
    if x1 == x2 % P256_P:
        if (y1 + y2) % P256_P == 0:
            return None
        return ec_double(pt1)
    lam = (y2 - y1) * _inv((x2 - x1) % P256_P, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def ec_double(pt):
    if pt is None or pt[1] % P256_P == 0:
        return None
    lam = (3 * pt[0] * pt[0] - 3) * _inv((2 * pt[1]) % P256_P, P256_P) % P256_P
    x3 = (lam * lam - 2 * pt[0]) % P256_P
    y3 = (lam * (pt[0] - x3) - pt[1]) % P256_P
    return (x3, y3)


def ec_mul(scalar, pt):
    result = None
    addend = pt
    while scalar:
        if scalar & 1:
            result = ec_add(result, addend)
        addend = ec_double(addend)
        scalar >>= 1
    return result


def ec_base_mul(scalar):
    return ec_mul(scalar, (P256_GX, P256_GY))


def public_point_for_scalar(d):
    if not 1 <= d < P256_N:
        raise SpecViolation("KEY_INVALID", "scalar out of range")
    return ec_base_mul(d)


def spki_der_for_point(point):
    body = b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    return SPKI_P256_PREFIX + body


def spki_der_for_scalar(d):
    return spki_der_for_point(public_point_for_scalar(d))


def spki_point(spki_der):
    if len(spki_der) != len(SPKI_P256_PREFIX) + 65:
        raise SpecViolation("KEY_INVALID", "SPKI length unexpected")
    if spki_der[: len(SPKI_P256_PREFIX)] != SPKI_P256_PREFIX:
        raise SpecViolation("KEY_INVALID", "SPKI prefix unexpected")
    if spki_der[len(SPKI_P256_PREFIX)] != 0x04:
        raise SpecViolation("KEY_INVALID", "SPKI point uncompressed flag missing")
    x = int.from_bytes(spki_der[-64:-32], "big")
    y = int.from_bytes(spki_der[-32:], "big")
    if x >= P256_P or y >= P256_P:
        raise SpecViolation("KEY_INVALID", "SPKI coordinate out of field")
    if (y * y - (x * x * x - 3 * x + P256_B)) % P256_P != 0:
        raise SpecViolation("KEY_INVALID", "SPKI point not on curve")
    return (x, y)


def _der_int_encode(value):
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


def encode_der_sig(r, s):
    body = _der_int_encode(r) + _der_int_encode(s)
    return b"\x30" + bytes([len(body)]) + body


def decode_strict_der_sig(sig):
    if not DER_SIG_MIN <= len(sig) <= DER_SIG_MAX:
        raise SpecViolation("BAD_PACKAGE", f"DER length {len(sig)} outside 8..72")
    if sig[0] != 0x30:
        raise SpecViolation("BAD_PACKAGE", "DER SEQUENCE tag missing")
    if sig[1] != len(sig) - 2:
        raise SpecViolation("BAD_PACKAGE", "DER SEQUENCE length not minimal/exact")
    idx = 2

    def read_int():
        nonlocal idx
        if idx + 2 > len(sig) or sig[idx] != 0x02:
            raise SpecViolation("BAD_PACKAGE", "DER INTEGER tag missing")
        length = sig[idx + 1]
        if length == 0 or length > 33 or idx + 2 + length > len(sig):
            raise SpecViolation("BAD_PACKAGE", "DER INTEGER length invalid")
        body = sig[idx + 2 : idx + 2 + length]
        if body[0] & 0x80:
            raise SpecViolation("BAD_PACKAGE", "DER INTEGER negative")
        if body[0] == 0 and length > 1 and body[1] < 0x80:
            raise SpecViolation("BAD_PACKAGE", "DER INTEGER not minimal")
        idx += 2 + length
        value = int.from_bytes(body, "big")
        if not 1 <= value < P256_N:
            raise SpecViolation("BAD_PACKAGE", "DER INTEGER out of 1..n-1")
        return value

    r = read_int()
    s = read_int()
    if idx != len(sig):
        raise SpecViolation("BAD_PACKAGE", "DER trailing bytes after SEQUENCE")
    return r, s


def _rfc6979_candidates(d, digest32):
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + d.to_bytes(32, "big") + digest32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + d.to_bytes(32, "big") + digest32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < P256_N:
            yield candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign(d, digest32):
    z = int.from_bytes(digest32, "big")
    for k in _rfc6979_candidates(d, digest32):
        pt = ec_base_mul(k)
        r = pt[0] % P256_N
        if r == 0:
            continue
        s = _inv(k, P256_N) * (z + r * d) % P256_N
        if s == 0:
            continue
        return r, s
    raise SpecViolation("KEY_INVALID", "no valid k found")


def sign_der(d, tbs):
    return encode_der_sig(*ecdsa_sign(d, sha256(tbs)))


def ecdsa_verify(spki_der, tbs, sig_der):
    public = spki_point(spki_der)
    try:
        r, s = decode_strict_der_sig(sig_der)
    except SpecViolation:
        return False
    z = int.from_bytes(sha256(tbs), "big")
    w = _inv(s, P256_N)
    u1 = z * w % P256_N
    u2 = r * w % P256_N
    point = ec_add(ec_base_mul(u1), ec_mul(u2, public))
    if point is None:
        return False
    return point[0] % P256_N == r


def _enc_identifier(text, width):
    raw = text.encode("ascii")
    if not 1 <= len(raw) <= width:
        raise SpecViolation("BAD_PACKAGE", f"identifier length {len(raw)} not in 1..{width}")
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in text):
        raise SpecViolation("BAD_PACKAGE", f"identifier charset: {text!r}")
    if not ("a" <= text[0] <= "z") or not text[-1].isalnum():
        raise SpecViolation("BAD_PACKAGE", f"identifier edge chars: {text!r}")
    return raw + b"\x00" * (width - len(raw))


def _check_identifier_slot(field, slot):
    text = slot.rstrip(b"\x00")
    if not text:
        raise SpecViolation("BAD_PACKAGE", f"{field}: empty identifier slot")
    if slot[len(text) :] != b"\x00" * (len(slot) - len(text)):
        raise SpecViolation("BAD_PACKAGE", f"{field}: non-zero right padding")
    try:
        s = text.decode("ascii")
    except UnicodeDecodeError:
        raise SpecViolation("BAD_PACKAGE", f"{field}: not ASCII")
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in s):
        raise SpecViolation("BAD_PACKAGE", f"{field}: identifier charset: {s!r}")
    if not ("a" <= s[0] <= "z") or not s[-1].isalnum():
        raise SpecViolation("BAD_PACKAGE", f"{field}: identifier edge chars: {s!r}")


def build_function_table_v4(pointers=None):
    if pointers is None:
        pointers = [SIM_POINTER_BASE + 4 * i for i in range(len(V4_FUNCTION_NAMES))]
    if len(pointers) != len(V4_FUNCTION_NAMES):
        raise SpecViolation("BAD_PACKAGE", f"v4 table needs {len(V4_FUNCTION_NAMES)} pointers")
    out = bytearray(V4_TABLE_SIZE)
    struct.pack_into("<II", out, 0, V4_TABLE_SIZE, ABI_V4)
    for off, ptr in zip(V4_TABLE_POINTER_OFFSETS, pointers):
        if not 0 <= ptr <= 0xFFFFFFFF:
            raise SpecViolation("BAD_PACKAGE", "function pointer out of u32")
        if not ptr & 1:
            raise SpecViolation("BAD_PACKAGE", "function pointer not Thumb")
        struct.pack_into("<I", out, off, ptr)
    return bytes(out)


def parse_function_table_v4(raw):
    if len(raw) != V4_TABLE_SIZE:
        raise SpecViolation(
            "ABI_INCOMPATIBLE",
            f"v4 table is {len(raw)}B, exactly {V4_TABLE_SIZE} required "
            "(a 60B v3 table is foreign input)",
        )
    table_size, abi = struct.unpack_from("<II", raw, 0)
    if table_size != V4_TABLE_SIZE:
        raise SpecViolation("ABI_INCOMPATIBLE", f"table_size {table_size} != {V4_TABLE_SIZE}")
    if abi != ABI_V4:
        raise SpecViolation(
            "ABI_INCOMPATIBLE", f"table abi_version {abi:#010x} != {ABI_V4:#010x}")
    pointers = []
    for name, off in zip(V4_FUNCTION_NAMES, V4_TABLE_POINTER_OFFSETS):
        ptr = struct.unpack_from("<I", raw, off)[0]
        if not ptr:
            raise SpecViolation("ABI_INCOMPATIBLE", f"null pointer for {name}")
        if not ptr & 1:
            raise SpecViolation("ABI_INCOMPATIBLE", f"{name} pointer not Thumb")
        pointers.append(ptr)
    return pointers


def build_native_image_v4(payload=None, target_addr=EXEC_BASE, entry_offset=None,
                          abi_version=ABI_V4):
    if payload is None:
        payload = build_function_table_v4() + THUMB_STUB
    if entry_offset is None:
        entry_offset = (len(payload) - len(THUMB_STUB)
                        if payload.endswith(THUMB_STUB) and len(payload) > len(THUMB_STUB)
                        else 0)
    if len(payload) > MAX_NATIVE_FILE_LEN:
        raise SpecViolation("RESOURCE_LIMIT", "payload over the v4 native file cap")
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    header = NATIVE_HDR.pack(
        0x3141454E, NATIVE_HEADER_SIZE, 1, abi_version,
        target_addr, len(payload), entry_offset, 0, crc)
    return header + payload


def parse_native_header_v4(image):
    if len(image) < NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "native shorter than the 32B header")
    (magic, header_size, format_version, abi_version, target_addr,
     image_size, entry_offset, reserved0, crc) = NATIVE_HDR.unpack_from(image)
    return {
        "magic": magic.to_bytes(4, "little"),
        "header_size": header_size,
        "format_version": format_version,
        "abi_version": abi_version,
        "target_addr": target_addr,
        "image_size": image_size,
        "entry_offset": entry_offset,
        "reserved0": reserved0,
        "crc32": crc,
    }


def validate_native_image_v4(image, manifest=None):
    native = parse_native_header_v4(image)
    if native["magic"] != NATIVE_MAGIC:
        raise SpecViolation("BAD_PACKAGE", "native magic is not NEA1")
    if native["header_size"] != NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", f"native header_size {native['header_size']} != 32")
    if native["format_version"] != 1:
        raise SpecViolation("BAD_PACKAGE", "native format_version != 1")
    if native["reserved0"] != 0:
        raise SpecViolation("BAD_PACKAGE", "native reserved0 not zero")
    if native["abi_version"] != ABI_V4:
        raise SpecViolation(
            "BAD_PACKAGE",
            f"native abi_version {native['abi_version']:#010x} != {ABI_V4:#010x} "
            "(v1/v2/v3 native ABI semantics are never back-filled)")
    if native["image_size"] != len(image) - NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "native image_size != payload bytes")
    if native["entry_offset"] >= native["image_size"]:
        raise SpecViolation("BAD_PACKAGE", "entry_offset outside payload")
    if native["entry_offset"] & 1:
        raise SpecViolation("BAD_PACKAGE", "entry_offset odd (Thumb must be even)")
    if zlib.crc32(image[NATIVE_HEADER_SIZE:]) & 0xFFFFFFFF != native["crc32"]:
        raise SpecViolation("BAD_PACKAGE", "native payload CRC-32 mismatch")
    if manifest is not None:
        if native["image_size"] != manifest["native_image_size"]:
            raise SpecViolation("BAD_PACKAGE", "manifest/native image_size mismatch")
        if native["entry_offset"] != manifest["native_entry_offset"]:
            raise SpecViolation("BAD_PACKAGE", "manifest/native entry_offset mismatch")
        if native["target_addr"] != manifest["native_target_addr"]:
            raise SpecViolation("BAD_PACKAGE", "manifest/native target_addr mismatch")
        if native["abi_version"] != manifest["required_host_abi"]:
            raise SpecViolation("BAD_PACKAGE", "manifest/native abi mismatch")
        if native["image_size"] + NATIVE_HEADER_SIZE != manifest["native_file_len"]:
            raise SpecViolation("BAD_PACKAGE", "manifest native_file_len != 32 + image_size")
        if sha256(image) != manifest["native_file_sha256"]:
            raise SpecViolation("BAD_PACKAGE", "manifest native_file_sha256 mismatch")
        if manifest["required_exec_region_bytes"] < native["image_size"]:
            raise SpecViolation("BAD_PACKAGE", "exec region smaller than payload")
    return native


def validate_policy_shape_v4(caps, run_profile, event_max, state_quota, report_max,
                             control_max, snapshot_max, live_publish_max, live_track_max):
    if caps & ~CAPS_KNOWN_MASK_V4:
        raise SpecViolation("BAD_PACKAGE", f"unknown capability bits {caps & ~CAPS_KNOWN_MASK_V4:#x}")
    if run_profile != RUN_PROFILE_V4:
        raise SpecViolation(
            "BAD_PACKAGE",
            f"unknown run_profile {run_profile} (v4 pins {RUN_PROFILE_V4})")
    if not caps & CAP_SESSION_LIFECYCLE:
        raise SpecViolation("BAD_PACKAGE", "v4 profile 3 requires session_lifecycle (bit5)")
    for bit, quota, cap_name, quota_name in (
        (CAP_AI_EVENTS, event_max, "ai_events (bit2)", "event_max"),
        (CAP_REPORT_SUBMIT, report_max, "report_submit (bit3)", "report_max"),
        (CAP_APP_STATE, state_quota, "app_state (bit4)", "state_quota"),
        (CAP_CONTROL_RECEIVE, control_max, "control_receive (bit6)", "control_max"),
        (CAP_BUSINESS_SNAPSHOT, snapshot_max, "business_snapshot (bit7)", "snapshot_max"),
    ):
        if caps & bit and quota == 0:
            raise SpecViolation("BAD_PACKAGE", f"{cap_name} requires nonzero {quota_name}")
        if quota and not caps & bit:
            raise SpecViolation("BAD_PACKAGE", f"{quota_name} set without {cap_name}")
    if caps & CAP_CONTROL_RECEIVE and control_max < CONTROL_WIRE_MIN:
        raise SpecViolation(
            "RESOURCE_LIMIT",
            f"control_max {control_max} below the generic 32B control-wire minimum")
    if caps & CAP_ENABLE_CONTROL:
        missing = [n for b, n in (
            (CAP_APP_STATE, "app_state (bit4)"),
            (CAP_SESSION_LIFECYCLE, "session_lifecycle (bit5)"),
            (CAP_CONTROL_RECEIVE, "control_receive (bit6)"),
        ) if not caps & b]
        if missing:
            raise SpecViolation(
                "BAD_PACKAGE", f"ENABLE_CONTROL (bit8) missing prerequisites: {', '.join(missing)}")
    if caps & CAP_LIVE_PUBLISH:
        if not caps & CAP_SESSION_LIFECYCLE:
            raise SpecViolation("BAD_PACKAGE", "LIVE_PUBLISH (bit9) requires bit5")
        if live_publish_max < LIVE_PUBLISH_MIN:
            raise SpecViolation(
                "RESOURCE_LIMIT",
                f"live_publish_max {live_publish_max} < {LIVE_PUBLISH_MIN}")
        if not 1 <= live_track_max <= LIVE_TRACK_MAX_LIMIT:
            raise SpecViolation(
                "BAD_PACKAGE", f"live_track_max {live_track_max} outside 1..{LIVE_TRACK_MAX_LIMIT}")
        closure = LIVE_HEADER_SIZE + live_track_max * (
            LIVE_TRACK_HEADER_SIZE + LIVE_TRACK_MAX_POINTS * LIVE_TRACK_POINT_SIZE)
        if live_publish_max < closure:
            raise SpecViolation(
                "RESOURCE_LIMIT",
                f"live_publish_max {live_publish_max} below the kind2 closure {closure}")
    else:
        if live_publish_max or live_track_max:
            raise SpecViolation(
                "BAD_PACKAGE",
                "live quotas must be 0 without LIVE_PUBLISH (bit9)")


def build_manifest_v4(publisher_id, app_id, version, caps, event_max, state_quota,
                      report_max, control_max, snapshot_max, live_publish_max,
                      live_track_max, native, spki_sha256, board_id=BOARD_ID,
                      psram_mib=PSRAM_MIB, exec_region=None):
    if len(native) < NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "native shorter than the header")
    native_hdr = parse_native_header_v4(native)
    if exec_region is None:
        exec_region = native_hdr["image_size"]
    validate_policy_shape_v4(caps, RUN_PROFILE_V4, event_max, state_quota, report_max,
                             control_max, snapshot_max, live_publish_max, live_track_max)
    m = bytearray(MANIFEST_LEN_V4)
    m[0:4] = MANIFEST_MAGIC_V4
    m[4:20] = _enc_identifier(publisher_id, 16)
    m[20:52] = _enc_identifier(app_id, 32)
    struct.pack_into("<HHH", m, 52, version[0], version[1], version[2])
    struct.pack_into("<I", m, 60, board_id)
    struct.pack_into("<I", m, 64, psram_mib)
    struct.pack_into("<I", m, 68, ABI_V4)
    struct.pack_into("<I", m, 72, caps)
    struct.pack_into("<I", m, 76, exec_region)
    struct.pack_into("<I", m, 80, len(native))
    struct.pack_into("<I", m, 84, len(native) - NATIVE_HEADER_SIZE)
    struct.pack_into("<I", m, 88, native_hdr["entry_offset"])
    struct.pack_into("<I", m, 92, native_hdr["target_addr"])
    m[96:128] = sha256(native)
    m[128:160] = spki_sha256
    struct.pack_into("<I", m, 160, RUN_PROFILE_V4)
    struct.pack_into("<I", m, 164, event_max)
    struct.pack_into("<I", m, 168, state_quota)
    struct.pack_into("<I", m, 172, report_max)
    struct.pack_into("<I", m, 176, control_max)
    struct.pack_into("<I", m, 180, snapshot_max)
    struct.pack_into("<I", m, 184, live_publish_max)
    struct.pack_into("<I", m, 188, live_track_max)
    return bytes(m)


def parse_manifest_v4(raw):
    if len(raw) != MANIFEST_LEN_V4:
        raise SpecViolation("BAD_PACKAGE", f"manifest is {len(raw)}B, exactly {MANIFEST_LEN_V4} required")
    if raw[0:4] != MANIFEST_MAGIC_V4:
        raise SpecViolation(
            "BAD_PACKAGE",
            f"manifest magic {raw[0:4]!r} != NMF4 (a v3 NMF3 manifest is foreign input)")
    if raw[58:60] != b"\x00\x00":
        raise SpecViolation("BAD_PACKAGE", "reserved [58..59] not zero")
    if raw[192:208] != b"\x00" * 16:
        raise SpecViolation("BAD_PACKAGE", "reserved [192..207] not zero")
    abi = struct.unpack_from("<I", raw, 68)[0]
    if abi != ABI_V4:
        raise SpecViolation(
            "BAD_PACKAGE", f"required_host_abi {abi:#010x} != {ABI_V4:#010x} (format invariant)")
    _check_identifier_slot("publisher_id", raw[4:20])
    _check_identifier_slot("app_id", raw[20:52])
    (board, psram, _abi, caps, exec_region, file_len, image_size, entry, target) = (
        struct.unpack_from("<9I", raw, 60))
    (run_profile, event_max, state_quota, report_max, control_max, snapshot_max) = (
        struct.unpack_from("<6I", raw, 160))
    live_publish_max, live_track_max = struct.unpack_from("<2I", raw, 184)
    return {
        "publisher_id": raw[4:20],
        "app_id": raw[20:52],
        "version": struct.unpack_from("<HHH", raw, 52),
        "target_board_id": board,
        "required_psram_mib": psram,
        "required_host_abi": abi,
        "required_host_caps": caps,
        "required_exec_region_bytes": exec_region,
        "native_file_len": file_len,
        "native_image_size": image_size,
        "native_entry_offset": entry,
        "native_target_addr": target,
        "native_file_sha256": raw[96:128],
        "publisher_key_sha256": raw[128:160],
        "run_profile": run_profile,
        "event_max": event_max,
        "state_quota": state_quota,
        "report_max": report_max,
        "control_max": control_max,
        "snapshot_max": snapshot_max,
        "live_publish_max": live_publish_max,
        "live_track_max": live_track_max,
    }


def build_container_prefix_v4(manifest, native):
    if len(manifest) != MANIFEST_LEN_V4:
        raise SpecViolation("BAD_PACKAGE", "manifest must be exactly 208B")
    return (CONTAINER_MAGIC_V4
            + struct.pack("<II", MANIFEST_LEN_V4, len(native))
            + manifest + native)


def verify_package_v4(data, trust, host_caps_provided=None, policy=None):
    """Structural/intrinsic verification in the frozen check order.

    trust: publisher_id-string -> (spki_der).  policy (optional dict):
    target_board_id, psram_mib, host_abi, host_caps, capacity ceilings,
    loader_base/loader_size/exec_region_bytes — Host-side admission facts;
    when absent the Host-admission tier is skipped entirely (the intrinsic
    tier alone never claims Host admission)."""
    if len(data) < HEADER_LEN:
        raise SpecViolation("BAD_PACKAGE", "shorter than the container header")
    if data[0:8] != CONTAINER_MAGIC_V4:
        raise SpecViolation(
            "BAD_PACKAGE",
            "container magic is not NEAPP v4; v1/v2/v3 majors are foreign input")
    manifest_len, native_len = struct.unpack_from("<II", data, 8)
    if manifest_len != MANIFEST_LEN_V4:
        raise SpecViolation("BAD_PACKAGE", f"manifest_len {manifest_len} != 208")
    if native_len < NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "native_file_len cannot hold the 32B header")
    if native_len > MAX_NATIVE_FILE_LEN:
        raise SpecViolation("BAD_PACKAGE", f"native_file_len {native_len} over the v4 cap")
    signed_len = 224 + native_len
    if len(data) < signed_len:
        raise SpecViolation("BAD_PACKAGE", "file truncated before the signed region")
    sig = data[signed_len:]
    if not DER_SIG_MIN <= len(sig) <= DER_SIG_MAX:
        raise SpecViolation("BAD_PACKAGE", f"signature segment {len(sig)}B outside 8..72")
    if signed_len + len(sig) > MAX_PACKAGE_LEN_V4:
        raise SpecViolation("BAD_PACKAGE", "package over the v4 cap")
    tbs = data[:signed_len]

    r, s = decode_strict_der_sig(sig)

    manifest = parse_manifest_v4(data[HEADER_LEN:HEADER_LEN + MANIFEST_LEN_V4])

    pub_id = manifest["publisher_id"].rstrip(b"\x00").decode("ascii")
    if pub_id not in trust:
        raise SpecViolation(
            "PUBLISHER_UNTRUSTED",
            f"publisher {pub_id!r} not in the local trust mapping (package keys never self-trust)")
    spki = trust[pub_id]
    if manifest["publisher_key_sha256"] != sha256(spki):
        raise SpecViolation(
            "PUBLISHER_UNTRUSTED",
            f"manifest publisher_key_sha256 does not match the trusted key for {pub_id!r}")
    if not ecdsa_verify(spki, tbs, sig):
        raise SpecViolation("SIGNATURE_INVALID", "ECDSA P-256/SHA-256 failed over the exact TBS")

    native = data[HEADER_LEN + MANIFEST_LEN_V4:signed_len]
    if manifest["native_file_len"] != native_len:
        raise SpecViolation("BAD_PACKAGE", "manifest native_file_len != container native_file_len")
    validate_native_image_v4(native, manifest)

    validate_policy_shape_v4(
        manifest["required_host_caps"], manifest["run_profile"],
        manifest["event_max"], manifest["state_quota"], manifest["report_max"],
        manifest["control_max"], manifest["snapshot_max"],
        manifest["live_publish_max"], manifest["live_track_max"])

    if policy is not None:
        if manifest["target_board_id"] != policy.get("target_board_id", BOARD_ID):
            raise SpecViolation("TARGET_INCOMPATIBLE", "board mismatch")
        if manifest["required_psram_mib"] > policy.get("psram_mib", PSRAM_MIB):
            raise SpecViolation("TARGET_INCOMPATIBLE", "psram unsupported")
        if manifest["required_host_abi"] != policy.get("host_abi", ABI_V4):
            raise SpecViolation("ABI_INCOMPATIBLE", "abi mismatch")
        provided = policy.get("host_caps", CAPS_KNOWN_MASK_V4)
        unsupported = manifest["required_host_caps"] & ~provided
        if unsupported:
            raise SpecViolation(
                "ABI_INCOMPATIBLE",
                f"Host does not provide capability bits {unsupported:#x}")
        for cap, manifest_key, policy_key in (
            (CAP_AI_EVENTS, "event_max", "event_buffer_bytes"),
            (CAP_REPORT_SUBMIT, "report_max", "report_capacity_bytes"),
            (CAP_APP_STATE, "state_quota", "state_quota_bytes"),
            (CAP_CONTROL_RECEIVE, "control_max", "control_msg_bytes"),
            (CAP_BUSINESS_SNAPSHOT, "snapshot_max", "snapshot_ram_bytes"),
        ):
            if manifest["required_host_caps"] & cap and policy.get(policy_key) is not None \
                    and manifest[manifest_key] > policy[policy_key]:
                raise SpecViolation(
                    "RESOURCE_LIMIT",
                    f"{policy_key} ceiling exceeded")
        if manifest["required_host_caps"] & CAP_LIVE_PUBLISH:
            if policy.get("live_capacity_bytes") is not None \
                    and manifest["live_publish_max"] > policy["live_capacity_bytes"]:
                raise SpecViolation(
                    "RESOURCE_LIMIT",
                    "live_publish_max over Host live capacity; the capability is refused "
                    "whole rather than degraded")
            if policy.get("live_capacity_tracks") is not None \
                    and manifest["live_track_max"] > policy["live_capacity_tracks"]:
                raise SpecViolation("RESOURCE_LIMIT", "live_track_max over Host capacity")
        base = policy.get("loader_base", EXEC_BASE)
        size = policy.get("loader_size", EXEC_REGION_BYTES)
        if not (base <= manifest["native_target_addr"] < base + size
                and manifest["native_target_addr"] + manifest["native_file_len"] <= base + size):
            raise SpecViolation("RESOURCE_LIMIT", "target outside the loader range")
        if manifest["required_exec_region_bytes"] > policy.get(
                "exec_region_bytes", EXEC_REGION_BYTES):
            raise SpecViolation("RESOURCE_LIMIT", "exec region over Host capacity")
        if manifest["native_file_len"] > policy.get("load_region_bytes", EXEC_REGION_BYTES):
            raise SpecViolation("RESOURCE_LIMIT", "native file over the load region")

    return {
        "result": "PASS",
        "format": "neapp-v4",
        "package_sha256": sha256_hex(data),
        "tbs_sha256": sha256_hex(tbs),
        "tbs_len": signed_len,
        "sig_len": len(sig),
        "publisher_id": pub_id,
        "app_id": manifest["app_id"].rstrip(b"\x00").decode("ascii"),
        "caps": manifest["required_host_caps"],
        "run_profile": manifest["run_profile"],
        "live_publish_max": manifest["live_publish_max"],
        "live_track_max": manifest["live_track_max"],
        "boundary": (
            "signed-format PASS only: NOT Host admission, NOT native runtime "
            "admission; ENABLE_CONTROL/LIVE_PUBLISH need actual Host grant"),
    }


# ---------------- NFC4 control wire (Host #104 F5) ----------------

def build_nfc4_header(msg_type, total_len, session_generation, request_id,
                      config_generation, state_revision, flags):
    out = bytearray(CONTROL_HEADER_SIZE)
    out[0:4] = NFC4_MAGIC
    struct.pack_into("<H", out, 4, NFC_HEADER_VERSION)
    struct.pack_into("<H", out, 6, msg_type)
    struct.pack_into("<I", out, 8, total_len)
    struct.pack_into("<I", out, 12, session_generation)
    struct.pack_into("<I", out, 16, request_id)
    struct.pack_into("<I", out, 20, config_generation)
    struct.pack_into("<I", out, 24, state_revision)
    struct.pack_into("<I", out, 28, flags)
    return bytes(out)


def parse_nfc4_header(data):
    if len(data) < CONTROL_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "control message shorter than the 32B header")
    if data[0:4] != NFC4_MAGIC:
        raise SpecViolation(
            "BAD_PACKAGE",
            f"control magic {data[0:4]!r} != NFC4 (a v3 NFC3 message is foreign input "
            "and must never be reinterpreted as v4)")
    version, msg_type = struct.unpack_from("<HH", data, 4)
    if version != NFC_HEADER_VERSION:
        raise SpecViolation("BAD_PACKAGE", f"control header_version {version} != 1")
    total_len = struct.unpack_from("<I", data, 8)[0]
    if total_len != len(data):
        raise SpecViolation("BAD_PACKAGE", f"total_len {total_len} != {len(data)}")
    return {
        "msg_type": msg_type,
        "total_len": total_len,
        "session_generation": struct.unpack_from("<I", data, 12)[0],
        "request_id": struct.unpack_from("<I", data, 16)[0],
        "config_generation": struct.unpack_from("<I", data, 20)[0],
        "state_revision": struct.unpack_from("<I", data, 24)[0],
        "flags": struct.unpack_from("<I", data, 28)[0],
    }


def build_enable_set(session_generation, request_id, config_generation,
                     expected_state_revision, desired_state):
    header = build_nfc4_header(MSG_ENABLE_SET, ENABLE_SET_LEN, session_generation,
                               request_id, config_generation, 0, 0)
    if desired_state not in (DESIRED_ENABLED, DESIRED_PAUSED):
        raise SpecViolation("BAD_PACKAGE", f"desired_state {desired_state} not in (1,2)")
    payload = bytearray(16)
    payload[0:4] = ENABLE_MAGIC
    struct.pack_into("<I", payload, 4, desired_state)
    struct.pack_into("<I", payload, 8, expected_state_revision)
    struct.pack_into("<I", payload, 12, 0)
    return header + bytes(payload)


def parse_enable_set(data):
    header = parse_nfc4_header(data)
    if header["msg_type"] != MSG_ENABLE_SET:
        raise SpecViolation("BAD_PACKAGE", f"msg_type {header['msg_type']} != 5 (ENABLE_SET)")
    if header["total_len"] != ENABLE_SET_LEN:
        raise SpecViolation("BAD_PACKAGE", f"ENABLE_SET is {header['total_len']}B, exactly 48 required")
    if header["session_generation"] == 0:
        raise SpecViolation("BAD_PACKAGE", "session_generation must be nonzero")
    if header["request_id"] == 0:
        raise SpecViolation("BAD_PACKAGE", "request_id must be nonzero")
    if header["config_generation"] == 0:
        raise SpecViolation("BAD_PACKAGE", "config_generation must be the active nonzero generation")
    if header["state_revision"] != 0:
        raise SpecViolation("BAD_PACKAGE", "state_revision must be 0 for ENABLE_SET")
    if header["flags"] != 0:
        raise SpecViolation("BAD_PACKAGE", "flags must be 0 for ENABLE_SET")
    if data[32:36] != ENABLE_MAGIC:
        raise SpecViolation("BAD_PACKAGE", f"payload magic {data[32:36]!r} != ENB1")
    desired_state = struct.unpack_from("<I", data, 36)[0]
    if desired_state not in (DESIRED_ENABLED, DESIRED_PAUSED):
        raise SpecViolation("BAD_PACKAGE", f"desired_state {desired_state} not in (1,2)")
    if struct.unpack_from("<I", data, 44)[0] != 0:
        raise SpecViolation("BAD_PACKAGE", "payload reserved must be 0")
    header["desired_state"] = desired_state
    header["expected_state_revision"] = struct.unpack_from("<I", data, 40)[0]
    return header


def build_enable_receipt(session_generation, request_id, config_generation,
                         state_revision, status, effective_state,
                         readback_state_revision):
    if status not in range(STATUS_KNOWN_MAX + 1):
        raise SpecViolation("BAD_PACKAGE", f"status {status} outside the known 0..7")
    if effective_state not in (EFFECTIVE_ENABLED, EFFECTIVE_PAUSED, EFFECTIVE_UNKNOWN):
        raise SpecViolation("BAD_PACKAGE", f"effective_state {effective_state} not in (1,2,3)")
    if readback_state_revision != state_revision:
        raise SpecViolation(
            "BAD_PACKAGE",
            "readback_state_revision must equal the header state_revision (F5)")
    header = build_nfc4_header(MSG_CMD_REPLY, ENABLE_RECEIPT_LEN, session_generation,
                               request_id, config_generation, state_revision, status)
    payload = bytearray(16)
    payload[0:4] = ENABLE_RECEIPT_MAGIC
    struct.pack_into("<I", payload, 4, effective_state)
    struct.pack_into("<I", payload, 8, readback_state_revision)
    struct.pack_into("<I", payload, 12, 0)
    return header + bytes(payload)


def parse_enable_receipt(data):
    header = parse_nfc4_header(data)
    if header["msg_type"] != MSG_CMD_REPLY:
        raise SpecViolation("BAD_PACKAGE", f"msg_type {header['msg_type']} != 3 (RECEIPT)")
    if header["total_len"] == ENABLE_RECEIPT_LEN:
        if data[32:36] != ENABLE_RECEIPT_MAGIC:
            raise SpecViolation("BAD_PACKAGE", f"48B receipt payload magic {data[32:36]!r} != ENR1")
        effective_state = struct.unpack_from("<I", data, 36)[0]
        if effective_state not in (EFFECTIVE_ENABLED, EFFECTIVE_PAUSED, EFFECTIVE_UNKNOWN):
            raise SpecViolation("BAD_PACKAGE", f"effective_state {effective_state} not in (1,2,3)")
        readback = struct.unpack_from("<I", data, 40)[0]
        if readback != header["state_revision"]:
            raise SpecViolation(
                "BAD_PACKAGE", "readback_state_revision != header state_revision")
        if struct.unpack_from("<I", data, 44)[0] != 0:
            raise SpecViolation("BAD_PACKAGE", "receipt reserved must be 0")
        header["effective_state"] = effective_state
        header["readback_state_revision"] = readback
    elif header["total_len"] != CONTROL_HEADER_SIZE:
        raise SpecViolation(
            "BAD_PACKAGE",
            f"v4 receipt is {header['total_len']}B; only 32B (non-enable) or the "
            "ENR1 48B enable receipt are defined")
    if header["flags"] > STATUS_KNOWN_MAX:
        raise SpecViolation("BAD_PACKAGE", f"status {header['flags']} outside the known 0..7")
    header["status"] = header["flags"]
    return header


class EnableCommandCache:
    """F5 dedup rule: identical envelope+payload under the same
    (session, request_id) may be served from cache; any other payload with
    the same id must be refused, never re-executed."""

    def __init__(self):
        self._cache = {}

    def feed(self, raw):
        header = parse_nfc4_header(raw)
        key = (header["session_generation"], header["request_id"])
        cached = self._cache.get(key)
        if cached is None:
            self._cache[key] = raw
            return "EXECUTED"
        if cached == raw:
            return "CACHED"
        raise SpecViolation(
            "BAD_PACKAGE",
            "same request_id with a different envelope/payload must be refused")


# ---------------- LVN4 live producer packets (Host #104 F8/F9) ----------------

def build_live_header(kind, total_len, packet_seq, event_through_seq,
                      cumulative_event_total, cumulative_source_gap, source_ts_ms,
                      config_generation, record_count, flags):
    if flags & ~LIVE_FLAGS_KNOWN_MASK:
        raise SpecViolation("BAD_PACKAGE", f"live flags {flags:#x} use reserved bits 3..31")
    out = bytearray(LIVE_HEADER_SIZE)
    out[0:4] = b"LVN4"
    struct.pack_into("<H", out, 4, 1)
    struct.pack_into("<H", out, 6, kind)
    struct.pack_into("<I", out, 8, total_len)
    struct.pack_into("<I", out, 12, packet_seq)
    struct.pack_into("<I", out, 16, event_through_seq)
    struct.pack_into("<I", out, 20, cumulative_event_total)
    struct.pack_into("<I", out, 24, cumulative_source_gap)
    struct.pack_into("<I", out, 28, source_ts_ms)
    struct.pack_into("<I", out, 32, config_generation)
    struct.pack_into("<I", out, 36, record_count)
    struct.pack_into("<I", out, 40, flags)
    struct.pack_into("<I", out, 44, 0)
    return bytes(out)


def build_event_batch(events, packet_seq, event_through_seq, cumulative_event_total,
                      cumulative_source_gap, source_ts_ms, config_generation, flags=0):
    if len(events) > LIVE_EVENT_MAX_RECORDS:
        raise SpecViolation(
            "RESOURCE_LIMIT",
            f"{len(events)} events over the {LIVE_EVENT_MAX_RECORDS}-record bound")
    for ev in events:
        if ev["direction"] not in (1, 2):
            raise SpecViolation("BAD_PACKAGE", f"direction {ev['direction']} not in (1,2)")
        if ev.get("flags", 0) & ~LIVE_EVENT_FLAG_SOURCE_UNCERTAIN:
            raise SpecViolation("BAD_PACKAGE", "event flags use reserved bits")
    payload = bytearray()
    prev_seq = None
    for ev in events:
        if prev_seq is not None and ev["event_seq"] <= prev_seq:
            raise SpecViolation(
                "BAD_PACKAGE", "event_seq values must strictly increase within a packet")
        prev_seq = ev["event_seq"]
        record = struct.pack(
            "<IIIBBBB",
            ev["event_seq"], ev["track_id"], ev["event_ts_ms"], ev["direction"],
            ev.get("flags", 0), ev.get("x_q8", 255), ev.get("y_q8", 255))
        payload += record
    total = LIVE_HEADER_SIZE + len(payload)
    return build_live_header(
        LIVE_KIND_EVENT_BATCH, total, packet_seq, event_through_seq,
        cumulative_event_total, cumulative_source_gap, source_ts_ms,
        config_generation, len(events), flags) + bytes(payload)


def build_tracks_snapshot(tracks, packet_seq, event_through_seq, cumulative_event_total,
                          cumulative_source_gap, source_ts_ms, config_generation,
                          live_track_max, flags=0):
    if len(tracks) > live_track_max or len(tracks) > LIVE_TRACK_MAX_LIMIT:
        raise SpecViolation(
            "RESOURCE_LIMIT",
            f"{len(tracks)} tracks over the signed/host bound {min(live_track_max, LIVE_TRACK_MAX_LIMIT)}")
    seen = set()
    payload = bytearray()
    for tr in tracks:
        if tr["track_id"] == 0:
            raise SpecViolation("BAD_PACKAGE", "track_id must be nonzero")
        if tr["track_id"] in seen:
            raise SpecViolation("BAD_PACKAGE", f"duplicate track_id {tr['track_id']}")
        seen.add(tr["track_id"])
        points = tr.get("points", [])
        if not 0 <= len(points) <= LIVE_TRACK_MAX_POINTS:
            raise SpecViolation("BAD_PACKAGE", f"point_count {len(points)} outside 0..{LIVE_TRACK_MAX_POINTS}")
        class_index = tr.get("class_index", 0xFFFF)
        state = tr.get("state", 1)
        if state != 1:
            raise SpecViolation("BAD_PACKAGE", f"track state {state} != 1 (ACTIVE)")
        tr_flags = tr.get("flags", 0)
        if tr_flags != 0:
            raise SpecViolation("BAD_PACKAGE", f"track flags {tr_flags} reserved (must be 0)")
        record = struct.pack(
            "<IHHBBH", tr["track_id"], len(points), class_index, state, tr_flags,
            tr.get("confidence_q16", 0xFFFF))
        record += b"".join(struct.pack("<IHH", p["ts_ms"], p["x_q16"], p["y_q16"])
                           for p in points)
        payload += record
    total = LIVE_HEADER_SIZE + len(payload)
    return build_live_header(
        LIVE_KIND_TRACKS_SNAPSHOT, total, packet_seq, event_through_seq,
        cumulative_event_total, cumulative_source_gap, source_ts_ms,
        config_generation, len(tracks), flags) + bytes(payload)


def parse_live_packet(data, live_publish_max=None, live_track_max=None):
    if len(data) < LIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "live packet shorter than the 48B header")
    if data[0:4] != b"LVN4":
        raise SpecViolation("BAD_PACKAGE", f"live magic {data[0:4]!r} != LVN4")
    version, kind = struct.unpack_from("<HH", data, 4)
    if version != 1:
        raise SpecViolation("BAD_PACKAGE", f"live header_version {version} != 1")
    if kind not in (LIVE_KIND_EVENT_BATCH, LIVE_KIND_TRACKS_SNAPSHOT):
        raise SpecViolation("BAD_PACKAGE", f"live kind {kind} not in (1,2)")
    total_len = struct.unpack_from("<I", data, 8)[0]
    if total_len != len(data):
        raise SpecViolation("BAD_PACKAGE", f"total_len {total_len} != {len(data)}")
    if live_publish_max is not None and total_len > live_publish_max:
        raise SpecViolation(
            "RESOURCE_LIMIT",
            f"packet {total_len}B over the signed live_publish_max {live_publish_max}")
    packet_seq = struct.unpack_from("<I", data, 12)[0]
    if packet_seq == 0:
        raise SpecViolation("BAD_PACKAGE", "packet_seq must be session-nonzero")
    if struct.unpack_from("<I", data, 32)[0] == 0:
        raise SpecViolation("BAD_PACKAGE", "config_generation must be nonzero")
    record_count = struct.unpack_from("<I", data, 36)[0]
    flags = struct.unpack_from("<I", data, 40)[0]
    if flags & ~LIVE_FLAGS_KNOWN_MASK:
        raise SpecViolation("BAD_PACKAGE", f"live flags {flags:#x} use reserved bits 3..31")
    if struct.unpack_from("<I", data, 44)[0] != 0:
        raise SpecViolation("BAD_PACKAGE", "live header reserved must be 0")
    header = {
        "kind": kind,
        "total_len": total_len,
        "packet_seq": packet_seq,
        "event_through_seq": struct.unpack_from("<I", data, 16)[0],
        "cumulative_event_total": struct.unpack_from("<I", data, 20)[0],
        "cumulative_source_gap": struct.unpack_from("<I", data, 24)[0],
        "source_ts_ms": struct.unpack_from("<I", data, 28)[0],
        "config_generation": struct.unpack_from("<I", data, 32)[0],
        "record_count": record_count,
        "flags": flags,
    }
    body = data[LIVE_HEADER_SIZE:]
    if kind == LIVE_KIND_EVENT_BATCH:
        if record_count > LIVE_EVENT_MAX_RECORDS:
            raise SpecViolation(
                "RESOURCE_LIMIT",
                f"{record_count} event records over the {LIVE_EVENT_MAX_RECORDS} bound")
        if len(body) != record_count * LIVE_EVENT_RECORD_SIZE:
            raise SpecViolation(
                "BAD_PACKAGE",
                f"event batch body {len(body)}B != {record_count} * 16B (exact closure)")
        events = []
        prev_seq = None
        for i in range(record_count):
            rec = body[i * LIVE_EVENT_RECORD_SIZE:(i + 1) * LIVE_EVENT_RECORD_SIZE]
            seq, track_id, ts, direction, ev_flags, x_q8, y_q8 = struct.unpack(
                "<IIIBBBB", rec)
            if prev_seq is not None and seq <= prev_seq:
                raise SpecViolation(
                    "BAD_PACKAGE", "event_seq values must strictly increase within a packet")
            prev_seq = seq
            if seq > header["event_through_seq"]:
                raise SpecViolation(
                    "BAD_PACKAGE", f"event_seq {seq} exceeds event_through_seq {header['event_through_seq']}")
            if direction not in (1, 2):
                raise SpecViolation("BAD_PACKAGE", f"direction {direction} not in (1,2)")
            if ev_flags & ~LIVE_EVENT_FLAG_SOURCE_UNCERTAIN:
                raise SpecViolation("BAD_PACKAGE", "event flags use reserved bits")
            events.append({"event_seq": seq, "track_id": track_id, "event_ts_ms": ts,
                           "direction": direction, "flags": ev_flags,
                           "x_q8": x_q8, "y_q8": y_q8})
        header["events"] = events
    else:
        if live_track_max is not None and record_count > min(live_track_max, LIVE_TRACK_MAX_LIMIT):
            raise SpecViolation(
                "RESOURCE_LIMIT",
                f"{record_count} tracks over the bound {min(live_track_max, LIVE_TRACK_MAX_LIMIT)}")
        tracks = []
        seen = set()
        pos = 0
        for _ in range(record_count):
            if pos + LIVE_TRACK_HEADER_SIZE > len(body):
                raise SpecViolation("BAD_PACKAGE", "track header overruns the packet")
            track_id, point_count, class_index, state, tr_flags, confidence = struct.unpack_from(
                "<IHHBBH", body, pos)
            pos += LIVE_TRACK_HEADER_SIZE
            if track_id == 0:
                raise SpecViolation("BAD_PACKAGE", "track_id must be nonzero")
            if track_id in seen:
                raise SpecViolation("BAD_PACKAGE", f"duplicate track_id {track_id}")
            seen.add(track_id)
            if point_count > LIVE_TRACK_MAX_POINTS:
                raise SpecViolation(
                    "BAD_PACKAGE", f"point_count {point_count} > {LIVE_TRACK_MAX_POINTS}")
            if state != 1:
                raise SpecViolation("BAD_PACKAGE", f"track state {state} != 1 (ACTIVE)")
            if tr_flags != 0:
                raise SpecViolation("BAD_PACKAGE", f"track flags {tr_flags} reserved (must be 0)")
            end = pos + point_count * LIVE_TRACK_POINT_SIZE
            if end > len(body):
                raise SpecViolation("BAD_PACKAGE", "track points overrun the packet")
            points = []
            while pos < end:
                ts, x_q16, y_q16 = struct.unpack_from("<IHH", body, pos)
                points.append({"ts_ms": ts, "x_q16": x_q16, "y_q16": y_q16})
                pos += LIVE_TRACK_POINT_SIZE
            tracks.append({"track_id": track_id, "class_index": class_index,
                           "state": state, "flags": tr_flags,
                           "confidence_q16": confidence, "points": points})
        if pos != len(body):
            raise SpecViolation(
                "BAD_PACKAGE",
                f"{len(body) - pos} trailing bytes after the last track record (exact parse required)")
        header["tracks"] = tracks
    return header


class Lvn4SessionModel:
    """F8 conservation model for one trusted session: packet_seq strictly +1,
    watermarks non-decreasing, u32 exhaustion fails closed (no silent wrap),
    and SOURCE_LOSS_UNKNOWN is never mistaken for a precise gap."""

    def __init__(self):
        self.last_packet_seq = None
        self.through_seq = 0
        self.cumulative_event_total = 0
        self.cumulative_source_gap = 0

    def feed(self, pkt):
        if pkt["packet_seq"] != (self.last_packet_seq + 1 if self.last_packet_seq is not None else 1):
            raise SpecViolation(
                "BAD_PACKAGE",
                f"packet_seq {pkt['packet_seq']} must be exactly "
                f"{(self.last_packet_seq or 0) + 1} in this session (no reuse/wrap)")
        if pkt["event_through_seq"] < self.through_seq:
            raise SpecViolation("BAD_PACKAGE", "event_through_seq regressed")
        if pkt["cumulative_event_total"] < self.cumulative_event_total:
            raise SpecViolation("BAD_PACKAGE", "cumulative_event_total regressed")
        if pkt["cumulative_source_gap"] < self.cumulative_source_gap:
            raise SpecViolation("BAD_PACKAGE", "cumulative_source_gap regressed")
        if pkt["cumulative_event_total"] >= 0xFFFFFFFF and not pkt["flags"] & LIVE_FLAG_RESYNC_REQUIRED:
            raise SpecViolation(
                "BAD_PACKAGE",
                "u32 cumulative near exhaustion requires explicit RESYNC_REQUIRED, "
                "never a silent wrap")
        if pkt["flags"] & LIVE_FLAG_SOURCE_LOSS_UNKNOWN \
                and not pkt["flags"] & LIVE_FLAG_SOURCE_GAP_DELTA \
                and pkt["cumulative_source_gap"] == self.cumulative_source_gap:
            raise SpecViolation(
                "BAD_PACKAGE",
                "SOURCE_LOSS_UNKNOWN must not be presented as a precise unchanged gap")
        self.last_packet_seq = pkt["packet_seq"]
        self.through_seq = pkt["event_through_seq"]
        self.cumulative_event_total = pkt["cumulative_event_total"]
        self.cumulative_source_gap = pkt["cumulative_source_gap"]
        return "OK"


def openssl_available():
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def openssl_verify(spki_der, tbs, sig_der, workdir):
    """Cross-proof of the golden signature with the OpenSSL CLI."""
    spki_bin = os.path.join(workdir, "cross-pub.spki.der")
    spki_pem = os.path.join(workdir, "cross-pub.pem")
    tbs_bin = os.path.join(workdir, "cross-tbs.bin")
    sig_bin = os.path.join(workdir, "cross-sig.der")
    with open(spki_bin, "wb") as f:
        f.write(spki_der)
    with open(spki_pem, "wb") as f:
        subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER",
                        "-in", spki_bin, "-out", spki_pem], check=True,
                       capture_output=True)
    with open(tbs_bin, "wb") as f:
        f.write(tbs)
    with open(sig_bin, "wb") as f:
        f.write(sig_der)
    proc = subprocess.run(["openssl", "dgst", "-sha256", "-verify", spki_pem,
                           "-signature", sig_bin, tbs_bin],
                          capture_output=True, text=True)
    return proc.returncode == 0 and "Verified OK" in proc.stdout


def load_json(data):
    return jsonlib.loads(data)
