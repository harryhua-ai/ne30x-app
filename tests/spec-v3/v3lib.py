import hashlib
import hmac
import json as jsonlib
import struct
import zlib

CONTAINER_MAGIC_V3 = bytes.fromhex("4e45415050030000")
CONTAINER_MAGIC_V2 = bytes.fromhex("4e45415050020000")
CONTAINER_MAGIC_V1 = bytes.fromhex("4e45415050010000")
MANIFEST_MAGIC_V3 = bytes.fromhex("4e4d4633")
MANIFEST_MAGIC_V2 = bytes.fromhex("4e4d4632")
MANIFEST_MAGIC_V1 = bytes.fromhex("4e4d4631")

MANIFEST_LEN_V3 = 192
MANIFEST_LEN_V2 = 192
MANIFEST_LEN_V1 = 160
NATIVE_HEADER_SIZE = 32

ABI_V3 = 0x00030000
ABI_V2 = 0x00020000
ABI_V1 = 0x00010000

CAP_LOG = 1 << 0
CAP_TICK_MS = 1 << 1
CAP_AI_EVENTS = 1 << 2
CAP_REPORT_SUBMIT = 1 << 3
CAP_APP_STATE = 1 << 4
CAP_SESSION_LIFECYCLE = 1 << 5
CAP_CONTROL_RECEIVE = 1 << 6
CAP_BUSINESS_SNAPSHOT = 1 << 7
CAPS_KNOWN_MASK_V3 = 0x000000FF
CAPS_KNOWN_MASK_V2 = 0x0000003F
CAPS_KNOWN_MASK_V1 = 0x00000003

PROFILE_V2_SINGLE_SESSION = 1
PROFILE_V3_HOT_COMMAND_SESSION = 2

EVENT_KIND_FRAME = 1
EVENT_KIND_MODEL_CHANGED = 2
EVENT_KIND_GAP = 3
EVENT_KIND_STOPPING = 4
EVENT_HEADER_SIZE = 40
EVENT_RECORD_SIZE = 24
EVENT_MAX_DETECTIONS = 64
EVENT_MAX_BYTES = EVENT_HEADER_SIZE + EVENT_MAX_DETECTIONS * EVENT_RECORD_SIZE

REPORT_BUSINESS_MAX = 6144
STATE_QUOTA_EXAMPLE = 4096

CONTROL_HEADER_SIZE = 32
PROTO_MAGIC = b"NFC3"
PROTO_HEADER_VERSION = 1
MSG_CONFIG_APPLY = 1
MSG_COUNTERS_RESET = 2
MSG_CMD_REPLY = 3
MSG_SNAPSHOT = 4
FLAG_DESTRUCTIVE_CONFIRMED = 1 << 0
FLAG_KNOWN_MASK_COMMAND = FLAG_DESTRUCTIVE_CONFIRMED

RESULT_APPLIED = 0
RESULT_REJECTED_STALE_CONFIG = 1
RESULT_REJECTED_INVALID = 2
RESULT_REJECTED_RESOURCE = 3
RESULT_REJECTED_UNCONFIRMED = 4
RESULT_FAILED_STATE_CONFLICT = 5
RESULT_FAILED_STORAGE_IO = 6
RESULT_FAILED_STORAGE_UNKNOWN = 7

CONTROL_WIRE_MIN = CONTROL_HEADER_SIZE

ABI_TABLE_SIZE_V3 = 60
ABI_TABLE_SIZE_V2 = 48
ABI_TABLE_SIZE_V1 = 16

SNAPSHOT_PUBLISH_INTERVAL_MS = 5000
SNAPSHOT_STALE_AFTER_MS = 10000

DER_SIG_MIN = 8
DER_SIG_MAX = 72

EXPERIMENTAL_REGION_BYTES = 2 * 1024 * 1024
PACKAGE_MAX_V3 = 16 + MANIFEST_LEN_V3 + EXPERIMENTAL_REGION_BYTES + DER_SIG_MAX

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
SPKI_P256_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200"
)


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


def ecdsa_verify(spki_der, digest32, sig_der):
    public = spki_point(spki_der)
    try:
        r, s = decode_strict_der_sig(sig_der)
    except SpecViolation:
        return False
    z = int.from_bytes(digest32, "big")
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


def _check_identifier_slot(slot):
    text = slot.rstrip(b"\x00")
    if not text:
        raise SpecViolation("BAD_PACKAGE", "empty identifier slot")
    if slot[len(text) :] != b"\x00" * (len(slot) - len(text)):
        raise SpecViolation("BAD_PACKAGE", "identifier non-zero right padding")
    try:
        s = text.decode("ascii")
    except UnicodeDecodeError:
        raise SpecViolation("BAD_PACKAGE", "identifier not ASCII")
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in s):
        raise SpecViolation("BAD_PACKAGE", f"identifier charset: {s!r}")
    if not ("a" <= s[0] <= "z") or not s[-1].isalnum():
        raise SpecViolation("BAD_PACKAGE", f"identifier edge chars: {s!r}")


def build_manifest_v3(publisher_id, app_id, version, board_id, psram_mib,
                      caps, exec_region, native, spki_sha256,
                      run_profile, event_max, state_quota, report_max,
                      control_max, snapshot_max):
    if len(native) < NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "native shorter than 32B header")
    m = bytearray(MANIFEST_LEN_V3)
    m[0:4] = MANIFEST_MAGIC_V3
    m[4:20] = _enc_identifier(publisher_id, 16)
    m[20:52] = _enc_identifier(app_id, 32)
    struct.pack_into("<HHH", m, 52, version[0], version[1], version[2])
    struct.pack_into("<I", m, 60, board_id)
    struct.pack_into("<I", m, 64, psram_mib)
    struct.pack_into("<I", m, 68, ABI_V3)
    struct.pack_into("<I", m, 72, caps)
    struct.pack_into("<I", m, 76, exec_region)
    struct.pack_into("<I", m, 80, len(native))
    struct.pack_into("<I", m, 84, len(native) - NATIVE_HEADER_SIZE)
    struct.pack_into("<I", m, 88, struct.unpack_from("<I", native, 20)[0])
    struct.pack_into("<I", m, 92, struct.unpack_from("<I", native, 12)[0])
    m[96:128] = sha256(native)
    m[128:160] = spki_sha256
    struct.pack_into("<I", m, 160, run_profile)
    struct.pack_into("<I", m, 164, event_max)
    struct.pack_into("<I", m, 168, state_quota)
    struct.pack_into("<I", m, 172, report_max)
    struct.pack_into("<I", m, 176, control_max)
    struct.pack_into("<I", m, 180, snapshot_max)
    return bytes(m)


def decode_manifest_v3(m):
    if len(m) != MANIFEST_LEN_V3:
        raise SpecViolation("BAD_PACKAGE", f"manifest length {len(m)} != 192")
    if m[0:4] != MANIFEST_MAGIC_V3:
        raise SpecViolation("BAD_PACKAGE", f"manifest magic {m[0:4].hex()} != NMF3")
    if m[58:60] != b"\x00\x00":
        raise SpecViolation("BAD_PACKAGE", "manifest reserved[58..59] not zero")
    (board_id, psram_mib, abi, caps, exec_region, native_file_len,
     native_image_size, native_entry_offset, native_target_addr) = struct.unpack_from("<9I", m, 60)
    if abi != ABI_V3:
        raise SpecViolation("BAD_PACKAGE", f"required_host_abi 0x{abi:08x} != 0x00030000")
    d = {
        "magic": m[0:4],
        "publisher_id": m[4:20],
        "app_id": m[20:52],
        "version": struct.unpack_from("<HHH", m, 52),
        "board_id": board_id,
        "psram_mib": psram_mib,
        "abi": abi,
        "caps": caps,
        "exec_region": exec_region,
        "native_file_len": native_file_len,
        "native_image_size": native_image_size,
        "native_entry_offset": native_entry_offset,
        "native_target_addr": native_target_addr,
        "native_file_sha256": m[96:128],
        "publisher_key_sha256": m[128:160],
    }
    (d["run_profile"], d["event_max"], d["state_quota"], d["report_max"],
     d["control_max"], d["snapshot_max"]) = struct.unpack_from("<6I", m, 160)
    if m[184:192] != bytes(8):
        raise SpecViolation("BAD_PACKAGE", "manifest reserved[184..191] not zero")
    _check_identifier_slot(d["publisher_id"])
    _check_identifier_slot(d["app_id"])
    return d


def build_native(payload, abi, target_addr=0x93E00000, entry_offset=0):
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    hdr = struct.pack("<IHHIIIIII", 0x3141454E, NATIVE_HEADER_SIZE, 1, abi,
                      target_addr, len(payload), entry_offset, 0, crc)
    return hdr + payload


def check_native_cross_v3(native, manifest):
    if len(native) < NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "native file shorter than 32B header")
    magic, hdr_size, fmt, abi, target, image_size, entry, reserved0, crc = \
        struct.unpack_from("<IHHIIIIII", native, 0)
    if magic != 0x3141454E:
        raise SpecViolation("BAD_PACKAGE", "native magic != NEA1")
    if hdr_size != NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", f"native header_size {hdr_size} != 32")
    if fmt != 1:
        raise SpecViolation("BAD_PACKAGE", f"native format_version {fmt} != 1")
    if abi != manifest["abi"]:
        raise SpecViolation("BAD_PACKAGE", f"native abi 0x{abi:08x} != manifest required_host_abi")
    if target != manifest["native_target_addr"]:
        raise SpecViolation("BAD_PACKAGE", "native target_addr != manifest")
    if image_size != manifest["native_image_size"]:
        raise SpecViolation("BAD_PACKAGE", "native image_size != manifest")
    if entry != manifest["native_entry_offset"]:
        raise SpecViolation("BAD_PACKAGE", "native entry_offset != manifest")
    if reserved0 != 0:
        raise SpecViolation("BAD_PACKAGE", "native header reserved0 != 0")
    if len(native) != NATIVE_HEADER_SIZE + image_size:
        raise SpecViolation("BAD_PACKAGE", "native_file_len != 32 + image_size")
    if manifest["native_file_len"] != len(native):
        raise SpecViolation("BAD_PACKAGE", "manifest native_file_len != actual native length")
    if not (entry < image_size and entry % 2 == 0):
        raise SpecViolation("BAD_PACKAGE", "entry_offset violates Thumb/size constraint")
    if (zlib.crc32(native[32:]) & 0xFFFFFFFF) != crc:
        raise SpecViolation("BAD_PACKAGE", "native CRC32 mismatch")
    if sha256(native) != manifest["native_file_sha256"]:
        raise SpecViolation("BAD_PACKAGE", "native_file_sha256 mismatch")


def build_container_v3(manifest, native, sig_der):
    if len(manifest) != MANIFEST_LEN_V3:
        raise SpecViolation("BAD_PACKAGE", "manifest must be exactly 192B")
    header = CONTAINER_MAGIC_V3 + struct.pack("<II", MANIFEST_LEN_V3, len(native))
    tbs = header + manifest + native
    return tbs + sig_der, tbs


def parse_container_v3(pkg):
    if len(pkg) < 16 + MANIFEST_LEN_V3 + NATIVE_HEADER_SIZE + DER_SIG_MIN:
        raise SpecViolation("BAD_PACKAGE", "package too short")
    if pkg[0:8] != CONTAINER_MAGIC_V3:
        raise SpecViolation("BAD_PACKAGE", f"container magic {pkg[0:8].hex()} != v3")
    manifest_len, image_len = struct.unpack_from("<II", pkg, 8)
    if manifest_len != MANIFEST_LEN_V3:
        raise SpecViolation("BAD_PACKAGE", f"manifest_len {manifest_len} != 192")
    native_off = 16 + manifest_len
    sig_off = native_off + image_len
    if image_len < NATIVE_HEADER_SIZE or sig_off >= len(pkg):
        raise SpecViolation("BAD_PACKAGE", "missing signature or image too short")
    sig_region = pkg[sig_off:]
    r, s = decode_strict_der_sig(sig_region)
    return {
        "tbs": pkg[:sig_off],
        "manifest": pkg[16:native_off],
        "native": pkg[native_off:sig_off],
        "sig": sig_region,
        "r": r,
        "s": s,
    }


def trusted_issuer_spki(host, manifest):
    try:
        pid = manifest["publisher_id"].rstrip(b"\x00").decode("ascii")
    except UnicodeDecodeError:
        raise SpecViolation("PUBLISHER_UNTRUSTED", "publisher_id not decodable")
    mapping = host.get("trusted_publishers", {})
    if pid not in mapping:
        raise SpecViolation("PUBLISHER_UNTRUSTED", f"publisher_id {pid!r} not trusted")
    spki = mapping[pid]
    if manifest["publisher_key_sha256"] != sha256(spki):
        raise SpecViolation("PUBLISHER_UNTRUSTED", f"publisher_key_sha256 mismatch for {pid!r}")
    return spki


def full_accept_v3(pkg, host):
    parsed = parse_container_v3(pkg)
    manifest = decode_manifest_v3(parsed["manifest"])
    spki = trusted_issuer_spki(host, manifest)
    if not ecdsa_verify(spki, sha256(parsed["tbs"]), parsed["sig"]):
        raise SpecViolation("SIGNATURE_INVALID", "ECDSA P-256 verification failed")
    check_native_cross_v3(parsed["native"], manifest)
    policy_check_v3_host(manifest, host)
    return {"manifest": manifest, "native": parsed["native"], "tbs": parsed["tbs"],
            "sig": parsed["sig"]}


def policy_check_v3_host(manifest, host, business="line-crossing-64"):
    if manifest["board_id"] != host["board_id"]:
        raise SpecViolation("TARGET_INCOMPATIBLE", f"board 0x{manifest['board_id']:08x}")
    if manifest["psram_mib"] > host["psram_mib"]:
        raise SpecViolation("TARGET_INCOMPATIBLE", "PSRAM requirement exceeds board")
    if manifest["abi"] != host["abi"]:
        raise SpecViolation("ABI_INCOMPATIBLE", f"host ABI is 0x{host['abi']:08x}")
    caps = manifest["caps"]
    if caps & ~CAPS_KNOWN_MASK_V3:
        raise SpecViolation("BAD_PACKAGE",
                            f"unknown capability bits 0x{caps & ~CAPS_KNOWN_MASK_V3:08x}")
    unsupported = caps & ~host["caps_supported"]
    if unsupported:
        raise SpecViolation("ABI_INCOMPATIBLE",
                            f"host does not provide capability bits 0x{unsupported:08x}")
    if manifest["run_profile"] != PROFILE_V3_HOT_COMMAND_SESSION:
        raise SpecViolation("BAD_PACKAGE", f"unknown run_profile {manifest['run_profile']}")
    if not (caps & CAP_SESSION_LIFECYCLE):
        raise SpecViolation("BAD_PACKAGE", "profile 2 must declare session_lifecycle (bit5)")
    if not (caps & CAP_CONTROL_RECEIVE):
        raise SpecViolation("BAD_PACKAGE", "profile 2 must declare control_receive (bit6)")
    if (caps & CAP_AI_EVENTS) and manifest["event_max"] == 0:
        raise SpecViolation("BAD_PACKAGE", "ai_events requires nonzero event_max")
    if (caps & CAP_REPORT_SUBMIT) and manifest["report_max"] == 0:
        raise SpecViolation("BAD_PACKAGE", "report_submit requires nonzero report_max")
    if (caps & CAP_APP_STATE) and manifest["state_quota"] == 0:
        raise SpecViolation("BAD_PACKAGE", "app_state requires nonzero state_quota")
    if (caps & CAP_CONTROL_RECEIVE) and manifest["control_max"] == 0:
        raise SpecViolation("BAD_PACKAGE", "control_receive requires nonzero control_max")
    if (caps & CAP_BUSINESS_SNAPSHOT) and manifest["snapshot_max"] == 0:
        raise SpecViolation("BAD_PACKAGE", "business_snapshot requires nonzero snapshot_max")
    if not (caps & CAP_AI_EVENTS) and manifest["event_max"] != 0:
        raise SpecViolation("BAD_PACKAGE", "event_max set without ai_events")
    if not (caps & CAP_REPORT_SUBMIT) and manifest["report_max"] != 0:
        raise SpecViolation("BAD_PACKAGE", "report_max set without report_submit")
    if not (caps & CAP_APP_STATE) and manifest["state_quota"] != 0:
        raise SpecViolation("BAD_PACKAGE", "state_quota set without app_state")
    if not (caps & CAP_CONTROL_RECEIVE) and manifest["control_max"] != 0:
        raise SpecViolation("BAD_PACKAGE", "control_max set without control_receive")
    if not (caps & CAP_BUSINESS_SNAPSHOT) and manifest["snapshot_max"] != 0:
        raise SpecViolation("BAD_PACKAGE", "snapshot_max set without business_snapshot")
    if (caps & CAP_CONTROL_RECEIVE) and manifest["control_max"] < CONTROL_WIRE_MIN:
        raise SpecViolation("RESOURCE_LIMIT",
                            f"control_max {manifest['control_max']} < "
                            f"{CONTROL_WIRE_MIN} (generic 32B control wire header)")
    if business == "line-crossing-64":
        required = (CAP_AI_EVENTS | CAP_REPORT_SUBMIT | CAP_APP_STATE |
                    CAP_SESSION_LIFECYCLE | CAP_CONTROL_RECEIVE | CAP_BUSINESS_SNAPSHOT)
        missing = required & ~caps
        if missing:
            raise SpecViolation("BAD_PACKAGE",
                                f"line-crossing-64 missing capability bits 0x{missing:08x}")
        if (caps & CAP_AI_EVENTS) and manifest["event_max"] < EVENT_MAX_BYTES:
            raise SpecViolation("RESOURCE_LIMIT",
                                f"event_max {manifest['event_max']} < {EVENT_MAX_BYTES}")
        if (caps & CAP_REPORT_SUBMIT) and manifest["report_max"] < REPORT_BUSINESS_MAX:
            raise SpecViolation("RESOURCE_LIMIT",
                                f"report_max {manifest['report_max']} < {REPORT_BUSINESS_MAX}")
    if (caps & CAP_AI_EVENTS) and manifest["event_max"] > host["event_buffer_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "event_max exceeds host event buffer")
    if (caps & CAP_REPORT_SUBMIT) and manifest["report_max"] > host["report_capacity_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "report_max exceeds host report capacity")
    if (caps & CAP_APP_STATE) and manifest["state_quota"] > host["state_quota_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "state_quota exceeds host state quota")
    if (caps & CAP_CONTROL_RECEIVE) and manifest["control_max"] > host["control_msg_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "control_max exceeds host control capacity")
    if (caps & CAP_BUSINESS_SNAPSHOT) and manifest["snapshot_max"] > host["snapshot_ram_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "snapshot_max exceeds host snapshot RAM")
    if manifest["native_file_len"] > host["load_region_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "native_file_len exceeds host load region")
    target = manifest["native_target_addr"]
    range_hi = host["loader_base"] + host["loader_size"]
    if not (host["loader_base"] <= target < range_hi
            and target + manifest["native_file_len"] <= range_hi):
        raise SpecViolation("RESOURCE_LIMIT",
                            f"native target_addr 0x{target:08x} outside host loader range")
    if manifest["exec_region"] < manifest["native_image_size"]:
        raise SpecViolation("RESOURCE_LIMIT", "exec_region < native payload residency")
    if manifest["exec_region"] > host["exec_region_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "exec_region exceeds host actual execution region")


HOST_POLICY_V3 = {
    "board_id": 0x00003010,
    "psram_mib": 64,
    "abi": ABI_V3,
    "caps_supported": CAPS_KNOWN_MASK_V3,
    "trusted_publishers": {},
    "loader_base": 0x93E00000,
    "loader_size": EXPERIMENTAL_REGION_BYTES,
    "load_region_bytes": EXPERIMENTAL_REGION_BYTES,
    "exec_region_bytes": EXPERIMENTAL_REGION_BYTES,
    "event_buffer_bytes": 2048,
    "report_capacity_bytes": REPORT_BUSINESS_MAX,
    "state_quota_bytes": STATE_QUOTA_EXAMPLE,
    "control_msg_bytes": 256,
    "snapshot_ram_bytes": 1024,
}


def encode_control_header(msg_type, total_len, session_generation, request_id,
                          config_generation, state_revision, flags):
    return struct.pack("<4sHH6I", PROTO_MAGIC, PROTO_HEADER_VERSION, msg_type,
                       total_len, session_generation, request_id,
                       config_generation, state_revision, flags)


def decode_control_header(buf):
    if len(buf) < CONTROL_HEADER_SIZE:
        raise SpecViolation("BAD_CONTROL_WIRE", f"shorter than {CONTROL_HEADER_SIZE}B header")
    magic, version, msg_type, total_len, session_generation, request_id, \
        config_generation, state_revision, flags = struct.unpack_from("<4sHH6I", buf, 0)
    if magic != PROTO_MAGIC:
        raise SpecViolation("BAD_CONTROL_WIRE", f"proto magic {magic!r} != NFC3")
    if version != PROTO_HEADER_VERSION:
        raise SpecViolation("BAD_CONTROL_WIRE", f"header version {version} != 1")
    if msg_type not in (MSG_CONFIG_APPLY, MSG_COUNTERS_RESET, MSG_CMD_REPLY, MSG_SNAPSHOT):
        raise SpecViolation("BAD_CONTROL_WIRE", f"unknown msg_type {msg_type}")
    if total_len != len(buf):
        raise SpecViolation("BAD_CONTROL_WIRE", f"total_len {total_len} != buffer {len(buf)}")
    if total_len < CONTROL_HEADER_SIZE:
        raise SpecViolation("BAD_CONTROL_WIRE", "total_len below header size")
    return {
        "msg_type": msg_type,
        "total_len": total_len,
        "session_generation": session_generation,
        "request_id": request_id,
        "config_generation": config_generation,
        "state_revision": state_revision,
        "flags": flags,
    }


def build_command(msg_type, session_generation, request_id, expected_config_generation,
                  flags, payload=b""):
    if msg_type not in (MSG_CONFIG_APPLY, MSG_COUNTERS_RESET):
        raise SpecViolation("BAD_CONTROL_WIRE", "command msg_type invalid")
    if session_generation == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "session_generation must be nonzero")
    if request_id == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "request_id must be nonzero")
    if msg_type == MSG_COUNTERS_RESET and payload:
        raise SpecViolation("BAD_CONTROL_WIRE", "COUNTERS_RESET must carry empty payload")
    if flags & ~FLAG_KNOWN_MASK_COMMAND:
        raise SpecViolation("BAD_CONTROL_WIRE", f"unknown command flags 0x{flags:08x}")
    if msg_type == MSG_CONFIG_APPLY and not payload:
        raise SpecViolation("BAD_CONTROL_WIRE", "CONFIG_APPLY requires a payload")
    total = CONTROL_HEADER_SIZE + len(payload)
    return encode_control_header(msg_type, total, session_generation, request_id,
                                 expected_config_generation, 0, flags) + payload


def validate_command(buf):
    h = decode_control_header(buf)
    if h["msg_type"] not in (MSG_CONFIG_APPLY, MSG_COUNTERS_RESET):
        raise SpecViolation("BAD_CONTROL_WIRE", f"msg_type {h['msg_type']} is not a command")
    if h["session_generation"] == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "command session_generation must be nonzero")
    if h["request_id"] == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "command request_id must be nonzero")
    if h["config_generation"] == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "command expected_config_generation must be nonzero")
    if h["state_revision"] != 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "command state_revision must be zero")
    if h["flags"] & ~FLAG_KNOWN_MASK_COMMAND:
        raise SpecViolation("BAD_CONTROL_WIRE", f"unknown command flags 0x{h['flags']:08x}")
    payload = buf[CONTROL_HEADER_SIZE:]
    if h["msg_type"] == MSG_CONFIG_APPLY and not payload:
        raise SpecViolation("BAD_CONTROL_WIRE", "CONFIG_APPLY payload empty")
    if h["msg_type"] == MSG_COUNTERS_RESET and payload:
        raise SpecViolation("BAD_CONTROL_WIRE", "COUNTERS_RESET payload must be empty")
    return {**h, "payload": payload}


RESULT_ENUM = (RESULT_APPLIED, RESULT_REJECTED_STALE_CONFIG,
               RESULT_REJECTED_INVALID, RESULT_REJECTED_RESOURCE,
               RESULT_REJECTED_UNCONFIRMED, RESULT_FAILED_STATE_CONFLICT,
               RESULT_FAILED_STORAGE_IO, RESULT_FAILED_STORAGE_UNKNOWN)


def build_reply(session_generation, request_id, result_status,
                new_config_generation, state_revision):
    if session_generation == 0 or request_id == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "reply session/request ids must be nonzero")
    if result_status not in RESULT_ENUM:
        raise SpecViolation("BAD_CONTROL_WIRE", f"unknown result_status {result_status}")
    if new_config_generation == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "reply active/new_config_generation must be nonzero")
    return encode_control_header(MSG_CMD_REPLY, CONTROL_HEADER_SIZE, session_generation,
                                 request_id, new_config_generation, state_revision,
                                 result_status)


def validate_reply(buf):
    h = decode_control_header(buf)
    if h["msg_type"] != MSG_CMD_REPLY:
        raise SpecViolation("BAD_CONTROL_WIRE", "reply msg_type invalid")
    if h["total_len"] != CONTROL_HEADER_SIZE:
        raise SpecViolation("BAD_CONTROL_WIRE", "reply must carry empty payload")
    if h["session_generation"] == 0 or h["request_id"] == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "reply session/request ids must be nonzero")
    if h["config_generation"] == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "reply new_config_generation must be nonzero")
    if h["flags"] not in RESULT_ENUM:
        raise SpecViolation("BAD_CONTROL_WIRE", f"unknown result_status {h['flags']}")
    return {"session_generation": h["session_generation"],
            "request_id": h["request_id"],
            "new_config_generation": h["config_generation"],
            "state_revision": h["state_revision"],
            "result_status": h["flags"]}


def build_snapshot(config_generation, state_revision, payload_text):
    if config_generation == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "snapshot config_generation must be nonzero")
    payload = payload_text.encode("utf-8")
    validate_snapshot_payload(payload)
    total = CONTROL_HEADER_SIZE + len(payload)
    return encode_control_header(MSG_SNAPSHOT, total, 0, 0, config_generation,
                                 state_revision, 0) + payload


def _json_object_pairs(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise SpecViolation("BAD_SNAPSHOT", "duplicate JSON object keys")
    return dict(pairs)


def _json_constant(name):
    raise SpecViolation("BAD_SNAPSHOT", f"non-JSON constant {name}")


def validate_snapshot_payload(payload):
    if not payload:
        raise SpecViolation("BAD_SNAPSHOT", "snapshot payload empty")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise SpecViolation("BAD_SNAPSHOT", "snapshot payload not valid UTF-8")
    decoder = jsonlib.JSONDecoder(object_pairs_hook=_json_object_pairs,
                                  parse_constant=_json_constant)
    try:
        obj, end = decoder.raw_decode(text)
    except jsonlib.JSONDecodeError:
        raise SpecViolation("BAD_SNAPSHOT", "snapshot payload not valid JSON")
    except SpecViolation:
        raise
    if text[end:].strip():
        raise SpecViolation("BAD_SNAPSHOT", "snapshot JSON has trailing data")
    if not isinstance(obj, dict):
        raise SpecViolation("BAD_SNAPSHOT", "snapshot JSON must be an object")
    return obj


def validate_snapshot(buf, snapshot_max=None):
    h = decode_control_header(buf)
    if h["msg_type"] != MSG_SNAPSHOT:
        raise SpecViolation("BAD_CONTROL_WIRE", "snapshot msg_type invalid")
    if h["session_generation"] != 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "snapshot session_generation must be zero")
    if h["request_id"] != 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "snapshot request_id must be zero")
    if h["config_generation"] == 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "snapshot config_generation must be nonzero")
    if h["flags"] != 0:
        raise SpecViolation("BAD_CONTROL_WIRE", "snapshot flags must be zero")
    payload = buf[CONTROL_HEADER_SIZE:]
    if snapshot_max is not None and len(buf) > snapshot_max:
        raise SpecViolation("QUOTA_EXCEEDED",
                            f"snapshot {len(buf)}B exceeds snapshot_max {snapshot_max}")
    obj = validate_snapshot_payload(payload)
    return {**h, "payload": payload, "json": obj}


ABI_TABLE_V3 = {
    "table_size": 60,
    "abi_version": 0x00030000,
    8: "log",
    12: "tick_ms",
    16: "event_next",
    20: "model_meta",
    24: "class_name",
    28: "report_submit",
    32: "report_status",
    36: "state_read",
    40: "state_commit",
    44: "should_stop",
    48: "control_next",
    52: "control_reply",
    56: "snapshot_publish",
}


def encode_abi_table_v3():
    out = struct.pack("<II", ABI_TABLE_V3["table_size"], ABI_TABLE_V3["abi_version"])
    for off in sorted(o for o in ABI_TABLE_V3 if isinstance(o, int)):
        out += struct.pack("<I", 0xE0000000 + off)
    return out


def validate_abi_table_v3(buf):
    if len(buf) != ABI_TABLE_SIZE_V3:
        raise SpecViolation("ABI_INCOMPATIBLE", f"v3 table length {len(buf)} != 60")
    table_size, abi_version = struct.unpack_from("<II", buf, 0)
    if table_size != 60:
        raise SpecViolation("ABI_INCOMPATIBLE", f"table_size {table_size} != 60")
    if abi_version != ABI_V3:
        raise SpecViolation("ABI_INCOMPATIBLE", f"abi_version 0x{abi_version:08x} != 0x00030000")
    for off in sorted(o for o in ABI_TABLE_V3 if isinstance(o, int)):
        if struct.unpack_from("<I", buf, off)[0] == 0:
            raise SpecViolation("ABI_INCOMPATIBLE", f"null pointer at offset {off}")
    return True


class HostV3:
    def __init__(self, host_policy=None, control_max_default=256, snapshot_max_default=1024):
        self.policy = dict(HOST_POLICY_V3 if host_policy is None else host_policy)
        self.policy.setdefault("control_msg_bytes", control_max_default)
        self.policy.setdefault("snapshot_ram_bytes", snapshot_max_default)
        self.session_generation = 0
        self.session_open = False
        self.known_config_generation = None
        self.pending = None
        self.delivered = None
        self.results = {}
        self.snapshot = None
        self.snapshot_version = 0
        self.snapshot_monotonic_ms = None
        self.now_ms = 0
        self.request_id_seq = 0
        self.closed_unknown_ids = []

    def open_session(self):
        self.session_generation += 1
        if self.session_generation == 0 or self.session_generation > 0xFFFFFFFF:
            raise SpecViolation("BAD_CONTROL_WIRE", "session_generation exhausted")
        self.session_open = True
        self.known_config_generation = None
        self.pending = None
        self.delivered = None
        self.results = {}
        self.snapshot = None
        self.snapshot_version = 0
        self.snapshot_monotonic_ms = None
        self.request_id_seq = 0

    def close_session(self):
        if self.delivered is not None:
            self.closed_unknown_ids.append(self.delivered["request_id"])
        self.session_open = False
        self.pending = None
        self.delivered = None
        self.snapshot = None
        self.snapshot_monotonic_ms = None

    def _command_semantics(self, msg_type, request_id, expected_gen, flags, payload):
        return (msg_type, request_id, expected_gen, flags, payload)

    def register_command(self, msg_type, expected_gen, flags, payload=b"", request_id=None,
                         now_ms=0):
        self.now_ms = now_ms
        if not self.session_open:
            return ("UNAUTHORIZED", None)
        if not (self.session_caps() & CAP_CONTROL_RECEIVE):
            return ("UNAUTHORIZED", None)
        if request_id is None:
            self.request_id_seq += 1
            request_id = self.request_id_seq
        if request_id in self.results:
            cached_sem, cached_result = self.results[request_id]
            if cached_sem == self._command_semantics(msg_type, request_id, expected_gen,
                                                     flags, payload):
                return ("CACHED", cached_result)
            return ("DUPLICATE_ID_CONFLICT", None)
        if expected_gen == 0:
            return ("INVALID", None)
        if self.pending is not None or self.delivered is not None:
            return ("BUSY", None)
        if self.known_config_generation is not None and expected_gen != self.known_config_generation:
            return ("CONFLICT", None)
        if msg_type == MSG_COUNTERS_RESET and not (flags & FLAG_DESTRUCTIVE_CONFIRMED):
            return ("UNCONFIRMED", None)
        total = CONTROL_HEADER_SIZE + len(payload)
        if total > self.policy["control_msg_bytes"]:
            return ("QUOTA_EXCEEDED", None)
        if msg_type == MSG_CONFIG_APPLY and not payload:
            return ("INVALID", None)
        self.pending = {
            "msg_type": msg_type,
            "request_id": request_id,
            "expected_config_generation": expected_gen,
            "flags": flags,
            "payload": payload,
            "state": "PENDING",
        }
        return ("PENDING", self.pending)

    def session_caps(self):
        return self.policy.get("session_caps", CAPS_KNOWN_MASK_V3)

    def control_next(self, cap):
        if not self.session_open:
            return (-3, None, None)
        if not (self.session_caps() & CAP_CONTROL_RECEIVE):
            return (-3, None, None)
        if self.pending is None:
            return (1, None, None)
        command = self.pending
        total = CONTROL_HEADER_SIZE + len(command["payload"])
        if cap < total:
            return (-2, None, total)
        buf = build_command(command["msg_type"], self.session_generation,
                            command["request_id"], command["expected_config_generation"],
                            command["flags"], command["payload"])
        command["state"] = "DELIVERED"
        self.delivered = command
        self.pending = None
        return (0, buf, total)

    def control_reply(self, buf):
        if not self.session_open:
            return -3
        if not (self.session_caps() & CAP_CONTROL_RECEIVE):
            return -3
        try:
            reply = validate_reply(buf)
        except SpecViolation:
            return -1
        if self.delivered is None or self.delivered["request_id"] != reply["request_id"]:
            return -1
        if reply["session_generation"] != self.session_generation:
            return -1
        command = self.delivered
        semantics = self._command_semantics(command["msg_type"], command["request_id"],
                                            command["expected_config_generation"],
                                            command["flags"], command["payload"])
        self.results[command["request_id"]] = (semantics, {
            "result_status": reply["result_status"],
            "new_config_generation": reply["new_config_generation"],
            "state_revision": reply["state_revision"],
        })
        self.delivered = None
        if reply["result_status"] == RESULT_APPLIED:
            self.known_config_generation = reply["new_config_generation"]
        return 0

    def snapshot_publish(self, buf, now_ms=None):
        if now_ms is not None:
            self.now_ms = now_ms
        if not self.session_open:
            return (-3)
        if not (self.session_caps() & CAP_BUSINESS_SNAPSHOT):
            return (-3)
        try:
            snap = validate_snapshot(buf, snapshot_max=self.policy["snapshot_ram_bytes"])
        except SpecViolation as e:
            if e.reason == "QUOTA_EXCEEDED":
                return (-5)
            return (-1)
        self.snapshot_version += 1
        self.snapshot = {
            "json": snap["json"],
            "config_generation": snap["config_generation"],
            "state_revision": snap["state_revision"],
            "session_generation": self.session_generation,
            "publisher": self.policy.get("session_publisher", "test-publisher"),
            "snapshot_version": self.snapshot_version,
            "received_monotonic_ms": self.now_ms,
        }
        self.known_config_generation = snap["config_generation"]
        return (0)

    def snapshot_observable(self, now_ms=None):
        if now_ms is not None:
            self.now_ms = now_ms
        if not self.session_open or self.snapshot is None:
            return {"state": "unavailable"}
        age = self.now_ms - self.snapshot["received_monotonic_ms"]
        if age > SNAPSHOT_STALE_AFTER_MS:
            return {"state": "stale"}
        return {"state": "current", "snapshot_version": self.snapshot["snapshot_version"]}

    def reconcile_unknown(self, request_id):
        if request_id not in self.closed_unknown_ids:
            return None
        if self.known_config_generation is None:
            return {"request_id": request_id, "outcome": "UNKNOWN", "evidence": None}
        return {"request_id": request_id, "outcome": "RECONCILED_READ_ONLY",
                "evidence": {"active_config_generation": self.known_config_generation}}


class AppV3:
    def __init__(self, active_config_generation=1, state_revision=0):
        self.active_config_generation = active_config_generation
        self.state_revision = state_revision
        self.blob = {"config": "active", "counters": {"in": 0, "out": 0}, "report_seq": 0}
        self.persisted_blob = None
        self.persisted_revision = None
        self.commit_mode = "ok"
        self.session_generation = None
        self.restricted = False

    def bind_session(self, session_generation):
        self.session_generation = session_generation

    def recover_trusted_state(self):
        self.restricted = False

    def _state_commit(self, blob):
        if self.commit_mode == "conflict":
            return ("REVISION_CONFLICT", None)
        if self.commit_mode == "io":
            return ("IO_ERROR", None)
        if self.commit_mode == "unknown":
            return ("STORAGE_UNKNOWN", None)
        self.state_revision += 1
        self.persisted_blob = blob
        self.persisted_revision = self.state_revision
        return ("OK", self.state_revision)

    def snapshot_json(self):
        return jsonlib.dumps({
            "schema": "line-crossing/1",
            "app_state": "restricted" if self.restricted else "running",
            "config_generation": self.active_config_generation,
            "state_revision": self.state_revision,
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
            "counters": self.blob["counters"],
            "report_seq": self.blob["report_seq"],
            "model": {"loaded": True, "target_class": "car", "valid": True},
            "gap": {"active": False},
            "quality": {"dropped_frames": 0},
            "storage": {"fault": self.restricted},
        }, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    def snapshot_bytes(self):
        return build_snapshot(self.active_config_generation, self.state_revision,
                              self.snapshot_json())

    def handle_command(self, command_buf, next_config_generation=None):
        cmd = validate_command(command_buf)
        if self.restricted:
            return build_reply(cmd["session_generation"], cmd["request_id"],
                               RESULT_FAILED_STORAGE_UNKNOWN,
                               self.active_config_generation, self.state_revision)
        if cmd["session_generation"] != self.session_generation:
            return build_reply(cmd["session_generation"], cmd["request_id"],
                               RESULT_REJECTED_INVALID, self.active_config_generation,
                               self.state_revision)
        if cmd["msg_type"] == MSG_COUNTERS_RESET:
            if not (cmd["flags"] & FLAG_DESTRUCTIVE_CONFIRMED):
                return build_reply(cmd["session_generation"], cmd["request_id"],
                                   RESULT_REJECTED_UNCONFIRMED,
                                   self.active_config_generation, self.state_revision)
            new_blob = {**self.blob, "counters": {"in": 0, "out": 0}}
            status, revision = self._state_commit(new_blob)
            if status == "OK":
                self.blob = new_blob
                return build_reply(cmd["session_generation"], cmd["request_id"],
                                   RESULT_APPLIED, self.active_config_generation, revision)
            if status == "REVISION_CONFLICT":
                return build_reply(cmd["session_generation"], cmd["request_id"],
                                   RESULT_FAILED_STATE_CONFLICT,
                                   self.active_config_generation, self.state_revision)
            if status == "IO_ERROR":
                return build_reply(cmd["session_generation"], cmd["request_id"],
                                   RESULT_FAILED_STORAGE_IO,
                                   self.active_config_generation, self.state_revision)
            self.restricted = True
            return build_reply(cmd["session_generation"], cmd["request_id"],
                               RESULT_FAILED_STORAGE_UNKNOWN,
                               self.active_config_generation, self.state_revision)
        if cmd["config_generation"] != self.active_config_generation:
            return build_reply(cmd["session_generation"], cmd["request_id"],
                               RESULT_REJECTED_STALE_CONFIG,
                               self.active_config_generation, self.state_revision)
        prepared_blob = {
            "config": "candidate",
            "counters": dict(self.blob["counters"]),
            "report_seq": self.blob["report_seq"],
        }
        status, revision = self._state_commit(prepared_blob)
        if status == "REVISION_CONFLICT":
            return build_reply(cmd["session_generation"], cmd["request_id"],
                               RESULT_FAILED_STATE_CONFLICT, self.active_config_generation,
                               self.state_revision)
        if status == "IO_ERROR":
            return build_reply(cmd["session_generation"], cmd["request_id"],
                               RESULT_FAILED_STORAGE_IO, self.active_config_generation,
                               self.state_revision)
        if status == "STORAGE_UNKNOWN":
            self.restricted = True
            return build_reply(cmd["session_generation"], cmd["request_id"],
                               RESULT_FAILED_STORAGE_UNKNOWN,
                               self.active_config_generation, self.state_revision)
        new_gen = (next_config_generation if next_config_generation is not None
                   else self.active_config_generation + 1)
        self.blob = prepared_blob
        self.blob["config"] = "active"
        self.active_config_generation = new_gen
        return build_reply(cmd["session_generation"], cmd["request_id"],
                           RESULT_APPLIED, new_gen, revision)


def migrate_v2_state(same_trusted_identity, v2_blob):
    if not same_trusted_identity:
        raise SpecViolation("FORBIDDEN", "cross-identity v2 state takeover refused")
    app = AppV3(active_config_generation=1, state_revision=0)
    app.blob = {**v2_blob, "config": "active"}
    return app


def control_next_no_event_code():
    return 1


def v1_gate_structural(pkg):
    if len(pkg) < 16 + MANIFEST_LEN_V1 + NATIVE_HEADER_SIZE + DER_SIG_MIN:
        raise SpecViolation("BAD_PACKAGE", "package too short")
    if pkg[0:8] != CONTAINER_MAGIC_V1:
        raise SpecViolation("BAD_PACKAGE", "container magic != v1")
    manifest_len, image_len = struct.unpack_from("<II", pkg, 8)
    if manifest_len != MANIFEST_LEN_V1:
        raise SpecViolation("BAD_PACKAGE", f"manifest_len {manifest_len} != 160")
    native_off = 16 + manifest_len
    sig_off = native_off + image_len
    if image_len < NATIVE_HEADER_SIZE or sig_off >= len(pkg):
        raise SpecViolation("BAD_PACKAGE", "v1 image/signature region invalid")
    r, s = decode_strict_der_sig(pkg[sig_off:])
    m = pkg[16:native_off]
    if m[0:4] != MANIFEST_MAGIC_V1:
        raise SpecViolation("BAD_PACKAGE", "manifest magic != NMF1")
    if m[58:60] != b"\x00\x00":
        raise SpecViolation("BAD_PACKAGE", "v1 manifest reserved nonzero")
    fields = struct.unpack_from("<9I", m, 60)
    abi, caps = fields[2], fields[3]
    if abi != ABI_V1:
        raise SpecViolation("BAD_PACKAGE", "v1 manifest abi != 0x00010000")
    if caps & ~CAPS_KNOWN_MASK_V1:
        raise SpecViolation("BAD_PACKAGE", "v1 unknown capability bits")
    native = pkg[native_off:sig_off]
    magic, hdr_size, fmt, nabi, target, image_size, entry, reserved0, crc = \
        struct.unpack_from("<IHHIIIIII", native, 0)
    if magic != 0x3141454E or hdr_size != 32 or fmt != 1 or nabi != ABI_V1:
        raise SpecViolation("BAD_PACKAGE", "v1 native header invalid")
    if reserved0 != 0:
        raise SpecViolation("BAD_PACKAGE", "v1 native reserved0 nonzero")
    if (zlib.crc32(native[32:]) & 0xFFFFFFFF) != crc:
        raise SpecViolation("BAD_PACKAGE", "v1 native CRC mismatch")
    if sha256(native) != m[96:128]:
        raise SpecViolation("BAD_PACKAGE", "v1 native sha mismatch")
    return {"tbs": pkg[:sig_off], "manifest": m, "native": native}


def v1_host_accept(pkg, trusted_spki_map):
    parsed = v1_gate_structural(pkg)
    pid = parsed["manifest"][4:20].rstrip(b"\x00").decode("ascii")
    if pid not in trusted_spki_map:
        raise SpecViolation("PUBLISHER_UNTRUSTED", "v1 publisher not trusted")
    spki = trusted_spki_map[pid]
    if parsed["manifest"][128:160] != sha256(spki):
        raise SpecViolation("PUBLISHER_UNTRUSTED", "v1 key fingerprint mismatch")
    if not ecdsa_verify(spki, sha256(parsed["tbs"]), pkg[len(parsed["tbs"]):]):
        raise SpecViolation("SIGNATURE_INVALID", "v1 signature invalid")
    return {"table_bytes": ABI_TABLE_SIZE_V1, "functions": ["log", "tick_ms"]}


def v2_gate_structural(pkg):
    if len(pkg) < 16 + MANIFEST_LEN_V2 + NATIVE_HEADER_SIZE + DER_SIG_MIN:
        raise SpecViolation("BAD_PACKAGE", "package too short")
    if pkg[0:8] != CONTAINER_MAGIC_V2:
        raise SpecViolation("BAD_PACKAGE", "container magic != v2")
    manifest_len, image_len = struct.unpack_from("<II", pkg, 8)
    if manifest_len != MANIFEST_LEN_V2:
        raise SpecViolation("BAD_PACKAGE", f"manifest_len {manifest_len} != 192")
    native_off = 16 + manifest_len
    sig_off = native_off + image_len
    if image_len < NATIVE_HEADER_SIZE or sig_off >= len(pkg):
        raise SpecViolation("BAD_PACKAGE", "v2 image/signature region invalid")
    r, s = decode_strict_der_sig(pkg[sig_off:])
    m = pkg[16:native_off]
    if m[0:4] != MANIFEST_MAGIC_V2:
        raise SpecViolation("BAD_PACKAGE", "manifest magic != NMF2")
    if m[58:60] != b"\x00\x00":
        raise SpecViolation("BAD_PACKAGE", "v2 manifest reserved[58..59] nonzero")
    (board, psram, abi, caps, exec_region, native_file_len, native_image_size,
     entry, target) = struct.unpack_from("<9I", m, 60)
    if abi != ABI_V2:
        raise SpecViolation("BAD_PACKAGE", "v2 manifest abi != 0x00020000")
    if caps & ~CAPS_KNOWN_MASK_V2:
        raise SpecViolation("BAD_PACKAGE", "v2 unknown capability bits")
    profile, event_max, state_quota, report_max = struct.unpack_from("<4I", m, 160)
    if m[176:192] != bytes(16):
        raise SpecViolation("BAD_PACKAGE", "v2 manifest reserved[176..191] nonzero")
    if profile != PROFILE_V2_SINGLE_SESSION:
        raise SpecViolation("BAD_PACKAGE", "v2 unknown run_profile")
    if not (caps & CAP_SESSION_LIFECYCLE):
        raise SpecViolation("BAD_PACKAGE", "v2 profile 1 missing bit5")
    native = pkg[native_off:sig_off]
    magic, hdr_size, fmt, nabi, ntarget, image_size, nentry, reserved0, crc = \
        struct.unpack_from("<IHHIIIIII", native, 0)
    if magic != 0x3141454E or hdr_size != 32 or fmt != 1 or nabi != ABI_V2:
        raise SpecViolation("BAD_PACKAGE", "v2 native header invalid")
    if reserved0 != 0:
        raise SpecViolation("BAD_PACKAGE", "v2 native reserved0 nonzero")
    if (zlib.crc32(native[32:]) & 0xFFFFFFFF) != crc:
        raise SpecViolation("BAD_PACKAGE", "v2 native CRC mismatch")
    if sha256(native) != m[96:128]:
        raise SpecViolation("BAD_PACKAGE", "v2 native sha mismatch")
    return {"tbs": pkg[:sig_off], "manifest": m, "native": native}


def v2_host_accept(pkg, trusted_spki_map):
    parsed = v2_gate_structural(pkg)
    pid = parsed["manifest"][4:20].rstrip(b"\x00").decode("ascii")
    if pid not in trusted_spki_map:
        raise SpecViolation("PUBLISHER_UNTRUSTED", "v2 publisher not trusted")
    spki = trusted_spki_map[pid]
    if parsed["manifest"][128:160] != sha256(spki):
        raise SpecViolation("PUBLISHER_UNTRUSTED", "v2 key fingerprint mismatch")
    if not ecdsa_verify(spki, sha256(parsed["tbs"]), pkg[len(parsed["tbs"]):]):
        raise SpecViolation("SIGNATURE_INVALID", "v2 signature invalid")
    return {"table_bytes": ABI_TABLE_SIZE_V2, "functions": 10,
            "caps": struct.unpack_from("<I", parsed["manifest"], 72)[0]}
