"""v2lib.py — self-contained reference implementation of the .neapp v2 candidate
container/signature/policy/event-wire rules specified in
docs/app-package-protocol-v2-draft.md (Issue #12).

Design boundaries (from the Issue #12 contract):
  * This module is the v2 spec test authority. It MUST NOT import anything from
    package/ or tools/ (v1 tooling owned by P3 #6), and does not.
  * Everything here is stdlib-only so the suite runs without third-party deps.
    OpenSSL (CLI) is used by the runner as an independent cross-verifier.
  * A minimal v1 structural gate is included ONLY to simulate old/new host
    interop discrimination (spec §8 M2/M3/M4); the frozen v1 spec remains the
    v1 authority and P3 #6 remains the v1 tool owner.
  * Host-side policy checks (board/ABI/quotas) simulate the acceptance policy
    defined in spec §4/§8/§9 for the current 64-detection line-crossing
    business. They are spec vectors, not a device implementation.
"""

import hashlib
import hmac
import struct
import zlib

# ---------------------------------------------------------------------------
# Fixed constants (spec §2/§3; v1 spec §2.2/§2.3 inherited)
# ---------------------------------------------------------------------------

MAGIC_V2 = bytes.fromhex("4e45415050020000")      # NEAPP container major 2
MAGIC_V1 = bytes.fromhex("4e45415050010000")      # NEAPP container major 1 (frozen v1)
MANIFEST_MAGIC_V2 = bytes.fromhex("4e4d4632")     # "NMF2"
MANIFEST_MAGIC_V1 = bytes.fromhex("4e4d4631")     # "NMF1"

V2_MANIFEST_LEN = 192
V1_MANIFEST_LEN = 160
NATIVE_HEADER_SIZE = 32

ABI_V1 = 0x00010000
ABI_V2 = 0x00020000

CAP_LOG = 1 << 0
CAP_TICK_MS = 1 << 1
CAP_AI_EVENTS = 1 << 2
CAP_REPORT_SUBMIT = 1 << 3
CAP_APP_STATE = 1 << 4
CAP_SESSION_LIFECYCLE = 1 << 5
CAP_KNOWN_MASK = 0x0000003F

PROFILE_SINGLE_TRUSTED_SESSION = 1

EVENT_KIND_FRAME = 1
EVENT_KIND_MODEL_CHANGED = 2
EVENT_KIND_GAP = 3
EVENT_KIND_STOPPING = 4
EVENT_HEADER_SIZE = 40
EVENT_RECORD_SIZE = 24
EVENT_MAX_DETECTIONS = 64                # LC_FRAME_MAX_DETECTIONS (ne301 @de25a6f1)
EVENT_MAX_BYTES = EVENT_HEADER_SIZE + EVENT_MAX_DETECTIONS * EVENT_RECORD_SIZE  # 1576
LOST_COUNT_UNKNOWN = 0xFFFFFFFF

REPORT_BUSINESS_MAX = 6144               # LC_DQ_SLOT_CAPACITY (ne301 @de25a6f1)
STATE_QUOTA_EXAMPLE = 4096
TARGET_CLASS_NAME_LEN = 32               # LC_TARGET_CLASS_NAME_LEN (ne301 @de25a6f1)

PP_TYPE_OD = 1

# Current line-crossing compatible profile example (spec §4.2): SIGNED REQUEST
# BOUNDS only, never a promise of actual host resources.
LINE_CROSSING_PROFILE = {
    "caps": 0x0000003F,
    "event_max": 2048,
    "state_quota": 4096,
    "report_max": 6144,
}

DER_SIG_MIN = 8
DER_SIG_MAX = 72

# v1 §2.3/§2.5 evidence baseline for the experimental Host (2 MiB PSRAM exec region).
EXPERIMENTAL_REGION_BYTES = 2 * 1024 * 1024

PACKAGE_MAX = 16 + V2_MANIFEST_LEN + EXPERIMENTAL_REGION_BYTES + DER_SIG_MAX


class SpecViolation(Exception):
    """Raised with a spec-referenced reason string on any rule violation."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# Pure-Python P-256 (verify + RFC6979 deterministic sign + strict DER)
# ---------------------------------------------------------------------------

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _inv(x, m):
    return pow(x, -1, m)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + P256_A) * _inv(2 * y1, P256_P) % P256_P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def _ec_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def p256_pubkey(d):
    """Public key point Q = d*G for private scalar d."""
    return _ec_mul(d, (P256_GX, P256_GY))


def p256_encode_spki(pub):
    """SubjectPublicKeyInfo DER for an uncompressed P-256 point (91 bytes)."""
    point = b"\x04" + pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    bitstring = b"\x03\x42\x00" + point                      # BIT STRING, 0x42=66
    algid = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    return b"\x30\x59" + algid + bitstring                   # SEQUENCE, 0x59=89


def p256_spki_for_d(d):
    return p256_encode_spki(p256_pubkey(d))


def p256_verify(spki_der, digest, sig_der):
    """Verify strict-DER ECDSA-P256 over a 32-byte digest against an SPKI.

    Returns True/False. Raises nothing for well-formed inputs; malformed DER
    returns False (callers should treat that as a structural rejection)."""
    try:
        r, s = parse_strict_der_sig(sig_der)
    except SpecViolation:
        return False
    if len(digest) != 32:
        return False
    if len(spki_der) != 91 or spki_der[0:1] != b"\x30":
        return False
    # [0..1] SEQUENCE, [2..22] AlgID SEQUENCE, [23..24] BIT STRING hdr,
    # [25] unused-bits, [26..90] uncompressed point 04||X||Y
    if spki_der[23:25] != b"\x03\x42" or spki_der[25:26] != b"\x00":
        return False
    point = spki_der[26:]
    if point[0:1] != b"\x04" or len(point) != 65:
        return False
    qx = int.from_bytes(point[1:33], "big")
    qy = int.from_bytes(point[33:65], "big")
    if not (1 <= qx < P256_P and 1 <= qy < P256_P):
        return False
    if (qy * qy - (qx * qx * qx + P256_A * qx + P256_B)) % P256_P != 0:
        return False  # not on curve
    e = int.from_bytes(digest, "big")
    w = _inv(s, P256_N)
    u1 = e * w % P256_N
    u2 = r * w % P256_N
    pt = _ec_add(_ec_mul(u1, (P256_GX, P256_GY)), _ec_mul(u2, (qx, qy)))
    if pt is None:
        return False
    return pt[0] % P256_N == r % P256_N


def _der_int(x):
    if x == 0:
        return b"\x02\x01\x00"
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return bytes([0x02, len(b)]) + b


def der_sig_from_rs(r, s):
    body = _der_int(r) + _der_int(s)
    return bytes([0x30, len(body)]) + body


def parse_strict_der_sig(sig):
    """Strict DER ECDSA-Sig-Value: must consume the whole input (spec §2.2)."""
    if len(sig) < DER_SIG_MIN:
        raise SpecViolation("BAD_PACKAGE", f"signature region too short ({len(sig)}B)")
    if len(sig) > DER_SIG_MAX:
        raise SpecViolation("BAD_PACKAGE", f"signature region too long ({len(sig)}B)")
    if sig[0] != 0x30:
        raise SpecViolation("BAD_PACKAGE", "signature not a DER SEQUENCE")
    if sig[1] & 0x80:
        raise SpecViolation("BAD_PACKAGE", "non-minimal DER length")
    if sig[1] != len(sig) - 2:
        raise SpecViolation("BAD_PACKAGE", "DER does not consume its tail exactly")
    ints = []
    off = 2
    for _ in range(2):
        if off + 2 > len(sig) or sig[off] != 0x02:
            raise SpecViolation("BAD_PACKAGE", "expected DER INTEGER")
        ln = sig[off + 1]
        if ln == 0 or ln & 0x80:
            raise SpecViolation("BAD_PACKAGE", "non-minimal/absent INTEGER length")
        val = sig[off + 2:off + 2 + ln]
        if len(val) != ln:
            raise SpecViolation("BAD_PACKAGE", "truncated INTEGER")
        if ln > 1 and val[0] == 0x00 and not (val[1] & 0x80):
            raise SpecViolation("BAD_PACKAGE", "non-minimal INTEGER padding")
        if val[0] & 0x80:
            raise SpecViolation("BAD_PACKAGE", "negative INTEGER")
        ints.append(int.from_bytes(val, "big"))
        off += 2 + ln
    if off != len(sig):
        raise SpecViolation("BAD_PACKAGE", "extra bytes after second INTEGER")
    r, s = ints
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        raise SpecViolation("BAD_PACKAGE", "r/s out of P-256 range")
    return r, s


def rfc6979_sign(d, digest):
    """Deterministic ECDSA-P256 (RFC 6979, SHA-256) -> strict DER."""
    def int2octets(x):
        return x.to_bytes(32, "big")

    def bits2int(b):
        return int.from_bytes(b, "big")

    h1 = digest
    K = b"\x00" * 32
    V = b"\x01" * 32
    K = hmac.new(K, V + b"\x00" + int2octets(d) + int2octets(bits2int(h1) % P256_N), hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + int2octets(d) + int2octets(bits2int(h1) % P256_N), hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = bits2int(V)
        if 1 <= k < P256_N:
            pt = _ec_mul(k, (P256_GX, P256_GY))
            r = pt[0] % P256_N
            if r != 0:
                s = (_inv(k, P256_N) * (bits2int(h1) + r * d)) % P256_N
                if s != 0:
                    return der_sig_from_rs(r, s)
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# v2 manifest (192B) — build + strict decode (spec §3)
# ---------------------------------------------------------------------------

def _enc_identifier(text, width):
    """v1 §2.3 identifier charset: [a-z0-9-], start [a-z], end alnum, right NUL pad."""
    b = text.encode("ascii")
    if not 1 <= len(b) <= width:
        raise SpecViolation("BAD_PACKAGE", f"identifier length {len(b)} not in 1..{width}")
    if text != text.lower() or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in text):
        raise SpecViolation("BAD_PACKAGE", f"identifier charset: {text!r}")
    if text[0] not in "abcdefghijklmnopqrstuvwxyz" or not text[-1].isalnum():
        raise SpecViolation("BAD_PACKAGE", f"identifier edge chars: {text!r}")
    return b + b"\x00" * (width - len(b))


def build_manifest(publisher_id, app_id, version, board_id, psram_mib, abi,
                   caps, exec_region, native, spki_sha256,
                   run_profile, event_max, state_quota, report_max,
                   manifest_magic=MANIFEST_MAGIC_V2):
    """native = full native file (32B header + payload). Returns 192B (v2) manifest."""
    if abi != ABI_V2 and manifest_magic == MANIFEST_MAGIC_V2:
        raise SpecViolation("BAD_PACKAGE", "v2 manifest requires required_host_abi=0x00020000")
    m = bytearray(192)
    m[0:4] = manifest_magic
    m[4:20] = _enc_identifier(publisher_id, 16)
    m[20:52] = _enc_identifier(app_id, 32)
    struct.pack_into("<HHH", m, 52, version[0], version[1], version[2])
    # [58..59] reserved stays zero
    struct.pack_into("<I", m, 60, board_id)
    struct.pack_into("<I", m, 64, psram_mib)
    struct.pack_into("<I", m, 68, abi)
    struct.pack_into("<I", m, 72, caps)
    struct.pack_into("<I", m, 76, exec_region)
    struct.pack_into("<I", m, 80, len(native))
    struct.pack_into("<I", m, 84, len(native) - 32)
    struct.pack_into("<I", m, 88, struct.unpack_from("<I", native, 20)[0])   # entry_offset
    struct.pack_into("<I", m, 92, struct.unpack_from("<I", native, 12)[0])   # target_addr
    m[96:128] = sha256(native)
    m[128:160] = spki_sha256
    if manifest_magic == MANIFEST_MAGIC_V2:
        struct.pack_into("<I", m, 160, run_profile)
        struct.pack_into("<I", m, 164, event_max)
        struct.pack_into("<I", m, 168, state_quota)
        struct.pack_into("<I", m, 172, report_max)
        # [176..191] reserved stays zero
    return bytes(m)


def decode_manifest_v2(m):
    """Strict decode of a 192B v2 manifest; raises SpecViolation on any rule break."""
    if len(m) != V2_MANIFEST_LEN:
        raise SpecViolation("BAD_PACKAGE", f"manifest length {len(m)} != 192")
    d = {}
    d["magic"] = m[0:4]
    if d["magic"] != MANIFEST_MAGIC_V2:
        raise SpecViolation("BAD_PACKAGE", f"manifest magic {m[0:4]!r} != NMF2")
    d["publisher_id"] = m[4:20]
    d["app_id"] = m[20:52]
    d["version"] = struct.unpack_from("<HHH", m, 52)
    if m[58:60] != b"\x00\x00":
        raise SpecViolation("BAD_PACKAGE", "manifest reserved[58..59] not zero")
    (d["board_id"], d["psram_mib"], d["abi"], d["caps"],
     d["exec_region"], d["native_file_len"], d["native_image_size"],
     d["native_entry_offset"], d["native_target_addr"]) = struct.unpack_from("<9I", m, 60)
    if d["abi"] != ABI_V2:
        raise SpecViolation("BAD_PACKAGE", f"v2 manifest required_host_abi=0x{d['abi']:08x} != 0x00020000")
    d["native_file_sha256"] = m[96:128]
    d["publisher_key_sha256"] = m[128:160]
    d["run_profile"], d["event_max"], d["state_quota"], d["report_max"] = struct.unpack_from("<4I", m, 160)
    if m[176:192] != bytes(16):
        raise SpecViolation("BAD_PACKAGE", "manifest reserved[176..191] not zero")
    _check_identifier_bytes(d["publisher_id"])
    _check_identifier_bytes(d["app_id"])
    return d


def _check_identifier_bytes(slot):
    text = slot.rstrip(b"\x00")
    if not text:
        raise SpecViolation("BAD_PACKAGE", "empty identifier slot")
    if slot[len(text):] != b"\x00" * (len(slot) - len(text)):
        raise SpecViolation("BAD_PACKAGE", "identifier has non-zero right padding")
    s = text.decode("ascii", errors="strict")  # non-ASCII -> BAD_PACKAGE via exception? keep explicit
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in s):
        raise SpecViolation("BAD_PACKAGE", f"identifier charset: {s!r}")
    if not ("a" <= s[0] <= "z") or not s[-1].isalnum():
        raise SpecViolation("BAD_PACKAGE", f"identifier edge chars: {s!r}")


# ---------------------------------------------------------------------------
# Native image (v1-inherited strict cross-checks, ABI pinned to v2) (spec §3.3)
# ---------------------------------------------------------------------------

def build_native(target_addr, entry_offset, payload, abi=ABI_V2,
                 magic=0x3141454E, header_size=32, format_version=1, reserved0=0):
    """32B native header + payload; CRC32 over payload (reflected IEEE, zlib)."""
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    hdr = struct.pack("<IHHIIIIII", magic, header_size, format_version, abi,
                      target_addr, len(payload), entry_offset, reserved0, crc)
    return hdr + payload


def check_native_cross(native, manifest):
    """v1 §2.3-inherited cross-checks; v2 pins abi to the manifest value."""
    if len(native) < NATIVE_HEADER_SIZE:
        raise SpecViolation("BAD_PACKAGE", "native file shorter than 32B header")
    magic, hdr_size, fmt, abi, target, image_size, entry, reserved0, crc = struct.unpack_from(
        "<IHHIIIIII", native, 0)
    if magic != 0x3141454E:
        raise SpecViolation("BAD_PACKAGE", f"native magic 0x{magic:08x} != NEA1")
    if hdr_size != 32:
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
    if len(native) != 32 + image_size:
        raise SpecViolation("BAD_PACKAGE", "native_file_len != 32 + image_size")
    if manifest["native_file_len"] != len(native):
        raise SpecViolation("BAD_PACKAGE", "manifest native_file_len != actual native length")
    if not (entry < image_size and entry % 2 == 0):
        raise SpecViolation("BAD_PACKAGE", "entry_offset violates Thumb/size constraint")
    actual_crc = zlib.crc32(native[32:]) & 0xFFFFFFFF
    if actual_crc != crc:
        raise SpecViolation("BAD_PACKAGE", f"native CRC32 0x{actual_crc:08x} != header 0x{crc:08x}")
    actual_sha = sha256(native)
    if actual_sha != manifest["native_file_sha256"]:
        raise SpecViolation("BAD_PACKAGE", "native_file_sha256 mismatch")


# ---------------------------------------------------------------------------
# v2 container (spec §2)
# ---------------------------------------------------------------------------

def build_container(manifest192, native, sig_der):
    if len(manifest192) != V2_MANIFEST_LEN:
        raise SpecViolation("BAD_PACKAGE", "manifest must be exactly 192B")
    header = MAGIC_V2 + struct.pack("<II", V2_MANIFEST_LEN, len(native))
    tbs = header + manifest192 + native
    return tbs + sig_der, tbs


def parse_container(pkg, expected_magic=MAGIC_V2):
    """Structural parse only (spec §2.1/§2.2). Returns dict with tbs/manifest/native/sig."""
    if len(pkg) < 16 + V2_MANIFEST_LEN + NATIVE_HEADER_SIZE + DER_SIG_MIN:
        raise SpecViolation("BAD_PACKAGE", "package too short")
    if pkg[0:8] != expected_magic:
        raise SpecViolation("BAD_PACKAGE", f"container magic {pkg[0:8].hex()} != {expected_magic.hex()}")
    manifest_len, image_len = struct.unpack_from("<II", pkg, 8)
    if manifest_len != (V2_MANIFEST_LEN if expected_magic == MAGIC_V2 else V1_MANIFEST_LEN):
        raise SpecViolation("BAD_PACKAGE", f"manifest_len {manifest_len} wrong for container")
    native_off = 16 + manifest_len
    sig_off = native_off + image_len
    if sig_off >= len(pkg):
        raise SpecViolation("BAD_PACKAGE", "missing signature")
    # overflow-safe: lengths already bounded by len(pkg); verify exact consumption:
    sig_region = pkg[sig_off:]
    r, s = parse_strict_der_sig(sig_region)   # raises BAD_PACKAGE incl. tail consumption
    return {
        "manifest_len": manifest_len,
        "image_len": image_len,
        "tbs": pkg[:sig_off],
        "manifest": pkg[16:native_off],
        "native": pkg[native_off:sig_off],
        "sig": sig_region,
        "r": r,
        "s": s,
    }


# ---------------------------------------------------------------------------
# Host-side policy simulation (spec §2.3/§4/§8/§9)
# ---------------------------------------------------------------------------

# Public, unsafe, non-production P-256 test key (scalar d=1) standing in for the
# Host's locally provisioned issuer key. MUST NEVER be a production trust anchor.
TEST_PUBLISHER_SPKI = p256_spki_for_d(1)

# Host acceptance policy simulated from spec §2.3/§3.1/§3.3/§4/§8/§9 for the
# current business. Everything under "trusted_publishers"/loader_* is the
# HOST's own independently configured state, not data taken from the package.
HOST_POLICY_V2 = {
    "board_id": 0x00003010,
    "psram_mib": 64,
    "abi": ABI_V2,
    "caps_supported": CAP_KNOWN_MASK,
    # §2.3 step 3 / §3.1: Host-local publisher_id -> SPKI DER trust store.
    # The package carries only the fingerprint; the Host compares it against
    # its own entry and verifies with its OWN key, never a package-supplied one.
    "trusted_publishers": {
        "test-publisher": TEST_PUBLISHER_SPKI,
    },
    # §3.3 / v1-inherited: Host independently known loader placement and sizes.
    "loader_base": 0x93E00000,              # evidence-anchor controlled exec base
    "loader_size": EXPERIMENTAL_REGION_BYTES,
    "load_region_bytes": EXPERIMENTAL_REGION_BYTES,   # temp load capacity (v1 rule)
    "exec_region_bytes": EXPERIMENTAL_REGION_BYTES,   # actual exec region (v1 rule 2)
    "event_buffer_bytes": 2048,          # example host provision (>= 1576 required)
    "report_capacity_bytes": REPORT_BUSINESS_MAX,
    "state_quota_bytes": STATE_QUOTA_EXAMPLE,
    "event_min_for_ai_events": EVENT_MAX_BYTES,      # spec §4.1: >= 1576
    "report_min_for_report_submit": REPORT_BUSINESS_MAX,  # spec §4.1/§8 M7
}


def trusted_issuer_spki(host, manifest):
    """Spec §2.3 step 3 / §3.1: resolve the Host-local trusted issuer key for
    the signed manifest identity, fail-closed.

    The publisher_id must exist in the Host's own configured mapping AND the
    manifest publisher_key_sha256 must equal SHA-256 of that stored SPKI DER.
    Returns the SPKI DER to verify with; raises PUBLISHER_UNTRUSTED otherwise.
    """
    pid_bytes = manifest["publisher_id"]
    pid = pid_bytes.rstrip(b"\x00").decode("ascii")
    mapping = host.get("trusted_publishers", {})
    if pid not in mapping:
        raise SpecViolation("PUBLISHER_UNTRUSTED",
                            f"publisher_id {pid!r} not in Host trusted mapping")
    spki = mapping[pid]
    if manifest["publisher_key_sha256"] != sha256(spki):
        raise SpecViolation("PUBLISHER_UNTRUSTED",
                            f"publisher_key_sha256 mismatch for {pid!r} vs Host trust store")
    return spki


def policy_check_v2_host(manifest, native, host=HOST_POLICY_V2,
                         business="line-crossing-64"):
    """Simulated v2 Host acceptance policy AFTER structural + signature success.

    Implements spec §4.1/§4.2/§8/§9: board/psram/ABI/caps/quotas/load-region.
    Returns nothing; raises SpecViolation with the spec §9 error class."""
    if manifest["board_id"] != host["board_id"]:
        raise SpecViolation("TARGET_INCOMPATIBLE", f"board 0x{manifest['board_id']:08x}")
    if manifest["psram_mib"] > host["psram_mib"]:
        raise SpecViolation("TARGET_INCOMPATIBLE", "PSRAM requirement exceeds board")
    if manifest["abi"] != host["abi"]:
        raise SpecViolation("ABI_INCOMPATIBLE", f"host ABI is 0x{host['abi']:08x}")
    caps = manifest["caps"]
    if caps & ~CAP_KNOWN_MASK:
        raise SpecViolation("BAD_PACKAGE", f"unknown capability bits 0x{caps & ~CAP_KNOWN_MASK:08x}")
    unsupported = caps & ~host["caps_supported"]
    if unsupported:
        # AC2 / spec §4.2: a signature is only a request. A KNOWN capability the
        # current Host does not actually provide must be fail-closed rejected at
        # install/start (runtime calls would be UNAUTHORIZED/INCOMPATIBLE, §6.4).
        raise SpecViolation("ABI_INCOMPATIBLE",
                            f"host does not provide capability bits 0x{unsupported:08x} "
                            "(known but unsupported)")
    if manifest["run_profile"] != PROFILE_SINGLE_TRUSTED_SESSION:
        raise SpecViolation("BAD_PACKAGE", f"unknown run_profile {manifest['run_profile']}")
    if manifest["run_profile"] == PROFILE_SINGLE_TRUSTED_SESSION and \
            not (caps & CAP_SESSION_LIFECYCLE):
        raise SpecViolation("BAD_PACKAGE", "profile 1 must declare session_lifecycle (bit5)")
    if (caps & CAP_AI_EVENTS) and manifest["event_max"] == 0:
        raise SpecViolation("BAD_PACKAGE", "ai_events requires nonzero event_max")
    if (caps & CAP_REPORT_SUBMIT) and manifest["report_max"] == 0:
        raise SpecViolation("BAD_PACKAGE", "report_submit requires nonzero report_max")
    if (caps & CAP_APP_STATE) and manifest["state_quota"] == 0:
        raise SpecViolation("BAD_PACKAGE", "app_state requires nonzero state_quota")
    if (not (caps & CAP_AI_EVENTS)) and manifest["event_max"] != 0:
        raise SpecViolation("BAD_PACKAGE", "event_max set without ai_events")
    if (not (caps & CAP_REPORT_SUBMIT)) and manifest["report_max"] != 0:
        raise SpecViolation("BAD_PACKAGE", "report_max set without report_submit")
    if (not (caps & CAP_APP_STATE)) and manifest["state_quota"] != 0:
        raise SpecViolation("BAD_PACKAGE", "state_quota set without app_state")
    if business == "line-crossing-64":
        if (caps & CAP_AI_EVENTS) and manifest["event_max"] < host["event_min_for_ai_events"]:
            raise SpecViolation("RESOURCE_LIMIT",
                                f"event_max {manifest['event_max']} < {host['event_min_for_ai_events']} "
                                f"required for 64-detection ai_events")
        if (caps & CAP_REPORT_SUBMIT) and manifest["report_max"] < host["report_min_for_report_submit"]:
            raise SpecViolation("RESOURCE_LIMIT",
                                f"report_max {manifest['report_max']} < {host['report_min_for_report_submit']} "
                                f"cannot carry max legal line_counting report")
    if (caps & CAP_AI_EVENTS) and manifest["event_max"] > host["event_buffer_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "event_max exceeds host event buffer")
    if (caps & CAP_REPORT_SUBMIT) and manifest["report_max"] > host["report_capacity_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "report_max exceeds host report capacity")
    if (caps & CAP_APP_STATE) and manifest["state_quota"] > host["state_quota_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "state_quota exceeds host state quota")
    if manifest["native_file_len"] > host["load_region_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT", "native_file_len exceeds host load region")
    # §3.3/v1-inherited: the target address is checked against the Host's
    # INDEPENDENTLY known loader base/range — not merely against the package's
    # own self-declared manifest target (which check_native_cross already
    # cross-compares with the native header).
    target = manifest["native_target_addr"]
    range_hi = host["loader_base"] + host["loader_size"]
    if not (host["loader_base"] <= target < range_hi
            and target + manifest["native_file_len"] <= range_hi):
        raise SpecViolation("RESOURCE_LIMIT",
                            f"native target_addr 0x{target:08x}+{manifest['native_file_len']}B outside "
                            f"host loader range 0x{host['loader_base']:08x}..0x{range_hi:08x}")
    if manifest["exec_region"] < manifest["native_image_size"]:
        raise SpecViolation("RESOURCE_LIMIT", "exec_region < native payload residency")
    if manifest["exec_region"] > host["exec_region_bytes"]:
        raise SpecViolation("RESOURCE_LIMIT",
                            f"exec_region {manifest['exec_region']} exceeds host actual "
                            f"execution region {host['exec_region_bytes']}")


# ---------------------------------------------------------------------------
# AI event wire (spec §5)
# ---------------------------------------------------------------------------

def float_to_bits(value):
    import math
    if not math.isfinite(value):
        raise SpecViolation("INVALID_ARGUMENT", f"non-finite float {value!r}")
    return struct.unpack("<I", struct.pack("<f", value))[0]


def bits_to_float(bits):
    return struct.unpack("<f", struct.pack("<I", bits))[0]


def encode_event(kind, sequence, monotonic_ms, model_generation, class_generation,
                 flags, lost_frame_count, detections=()):
    """detections: iterable of (x, y, w, h, conf, class_index)."""
    if kind not in (EVENT_KIND_FRAME, EVENT_KIND_MODEL_CHANGED,
                    EVENT_KIND_GAP, EVENT_KIND_STOPPING):
        raise SpecViolation("BAD_EVENT", f"unknown kind {kind}")
    if flags & ~0b11:
        raise SpecViolation("BAD_EVENT", f"undefined flag bits 0x{flags:08x}")
    if (flags & 0b10) and lost_frame_count != LOST_COUNT_UNKNOWN:
        raise SpecViolation("BAD_EVENT", "flags.bit1=1 requires lost_frame_count=0xFFFFFFFF")
    if (not (flags & 0b10)) and lost_frame_count == LOST_COUNT_UNKNOWN:
        raise SpecViolation("BAD_EVENT", "lost_frame_count sentinel without flags.bit1")
    dets = list(detections)
    if kind == EVENT_KIND_FRAME:
        if len(dets) > EVENT_MAX_DETECTIONS:
            raise SpecViolation("BAD_EVENT", f"{len(dets)} detections > {EVENT_MAX_DETECTIONS}")
        total = EVENT_HEADER_SIZE + EVENT_RECORD_SIZE * len(dets)
    else:
        if dets:
            raise SpecViolation("BAD_EVENT", f"kind {kind} must carry zero detections")
        total = EVENT_HEADER_SIZE
    head = struct.pack("<10I", total, kind, sequence, monotonic_ms,
                       model_generation, class_generation, flags,
                       len(dets) if kind == EVENT_KIND_FRAME else 0,
                       lost_frame_count, 0)
    recs = b"".join(
        struct.pack("<6I",
                    float_to_bits(d[0]), float_to_bits(d[1]), float_to_bits(d[2]),
                    float_to_bits(d[3]), float_to_bits(d[4]), d[5])
        for d in dets)
    return head + recs


def validate_event(buf, class_count=None):
    """Strict wire validation (spec §5.1/§5.2). Returns parsed dict or raises."""
    if len(buf) < EVENT_HEADER_SIZE:
        raise SpecViolation("BAD_EVENT", "shorter than 40B header")
    (total_len, kind, sequence, monotonic_ms, model_generation, class_generation,
     flags, detection_count, lost_frame_count, reserved0) = struct.unpack_from("<10I", buf, 0)
    if reserved0 != 0:
        raise SpecViolation("BAD_EVENT", "reserved0 != 0")
    if kind not in (EVENT_KIND_FRAME, EVENT_KIND_MODEL_CHANGED,
                    EVENT_KIND_GAP, EVENT_KIND_STOPPING):
        raise SpecViolation("BAD_EVENT", f"unknown kind {kind}")
    if flags & ~0b11:
        raise SpecViolation("BAD_EVENT", f"undefined flag bits 0x{flags:08x}")
    if kind == EVENT_KIND_FRAME:
        if detection_count > EVENT_MAX_DETECTIONS:
            raise SpecViolation("BAD_EVENT", f"detection_count {detection_count} > 64")
        if total_len != EVENT_HEADER_SIZE + EVENT_RECORD_SIZE * detection_count:
            raise SpecViolation("BAD_EVENT", "total_len != 40 + 24*detection_count")
    else:
        if detection_count != 0:
            raise SpecViolation("BAD_EVENT", f"kind {kind} must have detection_count=0")
        if total_len != EVENT_HEADER_SIZE:
            raise SpecViolation("BAD_EVENT", f"kind {kind} must have total_len=40")
    if len(buf) != total_len:
        raise SpecViolation("BAD_EVENT", f"buffer length {len(buf)} != total_len {total_len}")
    if (flags & 0b10) and lost_frame_count != LOST_COUNT_UNKNOWN:
        raise SpecViolation("BAD_EVENT", "flags.bit1=1 requires lost_frame_count=0xFFFFFFFF")
    if (not (flags & 0b10)) and lost_frame_count == LOST_COUNT_UNKNOWN:
        raise SpecViolation("BAD_EVENT", "lost_frame_count sentinel without flags.bit1")
    records = []
    for i in range(detection_count):
        (xb, yb, wb, hb, cb, cls) = struct.unpack_from("<6I", buf, EVENT_HEADER_SIZE + i * EVENT_RECORD_SIZE)
        for name, bits in (("x", xb), ("y", yb), ("width", wb), ("height", hb), ("confidence", cb)):
            if (bits & 0x7F800000) == 0x7F800000:
                raise SpecViolation("BAD_EVENT", f"record {i} {flags_name(name)} not finite")
        if class_count is not None and cls >= class_count:
            raise SpecViolation("BAD_EVENT", f"record {i} class_index {cls} >= class_count {class_count}")
        records.append((xb, yb, wb, hb, cb, cls))
    return {"total_len": total_len, "kind": kind, "sequence": sequence,
            "monotonic_ms": monotonic_ms, "model_generation": model_generation,
            "class_generation": class_generation, "flags": flags,
            "detection_count": detection_count, "lost_frame_count": lost_frame_count,
            "records": records}


def flags_name(n):
    return n


# ---------------------------------------------------------------------------
# model_meta / class_name host-side encodings (spec §6.5)
# ---------------------------------------------------------------------------

MODEL_META_SIZE = 128
MODEL_NAME_LEN = 64
MODEL_VERSION_LEN = 32


def encode_model_meta(loaded, model_generation, class_generation, class_count,
                      model_name, model_version, result_type=PP_TYPE_OD):
    name = model_name.encode("utf-8")
    ver = model_version.encode("utf-8")
    if len(name) > MODEL_NAME_LEN - 1 or len(ver) > MODEL_VERSION_LEN - 1:
        raise SpecViolation("INCOMPATIBLE", "model_name/model_version cannot be represented")
    out = bytearray(MODEL_META_SIZE)
    struct.pack_into("<6I", out, 0, 1 if loaded else 0, result_type,
                     model_generation, class_generation, class_count, 0)
    out[24:24 + len(name)] = name
    out[24 + MODEL_NAME_LEN:24 + MODEL_NAME_LEN + len(ver)] = ver
    # trailing 8B reserved stays zero
    return bytes(out)


def _strict_nul_field(field, label):
    """Spec §6.5 strict NUL-terminated/right-zero-padded UTF-8 field:
    at least one NUL must exist, every byte after the FIRST NUL must be zero,
    and the text must be valid UTF-8."""
    nul = field.find(b"\x00")
    if nul < 0:
        raise SpecViolation("INCOMPATIBLE", f"{label} missing NUL terminator")
    if field[nul:] != b"\x00" * (len(field) - nul):
        raise SpecViolation("INCOMPATIBLE", f"{label} has non-zero bytes after its NUL")
    try:
        return field[:nul].decode("utf-8")
    except UnicodeDecodeError:
        raise SpecViolation("INCOMPATIBLE", f"{label} is not valid UTF-8")


def validate_model_meta(buf):
    if len(buf) != MODEL_META_SIZE:
        raise SpecViolation("INCOMPATIBLE", "model_meta must be exactly 128B")
    loaded, result_type, mgen, cgen, ccount, res0 = struct.unpack_from("<6I", buf, 0)
    if res0 != 0:
        raise SpecViolation("INCOMPATIBLE", "model_meta reserved0 != 0")
    if result_type != PP_TYPE_OD:
        raise SpecViolation("INCOMPATIBLE", f"result_type {result_type} != PP_TYPE_OD")
    if buf[24 + MODEL_NAME_LEN + MODEL_VERSION_LEN:] != bytes(8):
        raise SpecViolation("INCOMPATIBLE", "model_meta trailing reserved not zero")
    name = buf[24:24 + MODEL_NAME_LEN]
    ver = buf[24 + MODEL_NAME_LEN:24 + MODEL_NAME_LEN + MODEL_VERSION_LEN]
    return {"loaded": loaded, "result_type": result_type, "model_generation": mgen,
            "class_generation": cgen, "class_count": ccount,
            "model_name": _strict_nul_field(name, "model_name"),
            "model_version": _strict_nul_field(ver, "model_version")}


# ---------------------------------------------------------------------------
# tick_ms modulo-2^32 semantics (A decision issuecomment-6093724900)
# ---------------------------------------------------------------------------

TICK_MODULUS = 1 << 32


def tick_delta_ms(prev_bits, cur_bits):
    """tick_ms returns the raw modulo-2^32 monotonic millisecond bit pattern —
    the single exception to the §6.4 negative-error-code channel. Forward
    progress is the mod-2^32 difference of the raw bit patterns, NEVER the
    signed int32 interpretation (whose negative values must not be read as
    §6.4 error codes)."""
    for bits in (prev_bits, cur_bits):
        if not 0 <= bits < TICK_MODULUS:
            raise SpecViolation("INVALID_ARGUMENT", f"tick bits 0x{bits:08x} outside u32")
    return (cur_bits - prev_bits) % TICK_MODULUS


# ---------------------------------------------------------------------------
# Minimal frozen-v1 structural gate — interop simulation ONLY (spec §8 M2/M3)
# The integrated v1 spec remains the v1 authority; P3 #6 owns v1 tooling.
# ---------------------------------------------------------------------------

def v1_gate_structural(pkg):
    """Frozen-v1 structural acceptance (v1 spec §2.2/§2.3), for interop tests."""
    if len(pkg) < 16 + V1_MANIFEST_LEN + NATIVE_HEADER_SIZE + DER_SIG_MIN:
        raise SpecViolation("BAD_PACKAGE", "v1: package too short")
    if pkg[0:8] != MAGIC_V1:
        raise SpecViolation("BAD_PACKAGE", f"v1: unknown container magic {pkg[0:8].hex()}")
    manifest_len, image_len = struct.unpack_from("<II", pkg, 8)
    if manifest_len != V1_MANIFEST_LEN:
        raise SpecViolation("BAD_PACKAGE", f"v1: manifest_len {manifest_len} != 160")
    sig_off = 16 + manifest_len + image_len
    sig = pkg[sig_off:]
    parse_strict_der_sig(sig)
    m = pkg[16:16 + 160]
    if m[0:4] != MANIFEST_MAGIC_V1:
        raise SpecViolation("BAD_PACKAGE", f"v1: manifest magic {m[0:4]!r} != NMF1")
    if m[58:60] != b"\x00\x00":
        raise SpecViolation("BAD_PACKAGE", "v1: reserved[58..59] not zero")
    abi = struct.unpack_from("<I", m, 68)[0]
    caps = struct.unpack_from("<I", m, 72)[0]
    if caps & ~0b11:
        raise SpecViolation("BAD_PACKAGE", f"v1: caps 0x{caps:08x} beyond log|tick_ms")
    native = pkg[16 + 160:sig_off]
    (magic, hdr_size, fmt, nabi, target, image_size, entry, reserved0,
     crc) = struct.unpack_from("<IHHIIIIII", native, 0)
    if magic != 0x3141454E or hdr_size != 32 or fmt != 1:
        raise SpecViolation("BAD_PACKAGE", "v1: bad native header identity")
    if nabi != abi:
        raise SpecViolation("BAD_PACKAGE", "v1: native abi != manifest abi")
    if reserved0 != 0:
        raise SpecViolation("BAD_PACKAGE", "v1: native reserved0 != 0")
    if len(native) != 32 + image_size:
        raise SpecViolation("BAD_PACKAGE", "v1: native length mismatch")
    if sha256(native) != m[96:128]:
        raise SpecViolation("BAD_PACKAGE", "v1: native_file_sha256 mismatch")
    return {"tbs": pkg[:sig_off], "sig": sig, "abi": abi, "caps": caps}
