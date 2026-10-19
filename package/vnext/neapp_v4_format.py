#!/usr/bin/env python3
"""neapp_v4_format — offline format/policy authority for signed .neapp v4
("signed native vNext", next-major) packages.

The single byte-level authority is the A-owned Host #104 architecture
freeze (harryhua-ai/ne301#104); this module implements ONLY the frozen
subset and invents no wire bytes of its own:

  F1 (comment 6258534821): container magic 4e45415050040000, manifest_len
      exactly 208, native_file_len, 208B NMF4 manifest, native image,
      exactly one trailing strict-DER ECDSA P-256 signature (8..72B, no
      length prefix, no chain, no tail); TBS = file[0 : 224 +
      native_file_len]; SHA-256(TBS) is the content identity and the only
      signed digest; native_file_len <= 2,097,152; package_len <=
      2,097,448; u64-checked length arithmetic; native NEA1 32B header
      with format_version 1, header_size 32, CRC-32 and abi_version pinned
      0x00040000; trust is the Host-local publisher_id ->
      SHA-256(SPKI DER) mapping — a public key carried in or near a
      package never becomes a trust root.
  F2 (same comment): 208B NMF4 layout; [58..59] and [192..207] reserved
      all-zero; required_host_abi pinned 0x00040000; run_profile pinned 3;
      quotas [164..183] reuse the v3 quota semantics for the same
      capability bits; [184..187] live_publish_max; [188..191]
      live_track_max.
  F3 (same comment): known_caps_mask 0x000003FF; bit8 = ENABLE_CONTROL
      requiring bit4+bit5+bit6 in the same package; bit9 = LIVE_PUBLISH
      requiring bit5, live_publish_max >= 312 and 1 <= live_track_max <=
      64; without bit9 both live quotas must be 0; bits 10..31 reject;
      the v4 ABI function table is exactly 64B: table_size 64, abi_version
      0x00040000, 13 pointers at offsets 8..56 with the v3 signatures, and
      live_publish at 60..63; every entry is a 32-bit Thumb pointer.
  F9 (comment 6258637748): a signed live_publish_max declaration must at
      least cover the worst-case ACTIVE_TRACKS_SNAPSHOT closure
      48 + live_track_max * (12 + 16*8) bytes (e.g. live_track_max=64
      requires >= 9008); staying within actual Host capacity is separate
      admission, never a packer choice.

Implementation independence (App #36 AC2/AC3): this module shares no code
with package/neapp_format.py / neapp_v2_format.py / neapp_v3_format.py;
all DER/SPKI/native/CRC primitives below are self-written for v4.  v4 is
an independent container major: v1/v2/v3 packages are never parsed here,
and v3 manifests, v3 run profiles, v3 capability bits beyond bit7, v3
function tables (60B) and v3 NFC3 control messages are all foreign input
that fails closed.

Verification tiers (mirrors the frozen v3 separation):

  * intrinsic tier (host_admission=False): bounded structure, manifest
    unique encoding, trust mapping, signature, native cross-checks and the
    Host-independent manifest policy rules (unknown capability bits, bit8/
    bit9 prerequisites, live quota closure, quota/capability consistency,
    generic 32B control-wire minimum).  Holds for ANY v4 Host.
  * target-Host admission tier (host_admission=True, verifier default):
    additionally applies one CONCRETE DevicePolicyV4 — board, PSRAM, ABI,
    Host-provided capability bits and Host capacity ceilings (quotas,
    live capacity, loader/exec geometry).  Those Host facts are device
    acceptance, not offline tooling facts.

BOUNDARY: signed-format PASS is offline tooling evidence only.  It never
means a Host admitted the package, a native image ran, or that
ENABLE_CONTROL / LIVE_PUBLISH are usable: those exist at runtime only when
the actual Host implements and grants them (UNAVAILABLE/UNAUTHORIZED
otherwise), and the remaining #104 control/live/floor bytes are still
being frozen there.  No device, production key, real issuance, network or
release is involved in this module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

CONTAINER_MAGIC = bytes.fromhex("4e45415050040000")
MANIFEST_MAGIC = b"NMF4"
MANIFEST_LEN = 208
HEADER_LEN = 16
MAX_NATIVE_FILE_LEN = 2_097_152
MAX_PACKAGE_LEN = 2_097_448
MIN_SIG_LEN = 8
MAX_SIG_LEN = 72

NATIVE_MAGIC = b"NEA1"
NATIVE_FORMAT_VERSION = 1
NATIVE_HEADER_SIZE = 32
NATIVE_HDR = struct.Struct("<IHHIIIIII")

HOST_ABI_V4 = 0x00040000
TARGET_BOARD_ID_V4 = 0x00003010
REQUIRED_PSRAM_MIB_V4 = 64
EXEC_BASE_V4 = 0x93E00000
EXEC_REGION_BYTES_V4 = 0x200000

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
HOST_CAPS_KNOWN_MASK = 0x000003FF

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

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")
OID_PRIME256V1 = bytes.fromhex("06082a8648ce3d030107")

V4_FUNCTION_NAMES = (
    "log", "tick_ms", "event_next", "model_meta", "class_name",
    "report_submit", "report_status", "state_read", "state_commit",
    "should_stop", "control_next", "control_reply", "snapshot_publish",
    "live_publish",
)
V4_TABLE_SIZE = 64
V4_TABLE_POINTER_OFFSETS = tuple(range(8, 64, 4))


class PackageError(Exception):
    code = "PACKAGE_ERROR"

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class BadPackage(PackageError):
    code = "BAD_PACKAGE"


class SignatureInvalid(PackageError):
    code = "SIGNATURE_INVALID"


class PublisherUntrusted(PackageError):
    code = "PUBLISHER_UNTRUSTED"


class TargetIncompatible(PackageError):
    code = "TARGET_INCOMPATIBLE"


class AbiIncompatible(PackageError):
    code = "ABI_INCOMPATIBLE"


class ResourceLimit(PackageError):
    code = "RESOURCE_LIMIT"


ERROR_CLASSES = (
    BadPackage,
    SignatureInvalid,
    PublisherUntrusted,
    TargetIncompatible,
    AbiIncompatible,
    ResourceLimit,
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def u64_checked_sum(*values: int) -> int:
    total = 0
    for v in values:
        total += v
        if total > 0xFFFFFFFFFFFFFFFF:
            raise BadPackage(f"length arithmetic exceeds u64: {values!r}")
    return total


def validate_identifier(field: str, value: bytes, max_len: int) -> str:
    if not value:
        raise BadPackage(f"{field}: manifest identifier slot is absent")
    text = value.rstrip(b"\x00")
    if not text:
        raise BadPackage(f"{field}: empty identifier")
    if len(text) > max_len:
        raise BadPackage(f"{field}: identifier longer than {max_len} bytes")
    if b"\x00" in text:
        raise BadPackage(f"{field}: embedded NUL inside identifier")
    if len(text) < len(value) and value[len(text):] != b"\x00" * (len(value) - len(text)):
        raise BadPackage(f"{field}: non-zero right padding after identifier")
    if not all(0x61 <= c <= 0x7A or 0x30 <= c <= 0x39 or c == 0x2D for c in text):
        raise BadPackage(f"{field}: character outside [a-z0-9-]")
    first, last = text[0], text[-1]
    if not (0x61 <= first <= 0x7A):
        raise BadPackage(f"{field}: must start with a lowercase letter")
    if not (0x61 <= last <= 0x7A or 0x30 <= last <= 0x39):
        raise BadPackage(f"{field}: must end with a letter or digit")
    return text.decode("ascii")


def live_track_snapshot_closure_bytes(live_track_max: int) -> int:
    return u64_checked_sum(
        LIVE_HEADER_SIZE, live_track_max * (LIVE_TRACK_HEADER_SIZE + LIVE_TRACK_MAX_POINTS * LIVE_TRACK_POINT_SIZE)
    )


def min_live_publish_max(live_track_max: int) -> int:
    return max(LIVE_PUBLISH_MIN, live_track_snapshot_closure_bytes(live_track_max))


@dataclass
class ManifestV4:
    publisher_id: str
    app_id: str
    version_major: int
    version_minor: int
    version_patch: int
    target_board_id: int
    required_psram_mib: int
    required_host_abi: int
    required_host_caps: int
    required_exec_region_bytes: int
    native_file_len: int
    native_image_size: int
    native_entry_offset: int
    native_target_addr: int
    native_file_sha256: bytes
    publisher_key_sha256: bytes
    run_profile: int
    event_max: int
    state_quota: int
    report_max: int
    control_max: int
    snapshot_max: int
    live_publish_max: int
    live_track_max: int


def validate_policy_shape(caps: int, run_profile: int, event_max: int, state_quota: int,
                          report_max: int, control_max: int, snapshot_max: int,
                          live_publish_max: int, live_track_max: int) -> None:
    if caps & ~HOST_CAPS_KNOWN_MASK:
        raise BadPackage(f"required_host_caps has unknown bits: {caps & ~HOST_CAPS_KNOWN_MASK:#x}")
    if run_profile != RUN_PROFILE_V4:
        raise BadPackage(
            f"unknown run_profile {run_profile} (v4 allows only {RUN_PROFILE_V4}; "
            "v3 profile 2 and v2 profile 1 are not reinterpreted here)"
        )
    if not caps & CAP_SESSION_LIFECYCLE:
        raise BadPackage("v4 run_profile 3 requires the session_lifecycle capability (bit5)")
    quota_pairs = (
        (CAP_AI_EVENTS, event_max, "ai_events (bit2)", "event_max"),
        (CAP_REPORT_SUBMIT, report_max, "report_submit (bit3)", "report_max"),
        (CAP_APP_STATE, state_quota, "app_state (bit4)", "state_quota"),
        (CAP_CONTROL_RECEIVE, control_max, "control_receive (bit6)", "control_max"),
        (CAP_BUSINESS_SNAPSHOT, snapshot_max, "business_snapshot (bit7)", "snapshot_max"),
    )
    for bit, quota, cap_name, quota_name in quota_pairs:
        if caps & bit and quota == 0:
            raise BadPackage(f"{cap_name} requires a nonzero {quota_name}")
        if quota != 0 and not caps & bit:
            raise BadPackage(f"{quota_name} set without the {cap_name} capability")
    if caps & CAP_CONTROL_RECEIVE and control_max < CONTROL_WIRE_MIN:
        raise ResourceLimit(
            f"control_max {control_max} is below the generic 32B control-wire minimum "
            f"{CONTROL_WIRE_MIN} (v3-inherited quota semantics, Host #104 F2)"
        )
    if caps & CAP_ENABLE_CONTROL:
        missing = {bit: name for bit, name in (
            (CAP_APP_STATE, "app_state (bit4)"),
            (CAP_SESSION_LIFECYCLE, "session_lifecycle (bit5)"),
            (CAP_CONTROL_RECEIVE, "control_receive (bit6)"),
        ) if not caps & bit}
        if missing:
            raise BadPackage(
                f"ENABLE_CONTROL (bit8) requires the same package to declare "
                + ", ".join(missing.values())
            )
    if caps & CAP_LIVE_PUBLISH:
        if not caps & CAP_SESSION_LIFECYCLE:
            raise BadPackage("LIVE_PUBLISH (bit9) requires the session_lifecycle capability (bit5)")
        if live_publish_max < LIVE_PUBLISH_MIN:
            raise ResourceLimit(
                f"LIVE_PUBLISH requires live_publish_max >= {LIVE_PUBLISH_MIN}, got {live_publish_max}"
            )
        if not 1 <= live_track_max <= LIVE_TRACK_MAX_LIMIT:
            raise BadPackage(
                f"LIVE_PUBLISH requires live_track_max in 1..{LIVE_TRACK_MAX_LIMIT}, got {live_track_max}"
            )
        closure = live_track_snapshot_closure_bytes(live_track_max)
        if live_publish_max < closure:
            raise ResourceLimit(
                f"live_publish_max {live_publish_max} is below the worst-case "
                f"ACTIVE_TRACKS_SNAPSHOT closure {closure} "
                f"(48 + {live_track_max} * 140, Host #104 F9)"
            )
    else:
        if live_publish_max != 0 or live_track_max != 0:
            raise BadPackage(
                "without LIVE_PUBLISH (bit9) both live_publish_max and live_track_max "
                f"must be 0 (got {live_publish_max}/{live_track_max})"
            )


def build_manifest_v4(m: ManifestV4) -> bytes:
    pub = validate_identifier("publisher_id", m.publisher_id.encode("ascii"), 16)
    app = validate_identifier("app_id", m.app_id.encode("ascii"), 32)
    for name, v in (("version_major", m.version_major),
                    ("version_minor", m.version_minor),
                    ("version_patch", m.version_patch)):
        if not 0 <= v <= 0xFFFF:
            raise BadPackage(f"{name} out of u16 range: {v}")
    if m.required_host_abi != HOST_ABI_V4:
        raise BadPackage(
            f"v4 manifest required_host_abi must be {HOST_ABI_V4:#010x}, "
            f"got {m.required_host_abi:#010x}"
        )
    validate_policy_shape(m.required_host_caps, m.run_profile, m.event_max, m.state_quota,
                          m.report_max, m.control_max, m.snapshot_max,
                          m.live_publish_max, m.live_track_max)
    if m.native_file_len != NATIVE_HEADER_SIZE + m.native_image_size:
        raise BadPackage("native_file_len != 32 + native_image_size")
    out = bytearray(MANIFEST_LEN)
    out[0:4] = MANIFEST_MAGIC
    out[4:20] = pub.encode("ascii").ljust(16, b"\x00")
    out[20:52] = app.encode("ascii").ljust(32, b"\x00")
    out[52:54] = struct.pack("<H", m.version_major)
    out[54:56] = struct.pack("<H", m.version_minor)
    out[56:58] = struct.pack("<H", m.version_patch)
    out[60:64] = struct.pack("<I", m.target_board_id)
    out[64:68] = struct.pack("<I", m.required_psram_mib)
    out[68:72] = struct.pack("<I", m.required_host_abi)
    out[72:76] = struct.pack("<I", m.required_host_caps)
    out[76:80] = struct.pack("<I", m.required_exec_region_bytes)
    out[80:84] = struct.pack("<I", m.native_file_len)
    out[84:88] = struct.pack("<I", m.native_image_size)
    out[88:92] = struct.pack("<I", m.native_entry_offset)
    out[92:96] = struct.pack("<I", m.native_target_addr)
    out[96:128] = m.native_file_sha256
    out[128:160] = m.publisher_key_sha256
    out[160:164] = struct.pack("<I", m.run_profile)
    out[164:168] = struct.pack("<I", m.event_max)
    out[168:172] = struct.pack("<I", m.state_quota)
    out[172:176] = struct.pack("<I", m.report_max)
    out[176:180] = struct.pack("<I", m.control_max)
    out[180:184] = struct.pack("<I", m.snapshot_max)
    out[184:188] = struct.pack("<I", m.live_publish_max)
    out[188:192] = struct.pack("<I", m.live_track_max)
    if len(out) != MANIFEST_LEN:
        raise BadPackage("v4 manifest encoder produced wrong length")
    return bytes(out)


def parse_manifest_v4(raw: bytes) -> ManifestV4:
    if len(raw) != MANIFEST_LEN:
        raise BadPackage(f"manifest is {len(raw)} bytes, v4 requires exactly {MANIFEST_LEN}")
    if raw[0:4] != MANIFEST_MAGIC:
        raise BadPackage(
            f"manifest magic is {raw[0:4]!r}, v4 requires exactly NMF4 "
            "(a v3 NMF3 manifest inside a v4 container is foreign input)"
        )
    if raw[58:60] != b"\x00\x00":
        raise BadPackage("manifest reserved bytes (58..59) are not zero")
    if raw[192:208] != b"\x00" * 16:
        raise BadPackage("manifest reserved bytes (192..207) are not zero")
    abi = struct.unpack_from("<I", raw, 68)[0]
    if abi != HOST_ABI_V4:
        raise BadPackage(
            f"v4 manifest required_host_abi must be {HOST_ABI_V4:#010x}, got {abi:#010x} "
            "(format invariant, Host #104 F1/F2)"
        )
    publisher_id = validate_identifier("publisher_id", raw[4:20], 16)
    app_id = validate_identifier("app_id", raw[20:52], 32)
    vmaj, vmin, vpat = struct.unpack_from("<HHH", raw, 52)
    (board, psram, _abi, caps, exec_region, file_len, image_size, entry, target) = (
        struct.unpack_from("<9I", raw, 60))
    run_profile, event_max, state_quota, report_max, control_max, snapshot_max = (
        struct.unpack_from("<6I", raw, 160))
    live_publish_max, live_track_max = struct.unpack_from("<2I", raw, 184)
    return ManifestV4(
        publisher_id=publisher_id,
        app_id=app_id,
        version_major=vmaj,
        version_minor=vmin,
        version_patch=vpat,
        target_board_id=board,
        required_psram_mib=psram,
        required_host_abi=abi,
        required_host_caps=caps,
        required_exec_region_bytes=exec_region,
        native_file_len=file_len,
        native_image_size=image_size,
        native_entry_offset=entry,
        native_target_addr=target,
        native_file_sha256=raw[96:128],
        publisher_key_sha256=raw[128:160],
        run_profile=run_profile,
        event_max=event_max,
        state_quota=state_quota,
        report_max=report_max,
        control_max=control_max,
        snapshot_max=snapshot_max,
        live_publish_max=live_publish_max,
        live_track_max=live_track_max,
    )


def build_container_prefix_v4(manifest: bytes, image: bytes) -> bytes:
    if len(manifest) != MANIFEST_LEN:
        raise BadPackage("manifest must be exactly 208 bytes")
    if len(image) > MAX_NATIVE_FILE_LEN:
        raise BadPackage("native image exceeds the v4 file cap")
    return (
        CONTAINER_MAGIC
        + struct.pack("<I", MANIFEST_LEN)
        + struct.pack("<I", len(image))
        + manifest
        + image
    )


@dataclass
class NativeHeaderV4:
    magic: bytes
    header_size: int
    format_version: int
    abi_version: int
    target_addr: int
    image_size: int
    entry_offset: int
    reserved0: int
    crc32: int


def parse_native_header_v4(image: bytes) -> NativeHeaderV4:
    if len(image) < NATIVE_HEADER_SIZE:
        raise BadPackage(f"native image shorter than the {NATIVE_HEADER_SIZE}-byte header")
    fields = NATIVE_HDR.unpack_from(image)
    return NativeHeaderV4(
        magic=fields[0].to_bytes(4, "little"),
        header_size=fields[1],
        format_version=fields[2],
        abi_version=fields[3],
        target_addr=fields[4],
        image_size=fields[5],
        entry_offset=fields[6],
        reserved0=fields[7],
        crc32=fields[8],
    )


def native_payload_crc32_v4(image: bytes, image_size: int) -> int:
    return zlib.crc32(image[NATIVE_HEADER_SIZE:NATIVE_HEADER_SIZE + image_size]) & 0xFFFFFFFF


def _read_der_length(data: bytes, pos: int, end: int) -> tuple[int, int]:
    if pos >= end:
        raise BadPackage("DER: truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    if first == 0x80:
        raise BadPackage("DER: indefinite length is not DER")
    n = first & 0x7F
    if n > 4:
        raise BadPackage("DER: implausible long-form length")
    if pos + n > end:
        raise BadPackage("DER: truncated long-form length")
    if data[pos] == 0:
        raise BadPackage("DER: long-form length has leading zero (non-minimal)")
    length = int.from_bytes(data[pos:pos + n], "big")
    if length < 0x80:
        raise BadPackage("DER: long form used for short length (non-minimal)")
    return length, pos + n


def _read_der_integer(data: bytes, pos: int, end: int) -> tuple[int, int]:
    if pos >= end or data[pos] != 0x02:
        raise BadPackage("DER: expected INTEGER tag")
    pos += 1
    length, pos = _read_der_length(data, pos, end)
    if pos + length > end:
        raise BadPackage("DER: INTEGER content overruns buffer")
    if length == 0:
        raise BadPackage("DER: zero-length INTEGER")
    content = data[pos:pos + length]
    if content[0] & 0x80:
        raise BadPackage("DER: negative INTEGER")
    if length > 1 and content[0] == 0 and (content[1] & 0x80) == 0:
        raise BadPackage("DER: non-minimal INTEGER (redundant leading zero)")
    return int.from_bytes(content, "big"), pos + length


def parse_strict_ecdsa_der_v4(sig: bytes) -> tuple[int, int]:
    end = len(sig)
    if end == 0 or sig[0] != 0x30:
        raise BadPackage("DER: signature does not start with SEQUENCE tag")
    seq_len, pos = _read_der_length(sig, 1, end)
    seq_end = pos + seq_len
    if seq_end > end:
        raise BadPackage("DER: SEQUENCE content overruns buffer")
    if seq_end != end:
        raise BadPackage("DER: SEQUENCE length does not consume the signature exactly")
    r, pos = _read_der_integer(sig, pos, seq_end)
    s, pos = _read_der_integer(sig, pos, seq_end)
    if pos != seq_end:
        raise BadPackage("DER: extra bytes inside SEQUENCE after the two INTEGERs")
    if pos != end:
        raise BadPackage("DER: trailing bytes after the DER object")
    if not 1 <= r < P256_ORDER:
        raise BadPackage("DER: r outside P-256 range")
    if not 1 <= s < P256_ORDER:
        raise BadPackage("DER: s outside P-256 range")
    return r, s


def parse_spki_p256_v4(spki: bytes):
    from cryptography.hazmat.primitives.asymmetric import ec

    end = len(spki)
    if end == 0 or spki[0] != 0x30:
        raise BadPackage("SPKI: does not start with SEQUENCE")
    seq_len, pos = _read_der_length(spki, 1, end)
    seq_end = pos + seq_len
    if seq_end != end:
        raise BadPackage("SPKI: SEQUENCE does not consume the input exactly")
    if pos >= end or spki[pos] != 0x30:
        raise BadPackage("SPKI: missing AlgorithmIdentifier SEQUENCE")
    alg_len, pos = _read_der_length(spki, pos + 1, end)
    alg_end = pos + alg_len
    if spki[pos:pos + len(OID_EC_PUBLIC_KEY)] != OID_EC_PUBLIC_KEY:
        raise BadPackage("SPKI: algorithm is not ecPublicKey")
    pos += len(OID_EC_PUBLIC_KEY)
    if spki[pos:pos + len(OID_PRIME256V1)] != OID_PRIME256V1:
        raise BadPackage("SPKI: curve parameter is not prime256v1")
    pos += len(OID_PRIME256V1)
    if pos != alg_end:
        raise BadPackage("SPKI: trailing bytes inside AlgorithmIdentifier")
    if pos >= end or spki[pos] != 0x03:
        raise BadPackage("SPKI: missing BIT STRING subjectPublicKey")
    bits_len, pos = _read_der_length(spki, pos + 1, end)
    if pos + bits_len != seq_end:
        raise BadPackage("SPKI: BIT STRING does not end the SPKI exactly")
    content = spki[pos:pos + bits_len]
    if len(content) < 2 or content[0] != 0:
        raise BadPackage("SPKI: BIT STRING has unused bits")
    point = content[1:]
    if len(point) != 65 or point[0] != 0x04:
        raise BadPackage("SPKI: subjectPublicKey is not an uncompressed P-256 point")
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    if key is None:
        raise BadPackage("SPKI: point is not on the P-256 curve")
    return key


def spki_der_from_public_key_v4(pub) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@dataclass
class TrustStoreV4:
    publishers: dict[str, tuple[str, bytes]]

    def lookup(self, publisher_id: str) -> tuple[str, bytes] | None:
        return self.publishers.get(publisher_id)


def load_trust_store_v4(path: Path) -> TrustStoreV4:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if raw.get("version") != 1:
        raise ValueError(f"unsupported trust store version: {raw.get('version')!r}")
    publishers: dict[str, tuple[str, bytes]] = {}
    for pub_id, entry in raw.get("publishers", {}).items():
        validate_identifier("trust store publisher_id", pub_id.encode("ascii"), 16)
        if "spki_der_hex" in entry:
            spki = bytes.fromhex(entry["spki_der_hex"])
        elif "spki_der_file" in entry:
            spki = (Path(path).parent / entry["spki_der_file"]).read_bytes()
        else:
            raise ValueError(f"trust store entry for {pub_id} has no SPKI material")
        digest = sha256_hex(spki)
        expected = entry.get("spki_sha256")
        if expected is not None and not constant_time_eq(digest.encode(), str(expected).encode()):
            raise ValueError(f"trust store SPKI sha256 mismatch for {pub_id}")
        publishers[pub_id] = (digest, spki)
    return TrustStoreV4(publishers=publishers)


@dataclass
class DevicePolicyV4:
    """Offline stand-in for one concrete v4 Host's admission facts.

    Defaults are golden SIMULATION reference values for reproducible
    evidence, never measured device capacity (Host #104 F1: board/PSRAM/
    live capacity "仍须独立校验")."""

    target_board_id: int = TARGET_BOARD_ID_V4
    psram_mib: int = REQUIRED_PSRAM_MIB_V4
    host_abi: int = HOST_ABI_V4
    host_caps: int = HOST_CAPS_KNOWN_MASK
    loader_base: int = EXEC_BASE_V4
    loader_size: int = EXEC_REGION_BYTES_V4
    load_region_bytes: int = EXEC_REGION_BYTES_V4
    exec_region_bytes: int = EXEC_REGION_BYTES_V4
    event_buffer_bytes: int = 2048
    report_capacity_bytes: int = 6144
    state_quota_bytes: int = 4096
    control_msg_bytes: int = 256
    snapshot_ram_bytes: int = 1024
    live_capacity_bytes: int = 16384
    live_capacity_tracks: int = 64

    @classmethod
    def from_json(cls, data: dict | None) -> "DevicePolicyV4":
        policy = cls()
        if not data:
            return policy
        for field in ("target_board_id", "psram_mib", "host_abi", "host_caps",
                      "loader_base", "loader_size", "load_region_bytes",
                      "exec_region_bytes", "event_buffer_bytes",
                      "report_capacity_bytes", "state_quota_bytes",
                      "control_msg_bytes", "snapshot_ram_bytes",
                      "live_capacity_bytes", "live_capacity_tracks"):
            if field in data:
                v = data[field]
                setattr(policy, field, int(v, 0) if isinstance(v, str) else int(v))
        return policy


def default_policy() -> DevicePolicyV4:
    return DevicePolicyV4()


def build_function_table_v4(pointers: list[int]) -> bytes:
    if len(pointers) != len(V4_FUNCTION_NAMES):
        raise AbiIncompatible(
            f"v4 function table needs exactly {len(V4_FUNCTION_NAMES)} pointers, got {len(pointers)}"
        )
    out = bytearray(V4_TABLE_SIZE)
    struct.pack_into("<II", out, 0, V4_TABLE_SIZE, HOST_ABI_V4)
    for offset, pointer in zip(V4_TABLE_POINTER_OFFSETS, pointers):
        if not 0 <= pointer <= 0xFFFFFFFF:
            raise AbiIncompatible(f"function pointer {pointer:#x} does not fit u32")
        if not pointer & 1:
            raise AbiIncompatible(f"function pointer {pointer:#x} is not Thumb (bit0 must be 1)")
        struct.pack_into("<I", out, offset, pointer)
    return bytes(out)


def parse_function_table_v4(raw: bytes) -> list[int]:
    if len(raw) != V4_TABLE_SIZE:
        raise AbiIncompatible(
            f"v4 function table is {len(raw)} bytes, exactly {V4_TABLE_SIZE} required "
            "(a 60B v3 table is foreign input and must not be reinterpreted)"
        )
    table_size, abi_version = struct.unpack_from("<II", raw, 0)
    if table_size != V4_TABLE_SIZE:
        raise AbiIncompatible(f"v4 table_size is {table_size}, must be {V4_TABLE_SIZE}")
    if abi_version != HOST_ABI_V4:
        raise AbiIncompatible(
            f"v4 function table abi_version is {abi_version:#010x}, "
            f"must be {HOST_ABI_V4:#010x}"
        )
    pointers = [struct.unpack_from("<I", raw, off)[0] for off in V4_TABLE_POINTER_OFFSETS]
    for name, pointer in zip(V4_FUNCTION_NAMES, pointers):
        if not pointer:
            raise AbiIncompatible(f"v4 function table entry {name} is a null pointer")
        if not pointer & 1:
            raise AbiIncompatible(f"v4 function table entry {name} is not Thumb (bit0 must be 1)")
    return pointers


def verify_package_v4(
    data: bytes,
    trust: TrustStoreV4,
    policy: DevicePolicyV4 | None = None,
    host_admission: bool = True,
) -> tuple[dict, None] | tuple[None, PackageError]:
    """Verify one signed v4 package offline; see the module docstring for
    the two tiers and the PASS boundary."""
    policy = policy or default_policy()
    try:
        return _verify_v4_impl(data, trust, policy, host_admission)
    except PackageError as exc:
        return None, exc


def _verify_v4_impl(data, trust, policy, host_admission=True):
    if len(data) < HEADER_LEN:
        raise BadPackage(f"file is {len(data)} bytes, shorter than the {HEADER_LEN}-byte container header")
    if data[0:8] != CONTAINER_MAGIC:
        raise BadPackage(
            "container magic is not NEAPP v4 (4e45415050 04 00 00); v1/v2/v3 and any "
            "other container major is foreign input, never negotiated"
        )
    manifest_len, image_len = struct.unpack_from("<II", data, 8)
    if manifest_len != MANIFEST_LEN:
        raise BadPackage(f"manifest_len is {manifest_len}, v4 allows only {MANIFEST_LEN}")
    if image_len < NATIVE_HEADER_SIZE:
        raise BadPackage(f"native_file_len {image_len} cannot hold the {NATIVE_HEADER_SIZE}-byte native header")
    if image_len > MAX_NATIVE_FILE_LEN:
        raise BadPackage(f"native_file_len {image_len} exceeds the v4 cap {MAX_NATIVE_FILE_LEN}")
    signed_len = u64_checked_sum(224, image_len)
    if len(data) < signed_len:
        raise BadPackage(f"file truncated: {len(data)} bytes < signed region {signed_len}")
    sig_len = len(data) - signed_len
    if sig_len < MIN_SIG_LEN:
        raise BadPackage(f"signature segment is {sig_len} bytes, below the DER minimum {MIN_SIG_LEN}")
    if sig_len > MAX_SIG_LEN:
        raise BadPackage(f"signature segment is {sig_len} bytes, above the DER maximum {MAX_SIG_LEN}")
    package_len = u64_checked_sum(signed_len, sig_len)
    if package_len != len(data):
        raise BadPackage("package_len != 224 + native_file_len + DER_len")
    if package_len > MAX_PACKAGE_LEN:
        raise BadPackage(f"package is {package_len} bytes, above the v4 cap {MAX_PACKAGE_LEN}")
    tbs = data[:signed_len]
    sig = data[signed_len:]

    parse_strict_ecdsa_der_v4(sig)

    manifest = parse_manifest_v4(data[HEADER_LEN:HEADER_LEN + MANIFEST_LEN])

    entry = trust.lookup(manifest.publisher_id)
    if entry is None:
        raise PublisherUntrusted(
            f"publisher_id {manifest.publisher_id!r} is not in the local trust mapping; "
            "key material inside or alongside a package never self-trusts"
        )
    trusted_fingerprint_hex, trusted_spki = entry
    if not constant_time_eq(manifest.publisher_key_sha256, bytes.fromhex(trusted_fingerprint_hex)):
        raise PublisherUntrusted(
            "manifest publisher_key_sha256 does not match the trusted key for "
            f"publisher_id {manifest.publisher_id!r}"
        )

    trusted_key = parse_spki_p256_v4(trusted_spki)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        trusted_key.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureInvalid("ECDSA P-256/SHA-256 verification failed over the exact TBS")

    image = data[HEADER_LEN + MANIFEST_LEN:signed_len]
    if manifest.native_file_len != image_len:
        raise BadPackage(f"manifest native_file_len {manifest.native_file_len} != container native_file_len {image_len}")
    if manifest.native_file_len != NATIVE_HEADER_SIZE + manifest.native_image_size:
        raise BadPackage("manifest native_file_len != 32 + native_image_size")
    native = parse_native_header_v4(image)
    if native.magic != NATIVE_MAGIC:
        raise BadPackage("native header magic is not NEA1")
    if native.header_size != NATIVE_HEADER_SIZE:
        raise BadPackage(f"native header_size {native.header_size} != {NATIVE_HEADER_SIZE} (exact)")
    if native.format_version != NATIVE_FORMAT_VERSION:
        raise BadPackage(f"native format_version {native.format_version} != 1")
    if native.reserved0 != 0:
        raise BadPackage(f"native header reserved0 is {native.reserved0:#x}, must be all zero")
    if native.abi_version != HOST_ABI_V4:
        raise BadPackage(
            f"native header abi_version {native.abi_version:#010x} != {HOST_ABI_V4:#010x} "
            "(only 0x00040000 is defined for v4; v1/v2/v3 native ABI semantics are "
            "never back-filled)"
        )
    if native.image_size != manifest.native_image_size:
        raise BadPackage("manifest native_image_size != native header image_size")
    if native.header_size + native.image_size != len(image):
        raise BadPackage("native file is not exactly 32-byte header + image_size payload")
    if native.entry_offset != manifest.native_entry_offset:
        raise BadPackage("manifest native_entry_offset != native header entry_offset")
    if native.entry_offset >= native.image_size:
        raise BadPackage(f"native entry_offset {native.entry_offset:#x} is outside the payload")
    if native.entry_offset & 1:
        raise BadPackage("native entry_offset is odd (Thumb entry must be even)")
    if native.target_addr != manifest.native_target_addr:
        raise BadPackage("manifest native_target_addr != native header target_addr")
    if native.abi_version != manifest.required_host_abi:
        raise BadPackage(
            f"manifest required_host_abi {manifest.required_host_abi:#010x} != native header "
            f"abi_version {native.abi_version:#010x} (cross-check, Host #104 F1)"
        )
    if native_payload_crc32_v4(image, native.image_size) != native.crc32:
        raise BadPackage("native payload CRC-32 mismatch")
    if not constant_time_eq(hashlib.sha256(image).digest(), manifest.native_file_sha256):
        raise BadPackage("manifest native_file_sha256 does not match the native image bytes")
    if manifest.required_exec_region_bytes < manifest.native_image_size:
        raise BadPackage(
            "required_exec_region_bytes is smaller than native_image_size (payload residency)"
        )

    caps = manifest.required_host_caps
    if caps & ~HOST_CAPS_KNOWN_MASK:
        raise BadPackage(
            f"required_host_caps has unknown bits {caps & ~HOST_CAPS_KNOWN_MASK:#x} "
            "(bits 10..31 must be zero, Host #104 F3)"
        )
    validate_policy_shape(caps, manifest.run_profile, manifest.event_max, manifest.state_quota,
                          manifest.report_max, manifest.control_max, manifest.snapshot_max,
                          manifest.live_publish_max, manifest.live_track_max)

    if host_admission and manifest.target_board_id != policy.target_board_id:
        raise TargetIncompatible(
            f"target_board_id {manifest.target_board_id:#010x} != policy {policy.target_board_id:#010x}"
        )
    if host_admission and manifest.required_psram_mib > policy.psram_mib:
        raise TargetIncompatible(
            f"required_psram_mib {manifest.required_psram_mib} unsupported (policy {policy.psram_mib})"
        )
    if host_admission and manifest.required_host_abi != policy.host_abi:
        raise AbiIncompatible(
            f"required_host_abi {manifest.required_host_abi:#010x} != policy {policy.host_abi:#010x}"
        )
    unsupported = caps & ~policy.host_caps
    if host_admission and unsupported:
        raise AbiIncompatible(
            f"Host does not provide capability bits {unsupported:#x} "
            f"(package requests {caps:#x}, Host provides {policy.host_caps:#x}); "
            "ENABLE_CONTROL/LIVE_PUBLISH without an actual Host grant are "
            "UNAVAILABLE/UNAUTHORIZED at runtime, never downgraded"
        )
    quota_pairs = (
        (CAP_AI_EVENTS, manifest.event_max, policy.event_buffer_bytes, "event_max"),
        (CAP_REPORT_SUBMIT, manifest.report_max, policy.report_capacity_bytes, "report_max"),
        (CAP_APP_STATE, manifest.state_quota, policy.state_quota_bytes, "state_quota"),
        (CAP_CONTROL_RECEIVE, manifest.control_max, policy.control_msg_bytes, "control_max"),
        (CAP_BUSINESS_SNAPSHOT, manifest.snapshot_max, policy.snapshot_ram_bytes, "snapshot_max"),
    )
    for bit, quota, capacity, name in quota_pairs:
        if host_admission and caps & bit and quota > capacity:
            raise ResourceLimit(
                f"{name} {quota} exceeds the Host capacity {capacity}"
            )
    if host_admission and caps & CAP_LIVE_PUBLISH:
        if manifest.live_publish_max > policy.live_capacity_bytes:
            raise ResourceLimit(
                f"live_publish_max {manifest.live_publish_max} exceeds the Host live "
                f"capacity {policy.live_capacity_bytes}; the live capability is refused "
                "whole rather than degraded"
            )
        if manifest.live_track_max > policy.live_capacity_tracks:
            raise ResourceLimit(
                f"live_track_max {manifest.live_track_max} exceeds the Host track "
                f"capacity {policy.live_capacity_tracks}"
            )
    if host_admission and manifest.native_file_len > policy.load_region_bytes:
        raise ResourceLimit(
            f"native_file_len {manifest.native_file_len} exceeds the Host load region "
            f"{policy.load_region_bytes}"
        )
    target = manifest.native_target_addr
    range_hi = policy.loader_base + policy.loader_size
    if host_admission and not (policy.loader_base <= target < range_hi
                               and target + manifest.native_file_len <= range_hi):
        raise ResourceLimit(
            f"native target_addr {target:#010x}+{manifest.native_file_len}B outside the Host "
            f"loader range {policy.loader_base:#010x}..{range_hi:#010x}"
        )
    if host_admission and manifest.required_exec_region_bytes > policy.exec_region_bytes:
        raise ResourceLimit(
            f"required_exec_region_bytes {manifest.required_exec_region_bytes} exceeds the Host "
            f"actual execution region {policy.exec_region_bytes}"
        )

    report = {
        "result": "PASS",
        "format": "neapp-v4",
        "package_sha256": sha256_hex(data),
        "content_identity_sha256": sha256_hex(tbs),
        "tbs_len": signed_len,
        "signature_len": sig_len,
        "publisher_id": manifest.publisher_id,
        "publisher_key_sha256": manifest.publisher_key_sha256.hex(),
        "app_id": manifest.app_id,
        "app_version": (
            f"{manifest.version_major}.{manifest.version_minor}.{manifest.version_patch}"
        ),
        "target_board_id": f"{manifest.target_board_id:#010x}",
        "required_psram_mib": manifest.required_psram_mib,
        "required_host_abi": f"{manifest.required_host_abi:#010x}",
        "required_host_caps": f"{manifest.required_host_caps:#x}",
        "required_exec_region_bytes": manifest.required_exec_region_bytes,
        "native_file_len": manifest.native_file_len,
        "native_image_size": manifest.native_image_size,
        "native_entry_offset": f"{manifest.native_entry_offset:#x}",
        "native_target_addr": f"{manifest.native_target_addr:#010x}",
        "native_file_sha256": manifest.native_file_sha256.hex(),
        "native_crc32": f"{native.crc32:#010x}",
        "run_profile": manifest.run_profile,
        "event_max": manifest.event_max,
        "state_quota": manifest.state_quota,
        "report_max": manifest.report_max,
        "control_max": manifest.control_max,
        "snapshot_max": manifest.snapshot_max,
        "live_publish_max": manifest.live_publish_max,
        "live_track_max": manifest.live_track_max,
        "boundary": (
            "signed-format PASS is offline tooling evidence only: NOT Host admission, "
            "NOT native runtime admission; ENABLE_CONTROL/LIVE_PUBLISH exist at runtime "
            "only where the actual Host implements and grants them; no device install, "
            "execution, floor, or live-delivery evidence"
        ),
    }
    return report, None
