#!/usr/bin/env python3
"""neapp_format — the single shared format authority for .neapp v1 tooling.

Every constant, layout and check in this module is dictated verbatim by the
integrated P2 protocol spec `docs/app-package-protocol-v1.md`:

  §2.2  container wire format (8B magic, two u32-le lengths, 160B manifest,
        unmodified native image, exactly one trailing DER signature, TBS)
  §2.3  160B fixed manifest encoding, identifier charset, resource limits,
        native 32B header cross-checks, security check order
  §2.4  target board id mapping (0x00003010) and evidence boundary
  §2.1  SHA-256 / ECDSA over secp256r1 (P-256) / strict DER / SPKI trust key
  §7.1  offline error classes and their precedence

The packer (neapp_pack.py) and the offline verifier (neapp_verify.py) both
consume this module so they cannot drift apart.  Independent correctness is
not claimed from this sharing: it is proven against the frozen golden and
negative vectors published in the spec §2.5 (tests/package/).

OFFLINE TOOLING ONLY: passing verification here never means a device has
installed, executed, or power-fail recovered the package.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------
# Frozen v1 container constants (spec §2.2 / §2.3).  No alternatives exist in
# v1; anything else must be rejected, never negotiated.
# --------------------------------------------------------------------------

CONTAINER_MAGIC = bytes.fromhex("4e45415050010000")  # "NEAPP", v1, 2 reserved 0x00 (§2.2)
MANIFEST_MAGIC = b"NMF1"                              # §2.3
MANIFEST_LEN = 160                                    # §2.3: only legal value in v1
HEADER_LEN = 16                                       # magic(8) + manifest_len(4) + image_len(4)

MAX_NATIVE_FILE_LEN = 2_097_152                       # §2.3 candidate cap: 2 MiB native file
MAX_PACKAGE_LEN = 2_097_400                           # §2.3 candidate cap: 16+160+2MiB+72
MIN_SIG_LEN = 8                                       # §2.3 DER length window
MAX_SIG_LEN = 72

# Native 32B image header (spec §2.3; layout = pinned public Host ABI header,
# see tools/pack_app_image.py struct "<IHHIIIIII").
NATIVE_MAGIC = b"NEA1"
NATIVE_FORMAT_VERSION = 1
NATIVE_HEADER_SIZE = 32
NATIVE_HDR = struct.Struct("<IHHIIIIII")

# Device/experiment facts pinned by the spec for v1 (§2.3/§2.4).  These are
# policy inputs, not hardware guarantees.
HOST_ABI_V1 = 0x00010000
TARGET_BOARD_ID_V1 = 0x00003010
REQUIRED_PSRAM_MIB_V1 = 64
EXEC_BASE_V1 = 0x93E00000
EXEC_REGION_BYTES_V1 = 0x200000  # 2 MiB experiment Host execution region (#27)

HOST_CAP_LOG = 1 << 0      # §2.3: bit0 = log
HOST_CAP_TICK_MS = 1 << 1  # §2.3: bit1 = tick_ms
HOST_CAPS_KNOWN_MASK = HOST_CAP_LOG | HOST_CAP_TICK_MS

# P-256 group order (spec §2.5 low-S discussion)
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# OID bodies (DER content bytes) for strict SPKI parsing:
OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")    # 1.2.840.10045.2.1
OID_PRIME256V1 = bytes.fromhex("06082a8648ce3d030107")     # 1.2.840.10045.3.1.7


# --------------------------------------------------------------------------
# Error classes — the offline subset of the P2 §7 taxonomy.  `code` strings
# are the stable external names; detail strings are diagnostic-only and never
# contain key material.
# --------------------------------------------------------------------------


class PackageError(Exception):
    code = "PACKAGE_ERROR"

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class BadPackage(PackageError):
    code = "BAD_PACKAGE"  # §7: structure / unique-encoding / internal inconsistency


class SignatureInvalid(PackageError):
    code = "SIGNATURE_INVALID"  # §7.1 step 2: crypto verify failure on trusted key


class PublisherUntrusted(PackageError):
    code = "PUBLISHER_UNTRUSTED"  # §7.1 step 2: not in the local trust mapping


class TargetIncompatible(PackageError):
    code = "TARGET_INCOMPATIBLE"  # §5.1/§7: board / hardware profile mismatch


class AbiIncompatible(PackageError):
    code = "ABI_INCOMPATIBLE"  # §5.1/§7: Host API/ABI or capability mismatch


class ResourceLimit(PackageError):
    code = "RESOURCE_LIMIT"  # §5.1/§7: execution-region / size budget exceeded


ERROR_CLASSES = (
    BadPackage,
    SignatureInvalid,
    PublisherUntrusted,
    TargetIncompatible,
    AbiIncompatible,
    ResourceLimit,
)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def validate_identifier(field: str, value: bytes, max_len: int) -> str:
    """Spec §2.3 identifier rules: canonical ASCII [a-z0-9-], starts with
    [a-z], ends with letter/digit, no empty, no embedded NUL, right 0x00
    padding only, exactly filled slots allowed."""
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


# --------------------------------------------------------------------------
# Manifest (§2.3, exactly 160 bytes)
# --------------------------------------------------------------------------


@dataclass
class Manifest:
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


def build_manifest(m: Manifest) -> bytes:
    """Encode the 160B manifest.  Identifier/charset validation happens here
    so the packer cannot emit a manifest the verifier would reject."""
    pub = validate_identifier("publisher_id", m.publisher_id.encode("ascii"), 16)
    app = validate_identifier("app_id", m.app_id.encode("ascii"), 32)
    for name, v in (("version_major", m.version_major),
                    ("version_minor", m.version_minor),
                    ("version_patch", m.version_patch)):
        if not 0 <= v <= 0xFFFF:
            raise BadPackage(f"{name} out of u16 range: {v}")
    if m.required_host_caps & ~HOST_CAPS_KNOWN_MASK:
        raise BadPackage(f"required_host_caps has unknown bits: {m.required_host_caps:#x}")
    if m.native_file_len != NATIVE_HEADER_SIZE + m.native_image_size:
        raise BadPackage("native_file_len != 32 + native_image_size")
    out = bytearray(MANIFEST_LEN)
    out[0:4] = MANIFEST_MAGIC
    out[4:20] = pub.encode("ascii").ljust(16, b"\x00")
    out[20:52] = app.encode("ascii").ljust(32, b"\x00")
    out[52:54] = struct.pack("<H", m.version_major)
    out[54:56] = struct.pack("<H", m.version_minor)
    out[56:58] = struct.pack("<H", m.version_patch)
    # 58..59 reserved: already zero
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
    if len(out) != MANIFEST_LEN:
        raise BadPackage("manifest encoder produced wrong length")
    return bytes(out)


def parse_manifest(raw: bytes) -> Manifest:
    """Strictly decode a 160B manifest; any non-canonical encoding is
    BAD_PACKAGE (§2.3 unique-encoding requirement)."""
    if len(raw) != MANIFEST_LEN:
        raise BadPackage(f"manifest is {len(raw)} bytes, v1 requires exactly {MANIFEST_LEN}")
    if raw[0:4] != MANIFEST_MAGIC:
        raise BadPackage("manifest magic is not NMF1")
    if raw[58:60] != b"\x00\x00":
        raise BadPackage("manifest reserved bytes (58..59) are not zero")
    publisher_id = validate_identifier("publisher_id", raw[4:20], 16)
    app_id = validate_identifier("app_id", raw[20:52], 32)
    vmaj, vmin, vpat = struct.unpack_from("<HHH", raw, 52)
    (board, psram, abi, caps, exec_region, file_len, image_size, entry, target) = struct.unpack_from(
        "<9I", raw, 60
    )
    if caps & ~HOST_CAPS_KNOWN_MASK:
        raise BadPackage(f"required_host_caps has unknown bits: {caps:#x}")
    return Manifest(
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
    )


def manifest_version_tuple(m: Manifest) -> tuple[int, int, int]:
    return (m.version_major, m.version_minor, m.version_patch)


# --------------------------------------------------------------------------
# Native 32B image header
# --------------------------------------------------------------------------


@dataclass
class NativeHeader:
    magic: bytes
    header_size: int
    format_version: int
    abi_version: int
    target_addr: int
    image_size: int
    entry_offset: int
    reserved0: int
    crc32: int


def parse_native_header(image: bytes) -> NativeHeader:
    if len(image) < NATIVE_HEADER_SIZE:
        raise BadPackage(f"native image shorter than the {NATIVE_HEADER_SIZE}-byte header")
    fields = NATIVE_HDR.unpack_from(image)
    return NativeHeader(
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


def native_payload_crc32(image: bytes, image_size: int) -> int:
    """Reflected IEEE CRC-32 over the payload (header excluded) — the same
    polynomial the pinned Host loader and tools/pack_app_image.py use."""
    return zlib.crc32(image[NATIVE_HEADER_SIZE:NATIVE_HEADER_SIZE + image_size]) & 0xFFFFFFFF


# --------------------------------------------------------------------------
# Strict DER: ECDSA-Sig-Value (§2.1) and SPKI (§2.1 trust key candidate)
# --------------------------------------------------------------------------


def _read_der_length(data: bytes, pos: int, end: int) -> tuple[int, int]:
    """Strict DER length decode at `pos`; returns (content_len, next_pos).
    Rejects indefinite form and non-minimal encodings."""
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
    """Strict DER INTEGER: minimal content, positive, no redundant leading
    zero.  Returns (value, next_pos)."""
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


def parse_strict_ecdsa_der(sig: bytes) -> tuple[int, int]:
    """Decode exactly one canonical-DER ECDSA-Sig-Value consuming ALL bytes.
    r,s must satisfy 1 <= r,s < P256_ORDER.  v1 does NOT reject high-S
    (spec §2.5).  Any violation is BAD_PACKAGE."""
    end = len(sig)
    if end == 0 or sig[0] != 0x30:
        raise BadPackage("DER: signature does not start with SEQUENCE tag")
    seq_len, pos = _read_der_length(sig, 1, end)
    seq_end = pos + seq_len
    if seq_end != end:
        # the single SEQUENCE must consume the whole signature segment
        raise BadPackage("DER: SEQUENCE length does not consume the signature exactly")
    if seq_end > end:
        raise BadPackage("DER: SEQUENCE content overruns buffer")
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


def parse_spki_p256(spki: bytes):
    """Strictly parse a SubjectPublicKeyInfo DER and return a cryptography
    P-256 public key.  Rejects anything that is not an uncompressed
    prime256v1 point (the v1-only trust-key encoding, spec §2.1)."""
    from cryptography.hazmat.primitives.asymmetric import ec

    end = len(spki)
    if end == 0 or spki[0] != 0x30:
        raise BadPackage("SPKI: does not start with SEQUENCE")
    seq_len, pos = _read_der_length(spki, 1, end)
    seq_end = pos + seq_len
    if seq_end != end:
        raise BadPackage("SPKI: SEQUENCE does not consume the input exactly")
    # AlgorithmIdentifier SEQUENCE
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
    # BIT STRING subjectPublicKey
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
    if key is None:  # defensive: from_encoded_point returns None off-curve
        raise BadPackage("SPKI: point is not on the P-256 curve")
    return key


def spki_der_from_public_key(pub) -> bytes:
    """Serialize a cryptography public key to SPKI DER (packer side)."""
    from cryptography.hazmat.primitives import serialization

    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --------------------------------------------------------------------------
# Container framing helpers
# --------------------------------------------------------------------------


def tbs_of(container_prefix: bytes) -> bytes:
    """Spec §2.2: TBS = file bytes [0 : 16 + manifest_len + image_len]."""
    return container_prefix


def content_identity(tbs: bytes) -> str:
    """Spec §2.2: idempotent content identity is SHA-256(TBS) — never the
    whole-file digest, which varies with the random/DER signature bytes."""
    return sha256_hex(tbs)


def build_container_prefix(manifest: bytes, image: bytes) -> bytes:
    if len(manifest) != MANIFEST_LEN:
        raise BadPackage("manifest must be exactly 160 bytes")
    if len(image) > MAX_NATIVE_FILE_LEN:
        raise BadPackage("native image exceeds the v1 file cap")
    return (
        CONTAINER_MAGIC
        + struct.pack("<I", len(manifest))
        + struct.pack("<I", len(image))
        + manifest
        + image
    )


# --------------------------------------------------------------------------
# Trust store and offline device-policy stand-in
# --------------------------------------------------------------------------


@dataclass
class TrustStore:
    # publisher_id -> SHA-256(SPKI DER) hex + the SPKI DER bytes themselves.
    # The SPKI bytes are LOCAL configuration (the offline stand-in for the
    # Host-built-in key); they are never taken from the package (§4.1).
    publishers: dict[str, tuple[str, bytes]]  # id -> (sha256_hex, spki_der)

    def lookup(self, publisher_id: str) -> tuple[str, bytes] | None:
        return self.publishers.get(publisher_id)


def load_trust_store(path: Path) -> TrustStore:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if raw.get("version") != 1:
        raise ValueError(f"unsupported trust store version: {raw.get('version')!r}")
    publishers: dict[str, tuple[str, bytes]] = {}
    for pub_id, entry in raw.get("publishers", {}).items():
        # validate the id shape so a mistyped store cannot widen trust
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
    return TrustStore(publishers=publishers)


@dataclass
class DevicePolicy:
    """Offline stand-in for the device/Host facts the spec pins for v1.
    Not a hardware probe: documentation values from §2.3/§2.4."""
    target_board_id: int = TARGET_BOARD_ID_V1
    psram_mib: int = REQUIRED_PSRAM_MIB_V1
    host_abi: int = HOST_ABI_V1
    host_caps: int = HOST_CAPS_KNOWN_MASK
    exec_base: int = EXEC_BASE_V1
    exec_region_bytes: int = EXEC_REGION_BYTES_V1

    @classmethod
    def from_json(cls, data: dict | None) -> "DevicePolicy":
        policy = cls()
        if not data:
            return policy
        for field in ("target_board_id", "psram_mib", "host_abi", "host_caps",
                      "exec_base", "exec_region_bytes"):
            if field in data:
                setattr(policy, field, int(data[field], 0) if isinstance(data[field], str) else int(data[field]))
        return policy


def default_policy() -> DevicePolicy:
    return DevicePolicy()


# --------------------------------------------------------------------------
# The v1 verification pipeline (spec §2.3 安全检查顺序 + §7.1 判定顺序)
# --------------------------------------------------------------------------


def verify_package(
    data: bytes,
    trust: TrustStore,
    policy: DevicePolicy | None = None,
) -> tuple[dict, None] | tuple[None, PackageError]:
    """Verify one .neapp v1 package offline.

    Order is normative (§7.1): bounded structure parse -> DER structural
    decode -> manifest unique-encoding decode -> local trust mapping ->
    ECDSA-P256/SHA-256 verify over the exact TBS -> signed-content
    cross-checks -> device/board/ABI/resource policy.  Returns
    (report, None) on success or (None, PackageError subclass) on failure.

    Passing here is OFFLINE evidence only: it never means a device has
    installed, executed, or power-fail recovered the package.
    """
    policy = policy or default_policy()
    try:
        return _verify_impl(data, trust, policy)
    except PackageError as exc:
        return None, exc


def _verify_impl(data, trust, policy):
    # ---- stage 1: bounded container structure (overflow-safe, no crypto) ----
    if len(data) < HEADER_LEN:
        raise BadPackage(f"file is {len(data)} bytes, shorter than the {HEADER_LEN}-byte container header")
    if data[0:8] != CONTAINER_MAGIC:
        raise BadPackage("container magic is not NEAPP v1 (4e45415050 01 00 00)")
    manifest_len, image_len = struct.unpack_from("<II", data, 8)
    if manifest_len != MANIFEST_LEN:
        raise BadPackage(f"manifest_len is {manifest_len}, v1 allows only {MANIFEST_LEN}")
    if image_len < NATIVE_HEADER_SIZE:
        raise BadPackage(f"image_len {image_len} cannot hold the {NATIVE_HEADER_SIZE}-byte native header")
    if image_len > MAX_NATIVE_FILE_LEN:
        raise BadPackage(f"image_len {image_len} exceeds the v1 native file cap {MAX_NATIVE_FILE_LEN}")
    signed_len = HEADER_LEN + manifest_len + image_len
    if len(data) < signed_len:
        raise BadPackage(f"file truncated: {len(data)} bytes < signed region {signed_len}")
    sig_len = len(data) - signed_len
    if sig_len < MIN_SIG_LEN:
        raise BadPackage(f"signature segment is {sig_len} bytes, below the DER minimum {MIN_SIG_LEN}")
    if sig_len > MAX_SIG_LEN:
        raise BadPackage(f"signature segment is {sig_len} bytes, above the DER maximum {MAX_SIG_LEN}")
    if len(data) > MAX_PACKAGE_LEN:
        raise BadPackage(f"package is {len(data)} bytes, above the v1 cap {MAX_PACKAGE_LEN}")
    tbs = data[:signed_len]
    sig = data[signed_len:]

    # ---- stage 2: strict DER structural decode (full consumption) ----
    parse_strict_ecdsa_der(sig)

    # ---- stage 3: manifest strict (unique) decoding ----
    manifest = parse_manifest(data[HEADER_LEN:HEADER_LEN + MANIFEST_LEN])

    # ---- stage 4: local trust mapping (package never self-trusts, §4.1) ----
    entry = trust.lookup(manifest.publisher_id)
    if entry is None:
        raise PublisherUntrusted(f"publisher_id {manifest.publisher_id!r} is not in the local trust mapping")
    trusted_fingerprint_hex, trusted_spki = entry
    if not constant_time_eq(manifest.publisher_key_sha256, bytes.fromhex(trusted_fingerprint_hex)):
        raise PublisherUntrusted(
            "manifest publisher_key_sha256 does not match the trusted key for "
            f"publisher_id {manifest.publisher_id!r}"
        )

    # ---- stage 5: cryptography — ECDSA P-256 / SHA-256 over the exact TBS ----
    trusted_key = parse_spki_p256(trusted_spki)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        trusted_key.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureInvalid("ECDSA P-256/SHA-256 verification failed over the exact TBS")

    # ---- stage 6: signed-content cross-checks (§2.3) ----
    image = data[HEADER_LEN + MANIFEST_LEN:signed_len]
    if manifest.native_file_len != image_len:
        raise BadPackage(f"manifest native_file_len {manifest.native_file_len} != container image_len {image_len}")
    if manifest.native_file_len != NATIVE_HEADER_SIZE + manifest.native_image_size:
        raise BadPackage("manifest native_file_len != 32 + native_image_size")
    native = parse_native_header(image)
    if native.magic != NATIVE_MAGIC:
        raise BadPackage("native header magic is not NEA1")
    if native.header_size != NATIVE_HEADER_SIZE:
        raise BadPackage(f"native header_size {native.header_size} != {NATIVE_HEADER_SIZE} (v1 is exact)")
    if native.format_version != NATIVE_FORMAT_VERSION:
        raise BadPackage(f"native format_version {native.format_version} != 1")
    if native.reserved0 != 0:
        raise BadPackage(f"native header reserved0 is {native.reserved0:#x}, must be all zero")
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
        raise BadPackage("manifest required_host_abi != native header abi_version")
    if native_payload_crc32(image, native.image_size) != native.crc32:
        raise BadPackage("native payload CRC-32 mismatch")
    if not constant_time_eq(
        hashlib.sha256(image).digest(), manifest.native_file_sha256
    ):
        raise BadPackage("manifest native_file_sha256 does not match the native image bytes")
    if manifest.required_exec_region_bytes < manifest.native_image_size:
        raise BadPackage(
            "required_exec_region_bytes is smaller than native_image_size (payload residency)"
        )

    # ---- stage 7: device/board/ABI/resource policy (§2.3/§2.4, §7.1 step 3) ----
    if manifest.target_board_id != policy.target_board_id:
        raise TargetIncompatible(
            f"target_board_id {manifest.target_board_id:#010x} != policy {policy.target_board_id:#010x}"
        )
    if manifest.required_psram_mib != policy.psram_mib:
        raise TargetIncompatible(
            f"required_psram_mib {manifest.required_psram_mib} unsupported (policy {policy.psram_mib})"
        )
    if manifest.native_target_addr != policy.exec_base:
        raise TargetIncompatible(
            f"native_target_addr {manifest.native_target_addr:#010x} != execution base {policy.exec_base:#010x}"
        )
    if manifest.required_host_abi != policy.host_abi:
        raise AbiIncompatible(
            f"required_host_abi {manifest.required_host_abi:#010x} != policy {policy.host_abi:#010x}"
        )
    if manifest.required_host_caps & ~policy.host_caps:
        raise AbiIncompatible(
            f"required_host_caps {manifest.required_host_caps:#x} not satisfied by Host caps {policy.host_caps:#x}"
        )
    if manifest.required_exec_region_bytes > policy.exec_region_bytes:
        raise ResourceLimit(
            f"required_exec_region_bytes {manifest.required_exec_region_bytes} exceeds "
            f"execution region {policy.exec_region_bytes}"
        )
    if manifest.native_file_len > policy.exec_region_bytes:
        raise ResourceLimit(
            f"native_file_len {manifest.native_file_len} exceeds the load transient budget "
            f"{policy.exec_region_bytes} (whole file is read into the region before de-headering)"
        )

    report = {
        "result": "PASS",
        "package_sha256": sha256_hex(data),
        "content_identity_sha256": content_identity(tbs),  # SHA-256(TBS), §2.2
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
        "boundary": (
            "offline verification only: not device install, execution, or "
            "power-fail recovery evidence"
        ),
    }
    return report, None
