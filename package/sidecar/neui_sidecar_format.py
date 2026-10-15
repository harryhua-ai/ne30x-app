#!/usr/bin/env python3
"""neui_sidecar_format — format authority and offline verify pipeline for the
frozen NEUI UI-Sidecar v1 wire (ne301 issue #79 §12, frozen 2026-10-15).

Container wire (all integers u16/u32 little-endian):

  0     8      magic = 4e 45 55 49 01 00 00 00 ("NEUI", major 1)
  8     4      manifest_len_u32          (128..16384)
  12    4      asset_payload_len_u32     (1..2097152)
  16    N      manifest = 128B fixed block + file_count ordered records
  16+N  A      raw asset payload bytes in record order (no compression)
  16+N+A 8..72 exactly one strict-DER ECDSA-Sig-Value, no other trailer

TBS = bytes[0 : 16 + manifest_len + asset_payload_len); ui_tbs_sha256 =
SHA-256(TBS) is the canonical Sidecar content identity.  The signed domain
always starts with the NEUI magic: it never overlaps the native NEAPP
v1/v2/v3 signature domains, and nothing is ever appended to a native
container.  Native binding is native_tbs_sha256 =
SHA-256(native .neapp v3 TBS) — the DER-independent content identity —
never the whole-file native package_sha256.

Trust: the v1/v2/v3 publisher trust store (publisher_id -> SHA-256(SPKI
DER) local mapping).  SHA-256 + ECDSA P-256 + strict-DER + SPKI primitives
are reused from package/neapp_format.py; every Sidecar-specific parse and
verdict in this module is implemented independently of the native
pack/verify pipelines.

Caps (§12.2) are maximum accepted bundle-INPUT limits, not a promise that
any device partition has room: file_count 1..64, path_len 1..160,
file_len 1..1048576, asset_payload_len 1..2097152, manifest_len <= 16384.

Install classification (§12.1/§12.3), per native identity
(publisher_id, app_id, publisher_key_sha256, native_tbs_sha256):
same ui_tbs -> IDEMPOTENT (any valid DER); higher semantic version ->
UPGRADE; same semantic version with different ui_tbs -> CONTENT_CONFLICT;
lower version -> DOWNGRADE; different native identity -> NATIVE_REBIND
(an old Sidecar is never inherited by a new native TBS).

OFFLINE TOOLING ONLY: a PASS here never means NE301 Host admission or
install, LittleFS free space, RAM fit, a dual-artifact transaction, camera
H264, browser trusted loading, or User product acceptance.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

import neapp_format as fmt

CONTAINER_MAGIC = bytes.fromhex("4e45554901000000")
HEADER_LEN = 16
MANIFEST_FIXED_LEN = 128
RECORD_FIXED_LEN = 2 + 4 + 32

MIN_MANIFEST_LEN = MANIFEST_FIXED_LEN + RECORD_FIXED_LEN + 1
MAX_MANIFEST_LEN = 16384
MIN_ASSET_PAYLOAD_LEN = 1
MAX_ASSET_PAYLOAD_LEN = 2_097_152
MIN_FILE_COUNT = 1
MAX_FILE_COUNT = 64
MIN_PATH_LEN = 1
MAX_PATH_LEN = 160
MIN_FILE_LEN = 1
MAX_FILE_LEN = 1_048_576
HOST_UI_ABI_V1 = 1
MIN_SIG_LEN = fmt.MIN_SIG_LEN
MAX_SIG_LEN = fmt.MAX_SIG_LEN
INDEX_PATH = "index.html"

PATH_FIRST = frozenset(range(0x41, 0x5B)) | frozenset(range(0x61, 0x7B)) | frozenset(range(0x30, 0x3A))
PATH_REST = PATH_FIRST | {0x2E, 0x5F, 0x2D}

ERROR_CLASSES = (fmt.BadPackage, fmt.SignatureInvalid, fmt.PublisherUntrusted)


class SidecarError(ValueError):
    pass


@dataclass
class AssetRecord:
    path: str
    file_len: int
    sha256: bytes


@dataclass
class SidecarManifest:
    publisher_id: str
    app_id: str
    publisher_key_sha256: bytes
    native_tbs_sha256: bytes
    version_major: int
    version_minor: int
    version_patch: int
    file_count: int
    host_ui_abi: int
    records: tuple[AssetRecord, ...]

    @property
    def version_tuple(self) -> tuple[int, int, int]:
        return (self.version_major, self.version_minor, self.version_patch)

    @property
    def native_identity(self) -> tuple[str, str, bytes, bytes]:
        return (self.publisher_id, self.app_id,
                self.publisher_key_sha256, self.native_tbs_sha256)


def validate_asset_path(path: bytes) -> str:
    if not path:
        raise fmt.BadPackage("asset path is empty")
    if len(path) > MAX_PATH_LEN:
        raise fmt.BadPackage(f"asset path is {len(path)} bytes, above the {MAX_PATH_LEN}-byte cap")
    for i, b in enumerate(path):
        if b == 0:
            raise fmt.BadPackage(f"asset path contains a NUL byte at offset {i}")
        if b < 0x20 or b > 0x7E:
            raise fmt.BadPackage(
                f"asset path byte {b:#04x} at offset {i} is non-ASCII or a control byte")
    if b"\\" in path:
        raise fmt.BadPackage("asset path contains a backslash separator")
    if b"%" in path:
        raise fmt.BadPackage("asset path contains a percent escape")
    if b":" in path:
        raise fmt.BadPackage("asset path contains a colon")
    if b"?" in path:
        raise fmt.BadPackage("asset path contains a query separator")
    if b"#" in path:
        raise fmt.BadPackage("asset path contains a fragment separator")
    if path.startswith(b"/"):
        raise fmt.BadPackage("asset path is absolute (leading '/')")
    if path.endswith(b"/"):
        raise fmt.BadPackage("asset path ends with '/'")
    segments = path.split(b"/")
    for seg in segments:
        if not seg:
            raise fmt.BadPackage("asset path contains an empty segment ('//')")
        if seg == b"." or seg == b"..":
            raise fmt.BadPackage(f"asset path contains the dot segment {seg.decode('ascii')!r}")
        if seg[0] not in PATH_FIRST:
            raise fmt.BadPackage(
                f"asset path segment {seg.decode('ascii', 'replace')!r} does not start with "
                "[A-Za-z0-9]")
        for b in seg[1:]:
            if b not in PATH_REST:
                raise fmt.BadPackage(
                    f"asset path segment {seg.decode('ascii', 'replace')!r} has a byte outside "
                    "[A-Za-z0-9._-]")
    return path.decode("ascii")


def build_manifest(m: SidecarManifest) -> bytes:
    pub = fmt.validate_identifier("publisher_id", m.publisher_id.encode("ascii"), 16)
    app = fmt.validate_identifier("app_id", m.app_id.encode("ascii"), 32)
    if not MIN_FILE_COUNT <= m.file_count <= MAX_FILE_COUNT:
        raise fmt.BadPackage(f"file_count {m.file_count} outside {MIN_FILE_COUNT}..{MAX_FILE_COUNT}")
    if m.version_major < 1:
        raise fmt.BadPackage(f"sidecar_version_major {m.version_major} must be >= 1")
    for name, v in (("version_minor", m.version_minor), ("version_patch", m.version_patch)):
        if not 0 <= v <= 0xFFFF:
            raise fmt.BadPackage(f"{name} out of u16 range: {v}")
    if m.host_ui_abi != HOST_UI_ABI_V1:
        raise fmt.BadPackage(f"host_ui_abi must be {HOST_UI_ABI_V1}, got {m.host_ui_abi}")
    if len(m.records) != m.file_count:
        raise fmt.BadPackage("file_count does not match the record list")
    out = bytearray(MANIFEST_FIXED_LEN)
    out[0:16] = pub.encode("ascii").ljust(16, b"\x00")
    out[16:48] = app.encode("ascii").ljust(32, b"\x00")
    out[48:80] = m.publisher_key_sha256
    out[80:112] = m.native_tbs_sha256
    struct.pack_into("<HHH", out, 112, m.version_major, m.version_minor, m.version_patch)
    struct.pack_into("<H", out, 118, m.file_count)
    struct.pack_into("<I", out, 120, m.host_ui_abi)
    struct.pack_into("<I", out, 124, 0)
    for rec in m.records:
        path_bytes = validate_asset_path(rec.path.encode("ascii")).encode("ascii")
        if not MIN_FILE_LEN <= rec.file_len <= MAX_FILE_LEN:
            raise fmt.BadPackage(
                f"asset {rec.path!r} file_len {rec.file_len} outside "
                f"{MIN_FILE_LEN}..{MAX_FILE_LEN}")
        if len(rec.sha256) != 32:
            raise fmt.BadPackage("record sha256 must be 32 bytes")
        out += struct.pack("<HI", len(path_bytes), rec.file_len) + rec.sha256 + path_bytes
    if len(out) > MAX_MANIFEST_LEN:
        raise fmt.BadPackage(f"manifest is {len(out)} bytes, above the {MAX_MANIFEST_LEN}-byte cap")
    return bytes(out)


def parse_manifest(raw: bytes) -> SidecarManifest:
    if len(raw) < MANIFEST_FIXED_LEN:
        raise fmt.BadPackage(
            f"manifest is {len(raw)} bytes, shorter than the {MANIFEST_FIXED_LEN}-byte fixed block")
    publisher_id = fmt.validate_identifier("publisher_id", raw[0:16], 16)
    app_id = fmt.validate_identifier("app_id", raw[16:48], 32)
    version_major, version_minor, version_patch = struct.unpack_from("<HHH", raw, 112)
    if version_major < 1:
        raise fmt.BadPackage(f"sidecar_version_major {version_major} must be >= 1")
    file_count = struct.unpack_from("<H", raw, 118)[0]
    if not MIN_FILE_COUNT <= file_count <= MAX_FILE_COUNT:
        raise fmt.BadPackage(
            f"file_count {file_count} outside {MIN_FILE_COUNT}..{MAX_FILE_COUNT}")
    host_ui_abi = struct.unpack_from("<I", raw, 120)[0]
    if host_ui_abi != HOST_UI_ABI_V1:
        raise fmt.BadPackage(f"host_ui_abi {host_ui_abi} is not {HOST_UI_ABI_V1}")
    reserved = struct.unpack_from("<I", raw, 124)[0]
    if reserved != 0:
        raise fmt.BadPackage(f"manifest reserved_u32 is {reserved:#010x}, must be zero")
    records: list[AssetRecord] = []
    pos = MANIFEST_FIXED_LEN
    running_len = 0
    for index in range(file_count):
        if pos + RECORD_FIXED_LEN > len(raw):
            raise fmt.BadPackage(f"manifest truncated inside record {index}")
        path_len, file_len = struct.unpack_from("<HI", raw, pos)
        if not MIN_PATH_LEN <= path_len <= MAX_PATH_LEN:
            raise fmt.BadPackage(
                f"record {index} path_len {path_len} outside {MIN_PATH_LEN}..{MAX_PATH_LEN}")
        if not MIN_FILE_LEN <= file_len <= MAX_FILE_LEN:
            raise fmt.BadPackage(
                f"record {index} file_len {file_len} outside {MIN_FILE_LEN}..{MAX_FILE_LEN}")
        running_len += file_len
        if running_len > MAX_ASSET_PAYLOAD_LEN:
            raise fmt.BadPackage(
                f"records {MIN_FILE_COUNT}..{index} sum to more than the "
                f"{MAX_ASSET_PAYLOAD_LEN}-byte asset payload cap")
        sha256 = raw[pos + 6:pos + 38]
        path_bytes = raw[pos + 38:pos + 38 + path_len]
        if len(path_bytes) != path_len:
            raise fmt.BadPackage(f"manifest truncated inside record {index} path")
        pos += RECORD_FIXED_LEN + path_len
        records.append(AssetRecord(path=validate_asset_path(path_bytes),
                                   file_len=file_len, sha256=sha256))
    if pos != len(raw):
        raise fmt.BadPackage(
            f"manifest has {len(raw) - pos} extra bytes after the last record")
    for index in range(1, file_count):
        prev_path = records[index - 1].path.encode("ascii")
        this_path = records[index].path.encode("ascii")
        if this_path == prev_path:
            raise fmt.BadPackage(
                f"duplicate asset path {this_path.decode('ascii')!r} (records must be "
                "strictly ascending)")
        if this_path < prev_path:
            raise fmt.BadPackage(
                f"records {index - 1}..{index} are not in strict ascending raw-ASCII path order")
    seen = set()
    folded = set()
    for rec in records:
        key = rec.path.encode("ascii")
        if key in seen:
            raise fmt.BadPackage(f"duplicate asset path {rec.path!r}")
        if key.lower() in folded:
            raise fmt.BadPackage(
                f"asset path {rec.path!r} collides with an earlier path under ASCII case folding")
        seen.add(key)
        folded.add(key.lower())
    index_count = sum(1 for r in records if r.path == INDEX_PATH)
    if index_count != 1:
        raise fmt.BadPackage(
            f"exactly one {INDEX_PATH!r} entry is required, found {index_count}")
    nested_index = [r.path for r in records
                    if r.path != INDEX_PATH and r.path.rsplit("/", 1)[-1] == INDEX_PATH]
    if nested_index:
        raise fmt.BadPackage(
            f"nested {INDEX_PATH!r} entries are not allowed: {nested_index!r}")
    return SidecarManifest(
        publisher_id=publisher_id,
        app_id=app_id,
        publisher_key_sha256=raw[48:80],
        native_tbs_sha256=raw[80:112],
        version_major=version_major,
        version_minor=version_minor,
        version_patch=version_patch,
        file_count=file_count,
        host_ui_abi=host_ui_abi,
        records=tuple(records),
    )


def build_container_prefix(manifest: bytes, payload: bytes) -> bytes:
    if not MIN_MANIFEST_LEN <= len(manifest) <= MAX_MANIFEST_LEN:
        raise fmt.BadPackage(
            f"manifest length {len(manifest)} outside {MIN_MANIFEST_LEN}..{MAX_MANIFEST_LEN}")
    if not MIN_ASSET_PAYLOAD_LEN <= len(payload) <= MAX_ASSET_PAYLOAD_LEN:
        raise fmt.BadPackage(
            f"asset payload length {len(payload)} outside "
            f"{MIN_ASSET_PAYLOAD_LEN}..{MAX_ASSET_PAYLOAD_LEN}")
    return (CONTAINER_MAGIC
            + struct.pack("<I", len(manifest))
            + struct.pack("<I", len(payload))
            + manifest
            + payload)


def native_v3_tbs_info(native_bytes: bytes, native_trust: fmt.TrustStore | None = None):
    import neapp_v3_format as fmt3

    if len(native_bytes) < fmt.HEADER_LEN:
        raise fmt.BadPackage("native package shorter than the 16-byte container header")
    if native_bytes[0:8] != fmt3.CONTAINER_MAGIC:
        raise fmt.BadPackage("native package is not a .neapp v3 container")
    manifest_len, image_len = struct.unpack_from("<II", native_bytes, 8)
    if manifest_len != fmt3.MANIFEST_LEN:
        raise fmt.BadPackage(f"native manifest_len {manifest_len} != {fmt3.MANIFEST_LEN}")
    if native_bytes[16:20] != fmt3.MANIFEST_MAGIC:
        raise fmt.BadPackage("native manifest magic is not NMF3")
    signed_len = fmt.HEADER_LEN + manifest_len + image_len
    if len(native_bytes) < signed_len:
        raise fmt.BadPackage("native package truncated below its signed region")
    if native_trust is not None:
        report, err = fmt3.verify_package_v3(native_bytes, native_trust, host_admission=False)
        if err is not None:
            raise fmt.BadPackage(
                "native package failed offline v3 verification: "
                f"{err.code}: {err.detail}")
    native_manifest = fmt3.parse_manifest_v3(native_bytes[16:16 + manifest_len])
    tbs = native_bytes[:signed_len]
    return hashlib.sha256(tbs).hexdigest(), native_manifest


def classify_install_transition(prev: SidecarManifest | None, prev_tbs_hex: str | None,
                                new: SidecarManifest, new_tbs_hex: str) -> str:
    if prev is None or prev_tbs_hex is None:
        return "FRESH_INSTALL"
    if prev.native_identity != new.native_identity:
        return "NATIVE_REBIND"
    if prev_tbs_hex == new_tbs_hex:
        return "IDEMPOTENT"
    if new.version_tuple > prev.version_tuple:
        return "UPGRADE"
    if new.version_tuple == prev.version_tuple:
        return "CONTENT_CONFLICT"
    return "DOWNGRADE"


def verify_bundle(data: bytes,
                  trust: fmt.TrustStore,
                  native_package: bytes | None = None,
                  native_trust: fmt.TrustStore | None = None):
    try:
        return _verify_impl(data, trust, native_package, native_trust)
    except fmt.PackageError as exc:
        return None, exc


def _verify_impl(data, trust, native_package, native_trust):
    if len(data) < HEADER_LEN:
        raise fmt.BadPackage(
            f"file is {len(data)} bytes, shorter than the {HEADER_LEN}-byte NEUI container header")
    if data[0:8] != CONTAINER_MAGIC:
        raise fmt.BadPackage(
            "container magic is not NEUI v1 (4e455549 01 00 00); unknown container "
            "versions are rejected, never negotiated")
    manifest_len, asset_payload_len = struct.unpack_from("<II", data, 8)
    if not MIN_MANIFEST_LEN <= manifest_len <= MAX_MANIFEST_LEN:
        raise fmt.BadPackage(
            f"manifest_len {manifest_len} outside {MIN_MANIFEST_LEN}..{MAX_MANIFEST_LEN}")
    if not MIN_ASSET_PAYLOAD_LEN <= asset_payload_len <= MAX_ASSET_PAYLOAD_LEN:
        raise fmt.BadPackage(
            f"asset_payload_len {asset_payload_len} outside "
            f"{MIN_ASSET_PAYLOAD_LEN}..{MAX_ASSET_PAYLOAD_LEN}")
    signed_len = HEADER_LEN + manifest_len + asset_payload_len
    if len(data) < signed_len:
        raise fmt.BadPackage(
            f"file truncated: {len(data)} bytes < signed region {signed_len}")
    sig_len = len(data) - signed_len
    if sig_len < MIN_SIG_LEN:
        raise fmt.BadPackage(
            f"signature segment is {sig_len} bytes, below the DER minimum {MIN_SIG_LEN}")
    if sig_len > MAX_SIG_LEN:
        raise fmt.BadPackage(
            f"signature segment is {sig_len} bytes, above the DER maximum {MAX_SIG_LEN}")
    tbs = data[:signed_len]
    sig = data[signed_len:]

    fmt.parse_strict_ecdsa_der(sig)

    manifest = parse_manifest(data[HEADER_LEN:HEADER_LEN + manifest_len])

    entry = trust.lookup(manifest.publisher_id)
    if entry is None:
        raise fmt.PublisherUntrusted(
            f"publisher_id {manifest.publisher_id!r} is not in the local trust mapping")
    trusted_fingerprint_hex, trusted_spki = entry
    if not fmt.constant_time_eq(manifest.publisher_key_sha256,
                                bytes.fromhex(trusted_fingerprint_hex)):
        raise fmt.PublisherUntrusted(
            "manifest publisher_key_sha256 does not match the trusted key for "
            f"publisher_id {manifest.publisher_id!r}")

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    trusted_key = fmt.parse_spki_p256(trusted_spki)
    try:
        trusted_key.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise fmt.SignatureInvalid("ECDSA P-256/SHA-256 verification failed over the exact TBS")

    declared_total = sum(rec.file_len for rec in manifest.records)
    if declared_total != asset_payload_len:
        raise fmt.BadPackage(
            f"asset_payload_len {asset_payload_len} != sum of record file_len {declared_total}")
    payload = data[HEADER_LEN + manifest_len:signed_len]
    cursor = 0
    for rec in manifest.records:
        chunk = payload[cursor:cursor + rec.file_len]
        actual = hashlib.sha256(chunk).digest()
        if not fmt.constant_time_eq(actual, rec.sha256):
            raise fmt.BadPackage(
                f"asset {rec.path!r} sha256 {actual.hex()} does not match the manifest record "
                f"{rec.sha256.hex()}")
        cursor += rec.file_len

    native_binding_checked = False
    if native_package is not None:
        native_tbs_hex, native_manifest = native_v3_tbs_info(native_package, native_trust)
        if not fmt.constant_time_eq(manifest.native_tbs_sha256, bytes.fromhex(native_tbs_hex)):
            raise fmt.BadPackage(
                f"native_tbs_sha256 {manifest.native_tbs_sha256.hex()} does not match the "
                f"native package TBS digest {native_tbs_hex}")
        if manifest.publisher_id != native_manifest.publisher_id:
            raise fmt.BadPackage(
                f"sidecar publisher_id {manifest.publisher_id!r} does not match the native "
                f"package publisher_id {native_manifest.publisher_id!r} (cross-App binding)")
        if manifest.app_id != native_manifest.app_id:
            raise fmt.BadPackage(
                f"sidecar app_id {manifest.app_id!r} does not match the native "
                f"package app_id {native_manifest.app_id!r} (cross-App binding)")
        if not fmt.constant_time_eq(manifest.publisher_key_sha256,
                                    native_manifest.publisher_key_sha256):
            raise fmt.BadPackage(
                "sidecar publisher_key_sha256 does not match the native package "
                "publisher_key_sha256")
        native_binding_checked = True

    report = {
        "result": "PASS",
        "format": "neui-sidecar-v1",
        "bundle_sha256": fmt.sha256_hex(data),
        "bundle_len": len(data),
        "ui_tbs_sha256": fmt.sha256_hex(tbs),
        "tbs_len": signed_len,
        "manifest_len": manifest_len,
        "asset_payload_len": asset_payload_len,
        "signature_len": sig_len,
        "publisher_id": manifest.publisher_id,
        "publisher_key_sha256": manifest.publisher_key_sha256.hex(),
        "app_id": manifest.app_id,
        "sidecar_version": (
            f"{manifest.version_major}.{manifest.version_minor}.{manifest.version_patch}"
        ),
        "native_tbs_sha256": manifest.native_tbs_sha256.hex(),
        "host_ui_abi": manifest.host_ui_abi,
        "file_count": manifest.file_count,
        "files": [
            {"path": rec.path, "file_len": rec.file_len, "sha256": rec.sha256.hex()}
            for rec in manifest.records
        ],
        "native_binding_checked": native_binding_checked,
        "boundary": (
            "offline verification only: not NE301 Host admission/install, LittleFS free "
            "space, RAM fit, dual-artifact transaction, camera H264, browser trusted "
            "loading, or User product acceptance"
        ),
    }
    return report, None
