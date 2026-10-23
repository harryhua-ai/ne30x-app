from __future__ import annotations

import hashlib
import hmac
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))
sys.path.insert(0, str(ROOT / "package" / "vnext"))

import neapp_v4_format as v4
import neui_sidecar_format as ui

CONTAINER_MAGIC = bytes.fromhex("4e45415050050000")
HEADER_LEN = 16
MANIFEST_MAGIC = b"NMF5"
MANIFEST_LEN = 208
PUBLISHER_SLOT_OFF = 4
PUBLISHER_SLOT_LEN = 16
PUBLISHER_KEY_SLOT_OFF = 128
PUBLISHER_KEY_SLOT_LEN = 32
MIN_NATIVE_MEMBER_LEN = MANIFEST_LEN + v4.NATIVE_HEADER_SIZE + 1
MAX_NATIVE_MEMBER_LEN = MANIFEST_LEN + v4.MAX_NATIVE_FILE_LEN

UI_MEMBER_MAGIC = bytes.fromhex("4e45554905000000")
UI_HEADER_LEN = 16
UI_PUBLISHER_SLOT_OFF = 0
UI_PUBLISHER_SLOT_LEN = 16
UI_PUBLISHER_KEY_SLOT_OFF = 48
UI_PUBLISHER_KEY_SLOT_LEN = 32
UI_NATIVE_BINDING_OFF = 80
MIN_UI_MEMBER_LEN = UI_HEADER_LEN + ui.MIN_MANIFEST_LEN + ui.MIN_ASSET_PAYLOAD_LEN
MAX_UI_MEMBER_LEN = UI_HEADER_LEN + ui.MAX_MANIFEST_LEN + ui.MAX_ASSET_PAYLOAD_LEN

MIN_PACKAGE_LEN = HEADER_LEN + MIN_NATIVE_MEMBER_LEN + MIN_UI_MEMBER_LEN
MAX_PACKAGE_LEN = HEADER_LEN + MAX_NATIVE_MEMBER_LEN + MAX_UI_MEMBER_LEN

LEGACY_SIGNED_MAGICS = (
    (bytes.fromhex("4e45415050010000"), "neapp v1"),
    (bytes.fromhex("4e45415050020000"), "neapp v2"),
    (bytes.fromhex("4e45415050030000"), "neapp v3"),
    (bytes.fromhex("4e45415050040000"), "neapp v4"),
    (bytes.fromhex("4e45554901000000"), "neui sidecar v1"),
)
LEGACY_SIGNED_PREFIXES = (
    (b"NEPK", "nepk v1.1"),
)


class LegacySignedFormat(v4.PackageError):
    code = "LEGACY_SIGNED_FORMAT"


class MemberMismatch(v4.PackageError):
    code = "MEMBER_MISMATCH"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def detect_legacy_signed(data: bytes) -> str | None:
    for magic, name in LEGACY_SIGNED_MAGICS:
        if data[:len(magic)] == magic:
            return name
    for prefix, name in LEGACY_SIGNED_PREFIXES:
        if data[:len(prefix)] == prefix:
            return name
    return None


@dataclass
class ManifestV5:
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
    run_profile: int
    event_max: int
    state_quota: int
    report_max: int
    control_max: int
    snapshot_max: int
    live_publish_max: int
    live_track_max: int


def build_manifest_v5(m: ManifestV5) -> bytes:
    v4.validate_identifier("app_id", m.app_id.encode("ascii"), 32)
    for name, v in (("version_major", m.version_major),
                    ("version_minor", m.version_minor),
                    ("version_patch", m.version_patch)):
        if not 0 <= v <= 0xFFFF:
            raise v4.BadPackage(f"{name} out of u16 range: {v}")
    if m.version_major < 1:
        raise v4.BadPackage(f"version_major {m.version_major} must be >= 1")
    if m.required_host_abi != v4.HOST_ABI_V4:
        raise v4.BadPackage(
            f"v5 manifest required_host_abi must be {v4.HOST_ABI_V4:#010x}, "
            f"got {m.required_host_abi:#010x}"
        )
    v4.validate_policy_shape(m.required_host_caps, m.run_profile, m.event_max,
                             m.state_quota, m.report_max, m.control_max,
                             m.snapshot_max, m.live_publish_max, m.live_track_max)
    if m.native_file_len != v4.NATIVE_HEADER_SIZE + m.native_image_size:
        raise v4.BadPackage("native_file_len != 32 + native_image_size")
    if len(m.native_file_sha256) != 32:
        raise v4.BadPackage("native_file_sha256 must be 32 bytes")
    out = bytearray(MANIFEST_LEN)
    out[0:4] = MANIFEST_MAGIC
    out[PUBLISHER_SLOT_OFF:PUBLISHER_SLOT_OFF + PUBLISHER_SLOT_LEN] = b"\x00" * PUBLISHER_SLOT_LEN
    out[20:52] = m.app_id.encode("ascii").ljust(32, b"\x00")
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
    out[PUBLISHER_KEY_SLOT_OFF:PUBLISHER_KEY_SLOT_OFF + PUBLISHER_KEY_SLOT_LEN] = (
        b"\x00" * PUBLISHER_KEY_SLOT_LEN)
    out[160:164] = struct.pack("<I", m.run_profile)
    out[164:168] = struct.pack("<I", m.event_max)
    out[168:172] = struct.pack("<I", m.state_quota)
    out[172:176] = struct.pack("<I", m.report_max)
    out[176:180] = struct.pack("<I", m.control_max)
    out[180:184] = struct.pack("<I", m.snapshot_max)
    out[184:188] = struct.pack("<I", m.live_publish_max)
    out[188:192] = struct.pack("<I", m.live_track_max)
    out[192:208] = b"\x00" * 16
    return bytes(out)


def parse_manifest_v5(raw: bytes) -> ManifestV5:
    if len(raw) != MANIFEST_LEN:
        raise v4.BadPackage(f"manifest is {len(raw)} bytes, v5 requires exactly {MANIFEST_LEN}")
    if raw[0:4] != MANIFEST_MAGIC:
        raise v4.BadPackage(
            f"manifest magic is {raw[0:4]!r}, v5 requires exactly NMF5 "
            "(an NMF4 signed-native manifest is a legacy signed format and is foreign input)"
        )
    if raw[PUBLISHER_SLOT_OFF:PUBLISHER_SLOT_OFF + PUBLISHER_SLOT_LEN] != b"\x00" * PUBLISHER_SLOT_LEN:
        raise v4.BadPackage("v5 manifest publisher_id slot must be all zero (no publisher trust)")
    if raw[PUBLISHER_KEY_SLOT_OFF:PUBLISHER_KEY_SLOT_OFF + PUBLISHER_KEY_SLOT_LEN] != (
            b"\x00" * PUBLISHER_KEY_SLOT_LEN):
        raise v4.BadPackage("v5 manifest publisher_key_sha256 slot must be all zero (no key trust)")
    if raw[58:60] != b"\x00\x00":
        raise v4.BadPackage("manifest reserved bytes (58..59) are not zero")
    if raw[192:208] != b"\x00" * 16:
        raise v4.BadPackage("manifest reserved bytes (192..207) are not zero")
    app_id = v4.validate_identifier("app_id", raw[20:52], 32)
    vmaj, vmin, vpat = struct.unpack_from("<HHH", raw, 52)
    if vmaj < 1:
        raise v4.BadPackage(f"version_major {vmaj} must be >= 1")
    (board, psram, abi, caps, exec_region, file_len, image_size, entry, target) = (
        struct.unpack_from("<9I", raw, 60))
    if abi != v4.HOST_ABI_V4:
        raise v4.BadPackage(
            f"v5 manifest required_host_abi must be {v4.HOST_ABI_V4:#010x}, got {abi:#010x}"
        )
    run_profile, event_max, state_quota, report_max, control_max, snapshot_max = (
        struct.unpack_from("<6I", raw, 160))
    live_publish_max, live_track_max = struct.unpack_from("<2I", raw, 184)
    return ManifestV5(
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
        run_profile=run_profile,
        event_max=event_max,
        state_quota=state_quota,
        report_max=report_max,
        control_max=control_max,
        snapshot_max=snapshot_max,
        live_publish_max=live_publish_max,
        live_track_max=live_track_max,
    )


@dataclass
class UiManifestV5:
    app_id: str
    native_member_sha256: bytes
    version_major: int
    version_minor: int
    version_patch: int
    file_count: int
    host_ui_abi: int
    records: tuple[ui.AssetRecord, ...]

    @property
    def version_tuple(self) -> tuple[int, int, int]:
        return (self.version_major, self.version_minor, self.version_patch)


def build_ui_manifest_v5(m: UiManifestV5) -> bytes:
    v4.validate_identifier("app_id", m.app_id.encode("ascii"), 32)
    if not ui.MIN_FILE_COUNT <= m.file_count <= ui.MAX_FILE_COUNT:
        raise v4.BadPackage(f"file_count {m.file_count} outside {ui.MIN_FILE_COUNT}..{ui.MAX_FILE_COUNT}")
    if m.version_major < 1:
        raise v4.BadPackage(f"ui_version_major {m.version_major} must be >= 1")
    for name, v in (("version_minor", m.version_minor), ("version_patch", m.version_patch)):
        if not 0 <= v <= 0xFFFF:
            raise v4.BadPackage(f"{name} out of u16 range: {v}")
    if m.host_ui_abi != ui.HOST_UI_ABI_V1:
        raise v4.BadPackage(f"host_ui_abi must be {ui.HOST_UI_ABI_V1}, got {m.host_ui_abi}")
    if len(m.records) != m.file_count:
        raise v4.BadPackage("file_count does not match the record list")
    if len(m.native_member_sha256) != 32:
        raise v4.BadPackage("native_member_sha256 must be 32 bytes")
    out = bytearray(ui.MANIFEST_FIXED_LEN)
    out[UI_PUBLISHER_SLOT_OFF:UI_PUBLISHER_SLOT_OFF + UI_PUBLISHER_SLOT_LEN] = (
        b"\x00" * UI_PUBLISHER_SLOT_LEN)
    out[16:48] = m.app_id.encode("ascii").ljust(32, b"\x00")
    out[UI_PUBLISHER_KEY_SLOT_OFF:UI_PUBLISHER_KEY_SLOT_OFF + UI_PUBLISHER_KEY_SLOT_LEN] = (
        b"\x00" * UI_PUBLISHER_KEY_SLOT_LEN)
    out[UI_NATIVE_BINDING_OFF:UI_NATIVE_BINDING_OFF + 32] = m.native_member_sha256
    struct.pack_into("<HHH", out, 112, m.version_major, m.version_minor, m.version_patch)
    struct.pack_into("<H", out, 118, m.file_count)
    struct.pack_into("<I", out, 120, m.host_ui_abi)
    struct.pack_into("<I", out, 124, 0)
    for rec in m.records:
        path_bytes = ui.validate_asset_path(rec.path.encode("ascii")).encode("ascii")
        if not ui.MIN_FILE_LEN <= rec.file_len <= ui.MAX_FILE_LEN:
            raise v4.BadPackage(
                f"asset {rec.path!r} file_len {rec.file_len} outside "
                f"{ui.MIN_FILE_LEN}..{ui.MAX_FILE_LEN}")
        if len(rec.sha256) != 32:
            raise v4.BadPackage("record sha256 must be 32 bytes")
        out += struct.pack("<HI", len(path_bytes), rec.file_len) + rec.sha256 + path_bytes
    if len(out) > ui.MAX_MANIFEST_LEN:
        raise v4.BadPackage(f"manifest is {len(out)} bytes, above the {ui.MAX_MANIFEST_LEN}-byte cap")
    return bytes(out)


def parse_ui_manifest_v5(raw: bytes) -> UiManifestV5:
    if len(raw) < ui.MANIFEST_FIXED_LEN:
        raise v4.BadPackage(
            f"ui manifest is {len(raw)} bytes, shorter than the {ui.MANIFEST_FIXED_LEN}-byte fixed block")
    if raw[UI_PUBLISHER_SLOT_OFF:UI_PUBLISHER_SLOT_OFF + UI_PUBLISHER_SLOT_LEN] != (
            b"\x00" * UI_PUBLISHER_SLOT_LEN):
        raise v4.BadPackage("v5 ui manifest publisher_id slot must be all zero (no publisher trust)")
    if raw[UI_PUBLISHER_KEY_SLOT_OFF:UI_PUBLISHER_KEY_SLOT_OFF + UI_PUBLISHER_KEY_SLOT_LEN] != (
            b"\x00" * UI_PUBLISHER_KEY_SLOT_LEN):
        raise v4.BadPackage("v5 ui manifest publisher_key_sha256 slot must be all zero (no key trust)")
    app_id = v4.validate_identifier("app_id", raw[16:48], 32)
    version_major, version_minor, version_patch = struct.unpack_from("<HHH", raw, 112)
    if version_major < 1:
        raise v4.BadPackage(f"ui_version_major {version_major} must be >= 1")
    file_count = struct.unpack_from("<H", raw, 118)[0]
    if not ui.MIN_FILE_COUNT <= file_count <= ui.MAX_FILE_COUNT:
        raise v4.BadPackage(f"file_count {file_count} outside {ui.MIN_FILE_COUNT}..{ui.MAX_FILE_COUNT}")
    host_ui_abi = struct.unpack_from("<I", raw, 120)[0]
    if host_ui_abi != ui.HOST_UI_ABI_V1:
        raise v4.BadPackage(f"host_ui_abi {host_ui_abi} is not {ui.HOST_UI_ABI_V1}")
    if struct.unpack_from("<I", raw, 124)[0] != 0:
        raise v4.BadPackage("ui manifest reserved_u32 is not zero")
    records: list[ui.AssetRecord] = []
    pos = ui.MANIFEST_FIXED_LEN
    running_len = 0
    for index in range(file_count):
        if pos + ui.RECORD_FIXED_LEN > len(raw):
            raise v4.BadPackage(f"ui manifest truncated inside record {index}")
        path_len, file_len = struct.unpack_from("<HI", raw, pos)
        if not ui.MIN_PATH_LEN <= path_len <= ui.MAX_PATH_LEN:
            raise v4.BadPackage(f"record {index} path_len {path_len} outside {ui.MIN_PATH_LEN}..{ui.MAX_PATH_LEN}")
        if not ui.MIN_FILE_LEN <= file_len <= ui.MAX_FILE_LEN:
            raise v4.BadPackage(f"record {index} file_len {file_len} outside {ui.MIN_FILE_LEN}..{ui.MAX_FILE_LEN}")
        running_len += file_len
        if running_len > ui.MAX_ASSET_PAYLOAD_LEN:
            raise v4.BadPackage(f"records 0..{index} exceed the {ui.MAX_ASSET_PAYLOAD_LEN}-byte payload cap")
        sha256 = raw[pos + 6:pos + 38]
        path_bytes = raw[pos + 38:pos + 38 + path_len]
        if len(path_bytes) != path_len:
            raise v4.BadPackage(f"ui manifest truncated inside record {index} path")
        pos += ui.RECORD_FIXED_LEN + path_len
        records.append(ui.AssetRecord(path=ui.validate_asset_path(path_bytes),
                                      file_len=file_len, sha256=sha256))
    if pos != len(raw):
        raise v4.BadPackage(f"ui manifest has {len(raw) - pos} extra bytes after the last record")
    for index in range(1, file_count):
        prev_path = records[index - 1].path.encode("ascii")
        this_path = records[index].path.encode("ascii")
        if this_path == prev_path:
            raise v4.BadPackage(f"duplicate asset path {this_path.decode('ascii')!r}")
        if this_path < prev_path:
            raise v4.BadPackage(
                f"records {index - 1}..{index} are not in strict ascending raw-ASCII path order")
    folded = set()
    for rec in records:
        key = rec.path.encode("ascii").lower()
        if key in folded:
            raise v4.BadPackage(f"asset path {rec.path!r} collides under ASCII case folding")
        folded.add(key)
    index_count = sum(1 for r in records if r.path == ui.INDEX_PATH)
    if index_count != 1:
        raise v4.BadPackage(f"exactly one {ui.INDEX_PATH!r} entry is required, found {index_count}")
    return UiManifestV5(
        app_id=app_id,
        native_member_sha256=raw[UI_NATIVE_BINDING_OFF:UI_NATIVE_BINDING_OFF + 32],
        version_major=version_major,
        version_minor=version_minor,
        version_patch=version_patch,
        file_count=file_count,
        host_ui_abi=host_ui_abi,
        records=tuple(records),
    )


def build_package_v5(manifest: bytes, image: bytes, ui_manifest: bytes, ui_payload: bytes) -> bytes:
    if len(manifest) != MANIFEST_LEN:
        raise v4.BadPackage("native manifest must be exactly 208 bytes")
    if not ui.MIN_MANIFEST_LEN <= len(ui_manifest) <= ui.MAX_MANIFEST_LEN:
        raise v4.BadPackage("ui manifest length is outside the NEUI limits")
    if not ui.MIN_ASSET_PAYLOAD_LEN <= len(ui_payload) <= ui.MAX_ASSET_PAYLOAD_LEN:
        raise v4.BadPackage("ui payload length is outside the NEUI limits")
    native_member = manifest + image
    ui_member = (UI_MEMBER_MAGIC
                 + struct.pack("<I", len(ui_manifest))
                 + struct.pack("<I", len(ui_payload))
                 + ui_manifest
                 + ui_payload)
    return (CONTAINER_MAGIC
            + struct.pack("<I", len(native_member))
            + struct.pack("<I", len(ui_member))
            + native_member
            + ui_member)


def verify_package_v5(
    data: bytes,
    policy: v4.DevicePolicyV4 | None = None,
    host_admission: bool = True,
) -> tuple[dict, None] | tuple[None, v4.PackageError]:
    policy = policy or v4.default_policy()
    try:
        return _verify_impl(data, policy, host_admission)
    except v4.PackageError as exc:
        return None, exc


def _verify_impl(data, policy, host_admission):
    if len(data) < HEADER_LEN:
        legacy = detect_legacy_signed(data) if data else None
        if legacy is not None:
            raise LegacySignedFormat(
                f"unsupported legacy signed format ({legacy}); this tool only accepts "
                "unsigned NEAPP v5 packages"
            )
        raise v4.BadPackage(f"file is {len(data)} bytes, shorter than the {HEADER_LEN}-byte container header")
    if data[0:8] != CONTAINER_MAGIC:
        legacy = detect_legacy_signed(data)
        if legacy is not None:
            raise LegacySignedFormat(
                f"unsupported legacy signed format ({legacy}); this tool only accepts "
                "unsigned NEAPP v5 packages"
            )
        raise v4.BadPackage(
            "container magic is not unsigned NEAPP v5 (4e45415050 05 00 00); unknown "
            "container magics are rejected, never negotiated"
        )
    native_len, ui_len = struct.unpack_from("<II", data, 8)
    if not MIN_NATIVE_MEMBER_LEN <= native_len <= MAX_NATIVE_MEMBER_LEN:
        raise v4.BadPackage(
            f"native_member_len {native_len} outside {MIN_NATIVE_MEMBER_LEN}..{MAX_NATIVE_MEMBER_LEN}")
    if not MIN_UI_MEMBER_LEN <= ui_len <= MAX_UI_MEMBER_LEN:
        raise v4.BadPackage(
            f"ui_member_len {ui_len} outside {MIN_UI_MEMBER_LEN}..{MAX_UI_MEMBER_LEN}")
    total_len = v4.u64_checked_sum(HEADER_LEN, native_len, ui_len)
    if total_len > MAX_PACKAGE_LEN:
        raise v4.BadPackage(f"package exceeds the {MAX_PACKAGE_LEN}-byte cap")
    if len(data) != total_len:
        raise v4.BadPackage(
            f"file length {len(data)} != header + native_member_len + ui_member_len "
            f"({total_len}); unsigned v5 has no trailer, no signature, no release sequence"
        )

    native_member = data[HEADER_LEN:HEADER_LEN + native_len]
    ui_member = data[HEADER_LEN + native_len:total_len]
    manifest = parse_manifest_v5(native_member[:MANIFEST_LEN])
    image = native_member[MANIFEST_LEN:]

    if manifest.native_file_len != len(image):
        raise v4.BadPackage(
            f"manifest native_file_len {manifest.native_file_len} != native member image bytes {len(image)}")
    if manifest.native_file_len != v4.NATIVE_HEADER_SIZE + manifest.native_image_size:
        raise v4.BadPackage("manifest native_file_len != 32 + native_image_size")
    native = v4.parse_native_header_v4(image)
    if native.magic != v4.NATIVE_MAGIC:
        raise v4.BadPackage("native header magic is not NEA1")
    if native.header_size != v4.NATIVE_HEADER_SIZE:
        raise v4.BadPackage(f"native header_size {native.header_size} != {v4.NATIVE_HEADER_SIZE} (exact)")
    if native.format_version != v4.NATIVE_FORMAT_VERSION:
        raise v4.BadPackage(f"native format_version {native.format_version} != 1")
    if native.reserved0 != 0:
        raise v4.BadPackage(f"native header reserved0 is {native.reserved0:#x}, must be all zero")
    if native.abi_version != v4.HOST_ABI_V4:
        raise v4.BadPackage(
            f"native header abi_version {native.abi_version:#010x} != {v4.HOST_ABI_V4:#010x}")
    if native.image_size != manifest.native_image_size:
        raise v4.BadPackage("manifest native_image_size != native header image_size")
    if native.header_size + native.image_size != len(image):
        raise v4.BadPackage("native file is not exactly 32-byte header + image_size payload")
    if native.entry_offset != manifest.native_entry_offset:
        raise v4.BadPackage("manifest native_entry_offset != native header entry_offset")
    if native.entry_offset >= native.image_size:
        raise v4.BadPackage(f"native entry_offset {native.entry_offset:#x} is outside the payload")
    if native.entry_offset & 1:
        raise v4.BadPackage("native entry_offset is odd (Thumb entry must be even)")
    if native.target_addr != manifest.native_target_addr:
        raise v4.BadPackage("manifest native_target_addr != native header target_addr")
    if native.abi_version != manifest.required_host_abi:
        raise v4.BadPackage(
            f"manifest required_host_abi {manifest.required_host_abi:#010x} != native header "
            f"abi_version {native.abi_version:#010x}")
    if v4.native_payload_crc32_v4(image, native.image_size) != native.crc32:
        raise v4.BadPackage("native payload CRC-32 mismatch")
    if not constant_time_eq(hashlib.sha256(image).digest(), manifest.native_file_sha256):
        raise v4.BadPackage("manifest native_file_sha256 does not match the native image bytes")
    if manifest.required_exec_region_bytes < manifest.native_image_size:
        raise v4.BadPackage(
            "required_exec_region_bytes is smaller than native_image_size (payload residency)")
    v4.validate_policy_shape(manifest.required_host_caps, manifest.run_profile, manifest.event_max,
                             manifest.state_quota, manifest.report_max, manifest.control_max,
                             manifest.snapshot_max, manifest.live_publish_max, manifest.live_track_max)

    if len(ui_member) < UI_HEADER_LEN:
        raise v4.BadPackage(f"ui member is {len(ui_member)} bytes, shorter than its {UI_HEADER_LEN}-byte header")
    if ui_member[0:8] != UI_MEMBER_MAGIC:
        raise v4.BadPackage(
            "ui member magic is not unsigned NEUI v5 (4e455549 05 00 00 00); a signed NEUI v1 "
            "sidecar is a legacy signed format and is foreign input"
        )
    ui_manifest_len, ui_payload_len = struct.unpack_from("<II", ui_member, 8)
    if not ui.MIN_MANIFEST_LEN <= ui_manifest_len <= ui.MAX_MANIFEST_LEN:
        raise v4.BadPackage(
            f"ui manifest_len {ui_manifest_len} outside {ui.MIN_MANIFEST_LEN}..{ui.MAX_MANIFEST_LEN}")
    if not ui.MIN_ASSET_PAYLOAD_LEN <= ui_payload_len <= ui.MAX_ASSET_PAYLOAD_LEN:
        raise v4.BadPackage(
            f"ui asset_payload_len {ui_payload_len} outside "
            f"{ui.MIN_ASSET_PAYLOAD_LEN}..{ui.MAX_ASSET_PAYLOAD_LEN}")
    ui_total = v4.u64_checked_sum(UI_HEADER_LEN, ui_manifest_len, ui_payload_len)
    if ui_total != len(ui_member):
        raise v4.BadPackage(
            f"ui member length {len(ui_member)} != 16 + manifest_len + payload_len ({ui_total}); "
            "the unsigned v5 ui member carries no signature trailer"
        )
    ui_manifest = parse_ui_manifest_v5(ui_member[UI_HEADER_LEN:UI_HEADER_LEN + ui_manifest_len])
    ui_payload = ui_member[UI_HEADER_LEN + ui_manifest_len:]
    declared_total = sum(rec.file_len for rec in ui_manifest.records)
    if declared_total != ui_payload_len:
        raise v4.BadPackage(
            f"asset_payload_len {ui_payload_len} != sum of record file_len {declared_total}")
    if not constant_time_eq(hashlib.sha256(native_member).digest(), ui_manifest.native_member_sha256):
        raise MemberMismatch(
            "ui manifest native_member_sha256 does not match the exact native member bytes "
            "(Native/UI binding)")
    if ui_manifest.app_id != manifest.app_id:
        raise MemberMismatch(
            f"ui manifest app_id {ui_manifest.app_id!r} != native manifest app_id "
            f"{manifest.app_id!r} (cross-App binding)")
    cursor = 0
    for rec in ui_manifest.records:
        chunk = ui_payload[cursor:cursor + rec.file_len]
        if not constant_time_eq(hashlib.sha256(chunk).digest(), rec.sha256):
            raise v4.BadPackage(
                f"asset {rec.path!r} sha256 does not match the manifest record {rec.sha256.hex()}")
        cursor += rec.file_len

    if host_admission and manifest.target_board_id != policy.target_board_id:
        raise v4.TargetIncompatible(
            f"target_board_id {manifest.target_board_id:#010x} != policy {policy.target_board_id:#010x}")
    if host_admission and manifest.required_psram_mib > policy.psram_mib:
        raise v4.TargetIncompatible(
            f"required_psram_mib {manifest.required_psram_mib} unsupported (policy {policy.psram_mib})")
    if host_admission and manifest.required_host_abi != policy.host_abi:
        raise v4.AbiIncompatible(
            f"required_host_abi {manifest.required_host_abi:#010x} != policy {policy.host_abi:#010x}")
    caps = manifest.required_host_caps
    unsupported = caps & ~policy.host_caps
    if host_admission and unsupported:
        raise v4.AbiIncompatible(
            f"Host does not provide capability bits {unsupported:#x} "
            f"(package requests {caps:#x}, Host provides {policy.host_caps:#x})")
    quota_pairs = (
        (v4.CAP_AI_EVENTS, manifest.event_max, policy.event_buffer_bytes, "event_max"),
        (v4.CAP_REPORT_SUBMIT, manifest.report_max, policy.report_capacity_bytes, "report_max"),
        (v4.CAP_APP_STATE, manifest.state_quota, policy.state_quota_bytes, "state_quota"),
        (v4.CAP_CONTROL_RECEIVE, manifest.control_max, policy.control_msg_bytes, "control_max"),
        (v4.CAP_BUSINESS_SNAPSHOT, manifest.snapshot_max, policy.snapshot_ram_bytes, "snapshot_max"),
    )
    for bit, quota, capacity, name in quota_pairs:
        if host_admission and caps & bit and quota > capacity:
            raise v4.ResourceLimit(f"{name} {quota} exceeds the Host capacity {capacity}")
    if host_admission and caps & v4.CAP_LIVE_PUBLISH:
        if manifest.live_publish_max > policy.live_capacity_bytes:
            raise v4.ResourceLimit(
                f"live_publish_max {manifest.live_publish_max} exceeds the Host live capacity "
                f"{policy.live_capacity_bytes}")
        if manifest.live_track_max > policy.live_capacity_tracks:
            raise v4.ResourceLimit(
                f"live_track_max {manifest.live_track_max} exceeds the Host track capacity "
                f"{policy.live_capacity_tracks}")
    if host_admission and manifest.native_file_len > policy.load_region_bytes:
        raise v4.ResourceLimit(
            f"native_file_len {manifest.native_file_len} exceeds the Host load region "
            f"{policy.load_region_bytes}")
    target = manifest.native_target_addr
    range_hi = policy.loader_base + policy.loader_size
    if host_admission and not (policy.loader_base <= target < range_hi
                               and target + manifest.native_file_len <= range_hi):
        raise v4.ResourceLimit(
            f"native target_addr {target:#010x}+{manifest.native_file_len}B outside the Host "
            f"loader range {policy.loader_base:#010x}..{range_hi:#010x}")
    if host_admission and manifest.required_exec_region_bytes > policy.exec_region_bytes:
        raise v4.ResourceLimit(
            f"required_exec_region_bytes {manifest.required_exec_region_bytes} exceeds the Host "
            f"actual execution region {policy.exec_region_bytes}")

    report = {
        "result": "PASS",
        "format": "neapp-v5-unsigned",
        "package_sha256": sha256_hex(data),
        "package_len": len(data),
        "app_id": manifest.app_id,
        "native_version": f"{manifest.version_major}.{manifest.version_minor}.{manifest.version_patch}",
        "ui_version": (
            f"{ui_manifest.version_major}.{ui_manifest.version_minor}.{ui_manifest.version_patch}"
        ),
        "native_member_len": native_len,
        "native_member_sha256": sha256_hex(native_member),
        "native_file_len": manifest.native_file_len,
        "native_image_size": manifest.native_image_size,
        "native_entry_offset": f"{manifest.native_entry_offset:#x}",
        "native_target_addr": f"{manifest.native_target_addr:#010x}",
        "native_file_sha256": manifest.native_file_sha256.hex(),
        "native_crc32": f"{native.crc32:#010x}",
        "target_board_id": f"{manifest.target_board_id:#010x}",
        "required_psram_mib": manifest.required_psram_mib,
        "required_host_abi": f"{manifest.required_host_abi:#010x}",
        "required_host_caps": f"{manifest.required_host_caps:#x}",
        "required_exec_region_bytes": manifest.required_exec_region_bytes,
        "run_profile": manifest.run_profile,
        "event_max": manifest.event_max,
        "state_quota": manifest.state_quota,
        "report_max": manifest.report_max,
        "control_max": manifest.control_max,
        "snapshot_max": manifest.snapshot_max,
        "live_publish_max": manifest.live_publish_max,
        "live_track_max": manifest.live_track_max,
        "ui_member_len": ui_len,
        "ui_member_sha256": sha256_hex(ui_member),
        "ui_manifest_len": ui_manifest_len,
        "ui_asset_payload_len": ui_payload_len,
        "ui_file_count": ui_manifest.file_count,
        "ui_files": [
            {"path": rec.path, "file_len": rec.file_len, "sha256": rec.sha256.hex()}
            for rec in ui_manifest.records
        ],
        "publisher_trust": "none: unsigned package; SHA-256 digests check member consistency only and do not prove origin",
        "boundary": (
            "offline unsigned-format verification only: SHA-256 here checks container/member "
            "consistency, never publisher authenticity or anti-rollback; NOT Host admission, "
            "install, execution, or device acceptance"
        ),
    }
    return report, None
