#!/usr/bin/env python3
"""neapp_v3_format — v3 format/policy authority for .neapp v3 tooling.

Layers on package/neapp_format.py and reuses the frozen v1 primitives
verbatim (strict DER, SPKI parsing, identifier charset, native header
parsing, CRC-32, trust store, error classes).  Every v3-specific constant
and check is dictated by the integrated v3 spec
docs/app-package-protocol-v3.md (Issue #19 merged baseline):

  §2.1  container: 8B magic 4e45415050030000, manifest_len exactly 192,
        image_len, 192B manifest, unmodified native image, exactly one
        trailing strict-DER signature
  §2.2  TBS = file[0 : 16 + 192 + image_len]; SHA-256(TBS) signs and
        identifies content; DER rules inherited from v1 §2.1/§2.2
  §2.3  caps 16+192+native+DER <= 2,097,432; normative order
        structure -> trust -> signature -> policy
  §3    192B NMF3 manifest: [0..159] v2-inherited layout, required_host_abi
        pinned 0x00030000, [160..175] run_profile/event_max/state_quota/
        report_max, [176..179] control_max, [180..183] snapshot_max,
        [184..191] reserved zero
  §3.3  native NEA1 header abi_version bound to the manifest value (0x00030000)
  §4    capability bits 0..7 (bit6 control_receive, bit7 business_snapshot,
        bit8..31 reject); run_profile 2 requires bit5+bit6; quota/capability
        mutual consistency incl. bit6/bit7; generic control-wire minimum
        control_max >= 32; line-crossing-64 floors event_max >= 1576 and
        report_max >= 6144; declaration != Host authorization
  §10/§11  interop matrix and error-class mapping (BAD_PACKAGE /
        PUBLISHER_UNTRUSTED / SIGNATURE_INVALID / TARGET_INCOMPATIBLE /
        ABI_INCOMPATIBLE / RESOURCE_LIMIT)

v3 is an independent container major: it never interprets v1/v2 packages,
and the v2 reserved bytes [176..191] cannot grant bit6/bit7 anywhere.

OFFLINE TOOLING ONLY: a PASS never means a device installed, executed, hot
reconfigured, or that an STM32/PKA device verifier agrees (spec §14).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

import neapp_format as fmt
from neapp_format import (
    HEADER_LEN,
    MAX_NATIVE_FILE_LEN,
    MAX_SIG_LEN,
    MIN_SIG_LEN,
    NATIVE_FORMAT_VERSION,
    NATIVE_HEADER_SIZE,
    NATIVE_MAGIC,
    AbiIncompatible,
    BadPackage,
    PackageError,
    PublisherUntrusted,
    ResourceLimit,
    SignatureInvalid,
    TargetIncompatible,
    constant_time_eq,
    content_identity,
    load_trust_store,
    native_payload_crc32,
    parse_native_header,
    parse_spki_p256,
    parse_strict_ecdsa_der,
    sha256_hex,
    validate_identifier,
)

CONTAINER_MAGIC = bytes.fromhex("4e45415050030000")
MANIFEST_MAGIC = b"NMF3"
MANIFEST_LEN = 192
MAX_PACKAGE_LEN = 2_097_432

HOST_ABI_V3 = 0x00030000

TARGET_BOARD_ID_V3 = fmt.TARGET_BOARD_ID_V1
REQUIRED_PSRAM_MIB_V3 = fmt.REQUIRED_PSRAM_MIB_V1
EXEC_BASE_V3 = fmt.EXEC_BASE_V1
EXEC_REGION_BYTES_V3 = fmt.EXEC_REGION_BYTES_V1

CAP_LOG = 1 << 0
CAP_TICK_MS = 1 << 1
CAP_AI_EVENTS = 1 << 2
CAP_REPORT_SUBMIT = 1 << 3
CAP_APP_STATE = 1 << 4
CAP_SESSION_LIFECYCLE = 1 << 5
CAP_CONTROL_RECEIVE = 1 << 6
CAP_BUSINESS_SNAPSHOT = 1 << 7
HOST_CAPS_KNOWN_MASK = 0x000000FF

RUN_PROFILE_HOT_COMMAND_SESSION = 2

CONTROL_WIRE_MIN = 32

EVENT_HEADER_SIZE = 40
EVENT_RECORD_SIZE = 24
EVENT_MAX_DETECTIONS = 64
EVENT_MIN_FOR_AI_EVENTS = EVENT_HEADER_SIZE + EVENT_MAX_DETECTIONS * EVENT_RECORD_SIZE
REPORT_MIN_FOR_REPORT_SUBMIT = 6144


@dataclass
class ManifestV3:
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


def _check_quota_consistency(caps: int, event_max: int, state_quota: int,
                             report_max: int, control_max: int, snapshot_max: int) -> None:
    pairs = (
        (CAP_AI_EVENTS, event_max, "ai_events (bit2)", "event_max"),
        (CAP_REPORT_SUBMIT, report_max, "report_submit (bit3)", "report_max"),
        (CAP_APP_STATE, state_quota, "app_state (bit4)", "state_quota"),
        (CAP_CONTROL_RECEIVE, control_max, "control_receive (bit6)", "control_max"),
        (CAP_BUSINESS_SNAPSHOT, snapshot_max, "business_snapshot (bit7)", "snapshot_max"),
    )
    for bit, quota, cap_name, quota_name in pairs:
        if caps & bit and quota == 0:
            raise BadPackage(f"{cap_name} requires a nonzero {quota_name}")
        if quota != 0 and not caps & bit:
            raise BadPackage(f"{quota_name} set without the {cap_name} capability")


def validate_policy_shape(caps: int, run_profile: int, event_max: int, state_quota: int,
                          report_max: int, control_max: int, snapshot_max: int) -> None:
    if caps & ~HOST_CAPS_KNOWN_MASK:
        raise BadPackage(f"required_host_caps has unknown bits: {caps & ~HOST_CAPS_KNOWN_MASK:#x}")
    if run_profile != RUN_PROFILE_HOT_COMMAND_SESSION:
        raise BadPackage(
            f"unknown run_profile {run_profile} (v3 allows only "
            f"{RUN_PROFILE_HOT_COMMAND_SESSION})"
        )
    if not caps & CAP_SESSION_LIFECYCLE:
        raise BadPackage("run_profile 2 requires the session_lifecycle capability (bit5)")
    if not caps & CAP_CONTROL_RECEIVE:
        raise BadPackage("run_profile 2 requires the control_receive capability (bit6)")
    _check_quota_consistency(caps, event_max, state_quota, report_max, control_max, snapshot_max)
    if caps & CAP_CONTROL_RECEIVE and control_max < CONTROL_WIRE_MIN:
        raise ResourceLimit(
            f"control_max {control_max} is below the generic 32B control-wire minimum "
            f"{CONTROL_WIRE_MIN} (§4.1: the smallest complete command is the 32B header)"
        )


def build_manifest_v3(m: ManifestV3) -> bytes:
    pub = validate_identifier("publisher_id", m.publisher_id.encode("ascii"), 16)
    app = validate_identifier("app_id", m.app_id.encode("ascii"), 32)
    for name, v in (("version_major", m.version_major),
                    ("version_minor", m.version_minor),
                    ("version_patch", m.version_patch)):
        if not 0 <= v <= 0xFFFF:
            raise BadPackage(f"{name} out of u16 range: {v}")
    if m.required_host_abi != HOST_ABI_V3:
        raise BadPackage(
            f"v3 manifest required_host_abi must be {HOST_ABI_V3:#010x}, "
            f"got {m.required_host_abi:#010x}"
        )
    validate_policy_shape(m.required_host_caps, m.run_profile, m.event_max,
                          m.state_quota, m.report_max, m.control_max, m.snapshot_max)
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
    if len(out) != MANIFEST_LEN:
        raise BadPackage("v3 manifest encoder produced wrong length")
    return bytes(out)


def parse_manifest_v3(raw: bytes) -> ManifestV3:
    if len(raw) != MANIFEST_LEN:
        raise BadPackage(f"manifest is {len(raw)} bytes, v3 requires exactly {MANIFEST_LEN}")
    if raw[0:4] != MANIFEST_MAGIC:
        raise BadPackage("manifest magic is not NMF3")
    if raw[58:60] != b"\x00\x00":
        raise BadPackage("manifest reserved bytes (58..59) are not zero")
    abi = struct.unpack_from("<I", raw, 68)[0]
    if abi != HOST_ABI_V3:
        raise BadPackage(
            f"v3 manifest required_host_abi must be {HOST_ABI_V3:#010x}, got {abi:#010x} "
            "(format invariant, §3.1/§10 M6)"
        )
    if raw[184:192] != b"\x00" * 8:
        raise BadPackage("manifest reserved bytes (184..191) are not zero")
    publisher_id = validate_identifier("publisher_id", raw[4:20], 16)
    app_id = validate_identifier("app_id", raw[20:52], 32)
    vmaj, vmin, vpat = struct.unpack_from("<HHH", raw, 52)
    (board, psram, _abi, caps, exec_region, file_len, image_size, entry, target) = (
        struct.unpack_from("<9I", raw, 60))
    run_profile, event_max, state_quota, report_max, control_max, snapshot_max = (
        struct.unpack_from("<6I", raw, 160))
    return ManifestV3(
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
    )


def build_container_prefix_v3(manifest: bytes, image: bytes) -> bytes:
    if len(manifest) != MANIFEST_LEN:
        raise BadPackage("manifest must be exactly 192 bytes")
    if len(image) > MAX_NATIVE_FILE_LEN:
        raise BadPackage("native image exceeds the v3 file cap")
    return (
        CONTAINER_MAGIC
        + struct.pack("<I", MANIFEST_LEN)
        + struct.pack("<I", len(image))
        + manifest
        + image
    )


@dataclass
class DevicePolicyV3:
    target_board_id: int = TARGET_BOARD_ID_V3
    psram_mib: int = REQUIRED_PSRAM_MIB_V3
    host_abi: int = HOST_ABI_V3
    host_caps: int = HOST_CAPS_KNOWN_MASK
    loader_base: int = EXEC_BASE_V3
    loader_size: int = EXEC_REGION_BYTES_V3
    load_region_bytes: int = EXEC_REGION_BYTES_V3
    exec_region_bytes: int = EXEC_REGION_BYTES_V3
    event_buffer_bytes: int = 2048
    report_capacity_bytes: int = REPORT_MIN_FOR_REPORT_SUBMIT
    state_quota_bytes: int = 4096
    control_msg_bytes: int = 256
    snapshot_ram_bytes: int = 1024
    business: str | None = "line-crossing-64"
    event_min_for_ai_events: int = EVENT_MIN_FOR_AI_EVENTS
    report_min_for_report_submit: int = REPORT_MIN_FOR_REPORT_SUBMIT

    @classmethod
    def from_json(cls, data: dict | None) -> "DevicePolicyV3":
        policy = cls()
        if not data:
            return policy
        for field in ("target_board_id", "psram_mib", "host_abi", "host_caps",
                      "loader_base", "loader_size", "load_region_bytes",
                      "exec_region_bytes", "event_buffer_bytes",
                      "report_capacity_bytes", "state_quota_bytes",
                      "control_msg_bytes", "snapshot_ram_bytes",
                      "event_min_for_ai_events", "report_min_for_report_submit"):
            if field in data:
                v = data[field]
                setattr(policy, field, int(v, 0) if isinstance(v, str) else int(v))
        if "business" in data:
            policy.business = data["business"]
        return policy


def default_policy() -> DevicePolicyV3:
    return DevicePolicyV3()


def verify_package_v3(
    data: bytes,
    trust: fmt.TrustStore,
    policy: DevicePolicyV3 | None = None,
) -> tuple[dict, None] | tuple[None, PackageError]:
    policy = policy or default_policy()
    try:
        return _verify_v3_impl(data, trust, policy)
    except PackageError as exc:
        return None, exc


def _verify_v3_impl(data, trust, policy):
    min_len = HEADER_LEN + MANIFEST_LEN + NATIVE_HEADER_SIZE + MIN_SIG_LEN
    if len(data) < min_len:
        raise BadPackage(f"file is {len(data)} bytes, shorter than the minimum v3 package {min_len}")
    if data[0:8] != CONTAINER_MAGIC:
        raise BadPackage(
            "container magic is not NEAPP v3 (4e45415050 03 00 00); unknown container "
            "versions are rejected, never negotiated (§1.3, §10 M2/M3/M4/M5)"
        )
    manifest_len, image_len = struct.unpack_from("<II", data, 8)
    if manifest_len != MANIFEST_LEN:
        raise BadPackage(f"manifest_len is {manifest_len}, v3 allows only {MANIFEST_LEN}")
    if image_len < NATIVE_HEADER_SIZE:
        raise BadPackage(f"image_len {image_len} cannot hold the {NATIVE_HEADER_SIZE}-byte native header")
    if image_len > MAX_NATIVE_FILE_LEN:
        raise BadPackage(f"image_len {image_len} exceeds the v3 native file cap {MAX_NATIVE_FILE_LEN}")
    signed_len = HEADER_LEN + manifest_len + image_len
    if len(data) < signed_len:
        raise BadPackage(f"file truncated: {len(data)} bytes < signed region {signed_len}")
    sig_len = len(data) - signed_len
    if sig_len < MIN_SIG_LEN:
        raise BadPackage(f"signature segment is {sig_len} bytes, below the DER minimum {MIN_SIG_LEN}")
    if sig_len > MAX_SIG_LEN:
        raise BadPackage(f"signature segment is {sig_len} bytes, above the DER maximum {MAX_SIG_LEN}")
    if len(data) > MAX_PACKAGE_LEN:
        raise BadPackage(f"package is {len(data)} bytes, above the v3 cap {MAX_PACKAGE_LEN}")
    tbs = data[:signed_len]
    sig = data[signed_len:]

    parse_strict_ecdsa_der(sig)

    manifest = parse_manifest_v3(data[HEADER_LEN:HEADER_LEN + MANIFEST_LEN])

    entry = trust.lookup(manifest.publisher_id)
    if entry is None:
        raise PublisherUntrusted(
            f"publisher_id {manifest.publisher_id!r} is not in the local trust mapping"
        )
    trusted_fingerprint_hex, trusted_spki = entry
    if not constant_time_eq(manifest.publisher_key_sha256, bytes.fromhex(trusted_fingerprint_hex)):
        raise PublisherUntrusted(
            "manifest publisher_key_sha256 does not match the trusted key for "
            f"publisher_id {manifest.publisher_id!r}"
        )

    trusted_key = parse_spki_p256(trusted_spki)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        trusted_key.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureInvalid("ECDSA P-256/SHA-256 verification failed over the exact TBS")

    image = data[HEADER_LEN + MANIFEST_LEN:signed_len]
    if manifest.native_file_len != image_len:
        raise BadPackage(f"manifest native_file_len {manifest.native_file_len} != container image_len {image_len}")
    if manifest.native_file_len != NATIVE_HEADER_SIZE + manifest.native_image_size:
        raise BadPackage("manifest native_file_len != 32 + native_image_size")
    native = parse_native_header(image)
    if native.magic != NATIVE_MAGIC:
        raise BadPackage("native header magic is not NEA1")
    if native.header_size != NATIVE_HEADER_SIZE:
        raise BadPackage(f"native header_size {native.header_size} != {NATIVE_HEADER_SIZE} (exact)")
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
        raise BadPackage(
            f"manifest required_host_abi {manifest.required_host_abi:#010x} != native header "
            f"abi_version {native.abi_version:#010x} (§3.3 cross-check, §10 M6)"
        )
    if native_payload_crc32(image, native.image_size) != native.crc32:
        raise BadPackage("native payload CRC-32 mismatch")
    if not constant_time_eq(hashlib.sha256(image).digest(), manifest.native_file_sha256):
        raise BadPackage("manifest native_file_sha256 does not match the native image bytes")
    if manifest.required_exec_region_bytes < manifest.native_image_size:
        raise BadPackage(
            "required_exec_region_bytes is smaller than native_image_size (payload residency)"
        )

    if manifest.target_board_id != policy.target_board_id:
        raise TargetIncompatible(
            f"target_board_id {manifest.target_board_id:#010x} != policy {policy.target_board_id:#010x}"
        )
    if manifest.required_psram_mib > policy.psram_mib:
        raise TargetIncompatible(
            f"required_psram_mib {manifest.required_psram_mib} unsupported (policy {policy.psram_mib})"
        )
    if manifest.required_host_abi != policy.host_abi:
        raise AbiIncompatible(
            f"required_host_abi {manifest.required_host_abi:#010x} != policy {policy.host_abi:#010x}"
        )
    caps = manifest.required_host_caps
    if caps & ~HOST_CAPS_KNOWN_MASK:
        raise BadPackage(
            f"required_host_caps has unknown bits {caps & ~HOST_CAPS_KNOWN_MASK:#x} "
            "(bit8..31 must be zero, §4.1/§10 M8)"
        )
    unsupported = caps & ~policy.host_caps
    if unsupported:
        raise AbiIncompatible(
            f"Host does not provide capability bits {unsupported:#x} "
            f"(package requests {caps:#x}, Host provides {policy.host_caps:#x}, §4.2/§10 M10)"
        )
    if manifest.run_profile != RUN_PROFILE_HOT_COMMAND_SESSION:
        raise BadPackage(
            f"unknown run_profile {manifest.run_profile} "
            f"(v3 allows only {RUN_PROFILE_HOT_COMMAND_SESSION}, §3.2/§10 M9)"
        )
    if not caps & CAP_SESSION_LIFECYCLE:
        raise BadPackage("run_profile 2 requires the session_lifecycle capability (bit5, §4.1)")
    if not caps & CAP_CONTROL_RECEIVE:
        raise BadPackage("run_profile 2 requires the control_receive capability (bit6, §4.1)")
    _check_quota_consistency(caps, manifest.event_max, manifest.state_quota,
                             manifest.report_max, manifest.control_max, manifest.snapshot_max)
    if caps & CAP_CONTROL_RECEIVE and manifest.control_max < CONTROL_WIRE_MIN:
        raise ResourceLimit(
            f"control_max {manifest.control_max} is below the generic 32B control-wire "
            f"minimum {CONTROL_WIRE_MIN} (§4.1/§10 M11)"
        )
    if policy.business == "line-crossing-64":
        required = (CAP_AI_EVENTS | CAP_REPORT_SUBMIT | CAP_APP_STATE |
                    CAP_SESSION_LIFECYCLE | CAP_CONTROL_RECEIVE | CAP_BUSINESS_SNAPSHOT)
        missing = required & ~caps
        if missing:
            raise BadPackage(
                f"line-crossing-64 requires capability bits {required:#x}, "
                f"package declares {caps:#x} (missing {missing:#x}, §4.1/§10 M11)"
            )
        if caps & CAP_AI_EVENTS and manifest.event_max < policy.event_min_for_ai_events:
            raise ResourceLimit(
                f"event_max {manifest.event_max} below the 64-detection ai_events minimum "
                f"{policy.event_min_for_ai_events} (§4.1, §10 M11)"
            )
        if caps & CAP_REPORT_SUBMIT and manifest.report_max < policy.report_min_for_report_submit:
            raise ResourceLimit(
                f"report_max {manifest.report_max} below the line_counting report minimum "
                f"{policy.report_min_for_report_submit} (§4.1, §10 M11)"
            )
    if caps & CAP_AI_EVENTS and manifest.event_max > policy.event_buffer_bytes:
        raise ResourceLimit(
            f"event_max {manifest.event_max} exceeds the Host event buffer "
            f"{policy.event_buffer_bytes}"
        )
    if caps & CAP_REPORT_SUBMIT and manifest.report_max > policy.report_capacity_bytes:
        raise ResourceLimit(
            f"report_max {manifest.report_max} exceeds the Host report capacity "
            f"{policy.report_capacity_bytes}"
        )
    if caps & CAP_APP_STATE and manifest.state_quota > policy.state_quota_bytes:
        raise ResourceLimit(
            f"state_quota {manifest.state_quota} exceeds the Host state quota "
            f"{policy.state_quota_bytes}"
        )
    if caps & CAP_CONTROL_RECEIVE and manifest.control_max > policy.control_msg_bytes:
        raise ResourceLimit(
            f"control_max {manifest.control_max} exceeds the Host control message capacity "
            f"{policy.control_msg_bytes} (§10 M11)"
        )
    if caps & CAP_BUSINESS_SNAPSHOT and manifest.snapshot_max > policy.snapshot_ram_bytes:
        raise ResourceLimit(
            f"snapshot_max {manifest.snapshot_max} exceeds the Host snapshot RAM "
            f"{policy.snapshot_ram_bytes} (§10 M11)"
        )
    if manifest.native_file_len > policy.load_region_bytes:
        raise ResourceLimit(
            f"native_file_len {manifest.native_file_len} exceeds the Host load region "
            f"{policy.load_region_bytes} (whole file is read into the region before de-headering)"
        )
    target = manifest.native_target_addr
    range_hi = policy.loader_base + policy.loader_size
    if not (policy.loader_base <= target < range_hi
            and target + manifest.native_file_len <= range_hi):
        raise ResourceLimit(
            f"native target_addr {target:#010x}+{manifest.native_file_len}B outside the Host "
            f"loader range {policy.loader_base:#010x}..{range_hi:#010x} (§3.3, independently "
            "known Host placement)"
        )
    if manifest.required_exec_region_bytes > policy.exec_region_bytes:
        raise ResourceLimit(
            f"required_exec_region_bytes {manifest.required_exec_region_bytes} exceeds the Host "
            f"actual execution region {policy.exec_region_bytes}"
        )

    report = {
        "result": "PASS",
        "format": "neapp-v3",
        "package_sha256": sha256_hex(data),
        "content_identity_sha256": content_identity(tbs),
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
        "boundary": (
            "offline verification only: not NE301 admission, install, execution, "
            "hot reconfiguration, STM32/PKA verification, or power-fail recovery evidence"
        ),
    }
    return report, None
