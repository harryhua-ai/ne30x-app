#!/usr/bin/env python3
"""neapp_v2_format — the v2 format/policy authority for .neapp v2 tooling.

Every v2-specific constant, layout and check in this module is dictated by the
integrated v2 protocol spec `docs/app-package-protocol-v2-draft.md` (the
Issue #12 merged baseline; historical file name retained):

  §2.1  v2 container wire format (8B magic NEAPP major 2, manifest_len must be
        exactly 192, image_len, 192B manifest, unmodified native image,
        exactly one trailing strict-DER signature, no second signature)
  §2.2  TBS = file[0 : 16 + 192 + image_len]; SHA-256(TBS) is both the signing
        input and the idempotent content identity; DER rules fully inherited
        from v1 §2.1/§2.2 (strict, canonical, tail fully consumed)
  §2.3  capacity caps and the normative verification ORDER: bounded structure
        (incl. DER structure and 192B manifest unique encoding) -> Host-local
        trusted-issuer mapping -> ECDSA over the raw TBS -> policy (native
        header / digests / CRC / board / ABI / caps / quotas / resources)
  §3    192B manifest: [0..159] strictly reuses the v1 same-position encoding
        with manifest magic NMF2, required_host_abi pinned to 0x00020000 and a
        v2 capability mask; [160..191] carries run_profile/event_max/
        state_quota/report_max and 16B reserved that must stay zero
  §3.3  native NEA1 32B header cross-checks inherited from v1 §2.3 with the
        native header abi_version bound to the manifest value
  §4    capability bits 0..5; bit6..31 reject; profile 1 requires bit5; each
        capability bit must match a nonzero quota and vice versa; the current
        64-detection line-crossing business floors (event_max >= 1576,
        report_max >= 6144); package declaration != Host authorization
  §8/§9 interop matrix and error-class mapping (BAD_PACKAGE /
        PUBLISHER_UNTRUSTED / SIGNATURE_INVALID / TARGET_INCOMPATIBLE /
        ABI_INCOMPATIBLE / RESOURCE_LIMIT)

This module LAYERS on package/neapp_format.py and reuses the frozen v1
primitives verbatim (strict DER, SPKI parsing, identifier charset, native
header parsing, CRC-32, trust store, error classes).  It does NOT redefine
any shared format concept and does not touch the v1 verify pipeline: v1
behavior stays byte-for-byte what P3 shipped.

OFFLINE TOOLING ONLY: passing verification here never means a device has
installed, executed, or power-fail recovered the package, and never means
the STM32/PKA device-side verifier agrees (spec §12).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

import neapp_format as fmt
from neapp_format import (  # re-exported shared primitives (single source)
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

# --------------------------------------------------------------------------
# Frozen v2 container constants (spec §2.1 / §3).  No alternatives exist in
# v2; anything else is rejected, never negotiated.
# --------------------------------------------------------------------------

CONTAINER_MAGIC = bytes.fromhex("4e45415050020000")  # "NEAPP", container major 2, 2×0x00 (§2.1)
MANIFEST_MAGIC = b"NMF2"                              # §3.1
MANIFEST_LEN = 192                                    # §2.1: only legal value in v2
MAX_PACKAGE_LEN = 2_097_432                           # §2.3 candidate cap: 16+192+2 MiB+72

# v2 manifest pins (§3.1): v2 containers must declare ABI 0x00020000 — any
# other value is a v2 format-invariant violation (BAD_PACKAGE, §9).
HOST_ABI_V2 = 0x00020000

# Device/experiment facts inherited from the v1 §2.3/§2.4 evidence baseline
# (same board, same 2 MiB experiment execution region; policy inputs only).
TARGET_BOARD_ID_V2 = fmt.TARGET_BOARD_ID_V1            # 0x00003010
REQUIRED_PSRAM_MIB_V2 = fmt.REQUIRED_PSRAM_MIB_V1      # 64
EXEC_BASE_V2 = fmt.EXEC_BASE_V1                        # 0x93E00000
EXEC_REGION_BYTES_V2 = fmt.EXEC_REGION_BYTES_V1        # 2 MiB experiment region

# Capability bits (§4.1).  bit6..31: any bit set -> reject (unknown capability).
CAP_LOG = 1 << 0
CAP_TICK_MS = 1 << 1
CAP_AI_EVENTS = 1 << 2
CAP_REPORT_SUBMIT = 1 << 3
CAP_APP_STATE = 1 << 4
CAP_SESSION_LIFECYCLE = 1 << 5
HOST_CAPS_KNOWN_MASK = 0x0000003F

# Run profiles (§3.2): this version has exactly one legal value.
RUN_PROFILE_SINGLE_TRUSTED_SESSION = 1

# §4.1 business floors for the current 64-detection line-crossing profile
# (LC_FRAME_MAX_DETECTIONS = 64; LC_DQ_SLOT_CAPACITY = 6144, ne301 @de25a6f1).
EVENT_HEADER_SIZE = 40
EVENT_RECORD_SIZE = 24
EVENT_MAX_DETECTIONS = 64
EVENT_MIN_FOR_AI_EVENTS = EVENT_HEADER_SIZE + EVENT_MAX_DETECTIONS * EVENT_RECORD_SIZE  # 1576
REPORT_MIN_FOR_REPORT_SUBMIT = 6144


# --------------------------------------------------------------------------
# v2 manifest (§3, exactly 192 bytes)
# --------------------------------------------------------------------------


@dataclass
class ManifestV2:
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


def build_manifest_v2(m: ManifestV2) -> bytes:
    """Encode the 192B v2 manifest.  Packer-side fail-closed validation so the
    packer cannot emit a manifest the verifier must reject (§3/§4.1)."""
    pub = validate_identifier("publisher_id", m.publisher_id.encode("ascii"), 16)
    app = validate_identifier("app_id", m.app_id.encode("ascii"), 32)
    for name, v in (("version_major", m.version_major),
                    ("version_minor", m.version_minor),
                    ("version_patch", m.version_patch)):
        if not 0 <= v <= 0xFFFF:
            raise BadPackage(f"{name} out of u16 range: {v}")
    if m.required_host_abi != HOST_ABI_V2:
        raise BadPackage(
            f"v2 manifest required_host_abi must be {HOST_ABI_V2:#010x}, got {m.required_host_abi:#010x}"
        )
    if m.required_host_caps & ~HOST_CAPS_KNOWN_MASK:
        raise BadPackage(f"required_host_caps has unknown bits: {m.required_host_caps:#x}")
    if m.run_profile != RUN_PROFILE_SINGLE_TRUSTED_SESSION:
        raise BadPackage(f"unknown run_profile {m.run_profile} (v2 allows only "
                         f"{RUN_PROFILE_SINGLE_TRUSTED_SESSION})")
    if not m.required_host_caps & CAP_SESSION_LIFECYCLE:
        raise BadPackage("run_profile 1 requires the session_lifecycle capability (bit5)")
    _check_quota_consistency(m.required_host_caps, m.event_max, m.state_quota, m.report_max)
    if m.native_file_len != NATIVE_HEADER_SIZE + m.native_image_size:
        raise BadPackage("native_file_len != 32 + native_image_size")
    out = bytearray(MANIFEST_LEN)
    out[0:4] = MANIFEST_MAGIC
    out[4:20] = pub.encode("ascii").ljust(16, b"\x00")
    out[20:52] = app.encode("ascii").ljust(32, b"\x00")
    out[52:54] = struct.pack("<H", m.version_major)
    out[54:56] = struct.pack("<H", m.version_minor)
    out[56:58] = struct.pack("<H", m.version_patch)
    # 58..59 reserved: v1-inherited invariant, stays zero (§3.1)
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
    # 176..191 reserved: must stay zero (§3.2)
    if len(out) != MANIFEST_LEN:
        raise BadPackage("v2 manifest encoder produced wrong length")
    return bytes(out)


def _check_quota_consistency(caps: int, event_max: int, state_quota: int, report_max: int) -> None:
    """§4.1: each capability bit requires a nonzero quota, and a nonzero quota
    requires its capability bit (no silent reservation)."""
    if (caps & CAP_AI_EVENTS) and event_max == 0:
        raise BadPackage("ai_events (bit2) requires a nonzero event_max")
    if (caps & CAP_REPORT_SUBMIT) and report_max == 0:
        raise BadPackage("report_submit (bit3) requires a nonzero report_max")
    if (caps & CAP_APP_STATE) and state_quota == 0:
        raise BadPackage("app_state (bit4) requires a nonzero state_quota")
    if event_max != 0 and not caps & CAP_AI_EVENTS:
        raise BadPackage("event_max set without the ai_events capability (bit2)")
    if report_max != 0 and not caps & CAP_REPORT_SUBMIT:
        raise BadPackage("report_max set without the report_submit capability (bit3)")
    if state_quota != 0 and not caps & CAP_APP_STATE:
        raise BadPackage("state_quota set without the app_state capability (bit4)")


def parse_manifest_v2(raw: bytes) -> ManifestV2:
    """Strictly decode a 192B v2 manifest; any non-canonical encoding is
    BAD_PACKAGE (§2.3 unique-encoding requirement, §3 format invariants).

    Mirrors the authoritative #12 decode order: magic, reserved invariants,
    the ABI format invariant, identifier slots.  Capability-bit semantics are
    deliberately NOT decided here — they are policy items checked after the
    signature succeeds (§9: 未知能力位 -> BAD_PACKAGE 策略项), matching the
    integrated tests/spec-v2 `full_accept` behavior."""
    if len(raw) != MANIFEST_LEN:
        raise BadPackage(f"manifest is {len(raw)} bytes, v2 requires exactly {MANIFEST_LEN}")
    if raw[0:4] != MANIFEST_MAGIC:
        raise BadPackage("manifest magic is not NMF2")
    if raw[58:60] != b"\x00\x00":
        raise BadPackage("manifest reserved bytes (58..59) are not zero")
    abi = struct.unpack_from("<I", raw, 68)[0]
    if abi != HOST_ABI_V2:
        raise BadPackage(
            f"v2 manifest required_host_abi must be {HOST_ABI_V2:#010x}, got {abi:#010x} "
            "(format invariant, §3.1/§9)"
        )
    if raw[176:192] != b"\x00" * 16:
        raise BadPackage("manifest reserved bytes (176..191) are not zero")
    publisher_id = validate_identifier("publisher_id", raw[4:20], 16)
    app_id = validate_identifier("app_id", raw[20:52], 32)
    vmaj, vmin, vpat = struct.unpack_from("<HHH", raw, 52)
    (board, psram, _abi, caps, exec_region, file_len, image_size, entry, target) = (
        struct.unpack_from("<9I", raw, 60))
    run_profile, event_max, state_quota, report_max = struct.unpack_from("<4I", raw, 160)
    return ManifestV2(
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
    )


def manifest_version_tuple(m: ManifestV2) -> tuple[int, int, int]:
    return (m.version_major, m.version_minor, m.version_patch)


# --------------------------------------------------------------------------
# Container framing (§2.1)
# --------------------------------------------------------------------------


def build_container_prefix_v2(manifest: bytes, image: bytes) -> bytes:
    if len(manifest) != MANIFEST_LEN:
        raise BadPackage("manifest must be exactly 192 bytes")
    if len(image) > MAX_NATIVE_FILE_LEN:
        raise BadPackage("native image exceeds the v2 file cap")
    return (
        CONTAINER_MAGIC
        + struct.pack("<I", MANIFEST_LEN)
        + struct.pack("<I", len(image))
        + manifest
        + image
    )


# --------------------------------------------------------------------------
# Host-side offline policy stand-in (§2.3 step 5, §4.2, §8, §9)
# --------------------------------------------------------------------------


@dataclass
class DevicePolicyV2:
    """Offline stand-in for the device/Host facts the v2 spec pins.  All of
    this is LOCAL Host configuration: nothing here is taken from a package
    (§4.2 包声明 ≠ Host 授权).  `host_caps` is the set of capabilities THIS
    Host actually provides — known bits the Host lacks must fail-closed
    reject (§4.2 reverse direction, §9 ABI_INCOMPATIBLE)."""
    target_board_id: int = TARGET_BOARD_ID_V2
    psram_mib: int = REQUIRED_PSRAM_MIB_V2
    host_abi: int = HOST_ABI_V2
    host_caps: int = HOST_CAPS_KNOWN_MASK
    loader_base: int = EXEC_BASE_V2
    loader_size: int = EXEC_REGION_BYTES_V2
    load_region_bytes: int = EXEC_REGION_BYTES_V2       # temp load capacity (v1 rule)
    exec_region_bytes: int = EXEC_REGION_BYTES_V2       # actual execution region
    event_buffer_bytes: int = 2048                      # example Host provision (>= 1576)
    report_capacity_bytes: int = REPORT_MIN_FOR_REPORT_SUBMIT
    state_quota_bytes: int = 4096
    # Business context for §4.1 floors; None disables the business minimums.
    business: str | None = "line-crossing-64"
    event_min_for_ai_events: int = EVENT_MIN_FOR_AI_EVENTS
    report_min_for_report_submit: int = REPORT_MIN_FOR_REPORT_SUBMIT

    @classmethod
    def from_json(cls, data: dict | None) -> "DevicePolicyV2":
        policy = cls()
        if not data:
            return policy
        for field in ("target_board_id", "psram_mib", "host_abi", "host_caps",
                      "loader_base", "loader_size", "load_region_bytes",
                      "exec_region_bytes", "event_buffer_bytes",
                      "report_capacity_bytes", "state_quota_bytes",
                      "event_min_for_ai_events", "report_min_for_report_submit"):
            if field in data:
                v = data[field]
                setattr(policy, field, int(v, 0) if isinstance(v, str) else int(v))
        if "business" in data:
            policy.business = data["business"]
        return policy


def default_policy() -> DevicePolicyV2:
    return DevicePolicyV2()


# --------------------------------------------------------------------------
# The v2 verification pipeline (spec §2.3 判定序; #12 full_accept order)
# --------------------------------------------------------------------------


def verify_package_v2(
    data: bytes,
    trust: fmt.TrustStore,
    policy: DevicePolicyV2 | None = None,
) -> tuple[dict, None] | tuple[None, PackageError]:
    """Verify one .neapp v2 package offline.

    Order is normative (§2.3):
      ① management-entry authorization is a device concern (out of scope offline)
      ② bounded structure parse: magic, both lengths, 192B manifest unique
        encoding, strict DER structure with the tail fully consumed
      ③ trusted issuer: Host-local publisher_id -> SPKI mapping, fail-closed
      ④ ECDSA P-256/SHA-256 over the exact raw TBS with the mapped Host key
      ⑤ policy: native header/digest/CRC cross-checks, board, ABI, capability
        subset, quotas, loader range and actual execution region

    Returns (report, None) on success or (None, PackageError subclass).

    OFFLINE ONLY: a PASS never means a device installed or executed the
    package, and never means the STM32/PKA device verifier agrees (§12)."""
    policy = policy or default_policy()
    try:
        return _verify_v2_impl(data, trust, policy)
    except PackageError as exc:
        return None, exc


def _verify_v2_impl(data, trust, policy):
    # ---- stage 2a: bounded container structure (overflow-safe, no crypto) ----
    min_len = HEADER_LEN + MANIFEST_LEN + NATIVE_HEADER_SIZE + MIN_SIG_LEN
    if len(data) < min_len:
        raise BadPackage(f"file is {len(data)} bytes, shorter than the minimum v2 package {min_len}")
    if data[0:8] != CONTAINER_MAGIC:
        raise BadPackage(
            "container magic is not NEAPP v2 (4e45415050 02 00 00); unknown container "
            "versions are rejected, never negotiated (§1.3/§8 M2)"
        )
    manifest_len, image_len = struct.unpack_from("<II", data, 8)
    if manifest_len != MANIFEST_LEN:
        raise BadPackage(f"manifest_len is {manifest_len}, v2 allows only {MANIFEST_LEN}")
    if image_len < NATIVE_HEADER_SIZE:
        raise BadPackage(f"image_len {image_len} cannot hold the {NATIVE_HEADER_SIZE}-byte native header")
    if image_len > MAX_NATIVE_FILE_LEN:
        raise BadPackage(f"image_len {image_len} exceeds the v2 native file cap {MAX_NATIVE_FILE_LEN}")
    signed_len = HEADER_LEN + manifest_len + image_len
    if len(data) < signed_len:
        raise BadPackage(f"file truncated: {len(data)} bytes < signed region {signed_len}")
    sig_len = len(data) - signed_len
    if sig_len < MIN_SIG_LEN:
        raise BadPackage(f"signature segment is {sig_len} bytes, below the DER minimum {MIN_SIG_LEN}")
    if sig_len > MAX_SIG_LEN:
        raise BadPackage(f"signature segment is {sig_len} bytes, above the DER maximum {MAX_SIG_LEN}")
    if len(data) > MAX_PACKAGE_LEN:
        raise BadPackage(f"package is {len(data)} bytes, above the v2 cap {MAX_PACKAGE_LEN}")
    tbs = data[:signed_len]
    sig = data[signed_len:]

    # ---- stage 2b: strict DER structural decode (tail fully consumed, §2.2) ----
    parse_strict_ecdsa_der(sig)

    # ---- stage 2c: 192B manifest unique-encoding decode (§3) ----
    manifest = parse_manifest_v2(data[HEADER_LEN:HEADER_LEN + MANIFEST_LEN])

    # ---- stage 3: Host-local trusted issuer mapping (§2.3 step 3, §3.1) ----
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

    # ---- stage 4: ECDSA P-256 / SHA-256 over the exact raw TBS ----
    trusted_key = parse_spki_p256(trusted_spki)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        trusted_key.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureInvalid("ECDSA P-256/SHA-256 verification failed over the exact TBS")

    # ---- stage 5a: signed-content native cross-checks (§3.3, v1 §2.3 rules) ----
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
            f"abi_version {native.abi_version:#010x} (§3.3 cross-check, §8 M8)"
        )
    if native_payload_crc32(image, native.image_size) != native.crc32:
        raise BadPackage("native payload CRC-32 mismatch")
    if not constant_time_eq(hashlib.sha256(image).digest(), manifest.native_file_sha256):
        raise BadPackage("manifest native_file_sha256 does not match the native image bytes")
    if manifest.required_exec_region_bytes < manifest.native_image_size:
        raise BadPackage(
            "required_exec_region_bytes is smaller than native_image_size (payload residency)"
        )

    # ---- stage 5b: Host policy (§2.3 step 5, §4, §8, §9) ----
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
            "(bit6..31 must be zero, §4.1)"
        )
    unsupported = caps & ~policy.host_caps
    if unsupported:
        # §4.2 reverse direction: a KNOWN capability the current Host does not
        # actually provide fails closed at install/start.  "All bits known" is
        # not "Host supports them".
        raise AbiIncompatible(
            f"Host does not provide capability bits {unsupported:#x} "
            f"(package requests {caps:#x}, Host provides {policy.host_caps:#x}, §4.2)"
        )
    if manifest.run_profile != RUN_PROFILE_SINGLE_TRUSTED_SESSION:
        raise BadPackage(
            f"unknown run_profile {manifest.run_profile} "
            f"(v2 allows only {RUN_PROFILE_SINGLE_TRUSTED_SESSION}, §3.2)"
        )
    if not caps & CAP_SESSION_LIFECYCLE:
        raise BadPackage("run_profile 1 requires the session_lifecycle capability (bit5, §4.1)")
    _check_quota_consistency(caps, manifest.event_max, manifest.state_quota, manifest.report_max)
    if policy.business == "line-crossing-64":
        if caps & CAP_AI_EVENTS and manifest.event_max < policy.event_min_for_ai_events:
            raise ResourceLimit(
                f"event_max {manifest.event_max} below the 64-detection ai_events minimum "
                f"{policy.event_min_for_ai_events} (§4.1, §8 M7)"
            )
        if caps & CAP_REPORT_SUBMIT and manifest.report_max < policy.report_min_for_report_submit:
            raise ResourceLimit(
                f"report_max {manifest.report_max} below the line_counting report minimum "
                f"{policy.report_min_for_report_submit} (§4.1, §8 M7)"
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
        "format": "neapp-v2",
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
        "run_profile": manifest.run_profile,
        "event_max": manifest.event_max,
        "state_quota": manifest.state_quota,
        "report_max": manifest.report_max,
        "boundary": (
            "offline verification only: not device install, execution, STM32/PKA "
            "verification, or power-fail recovery evidence"
        ),
    }
    return report, None
