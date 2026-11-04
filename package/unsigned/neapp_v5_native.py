from __future__ import annotations

"""Current NEAPP05 native ABI v4 geometry and admission-policy primitives.

Extracted without changing behavioral checks from the superseded signed-v4
package implementation. This file does not parse signed packages.
"""

import struct
import zlib
from dataclasses import dataclass

MAX_NATIVE_FILE_LEN = 2_097_152
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
# Product-version metadata gate (issue #6): bit 10 marks packages that carry
# the trusted product-version carrier asset (product-version.json). Bit 10 is
# outside the mask implemented by Hosts that predate product metadata
# (APP_ADMISSION_V4_KNOWN_CAPS_MASK / supported_caps_mask == 0x3ff), so their
# existing unknown-bit/unsupported-bit admission refusals fail closed on such
# packages BEFORE install. The bit only widens the package-side vocabulary;
# it adds no quota semantics and never relaxes any existing coupling.
CAP_PRODUCT_VERSION = 1 << 10
HOST_CAPS_KNOWN_MASK = 0x000003FF
HOST_CAPS_VOCABULARY_MASK = HOST_CAPS_KNOWN_MASK | CAP_PRODUCT_VERSION

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

class PackageError(Exception):
    code = "PACKAGE_ERROR"

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class BadPackage(PackageError):
    code = "BAD_PACKAGE"

class TargetIncompatible(PackageError):
    code = "TARGET_INCOMPATIBLE"


class AbiIncompatible(PackageError):
    code = "ABI_INCOMPATIBLE"


class ResourceLimit(PackageError):
    code = "RESOURCE_LIMIT"

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

def validate_policy_shape(caps: int, run_profile: int, event_max: int, state_quota: int,
                          report_max: int, control_max: int, snapshot_max: int,
                          live_publish_max: int, live_track_max: int) -> None:
    if caps & ~HOST_CAPS_VOCABULARY_MASK:
        raise BadPackage(f"required_host_caps has unknown bits: {caps & ~HOST_CAPS_VOCABULARY_MASK:#x} "
                         f"(vocabulary mask {HOST_CAPS_VOCABULARY_MASK:#x}; Hosts that do not "
                         "implement a declared bit still refuse the package at admission)")
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
    control_msg_bytes: int = 512
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
