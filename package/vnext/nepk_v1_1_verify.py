from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))

import neapp_format as v1
import neapp_v4_format as v4
import neui_sidecar_format as ui

MAGIC = b"NEPK"
MAJOR = 1
MINOR = 1
HEADER = struct.Struct("<4sHHII")
DOMAIN = b"NEPAIR1\x00"
PAIR_SUFFIX_LEN = 16
MAX_NATIVE_LEN = 2_097_448
MAX_UI_LEN = 2_113_624
MIN_SIGNATURE_LEN = 8
MAX_SIGNATURE_LEN = 72
MAX_PACKAGE_LEN = 4_211_176


class NePKError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TrustedHistory:
    publisher_id: str
    app_id: str
    publisher_key_sha256: str
    release_seq: int
    native_tbs_sha256: str
    ui_tbs_sha256: str
    native_version: tuple[int, int, int]
    ui_version: tuple[int, int, int]


def history_from_report(report: dict) -> TrustedHistory:
    history = report["history"]
    return TrustedHistory(
        publisher_id=history["publisher_id"],
        app_id=history["app_id"],
        publisher_key_sha256=history["publisher_key_sha256"],
        release_seq=history["release_seq"],
        native_tbs_sha256=history["native_tbs_sha256"],
        ui_tbs_sha256=history["ui_tbs_sha256"],
        native_version=tuple(history["native_version"]),
        ui_version=tuple(history["ui_version"]),
    )


def _validate_history(history: TrustedHistory) -> None:
    if not isinstance(history, TrustedHistory):
        raise NePKError("BAD_HISTORY", "trusted history must use the explicit NEPK history schema")
    try:
        v4.validate_identifier("history publisher_id", history.publisher_id.encode("ascii"), 16)
        v4.validate_identifier("history app_id", history.app_id.encode("ascii"), 32)
    except (AttributeError, UnicodeEncodeError, v4.PackageError) as error:
        raise NePKError("BAD_HISTORY", "trusted history publisher/app identity is malformed") from error
    for name, value in (("publisher_key_sha256", history.publisher_key_sha256),
                        ("native_tbs_sha256", history.native_tbs_sha256),
                        ("ui_tbs_sha256", history.ui_tbs_sha256)):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise NePKError("BAD_HISTORY", f"trusted history {name} must be canonical lowercase SHA-256")
    if isinstance(history.release_seq, bool) or not isinstance(history.release_seq, int):
        raise NePKError("BAD_HISTORY", "trusted history release_seq must be a u64 integer")
    if not 1 <= history.release_seq <= 0xFFFFFFFFFFFFFFFF:
        raise NePKError("BAD_HISTORY", "trusted history release_seq must be nonzero u64")
    for name, version in (("native_version", history.native_version), ("ui_version", history.ui_version)):
        if not isinstance(version, (tuple, list)) or len(version) != 3:
            raise NePKError("BAD_HISTORY", f"trusted history {name} must have three u16 segments")
        if any(isinstance(segment, bool) or not isinstance(segment, int) or not 0 <= segment <= 0xFFFF
               for segment in version):
            raise NePKError("BAD_HISTORY", f"trusted history {name} segments must fit u16")


def evaluate_history(previous: TrustedHistory | None, current: TrustedHistory) -> str:
    _validate_history(current)
    if previous is None:
        return "FRESH_INSTALL"
    _validate_history(previous)
    if (previous.publisher_id, previous.app_id, previous.publisher_key_sha256) != (
        current.publisher_id, current.app_id, current.publisher_key_sha256
    ):
        raise NePKError("IDENTITY_CONFLICT", "trusted history belongs to a different publisher, app, or SPKI")
    if previous.release_seq <= 0 or current.release_seq <= 0:
        raise NePKError("BAD_HISTORY", "trusted release sequence must be nonzero")
    if current.release_seq < previous.release_seq:
        raise NePKError("DOWNGRADE", "release_seq is below the trusted high-water mark")
    same_native = current.native_tbs_sha256 == previous.native_tbs_sha256
    same_ui = current.ui_tbs_sha256 == previous.ui_tbs_sha256
    if current.release_seq == previous.release_seq:
        if same_native and same_ui:
            return "IDEMPOTENT"
        raise NePKError("CONTENT_CONFLICT", "release_seq is reused for different native or UI content")
    previous_native_version = tuple(previous.native_version)
    previous_ui_version = tuple(previous.ui_version)
    if current.native_version < previous_native_version:
        raise NePKError("NATIVE_VERSION_DOWNGRADE", "native semantic version is below trusted history")
    if current.ui_version < previous_ui_version:
        raise NePKError("UI_VERSION_DOWNGRADE", "UI semantic version is below trusted history")
    if current.native_version == previous_native_version and not same_native:
        raise NePKError("NATIVE_CONTENT_CONFLICT", "native content changed without increasing its semantic version")
    if same_native and current.ui_version == previous_ui_version and not same_ui:
        raise NePKError("UI_CONTENT_CONFLICT", "UI content changed without increasing its semantic version")
    return "UPGRADE"


def _trust_stores(trusted_spki_by_publisher: dict[str, bytes]):
    publishers = {}
    for publisher_id, spki in trusted_spki_by_publisher.items():
        if not isinstance(spki, bytes) or not spki:
            raise NePKError("BAD_TRUST_STORE", f"trusted SPKI for {publisher_id!r} is empty or not bytes")
        digest = hashlib.sha256(spki).hexdigest()
        publishers[publisher_id] = (digest, spki)
    return v4.TrustStoreV4(publishers), v1.TrustStore(publishers)


def _reject_inner(error):
    raise NePKError(error.code, error.detail)


def _verify_ui(data: bytes, trust: v1.TrustStore):
    report, error = ui.verify_bundle(data, trust)
    if error is not None:
        _reject_inner(error)
    manifest_len = struct.unpack_from("<I", data, 8)[0]
    manifest = ui.parse_manifest(data[16:16 + manifest_len])
    return report, manifest, data[:16 + manifest_len + struct.unpack_from("<I", data, 12)[0]]


def verify_nepk(
    data: bytes,
    trusted_spki_by_publisher: dict[str, bytes],
    expected_publisher_id: str,
    expected_app_id: str,
    native_policy: v4.DevicePolicyV4 | None = None,
    trusted_history: TrustedHistory | None = None,
) -> dict:
    if not isinstance(data, bytes):
        raise NePKError("BAD_PACKAGE", "package input must be bytes")
    if len(data) < HEADER.size:
        raise NePKError("BAD_PACKAGE", f"file is shorter than the {HEADER.size}-byte NEPK header")
    magic, major, minor, native_len, ui_len = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise NePKError("BAD_PACKAGE", "container magic is not NEPK")
    if (major, minor) != (MAJOR, MINOR):
        raise NePKError("BAD_PACKAGE", f"unsupported NEPK version {major}.{minor}; only 1.1 is accepted")
    if not 1 <= native_len <= MAX_NATIVE_LEN:
        raise NePKError("BAD_PACKAGE", f"native_signed_len {native_len} outside 1..{MAX_NATIVE_LEN}")
    if not 1 <= ui_len <= MAX_UI_LEN:
        raise NePKError("BAD_PACKAGE", f"ui_signed_len {ui_len} outside 1..{MAX_UI_LEN}")
    signed_members_end = HEADER.size + native_len + ui_len
    pair_tbs_len = signed_members_end + PAIR_SUFFIX_LEN
    minimum_total = pair_tbs_len + MIN_SIGNATURE_LEN
    maximum_total = pair_tbs_len + MAX_SIGNATURE_LEN
    if maximum_total > MAX_PACKAGE_LEN:
        raise NePKError("BAD_PACKAGE", "declared member lengths exceed the NEPK v1.1 package cap")
    if len(data) < minimum_total:
        raise NePKError("BAD_PACKAGE", f"file is truncated below the minimum signed pair size {minimum_total}")
    if len(data) > maximum_total:
        raise NePKError("BAD_PACKAGE", f"file length {len(data)} exceeds declared signed pair maximum {maximum_total}")
    if len(data) > MAX_PACKAGE_LEN:
        raise NePKError("BAD_PACKAGE", f"package exceeds the {MAX_PACKAGE_LEN}-byte cap")
    if data[signed_members_end:signed_members_end + len(DOMAIN)] != DOMAIN:
        raise NePKError("BAD_PACKAGE", "pair authorization domain separator is not NEPAIR1 NUL")
    release_seq = struct.unpack_from("<Q", data, signed_members_end + len(DOMAIN))[0]
    if release_seq == 0:
        raise NePKError("BAD_PACKAGE", "release_seq must be nonzero")
    pair_tbs = data[:pair_tbs_len]
    pair_signature = data[pair_tbs_len:]
    try:
        v4.parse_strict_ecdsa_der_v4(pair_signature)
    except v4.PackageError as error:
        _reject_inner(error)

    native_bytes = data[HEADER.size:HEADER.size + native_len]
    ui_bytes = data[HEADER.size + native_len:signed_members_end]
    native_trust, ui_trust = _trust_stores(trusted_spki_by_publisher)
    native_report, error = v4.verify_package_v4(
        native_bytes,
        native_trust,
        policy=native_policy or v4.default_policy(),
        host_admission=True,
    )
    if error is not None:
        _reject_inner(error)
    native_manifest_len = struct.unpack_from("<I", native_bytes, 8)[0]
    native_manifest = v4.parse_manifest_v4(native_bytes[16:16 + native_manifest_len])
    if native_manifest.publisher_id != expected_publisher_id:
        raise NePKError("PUBLISHER_MISMATCH", "native publisher_id does not match the required publisher")
    if native_manifest.app_id != expected_app_id:
        raise NePKError("APP_MISMATCH", "native app_id does not match the required app")

    ui_report, ui_manifest, ui_tbs = _verify_ui(ui_bytes, ui_trust)
    native_tbs_sha256 = native_report["content_identity_sha256"]
    if ui_manifest.publisher_id != native_manifest.publisher_id:
        raise NePKError("PUBLISHER_MISMATCH", "UI publisher_id does not match the verified native member")
    if ui_manifest.app_id != native_manifest.app_id:
        raise NePKError("APP_MISMATCH", "UI app_id does not match the verified native member")
    if ui_manifest.publisher_key_sha256 != native_manifest.publisher_key_sha256:
        raise NePKError("PUBLISHER_UNTRUSTED", "UI SPKI fingerprint does not match the native publisher")
    if ui_manifest.native_tbs_sha256.hex() != native_tbs_sha256:
        raise NePKError("NATIVE_BINDING_MISMATCH", "UI native_tbs_sha256 does not match the exact verified native TBS")

    try:
        trusted_spki = trusted_spki_by_publisher[native_manifest.publisher_id]
        pair_key = v4.parse_spki_p256_v4(trusted_spki)
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        pair_key.verify(pair_signature, pair_tbs, ec.ECDSA(hashes.SHA256()))
    except KeyError:
        raise NePKError("PUBLISHER_UNTRUSTED", "native publisher has no local trust mapping")
    except InvalidSignature:
        raise NePKError("SIGNATURE_INVALID", "pair ECDSA P-256/SHA-256 verification failed over the exact TBS")
    except v4.PackageError as error:
        _reject_inner(error)

    native_tbs_len = native_report["tbs_len"]
    native_signature = native_bytes[native_tbs_len:]
    ui_signature = ui_bytes[len(ui_tbs):]
    identity = TrustedHistory(
        publisher_id=native_manifest.publisher_id,
        app_id=native_manifest.app_id,
        publisher_key_sha256=native_manifest.publisher_key_sha256.hex(),
        release_seq=release_seq,
        native_tbs_sha256=native_tbs_sha256,
        ui_tbs_sha256=ui_report["ui_tbs_sha256"],
        native_version=(native_manifest.version_major, native_manifest.version_minor, native_manifest.version_patch),
        ui_version=ui_manifest.version_tuple,
    )
    transition = evaluate_history(trusted_history, identity)
    return {
        "result": "PASS",
        "format": "nepk-v1.1",
        "package_sha256": hashlib.sha256(data).hexdigest(),
        "package_len": len(data),
        "native_len": native_len,
        "native_member_sha256": hashlib.sha256(native_bytes).hexdigest(),
        "native_tbs_sha256": native_tbs_sha256,
        "native_signature_sha256": hashlib.sha256(native_signature).hexdigest(),
        "native_signature_len": len(native_signature),
        "native_version": list(identity.native_version),
        "ui_len": ui_len,
        "ui_member_sha256": hashlib.sha256(ui_bytes).hexdigest(),
        "ui_tbs_sha256": identity.ui_tbs_sha256,
        "ui_signature_sha256": hashlib.sha256(ui_signature).hexdigest(),
        "ui_signature_len": len(ui_signature),
        "ui_version": list(identity.ui_version),
        "pair_tbs_sha256": hashlib.sha256(pair_tbs).hexdigest(),
        "pair_signature_sha256": hashlib.sha256(pair_signature).hexdigest(),
        "pair_signature_len": len(pair_signature),
        "release_seq": release_seq,
        "publisher_id": identity.publisher_id,
        "app_id": identity.app_id,
        "publisher_key_sha256": identity.publisher_key_sha256,
        "transition": transition,
        "history": asdict(identity),
        "boundary": "offline signatures and host-policy simulation only; not Host installation, persistent floor, or device acceptance",
    }


def _load_trusted_spki(path: Path) -> dict[str, bytes]:
    store = v4.load_trust_store_v4(path)
    return {publisher_id: spki for publisher_id, (_, spki) in store.publishers.items()}


def _history_from_json(path: Path) -> TrustedHistory:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return TrustedHistory(
        publisher_id=raw["publisher_id"],
        app_id=raw["app_id"],
        publisher_key_sha256=raw["publisher_key_sha256"],
        release_seq=raw["release_seq"],
        native_tbs_sha256=raw["native_tbs_sha256"],
        ui_tbs_sha256=raw["ui_tbs_sha256"],
        native_version=tuple(raw["native_version"]) if isinstance(raw["native_version"], list) else raw["native_version"],
        ui_version=tuple(raw["ui_version"]) if isinstance(raw["ui_version"], list) else raw["ui_version"],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path)
    parser.add_argument("--expect-publisher-id", required=True)
    parser.add_argument("--expect-app-id", required=True)
    parser.add_argument("--history", type=Path)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    try:
        report = verify_nepk(
            args.bundle.read_bytes(),
            _load_trusted_spki(args.trust),
            args.expect_publisher_id,
            args.expect_app_id,
            trusted_history=_history_from_json(args.history) if args.history else None,
        )
    except (OSError, ValueError, KeyError, NePKError) as error:
        result = {"result": getattr(error, "code", "INPUT_ERROR"), "detail": str(error)}
        print(json.dumps(result, sort_keys=True, indent=None if args.compact else 2))
        return 1
    print(json.dumps(report, sort_keys=True, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
