#!/usr/bin/env python3
"""neapp_pack_v4 — build a signed .neapp v4 package from a v4 native image.

Wire format, 208B NMF4 manifest, TBS and signature follow the A-frozen
Host #104 byte contract (comments 6258534821 / 6258601629 / 6258637748)
via package/vnext/neapp_v4_format.py.  The packer refuses inputs that
would violate the frozen constraints instead of emitting a package the
offline verifier must reject; it never invents values for reserved or
unknown spec fields and has no knob that could.

Pinned at pack time (not negotiable):
  * native image: NEA1 32B header, format_version 1, reserved0 0,
    abi_version exactly 0x00040000
  * manifest: NMF4, required_host_abi 0x00040000, caps within 0x000003FF,
    run_profile 3, bit8 requiring bit4+bit5+bit6, bit9 requiring bit5 and
    live_publish_max >= max(312, 48 + live_track_max*140) with
    1 <= live_track_max <= 64, both live quotas 0 without bit9,
    [58..59] and [192..207] reserved all zero
  * container: magic 4e45415050040000, manifest_len 208, exactly one
    trailing strict-DER P-256 signature over TBS = file[0:224+len(image)]

Key discipline (App #36 AC1/AC4): --key is a NON-PRODUCTION test identity
with documented provenance (e.g. the public spec scalar d=1); it is never
a production trust root, never committed, and only its SPKI SHA-256
fingerprint enters the manifest and provenance sidecar.

Self-verification is two-tier (the default tier makes NO Host-admission
claim; --host-policy additionally runs the target-Host admission pipeline
and refuses to emit on any rejection).

Output is OFFLINE evidence: packing plus self-verification does not mean
any Host admitted, installed, executed, floored, or live-enabled anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import neapp_v4_format as fmt4

PACKER_VERSION = "4.0.0"

SPEC_AUTHORITY = (
    "harryhua-ai/ne301#104 A architecture freeze comments "
    "6258534821 (F1-F4), 6258601629 (F5-F7), 6258637748 (F8-F10)"
)


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"version must be MAJOR.MINOR.PATCH of integers, got {value!r}")
    major, minor, patch = (int(p) for p in parts)
    if any(v > 0xFFFF for v in (major, minor, patch)):
        raise ValueError("version segments must fit u16")
    return major, minor, patch


def load_private_key(path: Path):
    from cryptography.hazmat.primitives import serialization

    data = path.read_bytes()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except ValueError:
        return serialization.load_der_private_key(data, password=None)


def detect_source_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
            cwd=Path(__file__).resolve().parent,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--image", required=True, type=Path,
                        help="native image file (32B NEA1 header + payload, abi_version 0x00040000)")
    parser.add_argument("--out", required=True, type=Path, help="output .neapp.v4 path")
    parser.add_argument("--key", required=True, type=Path,
                        help="signing private key (PEM/DER); NON-PRODUCTION test identity only")
    parser.add_argument("--publisher-id", required=True,
                        help="1-16 chars [a-z0-9-], must start with a letter")
    parser.add_argument("--app-id", required=True,
                        help="1-32 chars [a-z0-9-], must start with a letter")
    parser.add_argument("--version", required=True, type=parse_version, metavar="MAJOR.MINOR.PATCH")
    parser.add_argument("--target-board-id", type=parse_int, default=fmt4.TARGET_BOARD_ID_V4,
                        help=f"v4 evidence baseline board (default {fmt4.TARGET_BOARD_ID_V4:#010x})")
    parser.add_argument("--psram-mib", type=int, default=fmt4.REQUIRED_PSRAM_MIB_V4,
                        help=f"PSRAM evidence baseline (default {fmt4.REQUIRED_PSRAM_MIB_V4} MiB)")
    parser.add_argument("--host-abi", type=parse_int, default=fmt4.HOST_ABI_V4,
                        help=f"v4 pins Host ABI {fmt4.HOST_ABI_V4:#010x} (default)")
    parser.add_argument("--host-caps", type=parse_int,
                        default=fmt4.CAP_LOG | fmt4.CAP_TICK_MS | fmt4.CAP_SESSION_LIFECYCLE
                        | fmt4.CAP_CONTROL_RECEIVE,
                        help="v4 capability bitmask within 0x000003FF; run_profile 3 requires bit5; "
                             "bit8 requires bit4+bit5+bit6; bit9 requires bit5 plus live quotas "
                             "(default 0x63 = log|tick_ms|session_lifecycle|control_receive)")
    parser.add_argument("--event-max", type=parse_int, default=0,
                        help="AI event single-event max bytes declared (requires capability bit2)")
    parser.add_argument("--state-quota", type=parse_int, default=0,
                        help="app state blob quota declared (requires capability bit4)")
    parser.add_argument("--report-max", type=parse_int, default=0,
                        help="single business report max bytes declared (requires capability bit3)")
    parser.add_argument("--control-max", type=parse_int, default=256,
                        help="control message max bytes incl. 32B header "
                             "(requires capability bit6; minimum 32; default 256)")
    parser.add_argument("--snapshot-max", type=parse_int, default=0,
                        help="business snapshot message max bytes (requires capability bit7)")
    parser.add_argument("--live-publish-max", type=parse_int, default=0,
                        help="single live_publish call total bytes incl. 48B header "
                             "(requires capability bit9; >= max(312, 48+live_track_max*140))")
    parser.add_argument("--live-track-max", type=parse_int, default=0,
                        help="concurrent active tracks declared (requires capability bit9; 1..64)")
    parser.add_argument("--exec-region-bytes", type=parse_int, default=None,
                        help="required payload residency; defaults to the native image_size")
    parser.add_argument("--exec-base", type=parse_int, default=fmt4.EXEC_BASE_V4,
                        help=f"v4 loader base (default {fmt4.EXEC_BASE_V4:#010x})")
    parser.add_argument("--source-commit", default=None,
                        help="source commit recorded in the provenance sidecar (default: auto-detect)")
    parser.add_argument("--sidecar", default=None, metavar="PATH|none",
                        help="provenance JSON path (default: <out>.provenance.json)")
    parser.add_argument("--host-policy", type=Path, default=None, metavar="JSON",
                        help="optional target-Host policy for ADMISSION SIMULATION (board/PSRAM/"
                             "ABI/host_caps/capacity ceilings); given it, self-verification also "
                             "runs the full target-Host admission pipeline and refuses to emit "
                             "on any rejection; without it, self-verification covers format/"
                             "signature/intrinsic-manifest-policy only and makes NO "
                             "Host-admission claim")
    args = parser.parse_args()

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    image = args.image.read_bytes()
    if len(image) < fmt4.NATIVE_HEADER_SIZE + 1:
        print("ERROR: image too small to contain the 32B header + payload", file=sys.stderr)
        return 2
    if len(image) > fmt4.MAX_NATIVE_FILE_LEN:
        print(f"ERROR: image {len(image)} B exceeds the native file cap "
              f"{fmt4.MAX_NATIVE_FILE_LEN}", file=sys.stderr)
        return 2

    native = fmt4.parse_native_header_v4(image)
    checks = (
        (native.magic != fmt4.NATIVE_MAGIC, "native header magic is not NEA1"),
        (native.header_size != fmt4.NATIVE_HEADER_SIZE, "native header_size must be exactly 32"),
        (native.format_version != fmt4.NATIVE_FORMAT_VERSION, "native format_version must be 1"),
        (native.reserved0 != 0, "native header reserved0 must be zero"),
        (native.abi_version != args.host_abi,
         f"native header abi_version {native.abi_version:#010x} != requested host ABI "
         f"{args.host_abi:#010x} (v4 pins {fmt4.HOST_ABI_V4:#010x})"),
        (native.target_addr != args.exec_base, "native header target_addr != requested exec base"),
        (native.image_size != len(image) - fmt4.NATIVE_HEADER_SIZE,
         "native header image_size != actual payload bytes"),
        (native.entry_offset >= native.image_size, "entry_offset outside payload"),
        ((native.entry_offset & 1) != 0, "entry_offset must be even (Thumb)"),
        (fmt4.native_payload_crc32_v4(image, native.image_size) != native.crc32,
         "payload CRC-32 mismatch"),
    )
    for failed, message in checks:
        if failed:
            print(f"ERROR: {message}", file=sys.stderr)
            return 2

    if args.host_abi != fmt4.HOST_ABI_V4:
        print(f"ERROR: v4 pins Host ABI {fmt4.HOST_ABI_V4:#010x}", file=sys.stderr)
        return 2
    if args.target_board_id != fmt4.TARGET_BOARD_ID_V4:
        print(f"ERROR: v4 evidence baseline supports only board "
              f"{fmt4.TARGET_BOARD_ID_V4:#010x}", file=sys.stderr)
        return 2
    if args.psram_mib != fmt4.REQUIRED_PSRAM_MIB_V4:
        print(f"ERROR: v4 evidence baseline supports only {fmt4.REQUIRED_PSRAM_MIB_V4} MiB PSRAM",
              file=sys.stderr)
        return 2

    try:
        fmt4.validate_policy_shape(args.host_caps, fmt4.RUN_PROFILE_V4,
                                   args.event_max, args.state_quota, args.report_max,
                                   args.control_max, args.snapshot_max,
                                   args.live_publish_max, args.live_track_max)
    except fmt4.PackageError as exc:
        print(f"ERROR: capability/quota declaration rejected at pack time: {exc.detail}",
              file=sys.stderr)
        return 2

    exec_region = (args.exec_region_bytes if args.exec_region_bytes is not None
                   else native.image_size)
    if exec_region < native.image_size:
        print("ERROR: required_exec_region_bytes cannot be smaller than the payload", file=sys.stderr)
        return 2
    if exec_region > fmt4.EXEC_REGION_BYTES_V4:
        print(f"ERROR: required_exec_region_bytes exceeds the execution region "
              f"{fmt4.EXEC_REGION_BYTES_V4}", file=sys.stderr)
        return 2
    if len(image) > fmt4.EXEC_REGION_BYTES_V4:
        print(f"ERROR: native file exceeds the load-transient budget {fmt4.EXEC_REGION_BYTES_V4}",
              file=sys.stderr)
        return 2

    key = load_private_key(args.key)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        print("ERROR: signing key must be an EC P-256 private key", file=sys.stderr)
        return 2
    spki = fmt4.spki_der_from_public_key_v4(key.public_key())
    spki_sha = hashlib.sha256(spki).digest()

    try:
        manifest = fmt4.build_manifest_v4(fmt4.ManifestV4(
            publisher_id=args.publisher_id,
            app_id=args.app_id,
            version_major=args.version[0],
            version_minor=args.version[1],
            version_patch=args.version[2],
            target_board_id=args.target_board_id,
            required_psram_mib=args.psram_mib,
            required_host_abi=args.host_abi,
            required_host_caps=args.host_caps,
            required_exec_region_bytes=exec_region,
            native_file_len=len(image),
            native_image_size=native.image_size,
            native_entry_offset=native.entry_offset,
            native_target_addr=native.target_addr,
            native_file_sha256=hashlib.sha256(image).digest(),
            publisher_key_sha256=spki_sha,
            run_profile=fmt4.RUN_PROFILE_V4,
            event_max=args.event_max,
            state_quota=args.state_quota,
            report_max=args.report_max,
            control_max=args.control_max,
            snapshot_max=args.snapshot_max,
            live_publish_max=args.live_publish_max,
            live_track_max=args.live_track_max,
        ))
    except fmt4.PackageError as exc:
        print(f"ERROR: manifest rejected at pack time: {exc.code}: {exc.detail}", file=sys.stderr)
        return 2

    tbs = fmt4.build_container_prefix_v4(manifest, image)

    deterministic = True
    try:
        algorithm = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    except TypeError:
        algorithm = ec.ECDSA(hashes.SHA256())
        deterministic = False
    signature = key.sign(tbs, algorithm)

    package = tbs + signature

    self_trust = fmt4.TrustStoreV4(publishers={
        fmt4.validate_identifier("publisher_id", args.publisher_id.encode("ascii"), 16):
            (hashlib.sha256(spki).hexdigest(), spki),
    })
    host_policy = None
    if args.host_policy is not None:
        try:
            host_policy = fmt4.DevicePolicyV4.from_json(
                json.loads(args.host_policy.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError) as exc:
            print(f"ERROR: cannot load target-Host policy {args.host_policy}: {exc}",
                  file=sys.stderr)
            return 2
        report, err = fmt4.verify_package_v4(package, self_trust, host_policy)
        if err is not None:
            print(f"ERROR: target-Host admission simulation ({args.host_policy}) rejected "
                  f"the package: {err.code}: {err.detail}", file=sys.stderr)
            return 2
    else:
        report, err = fmt4.verify_package_v4(package, self_trust, host_admission=False)
        if err is not None:
            print(f"ERROR: packer self-verification rejected the package: {err.code}: {err.detail}",
                  file=sys.stderr)
            return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(package)

    sidecar_path = args.sidecar
    if sidecar_path is None:
        sidecar_path = str(args.out) + ".provenance.json"
    if sidecar_path != "none":
        provenance = {
            "format": "neapp-v4",
            "spec_authority": SPEC_AUTHORITY,
            "non_production_trust_root": (
                "signing key is a NON-PRODUCTION test identity with documented provenance; "
                "not a production trust anchor and never a device production root"
            ),
            "generator": f"neapp_pack_v4.py {PACKER_VERSION}",
            "source_commit": args.source_commit if args.source_commit else detect_source_commit(),
            "package_path": str(args.out),
            "package_sha256": hashlib.sha256(package).hexdigest(),
            "package_len": len(package),
            "tbs_len": len(tbs),
            "tbs_sha256": hashlib.sha256(tbs).hexdigest(),
            "image_len": len(image),
            "image_sha256": hashlib.sha256(image).hexdigest(),
            "signature_len": len(signature),
            "signature": "strict-DER ECDSA over secp256r1 (P-256), SHA-256 over TBS = file[0:224+native_file_len]",
            "signature_deterministic_rfc6979": deterministic,
            "signer_spki_sha256": spki_sha.hex(),
            "manifest": {
                "publisher_id": report["publisher_id"],
                "app_id": report["app_id"],
                "app_version": report["app_version"],
                "target_board_id": report["target_board_id"],
                "required_psram_mib": report["required_psram_mib"],
                "required_host_abi": report["required_host_abi"],
                "required_host_caps": report["required_host_caps"],
                "required_exec_region_bytes": report["required_exec_region_bytes"],
                "native_file_len": report["native_file_len"],
                "native_image_size": report["native_image_size"],
                "native_entry_offset": report["native_entry_offset"],
                "native_target_addr": report["native_target_addr"],
                "native_file_sha256": report["native_file_sha256"],
                "native_crc32": report["native_crc32"],
                "run_profile": report["run_profile"],
                "event_max": report["event_max"],
                "state_quota": report["state_quota"],
                "report_max": report["report_max"],
                "control_max": report["control_max"],
                "snapshot_max": report["snapshot_max"],
                "live_publish_max": report["live_publish_max"],
                "live_track_max": report["live_track_max"],
            },
        }
        Path(sidecar_path).write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")

    print(
        f"packed {args.out}: tbs {len(tbs)} B + der {len(signature)} B = {len(package)} B, "
        f"package_sha256 {hashlib.sha256(package).hexdigest()}, "
        f"content_identity(SHA-256(TBS)) {hashlib.sha256(tbs).hexdigest()}"
    )
    if sidecar_path != "none":
        print(f"provenance -> {sidecar_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
