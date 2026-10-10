#!/usr/bin/env python3
"""neapp_pack — build a signed .neapp v1 package from a native app image.

Wire format, manifest encoding, TBS and signature algorithm follow the
integrated P2 spec docs/app-package-protocol-v1.md (§2.1–§2.4) via the
shared module package/neapp_format.py; the packer refuses inputs that would
violate the v1 constraints rather than emitting a package the offline
verifier must later reject.

Key discipline (Issue #6 AC3): the signing key handed to --key is a
NON-PRODUCTION development/test identity.  It is generated at test time and
must never be committed; the packer only ever writes the SPKI SHA-256
fingerprint into the manifest and provenance sidecar — never key bytes.

The output package is OFFLINE evidence.  Packing (or packing plus
self-verification) does not mean any device has installed or executed the
image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import neapp_format as fmt  # noqa: E402

PACKER_VERSION = "1.0.0"


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"version must be MAJOR.MINOR.PATCH of integers, got {value!r}")
    v = tuple(int(p) for p in parts)
    if any(p > 0xFFFF for p in v):
        raise ValueError("version segments must fit u16")
    return v  # type: ignore[return-value]


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
                        help="native image file (32B header + payload, tools/pack_app_image.py output)")
    parser.add_argument("--out", required=True, type=Path, help="output .neapp path")
    parser.add_argument("--key", required=True, type=Path,
                        help="signing private key (PEM/DER); NON-PRODUCTION dev/test identity only")
    parser.add_argument("--publisher-id", required=True,
                        help="1-16 chars [a-z0-9-], must start with a letter")
    parser.add_argument("--app-id", required=True,
                        help="1-32 chars [a-z0-9-], must start with a letter")
    parser.add_argument("--version", required=True, type=parse_version, metavar="MAJOR.MINOR.PATCH")
    parser.add_argument("--target-board-id", type=parse_int, default=fmt.TARGET_BOARD_ID_V1,
                        help=f"v1 only allows {fmt.TARGET_BOARD_ID_V1:#010x} (default)")
    parser.add_argument("--psram-mib", type=int, default=fmt.REQUIRED_PSRAM_MIB_V1,
                        help=f"v1 evidence supports only {fmt.REQUIRED_PSRAM_MIB_V1} MiB (default)")
    parser.add_argument("--host-abi", type=parse_int, default=fmt.HOST_ABI_V1,
                        help=f"v1 only allows {fmt.HOST_ABI_V1:#010x} (default)")
    parser.add_argument("--host-caps", type=parse_int, default=fmt.HOST_CAP_LOG | fmt.HOST_CAP_TICK_MS,
                        help="capability bitmask; v1 Host exposes only log|tick_ms (default 3)")
    parser.add_argument("--exec-region-bytes", type=parse_int, default=None,
                        help="required payload residency; defaults to the native image_size")
    parser.add_argument("--exec-base", type=parse_int, default=fmt.EXEC_BASE_V1,
                        help=f"v1 only allows {fmt.EXEC_BASE_V1:#010x} (default)")
    parser.add_argument("--source-commit", default=None,
                        help="source commit recorded in the provenance sidecar (default: auto-detect)")
    parser.add_argument("--sidecar", default=None, metavar="PATH|none",
                        help="provenance JSON path (default: <out>.provenance.json)")
    args = parser.parse_args()

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    image = args.image.read_bytes()
    if len(image) < fmt.NATIVE_HEADER_SIZE + 1:
        print("ERROR: image too small to contain the 32B header + payload", file=sys.stderr)
        return 2
    if len(image) > fmt.MAX_NATIVE_FILE_LEN:
        print(f"ERROR: image {len(image)} B exceeds the v1 cap {fmt.MAX_NATIVE_FILE_LEN}", file=sys.stderr)
        return 2

    # Strict v1 native-header validation BEFORE anything is signed.
    native = fmt.parse_native_header(image)
    checks = (
        (native.magic != fmt.NATIVE_MAGIC, "native header magic is not NEA1"),
        (native.header_size != fmt.NATIVE_HEADER_SIZE, "native header_size must be exactly 32"),
        (native.format_version != fmt.NATIVE_FORMAT_VERSION, "native format_version must be 1"),
        (native.reserved0 != 0, "native header reserved0 must be zero"),
        (native.abi_version != args.host_abi, "native header ABI != requested host ABI"),
        (native.target_addr != args.exec_base, "native header target_addr != requested exec base"),
        (native.image_size != len(image) - fmt.NATIVE_HEADER_SIZE,
         "native header image_size != actual payload bytes"),
        (native.entry_offset >= native.image_size, "entry_offset outside payload"),
        ((native.entry_offset & 1) != 0, "entry_offset must be even (Thumb)"),
        (fmt.native_payload_crc32(image, native.image_size) != native.crc32, "payload CRC-32 mismatch"),
    )
    for failed, message in checks:
        if failed:
            print(f"ERROR: {message}", file=sys.stderr)
            return 2

    if args.target_board_id != fmt.TARGET_BOARD_ID_V1:
        print(f"ERROR: v1 supports only target board {fmt.TARGET_BOARD_ID_V1:#010x}", file=sys.stderr)
        return 2
    if args.psram_mib != fmt.REQUIRED_PSRAM_MIB_V1:
        print(f"ERROR: v1 evidence supports only {fmt.REQUIRED_PSRAM_MIB_V1} MiB PSRAM", file=sys.stderr)
        return 2
    if args.host_abi != fmt.HOST_ABI_V1:
        print(f"ERROR: v1 pins Host ABI {fmt.HOST_ABI_V1:#010x}", file=sys.stderr)
        return 2
    if args.host_caps & ~fmt.HOST_CAPS_KNOWN_MASK:
        print("ERROR: requested capabilities outside the v1 Host set (log|tick_ms)", file=sys.stderr)
        return 2

    exec_region = (args.exec_region_bytes if args.exec_region_bytes is not None
                   else native.image_size)
    if exec_region < native.image_size:
        print("ERROR: required_exec_region_bytes cannot be smaller than the payload", file=sys.stderr)
        return 2
    if exec_region > fmt.EXEC_REGION_BYTES_V1:
        print(f"ERROR: required_exec_region_bytes exceeds the v1 execution region "
              f"{fmt.EXEC_REGION_BYTES_V1}", file=sys.stderr)
        return 2
    if len(image) > fmt.EXEC_REGION_BYTES_V1:
        print(f"ERROR: native file exceeds the load-transient budget {fmt.EXEC_REGION_BYTES_V1}",
              file=sys.stderr)
        return 2

    key = load_private_key(args.key)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        print("ERROR: signing key must be an EC P-256 private key", file=sys.stderr)
        return 2
    spki = fmt.spki_der_from_public_key(key.public_key())
    spki_sha = hashlib.sha256(spki).digest()

    manifest = fmt.build_manifest(fmt.Manifest(
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
    ))

    tbs = fmt.build_container_prefix(manifest, image)

    deterministic = True
    try:
        algorithm = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    except TypeError:  # older cryptography without RFC-6979 option
        algorithm = ec.ECDSA(hashes.SHA256())
        deterministic = False
    signature = key.sign(tbs, algorithm)

    package = tbs + signature

    # Fail-closed self-verification with an equivalent trust store before the
    # package is allowed to exist on disk.
    self_trust = fmt.TrustStore(publishers={
        fmt.validate_identifier("publisher_id", args.publisher_id.encode("ascii"), 16):
            (hashlib.sha256(spki).hexdigest(), spki),
    })
    report, err = fmt.verify_package(package, self_trust)
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
            "format": "neapp-v1",
            "non_production_trust_root": (
                "signing key is a NON-PRODUCTION dev/test identity; not a production trust anchor"
            ),
            "generator": f"neapp_pack.py {PACKER_VERSION}",
            "source_commit": args.source_commit if args.source_commit else detect_source_commit(),
            "package_path": str(args.out),
            "package_sha256": hashlib.sha256(package).hexdigest(),
            "package_len": len(package),
            "tbs_len": len(tbs),
            "tbs_sha256": hashlib.sha256(tbs).hexdigest(),
            "image_len": len(image),
            "image_sha256": hashlib.sha256(image).hexdigest(),
            "signature_len": len(signature),
            "signature": "ECDSA over secp256r1 (P-256), SHA-256, strict DER",
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
