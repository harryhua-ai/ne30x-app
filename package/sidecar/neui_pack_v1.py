#!/usr/bin/env python3
"""neui_pack_v1 — build a signed NEUI UI-Sidecar v1 bundle from an asset tree.

Wire format, 128B manifest block, ordered records, TBS and signature follow
the frozen ne301 issue #79 §12 Sidecar v1 protocol via
package/sidecar/neui_sidecar_format.py.  The packer refuses inputs that
would violate the frozen caps or path rules rather than emitting a bundle
the offline verifier must later reject (fail-closed at pack time).

Pinning enforced here:
  * asset root: regular files only (symlinks, non-regular files and any
    escape from the root are rejected), relative POSIX paths, records in
    strict raw-ASCII ascending path order, exactly one root index.html
    (nested same-name assets such as docs/index.html are ordinary legal
    paths)
  * caps are the §12.2 maximum bundle-INPUT limits (file_count 1..64,
    path_len <= 160, file_len 1..1048576, payload 1..2097152,
    manifest_len <= 16384); they make no device storage promise
  * native binding: --native-package must offline-verify as a .neapp v3
    package under --native-trust (intrinsic tier); native_tbs_sha256 is
    derived from that VERIFIED native TBS, never from the DER-dependent
    whole-file package digest
  * publisher-key identity (§12.1): the SPKI SHA-256 fingerprint of the
    --key signing key must equal the VERIFIED native manifest
    publisher_key_sha256 — the same trusted SPKI publisher must sign the
    Sidecar and its native package; any other key is refused before
    anything is emitted
  * signature domain: NEUI magic + manifest + payload only; nothing is
    appended to any native .neapp container

Key discipline: the signing key handed to --key is a NON-PRODUCTION
development/test identity; it is never committed and never a device
production trust root.  Only the SPKI SHA-256 fingerprint is written into
the manifest and provenance sidecar.

The output bundle is OFFLINE evidence: packing (plus self-verification
under the --native-trust store) does not mean NE301 admitted or installed
anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import neapp_format as fmt
import neui_sidecar_format as sc

PACKER_VERSION = "1.0.0"


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


def collect_assets(root: Path) -> list[tuple[str, bytes]]:
    if not root.is_dir():
        raise NotADirectoryError(f"asset root {root} is not a directory")
    entries: list[tuple[str, bytes]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in sorted(dirnames):
            if os.path.islink(os.path.join(dirpath, name)):
                raise ValueError(
                    f"symbolic-link directory is not packable: "
                    f"{os.path.join(dirpath, name)}")
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                raise ValueError(f"symbolic-link asset is not packable: {full}")
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"non-regular asset is not packable: {full}")
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            entries.append((rel, Path(full).read_bytes()))
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--asset-root", required=True, type=Path,
                        help="asset tree root directory (regular files only)")
    parser.add_argument("--out", required=True, type=Path, help="output .neui bundle path")
    parser.add_argument("--key", required=True, type=Path,
                        help="signing private key (PEM/DER); NON-PRODUCTION dev/test identity only")
    parser.add_argument("--publisher-id", required=True,
                        help="1-16 chars [a-z0-9-], must start with a letter; must equal the "
                             "bound native package publisher_id")
    parser.add_argument("--app-id", required=True,
                        help="1-32 chars [a-z0-9-]; must equal the bound native package app_id")
    parser.add_argument("--version", required=True, type=parse_version,
                        metavar="MAJOR.MINOR.PATCH",
                        help="sidecar semantic UI version (major >= 1)")
    parser.add_argument("--native-package", required=True, type=Path,
                        help=".neapp v3 package the sidecar binds to")
    parser.add_argument("--native-trust", required=True, type=Path,
                        help="trust store JSON used to offline-verify the native package first")
    parser.add_argument("--source-commit", default=None,
                        help="source commit recorded in the provenance sidecar (default: auto-detect)")
    parser.add_argument("--sidecar", default=None, metavar="PATH|none",
                        help="provenance JSON path (default: <out>.provenance.json)")
    args = parser.parse_args()

    if args.version[0] < 1:
        print("ERROR: sidecar_version_major must be >= 1", file=sys.stderr)
        return 2

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = load_private_key(args.key)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        print("ERROR: signing key must be an EC P-256 private key", file=sys.stderr)
        return 2
    spki = fmt.spki_der_from_public_key(key.public_key())
    spki_sha = hashlib.sha256(spki).digest()

    native_bytes = args.native_package.read_bytes()
    native_trust = fmt.load_trust_store(args.native_trust)
    try:
        native_tbs_hex, native_manifest, _ = sc.native_v3_tbs_info(native_bytes, native_trust)
    except fmt.PackageError as exc:
        print(f"ERROR: native package rejected: {exc.code}: {exc.detail}", file=sys.stderr)
        return 2
    if args.publisher_id != native_manifest.publisher_id:
        print(f"ERROR: publisher_id {args.publisher_id!r} != native package publisher_id "
              f"{native_manifest.publisher_id!r}", file=sys.stderr)
        return 2
    if args.app_id != native_manifest.app_id:
        print(f"ERROR: app_id {args.app_id!r} != native package app_id "
              f"{native_manifest.app_id!r}", file=sys.stderr)
        return 2
    if not fmt.constant_time_eq(spki_sha, native_manifest.publisher_key_sha256):
        print(f"ERROR: sidecar signing key fingerprint {spki_sha.hex()} does not match the "
              f"native package publisher_key_sha256 "
              f"{native_manifest.publisher_key_sha256.hex()}; the same trusted SPKI publisher "
              "must sign both the Sidecar and its native package", file=sys.stderr)
        return 2

    try:
        assets = collect_assets(args.asset_root)
    except (OSError, ValueError) as exc:
        print(f"ERROR: asset root rejected: {exc}", file=sys.stderr)
        return 2
    if not assets:
        print("ERROR: asset root contains no files (index.html required)", file=sys.stderr)
        return 2

    try:
        for rel, blob in assets:
            sc.validate_asset_path(rel.encode("ascii"))
        paths = [rel for rel, _ in assets]
        if len(paths) > sc.MAX_FILE_COUNT:
            print(f"ERROR: {len(paths)} assets exceed the file_count cap {sc.MAX_FILE_COUNT}",
                  file=sys.stderr)
            return 2
        folded = {}
        for rel in paths:
            key_fold = rel.lower()
            if key_fold in folded:
                print(f"ERROR: asset paths {folded[key_fold]!r} and {rel!r} collide under "
                      "ASCII case folding", file=sys.stderr)
                return 2
            folded[key_fold] = rel
        assets = sorted(assets, key=lambda item: item[0].encode("ascii"))
        index_hits = [rel for rel in paths if rel == sc.INDEX_PATH]
        if len(index_hits) != 1:
            print(f"ERROR: exactly one root {sc.INDEX_PATH!r} is required, found "
                  f"{len(index_hits)}", file=sys.stderr)
            return 2
        total = 0
        for rel, blob in assets:
            if not sc.MIN_FILE_LEN <= len(blob) <= sc.MAX_FILE_LEN:
                print(f"ERROR: asset {rel!r} is {len(blob)} bytes, outside "
                      f"{sc.MIN_FILE_LEN}..{sc.MAX_FILE_LEN}", file=sys.stderr)
                return 2
            total += len(blob)
            if total > sc.MAX_ASSET_PAYLOAD_LEN:
                print(f"ERROR: assets sum to more than the {sc.MAX_ASSET_PAYLOAD_LEN}-byte "
                      "payload cap", file=sys.stderr)
                return 2
        manifest = sc.build_manifest(sc.SidecarManifest(
            publisher_id=args.publisher_id,
            app_id=args.app_id,
            publisher_key_sha256=spki_sha,
            native_tbs_sha256=bytes.fromhex(native_tbs_hex),
            version_major=args.version[0],
            version_minor=args.version[1],
            version_patch=args.version[2],
            file_count=len(assets),
            host_ui_abi=sc.HOST_UI_ABI_V1,
            records=tuple(sc.AssetRecord(path=rel, file_len=len(blob),
                                         sha256=hashlib.sha256(blob).digest())
                          for rel, blob in assets),
        ))
        payload = b"".join(blob for _, blob in assets)
        tbs = sc.build_container_prefix(manifest, payload)
    except (fmt.PackageError, ValueError, UnicodeEncodeError) as exc:
        print(f"ERROR: bundle input rejected at pack time: {exc}", file=sys.stderr)
        return 2

    try:
        algorithm = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    except TypeError:
        algorithm = ec.ECDSA(hashes.SHA256())
    signature = key.sign(tbs, algorithm)
    bundle = tbs + signature

    report, err = sc.verify_bundle(bundle, native_trust)
    if err is not None:
        print(f"ERROR: packer self-verification rejected the bundle: {err.code}: {err.detail}",
              file=sys.stderr)
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(bundle)

    sidecar_path = args.sidecar
    if sidecar_path is None:
        sidecar_path = str(args.out) + ".provenance.json"
    if sidecar_path != "none":
        provenance = {
            "format": "neui-sidecar-v1",
            "spec_authority": "ne301 issue #79 §12 (frozen Sidecar v1 wire, 2026-10-15)",
            "non_production_trust_root": (
                "signing key is a NON-PRODUCTION dev/test identity; not a production trust "
                "anchor and never a device production root"
            ),
            "generator": f"neui_pack_v1.py {PACKER_VERSION}",
            "source_commit": args.source_commit if args.source_commit else detect_source_commit(),
            "bundle_path": str(args.out),
            "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
            "bundle_len": len(bundle),
            "ui_tbs_sha256": hashlib.sha256(tbs).hexdigest(),
            "tbs_len": len(tbs),
            "signature_len": len(signature),
            "signature": "ECDSA over secp256r1 (P-256), SHA-256, strict DER",
            "signer_spki_sha256": spki_sha.hex(),
            "manifest": {
                "publisher_id": report["publisher_id"],
                "app_id": report["app_id"],
                "sidecar_version": report["sidecar_version"],
                "host_ui_abi": report["host_ui_abi"],
                "file_count": report["file_count"],
            },
            "native_binding": {
                "native_package_path": str(args.native_package),
                "native_package_sha256": hashlib.sha256(native_bytes).hexdigest(),
                "native_package_sha256_note": (
                    "whole-file digest recorded for traceability only; the wire binding value "
                    "is native_tbs_sha256, never this DER-dependent digest"
                ),
                "native_tbs_sha256": native_tbs_hex,
                "native_offline_verified": True,
                "native_publisher_key_match": True,
            },
            "files": report["files"],
        }
        Path(sidecar_path).write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")

    print(
        f"packed {args.out}: tbs {len(tbs)} B + der {len(signature)} B = {len(bundle)} B, "
        f"files {report['file_count']}, "
        f"ui_tbs_sha256 {hashlib.sha256(tbs).hexdigest()}"
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
