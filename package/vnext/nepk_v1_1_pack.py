from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))
sys.path.insert(0, str(ROOT / "package" / "vnext"))

import neapp_v4_format as v4
import neapp_v4_image as image_builder
import neui_sidecar_format as ui
from nepk_v1_1_verify import DOMAIN, HEADER, verify_nepk

EXPECTED_TEST_PUBLISHER_ID = "ne301-exp-pub"
EXPECTED_TEST_APP_ID = "line-crossing"
EXPECTED_TEST_SPKI_SHA256 = "06e732b1b94daeeef433297f7a8e797bf72b2fd3b882a4ec6a5490352931ebda"
NATIVE_PACKER = ROOT / "package" / "vnext" / "neapp_pack_v4.py"


class PackError(ValueError):
    pass


def parse_version(value: str, allow_zero_major: bool = False) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise argparse.ArgumentTypeError("version must be MAJOR.MINOR.PATCH")
    result = tuple(int(part) for part in parts)
    if any(part > 0xFFFF for part in result) or (not allow_zero_major and result[0] == 0):
        raise argparse.ArgumentTypeError("version segments must fit u16 and the major must be nonzero")
    return result


def _load_test_key(path: Path, expected_spki_sha256: str):
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise PackError("TEST ONLY signing key must be a regular file")
        raw = path.read_bytes()
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except ValueError:
            key = serialization.load_der_private_key(raw, password=None)
    except (OSError, ValueError) as error:
        raise PackError("cannot load the TEST ONLY P-256 signing key") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise PackError("TEST ONLY signing key must be ECDSA P-256")
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(spki).hexdigest()
    if fingerprint != expected_spki_sha256:
        raise PackError("TEST ONLY signing key does not match the pinned Host test SPKI")
    return key, spki, fingerprint


def _collect_assets(root: Path) -> list[tuple[str, bytes]]:
    if not root.is_dir() or root.is_symlink():
        raise PackError("UI asset root must be a regular directory")
    assets = []
    for directory, subdirs, filenames in os.walk(root, followlinks=False):
        for name in sorted(subdirs):
            if (Path(directory) / name).is_symlink():
                raise PackError("UI asset tree contains a symbolic-link directory")
        subdirs[:] = [name for name in subdirs if not (Path(directory) / name).is_symlink()]
        for name in sorted(filenames):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise PackError("UI asset tree contains a non-regular file")
            try:
                relative = path.relative_to(root).as_posix()
                relative.encode("ascii")
                ui.validate_asset_path(relative.encode("ascii"))
            except (ValueError, UnicodeEncodeError, ui.fmt.PackageError) as error:
                raise PackError("UI asset tree contains an invalid path") from error
            assets.append((relative, path.read_bytes()))
    assets.sort(key=lambda item: item[0].encode("ascii"))
    if not assets or sum(name == ui.INDEX_PATH for name, _ in assets) != 1:
        raise PackError("UI asset tree must contain exactly one root index.html")
    if len(assets) > ui.MAX_FILE_COUNT:
        raise PackError("UI asset tree exceeds the NEUI v1 file-count limit")
    folded = set()
    total = 0
    for name, blob in assets:
        key = name.lower()
        if key in folded:
            raise PackError("UI asset paths collide under ASCII case folding")
        folded.add(key)
        if not ui.MIN_FILE_LEN <= len(blob) <= ui.MAX_FILE_LEN:
            raise PackError("UI asset file size is outside the NEUI v1 limit")
        total += len(blob)
        if total > ui.MAX_ASSET_PAYLOAD_LEN:
            raise PackError("UI asset payload exceeds the NEUI v1 size limit")
    return assets


def _signed_ui(assets: list[tuple[str, bytes]], key, spki: bytes, native_tbs_sha256: str,
               publisher_id: str, app_id: str, version: tuple[int, int, int]) -> tuple[bytes, dict]:
    manifest = ui.build_manifest(ui.SidecarManifest(
        publisher_id=publisher_id,
        app_id=app_id,
        publisher_key_sha256=hashlib.sha256(spki).digest(),
        native_tbs_sha256=bytes.fromhex(native_tbs_sha256),
        version_major=version[0],
        version_minor=version[1],
        version_patch=version[2],
        file_count=len(assets),
        host_ui_abi=ui.HOST_UI_ABI_V1,
        records=tuple(ui.AssetRecord(
            path=name,
            file_len=len(blob),
            sha256=hashlib.sha256(blob).digest(),
        ) for name, blob in assets),
    ))
    payload = b"".join(blob for _, blob in assets)
    tbs = ui.build_container_prefix(manifest, payload)
    signature = key.sign(tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return tbs + signature, {
        "asset_count": len(assets),
        "asset_tree_sha256": _asset_tree_sha256(assets),
        "asset_records": [
            {"path": name, "file_len": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
            for name, blob in assets
        ],
        "tbs_sha256": hashlib.sha256(tbs).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "signature_len": len(signature),
        "member_sha256": hashlib.sha256(tbs + signature).hexdigest(),
        "member_len": len(tbs) + len(signature),
    }


def _asset_tree_sha256(assets: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for name, blob in assets:
        path_bytes = name.encode("ascii")
        digest.update(len(path_bytes).to_bytes(2, "little"))
        digest.update(path_bytes)
        digest.update(len(blob).to_bytes(8, "little"))
        digest.update(hashlib.sha256(blob).digest())
    return digest.hexdigest()


def _git_provenance() -> dict:
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                            capture_output=True, text=True).stdout.strip()
    diff = subprocess.run(["git", "diff", "--binary", "HEAD"], cwd=ROOT, check=True,
                          capture_output=True).stdout
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                            cwd=ROOT, check=True, capture_output=True).stdout
    return {
        "commit": commit,
        "tracked_worktree_clean": not bool(status),
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
    }


def _tool_version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        output = result.stdout or result.stderr
        return output.splitlines()[0] if output else None
    except (OSError, subprocess.CalledProcessError):
        return None


def build_nepk(
    elf_path: Path,
    ui_asset_root: Path,
    key_path: Path,
    output_path: Path,
    publisher_id: str,
    app_id: str,
    native_version: tuple[int, int, int],
    ui_version: tuple[int, int, int],
    release_seq: int,
    source_commit: str | None = None,
    provenance_path: Path | None = None,
    expected_spki_sha256: str = EXPECTED_TEST_SPKI_SHA256,
) -> dict:
    if (publisher_id, app_id) != (EXPECTED_TEST_PUBLISHER_ID, EXPECTED_TEST_APP_ID):
        raise PackError("this TEST ONLY builder is pinned to the authorized publisher and app IDs")
    if not 1 <= release_seq <= 0xFFFFFFFFFFFFFFFF:
        raise PackError("release_seq must be a nonzero u64")
    key, spki, spki_sha256 = _load_test_key(key_path, expected_spki_sha256)
    assets = _collect_assets(ui_asset_root)
    elf = elf_path.read_bytes()
    expected_native_version = ".".join(str(part) for part in native_version)
    if f"line-crossing-app {expected_native_version}: v4 session entry".encode("ascii") not in elf:
        raise PackError("ELF embedded Line Crossing v4 version does not match the signed native version")
    image, image_report = image_builder.image_from_elf(elf)
    output_path = output_path.resolve()
    provenance_path = (provenance_path or Path(str(output_path) + ".json")).resolve()
    if output_path == provenance_path:
        raise PackError("package and provenance output paths must differ")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    provenance_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="nepk-v1-1-") as work:
        work_root = Path(work)
        image_path = work_root / "native-image.bin"
        native_path = work_root / "native.neapp.v4"
        image_path.write_bytes(image)
        native_command = [
            sys.executable,
            str(NATIVE_PACKER),
            "--image", str(image_path),
            "--out", str(native_path),
            "--key", str(key_path),
            "--publisher-id", publisher_id,
            "--app-id", app_id,
            "--version", expected_native_version,
            "--source-commit", source_commit or _git_provenance()["commit"],
            "--sidecar", "none",
        ]
        result = subprocess.run(native_command, cwd=ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            raise PackError("frozen native v4 packer rejected the real ELF image")
        native = native_path.read_bytes()
        native_trust = v4.TrustStoreV4({
            publisher_id: (spki_sha256, spki),
        })
        native_report, native_error = v4.verify_package_v4(
            native, native_trust, v4.default_policy(), host_admission=True,
        )
        if native_error is not None:
            raise PackError(f"native v4 offline admission simulation failed: {native_error.code}")
        native_tbs_sha256 = native_report["content_identity_sha256"]
        ui_member, ui_report = _signed_ui(
            assets, key, spki, native_tbs_sha256, publisher_id, app_id, ui_version,
        )
        header = HEADER.pack(b"NEPK", 1, 1, len(native), len(ui_member))
        pair_tbs = header + native + ui_member + DOMAIN + release_seq.to_bytes(8, "little")
        pair_signature = key.sign(pair_tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        package = pair_tbs + pair_signature
        report = verify_nepk(
            package,
            {publisher_id: spki},
            expected_publisher_id=publisher_id,
            expected_app_id=app_id,
        )
        git = _git_provenance()
        if source_commit is not None:
            git["commit"] = source_commit
        native_tbs_len = native_report["tbs_len"]
        metadata = {
            "artifact_type": "TEST ONLY NEPK v1.1; not a production trust root or release",
            "key_source": "external TEST ONLY signing secret; private key omitted",
            "private_key_included": False,
            "publisher_id": publisher_id,
            "app_id": app_id,
            "publisher_spki_sha256": spki_sha256,
            "release_seq": release_seq,
            "native_version": list(native_version),
            "ui_version": list(ui_version),
            "source": git,
            "toolchain": {
                "python": platform.python_version(),
                "cryptography": importlib.metadata.version("cryptography"),
                "arm_none_eabi_gcc": _tool_version(["arm-none-eabi-gcc", "--version"]),
                "make": _tool_version(["make", "--version"]),
                "node": _tool_version(["node", "--version"]),
                "pnpm": _tool_version(["pnpm", "--version"]),
            },
            "native_build": {
                **image_report,
                "signed_member_sha256": hashlib.sha256(native).hexdigest(),
                "signed_member_len": len(native),
                "tbs_sha256": native_tbs_sha256,
                "tbs_len": native_tbs_len,
                "signature_sha256": hashlib.sha256(native[native_tbs_len:]).hexdigest(),
                "signature_len": len(native) - native_tbs_len,
            },
            "ui_build": ui_report,
            "pair_authorization": {
                "domain_separator_hex": DOMAIN.hex(),
                "tbs_sha256": hashlib.sha256(pair_tbs).hexdigest(),
                "tbs_len": len(pair_tbs),
                "signature_sha256": hashlib.sha256(pair_signature).hexdigest(),
                "signature_len": len(pair_signature),
            },
            "package": {
                "sha256": hashlib.sha256(package).hexdigest(),
                "len": len(package),
                "native_member_sha256": report["native_member_sha256"],
                "ui_member_sha256": report["ui_member_sha256"],
                "result": report["result"],
                "transition": report["transition"],
            },
            "verification_boundary": report["boundary"],
        }
        package_temp = work_root / output_path.name
        package_temp.write_bytes(package)
        output_path.write_bytes(package_temp.read_bytes())
        provenance_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--ui-assets", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--provenance-out", type=Path)
    parser.add_argument("--publisher-id", default=EXPECTED_TEST_PUBLISHER_ID)
    parser.add_argument("--app-id", default=EXPECTED_TEST_APP_ID)
    parser.add_argument("--native-version", required=True, type=parse_version)
    parser.add_argument("--ui-version", required=True, type=parse_version)
    parser.add_argument("--release-seq", required=True, type=int)
    parser.add_argument("--source-commit")
    args = parser.parse_args()
    try:
        metadata = build_nepk(
            args.elf, args.ui_assets, args.key, args.out,
            args.publisher_id, args.app_id,
            args.native_version, args.ui_version, args.release_seq,
            args.source_commit, args.provenance_out,
        )
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"result": "REJECTED", "detail": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"result": "PASS", "package": metadata["package"],
                      "provenance": str(args.provenance_out or Path(str(args.out) + ".json"))},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
