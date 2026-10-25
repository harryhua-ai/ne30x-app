from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))
sys.path.insert(0, str(ROOT / "package" / "unsigned"))
sys.path.insert(0, str(ROOT / "package" / "vnext"))

import neapp_v4_format as v4
import neapp_v4_image as image_builder
import neui_sidecar_format as ui
import neapp_v5_format as v5

PACKER_VERSION = "5.0.0"


class PackError(ValueError):
    pass


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise argparse.ArgumentTypeError("version must be MAJOR.MINOR.PATCH")
    result = tuple(int(p) for p in parts)
    if any(part > 0xFFFF for part in result) or result[0] == 0:
        raise argparse.ArgumentTypeError("version segments must fit u16 and the major must be nonzero")
    return result


def parse_ui_version(value: str) -> tuple[int, int, int]:
    result = parse_version(value)
    if not all(result):
        raise argparse.ArgumentTypeError("ui version segments must all be nonzero")
    return result


def collect_assets(root: Path) -> list[tuple[str, bytes]]:
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
            if not path.is_file() or path.is_symlink():
                raise PackError("UI asset tree contains a non-regular file")
            try:
                relative = path.relative_to(root).as_posix()
                relative.encode("ascii")
                ui.validate_asset_path(relative.encode("ascii"))
            except (ValueError, UnicodeEncodeError, v4.PackageError) as error:
                raise PackError("UI asset tree contains an invalid path") from error
            assets.append((relative, path.read_bytes()))
    assets.sort(key=lambda item: item[0].encode("ascii"))
    if not assets or sum(name == ui.INDEX_PATH for name, _ in assets) != 1:
        raise PackError("UI asset tree must contain exactly one root index.html")
    if len(assets) > ui.MAX_FILE_COUNT:
        raise PackError("UI asset tree exceeds the file-count limit")
    folded = set()
    total = 0
    for name, blob in assets:
        key = name.lower()
        if key in folded:
            raise PackError("UI asset paths collide under ASCII case folding")
        folded.add(key)
        if not ui.MIN_FILE_LEN <= len(blob) <= ui.MAX_FILE_LEN:
            raise PackError("UI asset file size is outside the limit")
        total += len(blob)
        if total > ui.MAX_ASSET_PAYLOAD_LEN:
            raise PackError("UI asset payload exceeds the size limit")
    return assets


def asset_tree_sha256(assets: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for name, blob in assets:
        path_bytes = name.encode("ascii")
        digest.update(len(path_bytes).to_bytes(2, "little"))
        digest.update(path_bytes)
        digest.update(len(blob).to_bytes(8, "little"))
        digest.update(hashlib.sha256(blob).digest())
    return digest.hexdigest()


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


def tool_version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        output = result.stdout or result.stderr
        return output.splitlines()[0] if output else None
    except (OSError, subprocess.CalledProcessError):
        return None


def build_v5(
    elf_path: Path,
    ui_asset_root: Path,
    output_path: Path,
    app_id: str,
    native_version: tuple[int, int, int],
    ui_version: tuple[int, int, int],
    host_caps: int,
    event_max: int,
    state_quota: int,
    report_max: int,
    control_max: int,
    snapshot_max: int,
    live_publish_max: int,
    live_track_max: int,
    source_commit: str | None = None,
    provenance_path: Path | None = None,
) -> dict:
    assets = collect_assets(ui_asset_root)
    elf = elf_path.read_bytes()
    version_text = ".".join(str(part) for part in native_version)
    marker = f"{app_id}-app {version_text}: v4 session entry".encode("ascii")
    if marker not in elf:
        raise PackError("ELF does not embed the expected app/version session-entry marker")
    image, image_report = image_builder.image_from_elf(elf)
    try:
        v4.validate_policy_shape(host_caps, v4.RUN_PROFILE_V4, event_max, state_quota,
                                 report_max, control_max, snapshot_max,
                                 live_publish_max, live_track_max)
    except v4.PackageError as exc:
        raise PackError(f"capability/quota declaration rejected at pack time: {exc.detail}") from exc
    manifest = v5.build_manifest_v5(v5.ManifestV5(
        app_id=app_id,
        version_major=native_version[0],
        version_minor=native_version[1],
        version_patch=native_version[2],
        target_board_id=v4.TARGET_BOARD_ID_V4,
        required_psram_mib=v4.REQUIRED_PSRAM_MIB_V4,
        required_host_abi=v4.HOST_ABI_V4,
        required_host_caps=host_caps,
        native_payload_len=image_report["image_len"] - v4.NATIVE_HEADER_SIZE,
        native_file_len=image_report["image_len"],
        native_image_size=image_report["image_len"] - v4.NATIVE_HEADER_SIZE,
        native_entry_offset=image_report["entry_offset"],
        native_target_addr=image_report["target_addr"],
        native_file_sha256=hashlib.sha256(image).digest(),
        run_profile=v4.RUN_PROFILE_V4,
        event_max=event_max,
        state_quota=state_quota,
        report_max=report_max,
        control_max=control_max,
        snapshot_max=snapshot_max,
        live_publish_max=live_publish_max,
        live_track_max=live_track_max,
    ))
    native_member = (v5.NATIVE_MEMBER_MAGIC
                     + struct.pack("<II", v5.MANIFEST_LEN, len(image))
                     + manifest + image)
    ui_manifest = v5.build_ui_manifest_v5(v5.UiManifestV5(
        app_id=app_id,
        native_member_sha256=hashlib.sha256(native_member).digest(),
        version_major=ui_version[0],
        version_minor=ui_version[1],
        version_patch=ui_version[2],
        file_count=len(assets),
        host_ui_abi=ui.HOST_UI_ABI_V1,
        native_version_major=native_version[0],
        native_version_minor=native_version[1],
        native_version_patch=native_version[2],
        records=tuple(ui.AssetRecord(
            path=name,
            file_len=len(blob),
            sha256=hashlib.sha256(blob).digest(),
        ) for name, blob in assets),
    ))
    ui_payload = b"".join(blob for _, blob in assets)
    package = v5.build_package_v5(manifest, image, ui_manifest, ui_payload)
    report, error = v5.verify_package_v5(package)
    if error is not None or report is None:
        raise PackError(f"packer self-verification rejected the package: "
                        f"{error.code if error else 'UNKNOWN'}: {error.detail if error else ''}")
    output_path = output_path.resolve()
    provenance_path = (provenance_path or Path(str(output_path) + ".provenance.json")).resolve()
    if output_path == provenance_path:
        raise PackError("package and provenance output paths must differ")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    provenance_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="neapp-v5-") as work:
        temp_path = Path(work) / output_path.name
        temp_path.write_bytes(package)
        output_path.write_bytes(temp_path.read_bytes())
    metadata = {
        "artifact_type": "unsigned NEAPP v5 package",
        "format": "neapp-v5-unsigned",
        "generator": f"neapp_pack_v5.py {PACKER_VERSION}",
        "signing_dependencies": "none: no private key, no SPKI, no signature, no sequence ledger",
        "source_commit": source_commit if source_commit else detect_source_commit(),
        "toolchain": {
            "python": platform.python_version(),
            "arm_none_eabi_gcc": tool_version(["arm-none-eabi-gcc", "--version"]),
        },
        "app_id": app_id,
        "native_version": list(native_version),
        "ui_version": list(ui_version),
        "native_build": {
            **image_report,
            "member_sha256": hashlib.sha256(native_member).hexdigest(),
            "member_len": len(native_member),
        },
        "ui_build": {
            "asset_count": len(assets),
            "asset_tree_sha256": asset_tree_sha256(assets),
            "asset_records": [
                {"path": name, "file_len": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
                for name, blob in assets
            ],
            "member_sha256": report["ui_member_sha256"],
            "member_len": report["ui_member_len"],
        },
        "package": {
            "sha256": hashlib.sha256(package).hexdigest(),
            "len": len(package),
        },
        "host_policy": {
            "host_caps": host_caps,
            "event_max": event_max,
            "state_quota": state_quota,
            "report_max": report_max,
            "control_max": control_max,
            "snapshot_max": snapshot_max,
            "live_publish_max": live_publish_max,
            "live_track_max": live_track_max,
            "run_profile": v4.RUN_PROFILE_V4,
        },
        "verification_boundary": report["boundary"],
    }
    provenance_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--ui-assets", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--provenance-out", type=Path)
    parser.add_argument("--app-id", default="line-crossing")
    parser.add_argument("--native-version", required=True, type=parse_version)
    parser.add_argument("--ui-version", required=True, type=parse_ui_version)
    parser.add_argument("--host-caps", type=parse_int,
                        default=v4.CAP_LOG | v4.CAP_TICK_MS | v4.CAP_SESSION_LIFECYCLE
                        | v4.CAP_CONTROL_RECEIVE)
    parser.add_argument("--event-max", type=parse_int, default=0)
    parser.add_argument("--state-quota", type=parse_int, default=0)
    parser.add_argument("--report-max", type=parse_int, default=0)
    parser.add_argument("--control-max", type=parse_int, default=256)
    parser.add_argument("--snapshot-max", type=parse_int, default=0)
    parser.add_argument("--live-publish-max", type=parse_int, default=0)
    parser.add_argument("--live-track-max", type=parse_int, default=0)
    parser.add_argument("--source-commit", default=None)
    args = parser.parse_args()
    try:
        metadata = build_v5(
            args.elf, args.ui_assets, args.out, args.app_id,
            args.native_version, args.ui_version,
            args.host_caps, args.event_max, args.state_quota, args.report_max,
            args.control_max, args.snapshot_max, args.live_publish_max,
            args.live_track_max,
            args.source_commit, args.provenance_out,
        )
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"result": "REJECTED", "detail": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"result": "PASS", "package": metadata["package"],
                      "provenance": str(args.provenance_out or Path(str(args.out) + ".provenance.json"))},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
