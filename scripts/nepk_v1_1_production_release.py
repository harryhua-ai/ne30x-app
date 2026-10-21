from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "package" / "vnext"))

from nepk_v1_1_pack import NON_PRODUCTION_PUBLISHER_IDS, NON_PRODUCTION_SPKI_SHA256S, PackError, _load_production_key, parse_version
import nepk_v1_1_pack as pack_module
from nepk_v1_1_release import (
    GitHubReleaseClient,
    ReleaseError,
    authorization_snapshot_for_record,
    build_release_plan,
    canonical_json_sha256,
    complete_release_sequence,
    initialize_sequence_ledger,
    initialize_sequence_ledger_ref,
    mark_sequence_published,
    mark_sequence_signed,
    parse_dispatch_version,
    publish_one_click_release,
    reserve_release_sequence,
    validate_sequence_ledger,
)
from nepk_v1_1_verify import TrustedHistory, verify_nepk


def _run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="", flush=True)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
    return result


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_production_signing_material(secret, publisher_id: str, spki_der: bytes, spki_sha256: str, key_path: Path):
    if not isinstance(secret, str) or not secret:
        raise ReleaseError("NEPK_PRODUCTION_ISSUER_KEY is missing from the protected production Environment")
    if publisher_id in NON_PRODUCTION_PUBLISHER_IDS or spki_sha256 in NON_PRODUCTION_SPKI_SHA256S:
        raise ReleaseError("TEST ONLY publisher or SPKI cannot be used for production signing")
    if re.fullmatch(r"[0-9a-f]{64}", spki_sha256 or "") is None or not isinstance(spki_der, bytes) or hashlib.sha256(spki_der).hexdigest() != spki_sha256:
        raise ReleaseError("production SPKI DER does not match the configured fingerprint")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(secret, encoding="utf-8")
    key_path.chmod(0o600)
    try:
        loaded = _load_production_key(key_path, spki_sha256)
    except PackError as error:
        raise ReleaseError(str(error)) from error
    if loaded[1] != spki_der or loaded[2] != spki_sha256:
        raise ReleaseError("production signing key does not match the configured production SPKI")
    return loaded


def read_line_crossing_versions(root: Path = ROOT) -> tuple[str, str]:
    makefile = (root / "apps" / "line-crossing" / "app" / "Makefile").read_text(encoding="utf-8")
    ui_packaging = (root / "tests" / "line-crossing-ui" / "package.sh").read_text(encoding="utf-8")
    native_matches = re.findall(r"^V4_APP_VERSION\s*\?=\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$", makefile, re.MULTILINE)
    ui_matches = re.findall(r"--version\s+([0-9]+\.[0-9]+\.[0-9]+)\b", ui_packaging)
    if len(native_matches) != 1 or len(ui_matches) != 1:
        raise ReleaseError("Line Crossing native or UI version is missing or ambiguous in its packaging source")
    try:
        native_version = parse_version(native_matches[0])
        ui_version = parse_version(ui_matches[0])
    except (argparse.ArgumentTypeError, ValueError) as error:
        raise ReleaseError("Line Crossing native or UI source version is invalid") from error
    if native_version[0] != 4 or ui_version[0] != 1:
        raise ReleaseError("Line Crossing production package requires source native v4 and NEUI v1")
    return ".".join(map(str, native_version)), ".".join(map(str, ui_version))


def initialize_production_sequence_ledger(
    client,
    publisher_id: str,
    app_id: str,
    publisher_spki_sha256: str,
    expected_genesis_sha256: str,
) -> dict:
    if app_id != "line-crossing":
        raise ReleaseError("one-time production sequence initialization is pinned to line-crossing")
    if publisher_id in NON_PRODUCTION_PUBLISHER_IDS or publisher_spki_sha256 in NON_PRODUCTION_SPKI_SHA256S:
        raise ReleaseError("one-time ledger initialization rejects TEST ONLY publishers and SPKIs")
    ledger = initialize_sequence_ledger(publisher_id, app_id, publisher_spki_sha256)
    validate_sequence_ledger(
        ledger,
        expected_genesis_sha256,
        publisher_id,
        app_id,
        publisher_spki_sha256,
    )
    return initialize_sequence_ledger_ref(
        client,
        ledger,
        expected_genesis_sha256,
        publisher_id,
        app_id,
        publisher_spki_sha256,
    )


def _tool_version(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise ReleaseError(f"required build tool is unavailable: {command[0]}")
    version = (result.stdout or result.stderr).splitlines()
    if not version:
        raise ReleaseError(f"required build tool returned no version: {command[0]}")
    return version[0].strip()


def _build_input_fingerprint(elf_path: Path, ui_root: Path, source_sha: str, publisher_id: str, spki_sha256: str, native_version: str, ui_version: str) -> str:
    assets = pack_module._collect_assets(ui_root)
    identity = {
        "version": 1,
        "source_sha": source_sha,
        "publisher_id": publisher_id,
        "app_id": "line-crossing",
        "publisher_spki_sha256": spki_sha256,
        "native_version": native_version,
        "ui_version": ui_version,
        "elf_sha256": hashlib.sha256(elf_path.read_bytes()).hexdigest(),
        "ui_assets": [
            {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in assets
        ],
        "toolchain": {
            "python": sys.version.split()[0],
            "cryptography": importlib.metadata.version("cryptography"),
            "arm_none_eabi_gcc": _tool_version(["arm-none-eabi-gcc", "--version"]),
            "make": _tool_version(["make", "--version"]),
            "node": _tool_version(["node", "--version"]),
            "pnpm": _tool_version(["pnpm", "--version"]),
        },
    }
    return canonical_json_sha256(identity)


def _latest_trusted_history(ledger: dict, publisher_id: str, app_id: str, before_seq: int):
    records = [
        row for row in ledger.get("records", [])
        if row.get("publisher_id") == publisher_id
        and row.get("app_id") == app_id
        and row.get("release_seq", 0) < before_seq
        and row.get("status") in {"authorized", "signed", "published", "abandoned-signed"}
    ]
    if not records:
        return None
    latest = max(records, key=lambda row: row["release_seq"])
    return TrustedHistory(
        publisher_id=publisher_id,
        app_id=app_id,
        publisher_key_sha256=latest["publisher_spki_sha256"],
        release_seq=latest["release_seq"],
        native_tbs_sha256=latest["native_tbs_sha256"],
        ui_tbs_sha256=latest["ui_tbs_sha256"],
        pair_tbs_sha256=latest["pair_tbs_sha256"],
        native_version=tuple(latest["native_version"]),
        ui_version=tuple(latest["ui_version"]),
    )


def _build_preview_package(elf_path: Path, ui_root: Path, key_path: Path, publisher_id: str, spki_sha256: str, source_sha: str, native_version: str, ui_version: str, release_seq: int, trusted_history):
    key, spki_der, fingerprint = _load_production_key(key_path, spki_sha256)
    if fingerprint != spki_sha256:
        raise ReleaseError("production signing key does not match the configured Host trust root")
    assets = pack_module._collect_assets(ui_root)
    elf = elf_path.read_bytes()
    expected_native_version = ".".join(map(str, parse_version(native_version)))
    if f"line-crossing-app {expected_native_version}: v4 session entry".encode("ascii") not in elf:
        raise ReleaseError("built ELF does not contain its source-derived native version")
    image, _ = pack_module.image_builder.image_from_elf(elf)
    with tempfile.TemporaryDirectory(prefix="nepk-oneclick-preview-") as temporary:
        work = Path(temporary)
        image_path = work / "native-image.bin"
        native_path = work / "native.neapp.v4"
        image_path.write_bytes(image)
        _run([
            sys.executable, str(pack_module.NATIVE_PACKER),
            "--image", str(image_path),
            "--out", str(native_path),
            "--key", str(key_path),
            "--publisher-id", publisher_id,
            "--app-id", "line-crossing",
            "--version", expected_native_version,
            "--source-commit", source_sha,
            "--sidecar", "none",
        ])
        native = native_path.read_bytes()
    native_trust = pack_module.v4.TrustStoreV4({publisher_id: (spki_sha256, spki_der)})
    native_report, native_error = pack_module.v4.verify_package_v4(
        native,
        native_trust,
        pack_module.v4.default_policy(),
        host_admission=True,
    )
    if native_error is not None:
        raise ReleaseError(f"native v4 offline admission simulation failed: {native_error.code}")
    ui_member, _ = pack_module._signed_ui(
        assets,
        key,
        spki_der,
        native_report["content_identity_sha256"],
        publisher_id,
        "line-crossing",
        tuple(parse_version(ui_version)),
    )
    header = pack_module.HEADER.pack(b"NEPK", 1, 1, len(native), len(ui_member))
    pair_tbs = header + native + ui_member + pack_module.DOMAIN + release_seq.to_bytes(8, "little")
    pair_signature = key.sign(
        pair_tbs,
        pack_module.ec.ECDSA(pack_module.hashes.SHA256(), deterministic_signing=True),
    )
    package = pair_tbs + pair_signature
    report = verify_nepk(
        package,
        {publisher_id: spki_der},
        expected_publisher_id=publisher_id,
        expected_app_id="line-crossing",
        trusted_history=trusted_history,
    )
    if report.get("source_commit") not in {None, source_sha}:
        raise ReleaseError("independent preview verifier returned an unexpected source identity")
    return package, report


def _build_and_verify_elf(native_version: str) -> tuple[Path, Path]:
    _run([
        "make", "-C", "apps/line-crossing/app", "elf-v4",
        f"V4_APP_VERSION={native_version}",
    ])
    _run(["node", "tests/line-crossing-ui/browser-runner/build.mjs"])
    elf_path = ROOT / "apps" / "line-crossing" / "app" / "build" / "lc-line-crossing-v4.elf"
    ui_root = ROOT / "tests" / "line-crossing-ui" / ".build" / "production"
    if not elf_path.is_file() or not ui_root.is_dir():
        raise ReleaseError("Line Crossing native or production UI build did not produce its expected output")
    return elf_path, ui_root


def _independent_verify(package_path: Path, trust_path: Path, publisher_id: str) -> dict:
    result = _run([
        sys.executable, "package/vnext/nepk_v1_1_verify.py",
        "--bundle", str(package_path),
        "--trust", str(trust_path),
        "--expect-publisher-id", publisher_id,
        "--expect-app-id", "line-crossing",
        "--compact",
    ])
    report = json.loads(result.stdout)
    if report.get("result") != "PASS":
        raise ReleaseError("independent NEPK v1.1 native, UI, or Pair signature verification did not PASS")
    if hashlib.sha256(package_path.read_bytes()).hexdigest() != report.get("package_sha256"):
        raise ReleaseError("independent verification package digest differs from the exact package bytes")
    return report


def _request_and_snapshot(ledger: dict, record: dict, genesis_sha256: str, publisher_id: str, spki_sha256: str) -> tuple[dict, dict]:
    snapshot = authorization_snapshot_for_record(
        ledger,
        record["record_id"],
        genesis_sha256,
        publisher_id,
        "line-crossing",
        spki_sha256,
    )
    compatibility = (
        "Install only on a Host that admits NEPK v1.1, supports native v4 and NEUI v1, "
        f"and trusts publisher SPKI SHA-256 {spki_sha256}."
    )
    request = {
        "version": 1,
        "action": "publish",
        "batch_version": record["batch_version"],
        "source_sha": record["source_sha"],
        "authorization": {
            "request_id": record["record_id"],
            "authorization_ref": record["run_url"],
            "source_sha": record["source_sha"],
            "action": "publish",
        },
        "sequence_ledger": snapshot,
        "apps": [{
            "app_id": "line-crossing",
            "publisher_id": publisher_id,
            "native_version": ".".join(map(str, record["native_version"])),
            "ui_version": ".".join(map(str, record["ui_version"])),
            "release_seq": record["release_seq"],
            "sequence_record_id": record["record_id"],
            "compatibility": compatibility,
        }],
    }
    return request, snapshot


def _synthetic_provenance(package_path: Path, report: dict, record: dict) -> dict:
    return {
        "artifact_type": "Production signed NEPK v1.1",
        "publisher_id": report["publisher_id"],
        "app_id": report["app_id"],
        "release_seq": report["release_seq"],
        "source": {"commit": record["source_sha"]},
        "package": {
            "sha256": hashlib.sha256(package_path.read_bytes()).hexdigest(),
            "len": package_path.stat().st_size,
        },
        "reconstructed_for_release_recovery": True,
    }


def _existing_asset(client, release: dict | None, record: dict) -> bytes | None:
    if release is None:
        return None
    if release.get("draft") is False and record.get("status") == "published" and not release.get("assets"):
        raise ReleaseError("published Release is missing its package asset; public releases are never repaired by overwriting")
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ReleaseError("existing Release asset list is unreadable")
    expected_name = f"line-crossing-{record['batch_version']}.neapp"
    matching = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == expected_name]
    if any(not isinstance(asset, dict) or asset.get("name") != expected_name for asset in assets):
        raise ReleaseError("existing Release contains an unexpected asset; refusing publication")
    if len(matching) > 1:
        raise ReleaseError("existing Release contains duplicate package assets")
    if not matching:
        if release.get("draft") is False:
            raise ReleaseError("published Release is missing its package asset; refusing modification")
        return None
    package = client.download_asset(matching[0])
    if hashlib.sha256(package).hexdigest() != record["package_sha256"]:
        raise ReleaseError("existing Release package bytes differ from the immutable sequence-ledger record")
    return package


def _write_publisher_trust(path: Path, publisher_id: str, spki_der: bytes, spki_sha256: str) -> None:
    _write_json(path, {
        "version": 1,
        "publishers": {
            publisher_id: {
                "spki_der_hex": spki_der.hex(),
                "spki_sha256": spki_sha256,
            },
        },
    })


def execute(args) -> dict:
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ReleaseError("production signing is restricted to a manually dispatched main workflow")
    source_sha = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ReleaseError("accepted main source SHA is missing or malformed")
    checked_out_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip()
    if checked_out_sha != source_sha:
        raise ReleaseError("checked out source SHA differs from github.sha")
    batch_version = parse_dispatch_version(args.version)
    publisher_id = os.environ.get("NEPK_PRODUCTION_PUBLISHER_ID", "")
    if publisher_id in NON_PRODUCTION_PUBLISHER_IDS or re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", publisher_id) is None:
        raise ReleaseError("production publisher ID is missing, malformed, or TEST ONLY")
    spki_sha256 = os.environ.get("NEPK_PRODUCTION_SPKI_SHA256", "")
    spki_hex = os.environ.get("NEPK_PRODUCTION_SPKI_DER_HEX", "")
    if re.fullmatch(r"[0-9a-f]{64}", spki_sha256) is None or re.fullmatch(r"(?:[0-9a-f]{2})+", spki_hex) is None:
        raise ReleaseError("production publisher SPKI configuration is missing or malformed")
    spki_der = bytes.fromhex(spki_hex)
    if hashlib.sha256(spki_der).hexdigest() != spki_sha256 or spki_sha256 in NON_PRODUCTION_SPKI_SHA256S:
        raise ReleaseError("configured SPKI does not match its SHA-256 or is TEST ONLY")
    genesis_sha256 = os.environ.get("NEPK_PRODUCTION_SEQUENCE_LEDGER_GENESIS_SHA256", "")
    if re.fullmatch(r"[0-9a-f]{64}", genesis_sha256) is None:
        raise ReleaseError("protected ledger genesis fingerprint is missing; configure it after one-time administrator initialization")
    secret = os.environ.pop("NEPK_PRODUCTION_ISSUER_KEY", None)
    if not secret:
        raise ReleaseError("NEPK_PRODUCTION_ISSUER_KEY is missing from the protected production Environment")
    native_version, ui_version = read_line_crossing_versions(ROOT)
    if os.environ.get("GITHUB_RUN_ID", "").isdigit() is False:
        raise ReleaseError("GitHub Actions run ID is missing or malformed")
    run_id = os.environ["GITHUB_RUN_ID"]
    try:
        run_attempt = int(os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    except ValueError as error:
        raise ReleaseError("GitHub Actions run attempt is missing or malformed") from error
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise ReleaseError("GITHUB_TOKEN is unavailable to the protected production job")
    client = GitHubReleaseClient(repository, token)
    current = client.read_sequence_ledger()
    if current is None:
        raise ReleaseError("production sequence ledger is not initialized; run the one-time administrator ledger initialization")
    ledger_head, ledger = current
    validate_sequence_ledger(ledger, genesis_sha256, publisher_id, "line-crossing", spki_sha256)
    run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com').rstrip('/')}/{repository}/actions/runs/{run_id}"
    if run_attempt < 1:
        raise ReleaseError("GitHub Actions run attempt must be positive")
    tag = f"v{batch_version}"
    tag_ref = client.get_tag(tag)
    release = client.get_release_by_tag(tag)
    if tag_ref is not None and client.tag_commit(tag_ref) != source_sha:
        raise ReleaseError("version tag already exists at a different source SHA; tags are never moved")
    reservations = [
        event for event in ledger["events"]
        if event.get("kind") == "reserved" and event.get("batch_version") == batch_version
    ]
    if len(reservations) > 1:
        raise ReleaseError("production sequence ledger binds this version more than once; manual ledger review is required")
    records = [row for row in ledger["records"] if row.get("batch_version") == batch_version]
    if len(records) > 1:
        raise ReleaseError("production sequence ledger has conflicting records for this version")
    record = records[0] if records else None
    if record is None and (release is not None or tag_ref is not None):
        raise ReleaseError("version tag or Release exists without a sequence-ledger record; refusing to attach or overwrite")
    if record is not None:
        if record["source_sha"] != source_sha:
            raise ReleaseError("version is already bound to a different source SHA")
        if record["native_version"] != list(parse_version(native_version)) or record["ui_version"] != list(parse_version(ui_version)):
            raise ReleaseError("source-derived native or UI versions differ from the immutable ledger record")
        if record["status"] == "published" and release is None:
            raise ReleaseError("ledger records this version as published but GitHub Release is missing; manual recovery is required")
        if record["status"] == "published" and release is not None and release.get("draft") is True:
            raise ReleaseError("ledger records this version as published but GitHub Release is still a Draft; manual recovery is required")
        if release is not None and release.get("draft") is False and record["status"] not in {"signed", "published"}:
            raise ReleaseError("public Release conflicts with the sequence-ledger publication state")
    with tempfile.TemporaryDirectory(prefix="nepk-oneclick-release-") as temporary:
        work = Path(temporary)
        key_path = work / "issuer.pem"
        validate_production_signing_material(secret, publisher_id, spki_der, spki_sha256, key_path)
        del secret
        trust_path = work / "trust.json"
        _write_publisher_trust(trust_path, publisher_id, spki_der, spki_sha256)
        package_path = work / f"line-crossing-{batch_version}.neapp"
        provenance_path = work / "provenance.json"
        ledger_path = work / "sequence-ledger.json"
        verification_path = work / "independent-verification.json"
        existing_bytes = _existing_asset(client, release, record) if record is not None else None
        if record is not None and existing_bytes is not None:
            package_path.write_bytes(existing_bytes)
            independent_report = _independent_verify(package_path, trust_path, publisher_id)
            if independent_report.get("release_seq") != record["release_seq"] or independent_report.get("publisher_key_sha256") != spki_sha256:
                raise ReleaseError("existing Release package does not match its immutable signed sequence identity")
            if independent_report.get("native_tbs_sha256") != record["native_tbs_sha256"] or independent_report.get("ui_tbs_sha256") != record["ui_tbs_sha256"] or independent_report.get("pair_tbs_sha256") != record["pair_tbs_sha256"]:
                raise ReleaseError("existing Release signature TBS digests differ from the ledger")
            _write_json(provenance_path, _synthetic_provenance(package_path, independent_report, record))
            packer_result = "RECOVERED_VERIFIED_BYTES"
        else:
            elf_path, ui_root = _build_and_verify_elf(native_version)
            build_input_sha256 = _build_input_fingerprint(
                elf_path,
                ui_root,
                source_sha,
                publisher_id,
                spki_sha256,
                native_version,
                ui_version,
            )
            if record is not None and record.get("build_input_sha256") != build_input_sha256:
                raise ReleaseError("recovered build inputs differ from the version reservation; refusing to sign different bytes")
            if record is None:
                reservation = reserve_release_sequence(
                    client,
                    genesis_sha256=genesis_sha256,
                    publisher_id=publisher_id,
                    app_id="line-crossing",
                    publisher_spki_sha256=spki_sha256,
                    batch_version=batch_version,
                    source_sha=source_sha,
                    build_input_sha256=build_input_sha256,
                    run_id=run_id,
                    run_attempt=run_attempt,
                    run_url=run_url,
                )
                current = client.read_sequence_ledger()
                if current is None:
                    raise ReleaseError("production sequence ledger disappeared after sequence reservation")
                ledger_head, ledger = current
                validate_sequence_ledger(ledger, genesis_sha256, publisher_id, "line-crossing", spki_sha256)
            else:
                reservation = next((event for event in ledger["events"] if event.get("kind") == "reserved" and event.get("record_id") == record["record_id"]), None)
                if reservation is None:
                    raise ReleaseError("existing sequence record has no reservation event")
            preview, preview_report = _build_preview_package(
                elf_path,
                ui_root,
                key_path,
                publisher_id,
                spki_sha256,
                source_sha,
                native_version,
                ui_version,
                reservation["release_seq"],
                _latest_trusted_history(ledger, publisher_id, "line-crossing", reservation["release_seq"]),
            )
            if record is None:
                record = complete_release_sequence(
                    client,
                    reservation,
                    preview_report,
                    genesis_sha256=genesis_sha256,
                    publisher_id=publisher_id,
                    app_id="line-crossing",
                    publisher_spki_sha256=spki_sha256,
                    run_id=run_id,
                    run_attempt=run_attempt,
                    run_url=run_url,
                )
            elif any(record.get(field) != preview_report.get(report_field) for field, report_field in (
                ("package_sha256", "package_sha256"),
                ("native_tbs_sha256", "native_tbs_sha256"),
                ("ui_tbs_sha256", "ui_tbs_sha256"),
                ("pair_tbs_sha256", "pair_tbs_sha256"),
            )):
                raise ReleaseError("recovered deterministic package differs from its immutable signed ledger record")
            current = client.read_sequence_ledger()
            if current is None:
                raise ReleaseError("production sequence ledger disappeared after signed package authorization")
            ledger_head, ledger = current
            validate_sequence_ledger(ledger, genesis_sha256, publisher_id, "line-crossing", spki_sha256)
            request, snapshot = _request_and_snapshot(ledger, record, genesis_sha256, publisher_id, spki_sha256)
            snapshot_sha256 = canonical_json_sha256(snapshot)
            _write_json(ledger_path, snapshot)
            packer = _run([
                sys.executable, "package/vnext/nepk_v1_1_pack.py",
                "--mode", "production",
                "--elf", str(elf_path),
                "--ui-assets", str(ui_root),
                "--key", str(key_path),
                "--out", str(package_path),
                "--provenance-out", str(provenance_path),
                "--publisher-id", publisher_id,
                "--app-id", "line-crossing",
                "--native-version", native_version,
                "--ui-version", ui_version,
                "--release-seq", str(record["release_seq"]),
                "--source-commit", source_sha,
                "--expected-spki-sha256", spki_sha256,
                "--sequence-ledger", str(ledger_path),
                "--expected-ledger-sha256", snapshot_sha256,
                "--sequence-record-id", record["record_id"],
            ])
            if package_path.read_bytes() != preview:
                raise ReleaseError("official NEPK packer output differs from the independently assembled deterministic preview")
            packer_result = json.loads(packer.stdout).get("result")
            independent_report = _independent_verify(package_path, trust_path, publisher_id)
            if independent_report.get("package_sha256") != record["package_sha256"]:
                raise ReleaseError("official packer bytes differ from the immutable ledger package digest")
        _write_json(verification_path, independent_report)
        request, snapshot = _request_and_snapshot(ledger, record, genesis_sha256, publisher_id, spki_sha256)
        plan = build_release_plan(
            request,
            {"line-crossing": package_path},
            {"line-crossing": provenance_path},
            {publisher_id: spki_der},
            {"line-crossing": independent_report},
            expected_source_sha=source_sha,
            expected_ledger_sha256=canonical_json_sha256(snapshot),
        )
        def before_publish(release_data):
            mark_sequence_signed(
                client,
                record["record_id"],
                release_url=release_data.get("html_url", ""),
                genesis_sha256=genesis_sha256,
                publisher_id=publisher_id,
                app_id="line-crossing",
                publisher_spki_sha256=spki_sha256,
                run_id=run_id,
                run_attempt=run_attempt,
                run_url=run_url,
            )

        def after_publish(release_data):
            mark_sequence_published(
                client,
                record["record_id"],
                release_url=release_data.get("html_url", ""),
                genesis_sha256=genesis_sha256,
                publisher_id=publisher_id,
                app_id="line-crossing",
                publisher_spki_sha256=spki_sha256,
                run_id=run_id,
                run_attempt=run_attempt,
                run_url=run_url,
            )

        release_result = publish_one_click_release(
            plan,
            client,
            authorized=True,
            before_publish=before_publish,
            after_publish=after_publish,
        )
        final_ledger = client.read_sequence_ledger()
        if final_ledger is None:
            raise ReleaseError("production sequence ledger disappeared after Release publication")
        ledger_head, ledger = final_ledger
        validate_sequence_ledger(ledger, genesis_sha256, publisher_id, "line-crossing", spki_sha256)
        final_record = next((row for row in ledger["records"] if row.get("record_id") == record["record_id"]), None)
        if final_record is None or final_record.get("status") != "published":
            raise ReleaseError("published Release is missing its final sequence-ledger publication event")
        package_sha256 = hashlib.sha256(package_path.read_bytes()).hexdigest()
        evidence = {
            "version": 1,
            "result": "PASS",
            "tag": plan["tag"],
            "release_tag_target_sha": source_sha,
            "source_sha": source_sha,
            "run_url": run_url,
            "sequence_record_id": record["record_id"],
            "sequence_record_status": final_record["status"],
            "sequence_ledger_head_sha": ledger_head,
            "sequence_ledger_json_sha256": canonical_json_sha256(ledger),
            "sequence_ledger_genesis_sha256": genesis_sha256,
            "publisher_id": publisher_id,
            "publisher_spki_sha256": spki_sha256,
            "app_id": "line-crossing",
            "native_version": record["native_version"],
            "ui_version": record["ui_version"],
            "release_seq": record["release_seq"],
            "asset_name": f"line-crossing-{batch_version}.neapp",
            "package_sha256": package_sha256,
            "package_len": package_path.stat().st_size,
            "release_asset_count": 1,
            "independent_verification": independent_report,
            "provenance": json.loads(provenance_path.read_text(encoding="utf-8")),
            "release_notes": plan["release_notes"],
            "release_notes_sha256": hashlib.sha256(plan["release_notes"].encode("utf-8")).hexdigest(),
            "packer_result": packer_result,
            "release_result": release_result,
        }
        _write_json(args.evidence, evidence)
        return evidence


def _github_token() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    result = subprocess.run(["gh", "auth", "token"], text=True, capture_output=True)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    raise ReleaseError("GitHub API token is unavailable; authenticate with gh or set GH_TOKEN")


def _parser():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    release_parser = commands.add_parser("release")
    release_parser.add_argument("--version", required=True)
    release_parser.add_argument("--evidence", required=True, type=Path)
    release_parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    genesis_parser = commands.add_parser("genesis-sha256")
    genesis_parser.add_argument("--publisher-id", required=True)
    genesis_parser.add_argument("--app-id", default="line-crossing")
    genesis_parser.add_argument("--spki-sha256", required=True)
    initialize_parser = commands.add_parser("initialize-ledger")
    initialize_parser.add_argument("--repository", required=True)
    initialize_parser.add_argument("--publisher-id", required=True)
    initialize_parser.add_argument("--app-id", default="line-crossing")
    initialize_parser.add_argument("--spki-sha256", required=True)
    initialize_parser.add_argument("--expected-genesis-sha256", required=True)
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    try:
        if args.command == "genesis-sha256":
            if args.app_id != "line-crossing":
                raise ReleaseError("production sequence genesis is pinned to line-crossing")
            if args.publisher_id in NON_PRODUCTION_PUBLISHER_IDS or args.spki_sha256 in NON_PRODUCTION_SPKI_SHA256S:
                raise ReleaseError("genesis fingerprint calculation rejects TEST ONLY publisher identities")
            ledger = initialize_sequence_ledger(args.publisher_id, args.app_id, args.spki_sha256)
            print(ledger["genesis_sha256"])
            return 0
        if args.command == "initialize-ledger":
            protected_fingerprint = os.environ.get("NEPK_PRODUCTION_SEQUENCE_LEDGER_GENESIS_SHA256", "")
            if not protected_fingerprint or protected_fingerprint != args.expected_genesis_sha256:
                raise ReleaseError("expected genesis fingerprint must exactly match the protected Environment variable")
            client = GitHubReleaseClient(args.repository, _github_token())
            result = initialize_production_sequence_ledger(
                client,
                args.publisher_id,
                args.app_id,
                args.spki_sha256,
                args.expected_genesis_sha256,
            )
            print(json.dumps({"result": "INITIALIZED", **result}, sort_keys=True))
            return 0
        evidence_path = args.evidence
        try:
            evidence = execute(args)
        except (OSError, ValueError, KeyError, TypeError, PackError, ReleaseError, subprocess.CalledProcessError) as error:
            _write_json(evidence_path, {
                "version": 1,
                "result": "REJECTED",
                "version_input": args.version,
                "detail": str(error),
            })
            raise
        print(json.dumps({"result": "PASS", "tag": evidence["tag"], "package_sha256": evidence["package_sha256"], "release_result": evidence["release_result"]["result"]}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, PackError, ReleaseError, subprocess.CalledProcessError) as error:
        print(json.dumps({"result": "REJECTED", "detail": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
