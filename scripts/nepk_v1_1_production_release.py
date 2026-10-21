from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "package" / "vnext"))

from nepk_v1_1_pack import NON_PRODUCTION_PUBLISHER_IDS, PackError, _load_production_key, parse_version
from nepk_v1_1_release import ReleaseError, validate_release_request


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


def execute(args) -> dict:
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ReleaseError("production signing is restricted to a manually dispatched main workflow")
    source_sha = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ReleaseError("accepted main source SHA is missing or malformed")
    action = args.action
    request = json.loads(args.request.read_text(encoding="utf-8"))
    expected_ledger_sha256 = os.environ.get("NEPK_PRODUCTION_SEQUENCE_LEDGER_SHA256", "")
    validated = validate_release_request(
        request,
        expected_source_sha=source_sha,
        expected_action=action,
        expected_ledger_sha256=expected_ledger_sha256,
    )
    if len(validated["apps"]) != 1 or validated["apps"][0]["app_id"] != "line-crossing":
        raise ReleaseError("this production builder supports only the current line-crossing App")
    app = validated["apps"][0]
    publisher_id = os.environ.get("NEPK_PRODUCTION_PUBLISHER_ID", "")
    if publisher_id in NON_PRODUCTION_PUBLISHER_IDS or app["publisher_id"] != publisher_id:
        raise ReleaseError("selected App publisher does not match a production publisher")
    spki_sha256 = os.environ.get("NEPK_PRODUCTION_SPKI_SHA256", "")
    spki_hex = os.environ.get("NEPK_PRODUCTION_SPKI_DER_HEX", "")
    if re.fullmatch(r"[0-9a-f]{64}", spki_sha256) is None or re.fullmatch(r"(?:[0-9a-f]{2})+", spki_hex) is None:
        raise ReleaseError("production publisher SPKI configuration is missing or malformed")
    spki_der = bytes.fromhex(spki_hex)
    if hashlib.sha256(spki_der).hexdigest() != spki_sha256:
        raise ReleaseError("configured production SPKI DER does not match its pinned SHA-256")
    secret = os.environ.pop("NEPK_PRODUCTION_ISSUER_KEY", None)
    if not secret:
        raise ReleaseError("production signing key is unavailable in the protected Environment")
    native_version = tuple(parse_version(".".join(map(str, app["native_version"]))))
    ui_version = tuple(parse_version(".".join(map(str, app["ui_version"]))))
    if native_version[0] != 4 or ui_version[0] != 1:
        raise ReleaseError("line-crossing production versions must use native v4 and UI ABI v1")
    request_path = args.request.resolve()
    with tempfile.TemporaryDirectory(prefix="nepk-production-release-") as temporary:
        work = Path(temporary)
        key_path = work / "issuer.pem"
        key_path.write_text(secret, encoding="utf-8")
        key_path.chmod(0o600)
        del secret
        _, loaded_spki, fingerprint = _load_production_key(key_path, spki_sha256)
        if loaded_spki != spki_der or fingerprint != spki_sha256:
            raise ReleaseError("protected signing key does not match the configured production SPKI")
        spki_path = work / "issuer.spki.der"
        spki_path.write_bytes(spki_der)
        spki_path.chmod(0o600)
        ledger_path = work / "sequence-ledger.json"
        _write_json(ledger_path, request["sequence_ledger"])
        package_path = work / f"{app['asset_name']}"
        provenance_path = work / "provenance.json"
        verification_path = work / "independent-verification.json"
        trust_path = work / "trust.json"
        _write_json(trust_path, {
            "version": 1,
            "publishers": {
                publisher_id: {
                    "spki_der_hex": spki_der.hex(),
                    "spki_sha256": spki_sha256,
                },
            },
        })
        _run([
            "make", "-C", "apps/line-crossing/app", "elf-v4",
            f"V4_APP_VERSION={'.'.join(map(str, native_version))}",
        ])
        _run(["node", "tests/line-crossing-ui/browser-runner/build.mjs"])
        packer = _run([
            sys.executable, "package/vnext/nepk_v1_1_pack.py",
            "--mode", "production",
            "--elf", "apps/line-crossing/app/build/lc-line-crossing-v4.elf",
            "--ui-assets", "tests/line-crossing-ui/.build/production",
            "--key", str(key_path),
            "--out", str(package_path),
            "--provenance-out", str(provenance_path),
            "--publisher-id", publisher_id,
            "--app-id", app["app_id"],
            "--native-version", ".".join(map(str, native_version)),
            "--ui-version", ".".join(map(str, ui_version)),
            "--release-seq", str(app["release_seq"]),
            "--source-commit", source_sha,
            "--expected-spki-sha256", spki_sha256,
            "--sequence-ledger", str(ledger_path),
            "--expected-ledger-sha256", expected_ledger_sha256,
            "--sequence-record-id", app["sequence_record_id"],
        ])
        packer_report = json.loads(packer.stdout)
        independent = _run([
            sys.executable, "package/vnext/nepk_v1_1_verify.py",
            "--bundle", str(package_path),
            "--trust", str(trust_path),
            "--expect-publisher-id", publisher_id,
            "--expect-app-id", app["app_id"],
            "--compact",
        ])
        independent_report = json.loads(independent.stdout)
        _write_json(verification_path, independent_report)
        if independent_report.get("result") != "PASS":
            raise ReleaseError("independent NEPK verification did not PASS")
        package_sha256 = hashlib.sha256(package_path.read_bytes()).hexdigest()
        if package_sha256 != independent_report.get("package_sha256"):
            raise ReleaseError("independently verified package bytes changed before release planning")
        environment = os.environ.copy()
        environment["GITHUB_TOKEN"] = os.environ.get("GITHUB_TOKEN", "")
        release = subprocess.run([
            sys.executable, "package/vnext/nepk_v1_1_release.py", "execute",
            "--request", str(request_path),
            "--package", str(package_path),
            "--provenance", str(provenance_path),
            "--independent-report", str(verification_path),
            "--spki-der", str(spki_path),
            "--source-sha", source_sha,
            "--action", action,
            "--ledger-sha256", expected_ledger_sha256,
            "--repository", os.environ.get("GITHUB_REPOSITORY", ""),
        ], cwd=ROOT, text=True, capture_output=True, env=environment)
        evidence = {
            "version": 1,
            "action": action,
            "tag": validated["tag"],
            "source_sha": source_sha,
            "authorization_request_id": validated["request_id"],
            "sequence_ledger_sha256": validated["ledger_sha256"],
            "publisher_id": publisher_id,
            "publisher_spki_sha256": spki_sha256,
            "app_id": app["app_id"],
            "native_version": app["native_version"],
            "ui_version": app["ui_version"],
            "release_seq": app["release_seq"],
            "asset_name": app["asset_name"],
            "package_sha256": package_sha256,
            "independent_verification": independent_report,
            "provenance": json.loads(provenance_path.read_text(encoding="utf-8")),
            "packer_result": packer_report.get("result"),
            "release_result": "FAILED" if release.returncode else json.loads(release.stdout),
        }
        _write_json(args.evidence, evidence)
        if release.stdout:
            print(release.stdout, end="")
        if release.stderr:
            print(release.stderr, file=sys.stderr, end="")
        if release.returncode:
            raise ReleaseError("GitHub Release operation did not complete successfully")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--action", required=True, choices=("draft", "publish"))
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    try:
        evidence = execute(args)
    except (OSError, ValueError, KeyError, TypeError, PackError, ReleaseError, subprocess.CalledProcessError) as error:
        print(json.dumps({"result": "REJECTED", "detail": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"result": "PASS", "tag": evidence["tag"], "package_sha256": evidence["package_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
