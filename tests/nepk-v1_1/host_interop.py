from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / "package" / "vnext"))
sys.path.insert(0, str(ROOT / "package"))

import neapp_v4_format as v4
from nepk_v1_1_verify import verify_nepk

HOST_SOURCE_SHA = "dc0948c1e12e954612fbfa9769434bf01e449c3c"
EXPECTED_PUBLISHER = "ne301-exp-pub"
EXPECTED_APP = "line-crossing"
EXPECTED_SPKI_SHA256 = "06e732b1b94daeeef433297f7a8e797bf72b2fd3b882a4ec6a5490352931ebda"
HOST_PATHS = (
    "tests/sign_spike/shim",
    "tests/storage_gate/shim",
    "tests/app_installer",
    "tests/app_admission",
    "tests/sign_spike",
    "Custom/Services/AppHost",
    "Custom/Common/Inc",
    "Custom/Common/Utils",
    "Custom/Common/Lib",
    "tests/app_native_vnext",
)
INCLUDES = (
    "tests/sign_spike/shim",
    "tests/storage_gate/shim",
    "tests/app_installer",
    "tests/app_admission",
    "tests/sign_spike",
    "Custom/Services/AppHost",
    "Custom/Common/Inc",
    "Custom/Common/Utils",
    "Custom/Common/Lib",
    "Custom/Common/Lib/MbedTLS/include",
    "Custom/Common/Lib/MbedTLS/configs",
    "tests/app_native_vnext/build",
)


def _git(repo: Path, *args: str, text: bool = True):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text)


def _archive_host(repo: Path, target: Path) -> None:
    archive = _git(repo, "archive", "--format=tar", HOST_SOURCE_SHA, *HOST_PATHS,
                   text=False).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(target, filter="data")


def _run(command: list[str], cwd: Path, allow_failure: bool = False):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if result.returncode and not allow_failure:
        raise RuntimeError(f"pinned Host tool failed ({result.returncode})")
    return result


def _compile_host_runner(host_root: Path, app_runner: Path) -> Path:
    test_dir = host_root / "tests/app_native_vnext"
    build_dir = test_dir / "build"
    compiler = shlex.split(os.environ.get("CC", "cc"))
    flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
    flags.extend(f"-I{host_root / item}" for item in INCLUDES)
    flags.extend(["-DMBEDTLS_CONFIG_FILE=\"host_user_config.h\"", "-DMBEDTLS_ALLOW_PRIVATE_ACCESS"])
    object_path = build_dir / "nepk_host_parser.o"
    binary_path = test_dir / "nepk_host_parser"
    _run(compiler + flags + ["-c", str(app_runner), "-o", str(object_path)], host_root)
    library_objects = sorted(path for path in build_dir.glob("*.o") if path != object_path)
    parser_objects = [test_dir / "app_admission.o", test_dir / "generic_math.o"]
    _run(compiler + flags + ["-o", str(binary_path), str(object_path)]
         + [str(path) for path in parser_objects + library_objects], host_root)
    return binary_path


def _host_result(runner: Path, package: Path, publisher: str, spki_path: Path,
                 case: str) -> dict:
    result = _run([str(runner), case, str(package), publisher, str(spki_path), "0x3ff", str(2 * 1024 * 1024)],
                  runner.parent, allow_failure=True)
    match = re.search(r"HOST_C case=([^ ]+) result=([A-Z_]+) raw=([^ ]+) package_sha256=([0-9a-f]+)(.*)",
                      result.stdout.strip())
    if match is None:
        raise RuntimeError("pinned Host C admission parser returned no verdict")
    fields = dict(re.findall(r"([a-z0-9_]+)=([^ ]+)", result.stdout.strip()))
    return {
        "case": case,
        "result": match.group(2),
        "raw": match.group(3),
        "package_sha256": fields.get("package_sha256"),
        "native_tbs_sha256": fields.get("tbs_sha256"),
        "image_sha256": fields.get("image_sha256"),
        "publisher_spki_sha256": fields.get("spki_sha256"),
        "exit_code": result.returncode,
    }


def run_interop(package_path: Path, trust_path: Path, host_repo: Path) -> dict:
    host_repo = host_repo.resolve()
    commit_type = _git(host_repo, "cat-file", "-t", f"{HOST_SOURCE_SHA}^{{commit}}").stdout.strip()
    if commit_type != "commit":
        raise RuntimeError("pinned Host #104 source commit is unavailable")
    status = _git(host_repo, "status", "--porcelain").stdout.strip()
    if status:
        raise RuntimeError("Host checkout is dirty; the pinned archive was not built")
    trust = v4.load_trust_store_v4(trust_path)
    trusted_entry = trust.lookup(EXPECTED_PUBLISHER)
    if trusted_entry is None or trusted_entry[0] != EXPECTED_SPKI_SHA256:
        raise RuntimeError("external trust store does not contain the pinned Host TEST SPKI")
    spki = trusted_entry[1]
    data = package_path.read_bytes()
    report = verify_nepk(data, {EXPECTED_PUBLISHER: spki}, EXPECTED_PUBLISHER, EXPECTED_APP)
    native_len = int.from_bytes(data[8:12], "little")
    native = data[16:16 + native_len]
    with tempfile.TemporaryDirectory(prefix="nepk-v1-1-host-") as raw_work:
        work = Path(raw_work)
        host_root = work / "host"
        host_root.mkdir()
        _archive_host(host_repo, host_root)
        host_test = host_root / "tests/app_native_vnext"
        suite = _run(["make", "-s", "-C", str(host_test), "test"], host_root)
        suite_match = re.search(r"app_native_vnext: (\d+) checks, (\d+) failures", suite.stdout)
        if suite_match is None or int(suite_match.group(2)) != 0:
            raise RuntimeError("pinned Host native admission suite did not report zero failures")
        runner = _compile_host_runner(host_root, ROOT / "tests/package-vnext/joint_host_parser.c")
        native_path = work / "native.neapp.v4"
        native_path.write_bytes(native)
        spki_path = work / "trusted-test.spki.der"
        spki_path.write_bytes(spki)
        positive = _host_result(runner, native_path, EXPECTED_PUBLISHER, spki_path, "nepk-native")
        if positive["result"] != "PASS" or positive["exit_code"] != 0:
            raise RuntimeError("pinned Host C verifier rejected the NEPK native member")
        native_report, native_error = v4.verify_package_v4(
            native, trust, v4.default_policy(), host_admission=True,
        )
        if native_error is not None:
            raise RuntimeError("App v4 verifier rejected the NEPK native member")
        if positive["native_tbs_sha256"] != native_report["content_identity_sha256"]:
            raise RuntimeError("Host and App native TBS identities differ")
        if positive["publisher_spki_sha256"] != EXPECTED_SPKI_SHA256:
            raise RuntimeError("Host C verifier reported a different SPKI fingerprint")

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_spki_path = work / "wrong.spki.der"
        wrong_spki_path.write_bytes(wrong_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        wrong_spki = _host_result(runner, native_path, EXPECTED_PUBLISHER, wrong_spki_path,
                                  "wrong-spki")
        if wrong_spki["result"] != "PUBLISHER_UNTRUSTED":
            raise RuntimeError("pinned Host C verifier accepted the wrong SPKI")

        tampered = bytearray(native)
        tampered[224 + v4.NATIVE_HEADER_SIZE] ^= 1
        tampered_path = work / "native-signature-tampered.neapp.v4"
        tampered_path.write_bytes(tampered)
        tampered_result = _host_result(runner, tampered_path, EXPECTED_PUBLISHER, spki_path,
                                       "signature-tamper")
        if tampered_result["result"] != "SIGNATURE_INVALID":
            raise RuntimeError("pinned Host C verifier accepted a tampered native signature TBS")
        return {
            "result": "PASS",
            "host_source_sha": HOST_SOURCE_SHA,
            "host_worktree_clean": True,
            "host_admission_suite": suite_match.group(0),
            "outer_package_sha256": report["package_sha256"],
            "native_member_sha256": report["native_member_sha256"],
            "native_tbs_sha256": report["native_tbs_sha256"],
            "spki_sha256": EXPECTED_SPKI_SHA256,
            "cases": [positive, wrong_spki, tampered_result],
            "boundary": "Host #104 native member admission parser only; no Host NEPK/NEUI admission, install, persistent floor, or device behavior claim",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path)
    parser.add_argument("--host-repo", type=Path, default=Path("/Users/harryhua/Documents/GitHub/ne301"))
    parser.add_argument("--evidence-out", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = run_interop(args.package, args.trust, args.host_repo)
        args.evidence_out.parent.mkdir(parents=True, exist_ok=True)
        args.evidence_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(json.dumps({"result": "REJECTED", "detail": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
