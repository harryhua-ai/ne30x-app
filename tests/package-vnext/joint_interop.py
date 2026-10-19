#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_BASE = "71f1850063f022b86f3b027e27eaabb992de60b0"
HOST_BASE = "f6a851a3c1c116f85d9a2609c9d8b63b1d0a66f1"
EVIDENCE = ROOT / "docs/evidence/package-vnext"
GOLDENS = EVIDENCE / "spec/app-pr37"
HOST_PATHS = (
    "Custom/Services/AppHost",
    "Custom/Common/Inc",
    "Custom/Common/Utils",
    "Custom/Common/Lib/MbedTLS",
    "Custom/Common/Lib/cJSON",
    "Custom/Common/Lib/mongoose",
    "Custom/Common/Lib/mmx108",
    "Custom/Hal",
    "Custom/Core/Video",
    "Custom/Core/System",
    "Custom/Core/Data",
    "Custom/Services/Video",
    "Custom/Services/AI",
    "Custom/Services/Web",
    "Custom/Common/Lib/nvs",
    "Custom/Common/Lib/pp",
    "Middlewares/ST/STM32_ISP_Library/isp/Inc",
    "BSP/Utilities/Fonts",
    "tests/app_native_vnext",
    "tests/app_host_session",
    "tests/app_installer",
    "tests/app_admission",
    "tests/sign_spike",
    "tests/storage_gate",
)
HOST_PIN_PATHS = (
    "Custom/Services/AppHost/app_admission.c",
    "Custom/Services/AppHost/app_admission.h",
    "tests/app_native_vnext/Makefile",
    "tests/app_native_vnext/test_app_native_vnext.c",
    "tests/app_admission/gen_v4_vectors.py",
    "tests/app_host_session/Makefile",
    "tests/app_host_session/test_app_host_session.c",
    "Custom/Services/AppHost/app_host_session.c",
)
FULL_CAPS = 0x3FF
FULL_EXEC_REGION = 2 * 1024 * 1024


def show(command: list[str], cwd: Path | None = None, allow_failure: bool = False):
    print(f"$ cd {cwd}" if cwd else "$ (current directory)")
    print(f"$ {shlex.join([str(x) for x in command])}")
    proc = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if proc.returncode and not allow_failure:
        raise RuntimeError(f"command failed ({proc.returncode}): {shlex.join(command)}")
    return proc


def git_text(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def git_blob(repo: Path, commit: str, path: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{path}"],
                          check=True, stdout=subprocess.PIPE).stdout


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tbs_prefix(data: bytes) -> bytes:
    manifest_len = struct.unpack_from("<I", data, 8)[0]
    native_len = struct.unpack_from("<I", data, 12)[0]
    return data[:16 + manifest_len + native_len]


def extract_archive(repo: Path, commit: str, paths: tuple[str, ...], target: Path):
    target.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar",
                           commit, *paths], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as archive:
        archive.extractall(target)


def write_trust(path: Path, publisher: str, spki: bytes):
    path.write_text(json.dumps({
        "version": 1,
        "publishers": {
            publisher: {
                "spki_der_hex": spki.hex(),
                "spki_sha256": sha256(spki),
            }
        },
    }, indent=2) + "\n", encoding="utf-8")


def sign_package(data: bytes, key) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    blob = bytearray(data)
    manifest_len = struct.unpack_from("<I", blob, 8)[0]
    native_len = struct.unpack_from("<I", blob, 12)[0]
    tbs_len = 16 + manifest_len + native_len
    tbs = bytes(blob[:tbs_len])
    sig = key.sign(tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return tbs + sig


def make_vectors(live: bytes, enable: bytes, d1_key, d2_key,
                 work: Path, d1_spki: bytes, d2_spki: bytes):
    vectors = work / "vectors"
    vectors.mkdir(parents=True, exist_ok=True)

    def save(name: str, data: bytes):
        path = vectors / f"{name}.neapp.v4"
        path.write_bytes(data)
        return path

    out = {}
    out["live-only"] = save("live-only", live)
    out["enable"] = save("enable", enable)
    tbs_len = 16 + struct.unpack_from("<I", live, 8)[0] + struct.unpack_from("<I", live, 12)[0]
    out["tbs-tamper"] = save("tbs-tamper", live[:224 + 32] +
                             bytes([live[224 + 32] ^ 1]) + live[224 + 33:])
    sig_tamper = bytearray(live)
    sig_tamper[-1] ^= 1
    out["signature-tamper"] = save("signature-tamper", bytes(sig_tamper))
    out["unsigned"] = save("unsigned", live[:tbs_len])
    unknown_major = bytearray(live)
    unknown_major[5] = 5
    out["cross-major"] = save("cross-major", bytes(unknown_major))

    cap_dependency = bytearray(enable[:16 + struct.unpack_from("<I", enable, 8)[0] +
                                  struct.unpack_from("<I", enable, 12)[0]])
    caps = struct.unpack_from("<I", cap_dependency, 16 + 72)[0]
    struct.pack_into("<I", cap_dependency, 16 + 72, caps & ~(1 << 6))
    struct.pack_into("<I", cap_dependency, 16 + 176, 0)
    out["enable-missing-bit6"] = save("enable-missing-bit6",
                                      sign_package(bytes(cap_dependency), d2_key))

    live_closure = bytearray(live[:tbs_len])
    struct.pack_into("<I", live_closure, 16 + 184, 9007)
    out["live-closure"] = save("live-closure", sign_package(bytes(live_closure), d2_key))

    write_trust(work / "trust-d2.json", "dev-publisher", d2_spki)
    write_trust(work / "trust-wrong-spki.json", "dev-publisher", d1_spki)
    write_trust(work / "trust-wrong-owner.json", "other-publisher", d2_spki)
    out["trust-d2"] = work / "trust-d2.json"
    out["trust-wrong-spki"] = work / "trust-wrong-spki.json"
    out["trust-wrong-owner"] = work / "trust-wrong-owner.json"
    return out


def compile_host_runner(host_root: Path, app_runner: Path, work: Path):
    source_root = host_root
    test_dir = source_root / "tests/app_native_vnext"
    build_dir = test_dir / "build"
    includes = (
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
    cc = shlex.split(os.environ.get("CC", "cc"))
    flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
    flags.extend(f"-I{source_root / item}" for item in includes)
    flags.extend(["-DMBEDTLS_CONFIG_FILE=\"host_user_config.h\"",
                  "-DMBEDTLS_ALLOW_PRIVATE_ACCESS"])
    runner_obj = build_dir / "joint_host_parser.o"
    runner_bin = test_dir / "joint_host_parser"
    show(cc + flags + ["-c", str(app_runner), "-o", str(runner_obj)], cwd=source_root)
    library_objects = sorted(path for path in build_dir.glob("*.o") if path != runner_obj)
    parser_objects = [test_dir / "app_admission.o", test_dir / "generic_math.o"]
    link_command = cc + flags + ["-o", str(runner_bin), str(runner_obj)]
    link_command += [str(path) for path in parser_objects]
    link_command += [str(path) for path in library_objects]
    show(link_command, cwd=source_root)
    return runner_bin


def app_verify(verifier: Path, package: Path, trust: Path, work: Path,
               host_caps: int = FULL_CAPS, exec_region: int = FULL_EXEC_REGION):
    policy_path = work / f"policy-{package.stem}-{host_caps:x}-{exec_region:x}.json"
    policy_path.write_text(json.dumps({
        "host_caps": host_caps,
        "exec_region_bytes": exec_region,
    }, sort_keys=True) + "\n", encoding="utf-8")
    proc = show([sys.executable, str(verifier), "--package", str(package),
                 "--trust", str(trust), "--policy", str(policy_path), "--compact"],
                cwd=ROOT, allow_failure=True)
    json_lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    try:
        payload = json.loads(json_lines[-1])
    except (IndexError, ValueError) as exc:
        raise RuntimeError(f"App verifier did not return JSON for {package}: {proc.stdout}") from exc
    return payload.get("result", "PASS"), payload


def host_verify(runner: Path, case_name: str, package: Path, publisher: str,
                spki: Path, host_caps: int = FULL_CAPS,
                exec_region: int = FULL_EXEC_REGION):
    proc = show([str(runner), case_name, str(package), publisher, str(spki),
                 hex(host_caps), str(exec_region)], cwd=runner.parent, allow_failure=True)
    match = re.search(r"HOST_C case=.* result=([A-Z_]+) raw=([^ ]+)", proc.stdout)
    if proc.returncode != 0 or match is None:
        raise RuntimeError(f"Host C parser did not return a category for {case_name}")
    fields = dict(re.findall(r"([a-z0-9_]+)=([^ ]+)", proc.stdout.strip()))
    return fields["result"], fields


def packer_command(packer: Path, image: Path, output: Path, key: Path,
                   publisher: str, caps: str, extra: tuple[str, ...]):
    return [sys.executable, str(packer), "--image", str(image), "--out", str(output),
            "--key", str(key), "--publisher-id", publisher,
            "--app-id", "lc-test-app", "--version", "4.0.0",
            "--host-caps", caps, *extra, "--sidecar", "none"]


def write_markdown_report(report: dict):
    lines = [
        "# AC3 App/Host signed-package interoperability",
        "",
        "Status: PASS for the offline cross-repository parser matrix.",
        "",
        f"- App signer/independent verifier source: `{report['app_base_sha']}`",
        f"- App candidate at evidence run: `{report['app_candidate_sha']}`",
        f"- Host parser/verifier source: `{report['host_parser_sha']}`",
        "- Host source was archived from that exact commit into a temporary directory; the Host repository was not modified.",
        "- Reproduction: `bash tests/package-vnext/run.sh` or `python3 tests/package-vnext/joint_interop.py`.",
        "- Complete commands and stdout: [`joint-interop.log`](joint-interop.log).",
        "- Structured report includes exact package bytes as hex: [`joint-interop.json`](joint-interop.json).",
        "",
        "## Exact App-signed packages",
        "",
        "The App baseline packer generated each signed package, and the script required full-byte equality with both the archived golden and the Host fixture before invoking the Host C parser.",
        "",
        "| Profile | Binary | Bytes | Package SHA-256 | SHA-256(TBS) | Image SHA-256 | Publisher / SPKI SHA-256 | Required caps | Signature | Quotas |",
        "| --- | --- | ---: | --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for name in ("live-only", "enable"):
        item = report["goldens"][name]
        quotas = ", ".join(f"{key}={value}" for key, value in item["quotas"].items())
        binary_path = Path(item["file"]).relative_to("docs/evidence/package-vnext")
        lines.append(
            f"| {name} | [`{Path(item['file']).name}`]({binary_path}) | {item['bytes']} | "
            f"`{item['package_sha256']}` | `{item['tbs_sha256']}` | "
            f"`{item['native_file_sha256']}` | `{item['publisher_id']}` / "
            f"`{item['publisher_spki_sha256']}` | `{item['required_host_caps']}` | "
            f"{item['signature_len']} B DER | {quotas} |"
        )
    lines.extend([
        "",
        "The live-only profile is caps `0x223` (bits 0, 1, 5, 9), with no bit 6 and zero control/snapshot quotas; its 9008-byte publish and 64-track closure passes. The Enable profile is caps `0x173` (bits 0, 1, 4, 5, 6, 8), with `state_quota=4096` and `control_max=256` for ENB1 control.",
        "",
        "Both package byte strings and SPKI DER byte strings are preserved under [`spec/app-pr37/`](spec/app-pr37/). Their exact bytes are also embedded in `joint-interop.json`.",
        "",
        "## Same-byte App verifier / Host C parser matrix",
        "",
        "Each row feeds the same package file to the App v4 verifier and the compiled `app_admission_verify_package` C implementation from the pinned Host source. The table reports the full package SHA-256 so the compared input is unambiguous.",
        "",
        "| Case | App result | Host C result | Expected category | Same category | Package SHA-256 |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for row in report["joint_matrix"]:
        lines.append(
            f"| {row['case']} | `{row['app_result']}` | `{row['host_result']}` | "
            f"`{row['expected']}` | {'PASS' if row['same_category'] and row['pass'] else 'FAIL'} | "
            f"`{row['package_sha256']}` |"
        )
    lines.extend([
        "",
        "The negatives exercise TBS/signature mutation, unsigned input, unknown major generation, wrong SPKI and publisher owner, missing Enable dependency bit 6, live closure overrun, unsupported live capability, and execution-region floor. Each was constructed so the tested parser rule fires; signed semantic negatives were re-signed with the public d=2 test scalar.",
        "",
        "## Host integration and runtime boundary",
        "",
        f"- `app_native_vnext`: {report['host_integration_suite']['checks']} checks, {report['host_integration_suite']['failures']} failures.",
        f"- `app_host_session`: {report['host_session_suite']['checks']} checks, {report['host_session_suite']['failures']} failures.",
        f"- Live runtime authorization: `{report['runtime_live_authorization']}`. Shape verification PASS does not grant live runtime access; Host #91 producer-ingest remains unavailable.",
        "- NE301 firmware ARM target build, device install/execute, production signing keys, and production/device behavior: NOT_RUN.",
        "- The separate required package-v3 legacy regression cross-compiled only its synthetic hello-app fixtures with `arm-none-eabi-gcc`; it did not build NE301 firmware.",
        "",
    ])
    (EVIDENCE / "joint-interoperability.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-repo", type=Path, default=Path("/Users/harryhua/Documents/GitHub/ne301"))
    parser.add_argument("--update-goldens", action="store_true")
    parser.add_argument("--no-report", action="store_true")
    args = parser.parse_args()
    host_repo = args.host_repo.resolve()
    if not host_repo.is_dir():
        raise RuntimeError(f"Host repository is unavailable: {host_repo}")

    app_candidate = git_text(ROOT, "rev-parse", "HEAD")
    if git_text(ROOT, "cat-file", "-t", f"{APP_BASE}^{{commit}}") != "commit":
        raise RuntimeError(f"App baseline commit is unavailable: {APP_BASE}")
    if git_text(host_repo, "cat-file", "-t", f"{HOST_BASE}^{{commit}}") != "commit":
        raise RuntimeError(f"Host parser commit is unavailable: {HOST_BASE}")
    print(f"APP_BASE_SHA={APP_BASE}")
    print(f"APP_CANDIDATE_SHA={app_candidate}")
    print(f"HOST_SOURCE_SHA={HOST_BASE}")
    print(f"HOST_SOURCE_REPO={host_repo}")

    work_parent = ROOT / "tests/package-vnext/work"
    work_parent.mkdir(parents=True, exist_ok=True)
    report_rows = []
    with tempfile.TemporaryDirectory(prefix="joint-interop-", dir=work_parent) as raw_work:
        work = Path(raw_work)
        app_root = work / "app-71f18500"
        host_root = work / "host-f6a851a3"
        extract_archive(ROOT, APP_BASE, (
            "package/vnext", "tests/package-vnext", "tests/spec-vnext",
            "docs/evidence/package-vnext/spec/golden.neapp.v4",
        ), app_root)
        extract_archive(host_repo, HOST_BASE, HOST_PATHS, host_root)

        app_tests = app_root / "tests/package-vnext"
        identity_dir = work / "identity"
        show([sys.executable, str(app_tests / "make_test_identity.py"),
              "--out-dir", str(identity_dir)], cwd=app_root)
        image = work / "golden-native.bin"
        show([sys.executable, str(app_tests / "make_v4_test_image.py"),
              "--out", str(image)], cwd=app_root)
        image_bytes = image.read_bytes()
        key_d1 = identity_dir / "keys/d1-test-signer.pem"
        key_d2 = identity_dir / "keys/d2-test-signer.pem"
        d1_spki = (identity_dir / "test-publisher.spki.der").read_bytes()
        d2_spki = (identity_dir / "dev-publisher.spki.der").read_bytes()
        trust_both = identity_dir / "trust-both.json"

        live_pack_output = work / "live-only-repack.neapp.v4"
        enable_pack_output = work / "enable-repack.neapp.v4"
        show(packer_command(app_root / "package/vnext/neapp_pack_v4.py", image,
                            live_pack_output, key_d2, "dev-publisher", "0x223",
                            ("--control-max", "0", "--snapshot-max", "0",
                             "--live-publish-max", "9008", "--live-track-max", "64")),
             cwd=app_root)
        show(packer_command(app_root / "package/vnext/neapp_pack_v4.py", image,
                            enable_pack_output, key_d2, "dev-publisher", "0x173",
                            ("--state-quota", "4096", "--control-max", "256")),
             cwd=app_root)
        host_live = git_blob(host_repo, HOST_BASE,
                             "tests/app_native_vnext/fixtures/app-pr37/live-only.neapp.v4")
        host_enable = git_blob(host_repo, HOST_BASE,
                               "tests/app_native_vnext/fixtures/app-pr37/enable.neapp.v4")
        host_golden = git_blob(host_repo, HOST_BASE,
                               "tests/app_native_vnext/fixtures/app-pr37/golden.neapp.v4")
        live = live_pack_output.read_bytes()
        enable = enable_pack_output.read_bytes()
        if live != host_live:
            raise RuntimeError("App 71f18500 packer live-only package differs from the preserved App golden")
        if enable != host_enable:
            raise RuntimeError("App 71f18500 packer Enable package differs from the preserved App golden")
        print(f"PACKER_PACKAGE_MATCH live-only sha256={sha256(live)} bytes={len(live)}")
        print(f"PACKER_PACKAGE_MATCH enable sha256={sha256(enable)} bytes={len(enable)}")
        print(f"PACKER_TBS_MATCH live-only sha256={sha256(tbs_prefix(live))} "
              f"exact_package_sha256={sha256(live)}")
        print(f"PACKER_TBS_MATCH enable sha256={sha256(tbs_prefix(enable))} "
              f"exact_package_sha256={sha256(enable)}")
        live_path = work / "live-only.neapp.v4"
        enable_path = work / "enable.neapp.v4"
        live_path.write_bytes(live)
        enable_path.write_bytes(enable)

        generated = {
            "golden.neapp.v4": host_golden,
            "live-only.neapp.v4": live,
            "enable.neapp.v4": enable,
            "test-publisher.spki.der": git_blob(
                host_repo, HOST_BASE,
                "tests/app_native_vnext/fixtures/app-pr37/test-publisher.spki.der"),
            "dev-publisher.spki.der": git_blob(
                host_repo, HOST_BASE,
                "tests/app_native_vnext/fixtures/app-pr37/dev-publisher.spki.der"),
        }
        if generated["golden.neapp.v4"] != (app_root / "docs/evidence/package-vnext/spec/golden.neapp.v4").read_bytes():
            raise RuntimeError("Host fixture tracked golden differs from the App 71f18500 golden")
        if generated["test-publisher.spki.der"] != d1_spki or generated["dev-publisher.spki.der"] != d2_spki:
            raise RuntimeError("Host fixture SPKIs differ from the App 71f18500 test identities")
        if args.update_goldens:
            GOLDENS.mkdir(parents=True, exist_ok=True)
            for name, data in generated.items():
                target = GOLDENS / name
                target.write_bytes(data)
                print(f"GOLDEN_WRITE {target.relative_to(ROOT)} bytes={len(data)} sha256={sha256(data)}")
        else:
            for name, data in generated.items():
                target = (EVIDENCE / "spec" / name) if name == "golden.neapp.v4" else GOLDENS / name
                if not target.is_file() or target.read_bytes() != data:
                    raise RuntimeError(f"App baseline output differs byte-for-byte from {target}")
                print(f"GOLDEN_MATCH {target.relative_to(ROOT)} bytes={len(data)} sha256={sha256(data)}")

        baseline_verifier = app_root / "package/vnext/neapp_verify_v4.py"
        from cryptography.hazmat.primitives import serialization
        d1_private = serialization.load_pem_private_key(key_d1.read_bytes(), password=None)
        d2_private = serialization.load_pem_private_key(key_d2.read_bytes(), password=None)
        vectors = make_vectors(live, enable, d1_private, d2_private,
                               work, d1_spki, d2_spki)

        host_fixture = host_root / "tests/app_native_vnext/fixtures/app-pr37"
        host_fixture.mkdir(parents=True, exist_ok=True)
        for name, data in generated.items():
            if name == "golden.neapp.v4":
                target = host_fixture / name
            elif name in ("live-only.neapp.v4", "enable.neapp.v4",
                          "test-publisher.spki.der", "dev-publisher.spki.der"):
                target = host_fixture / name
            else:
                continue
            target.write_bytes(data)
            print(f"HOST_FIXTURE {name} bytes={len(data)} sha256={sha256(data)}")

        host_test = host_root / "tests/app_native_vnext"
        host_suite = show(["make", "-s", "-C", str(host_test), "test"], cwd=host_root,
                          allow_failure=True)
        if host_suite.returncode != 0:
            raise RuntimeError("pinned Host app_native_vnext C integration suite failed")
        suite_match = re.search(r"app_native_vnext: (\d+) checks, (\d+) failures", host_suite.stdout)
        if suite_match is None or int(suite_match.group(2)) != 0:
            raise RuntimeError("pinned Host C integration suite did not report zero failures")
        suite_checks = int(suite_match.group(1))

        host_session_test = host_root / "tests/app_host_session"
        session_suite = show(["make", "-s", "-C", str(host_session_test), "test"],
                             cwd=host_root, allow_failure=True)
        if session_suite.returncode != 0:
            raise RuntimeError("pinned Host app_host_session C suite failed")
        session_match = re.search(r"app_host_session: total=(\d+) fail=(\d+)",
                                  session_suite.stdout)
        if session_match is None or int(session_match.group(2)) != 0:
            raise RuntimeError("pinned Host session C suite did not report zero failures")
        session_checks = int(session_match.group(1))
        runtime_source_path = "Custom/Services/AppHost/app_host_session.c"
        runtime_source = git_blob(host_repo, HOST_BASE, runtime_source_path).decode("utf-8")
        runtime_start = runtime_source.index("static int32_t sess_api_live_publish")
        runtime_end = runtime_source.index("\n}", runtime_start) + 2
        runtime_handler = runtime_source[runtime_start:runtime_end]
        if "return APP_SESSION_ERR_UNAVAILABLE;" not in runtime_handler:
            raise RuntimeError("Host live_publish runtime handler no longer returns UNAVAILABLE")
        print("HOST_RUNTIME_LIVE_PUBLISH=APP_SESSION_ERR_UNAVAILABLE "
              "(Host #91 producer-ingest is not implemented)")
        runner = compile_host_runner(host_root, ROOT / "tests/package-vnext/joint_host_parser.c", work)

        case_specs = (
            ("live-only", live_path, "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, FULL_EXEC_REGION, "PASS"),
            ("enable", enable_path, "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, FULL_EXEC_REGION, "PASS"),
            ("tbs-tamper", vectors["tbs-tamper"], "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, FULL_EXEC_REGION, "SIGNATURE_INVALID"),
            ("signature-tamper", vectors["signature-tamper"], "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, FULL_EXEC_REGION, "SIGNATURE_INVALID"),
            ("unsigned", vectors["unsigned"], "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, FULL_EXEC_REGION, "BAD_PACKAGE"),
            ("cross-major", vectors["cross-major"], "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, FULL_EXEC_REGION, "BAD_PACKAGE"),
            ("wrong-spki", live_path, "dev-publisher", identity_dir / "test-publisher.spki.der", vectors["trust-wrong-spki"], FULL_CAPS, FULL_EXEC_REGION, "PUBLISHER_UNTRUSTED"),
            ("wrong-owner", live_path, "other-publisher", identity_dir / "dev-publisher.spki.der", vectors["trust-wrong-owner"], FULL_CAPS, FULL_EXEC_REGION, "PUBLISHER_UNTRUSTED"),
            ("enable-missing-bit6", vectors["enable-missing-bit6"], "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, FULL_EXEC_REGION, "BAD_PACKAGE"),
            ("live-closure", vectors["live-closure"], "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, FULL_EXEC_REGION, "RESOURCE_LIMIT"),
            ("host-live-capability-denied", live_path, "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, 0x1FF, FULL_EXEC_REGION, "ABI_INCOMPATIBLE"),
            ("exec-region-floor", live_path, "dev-publisher", identity_dir / "dev-publisher.spki.der", trust_both, FULL_CAPS, 64, "RESOURCE_LIMIT"),
        )

        for name, package, publisher, spki, trust, host_caps, exec_region, expected in case_specs:
            app_category, app_payload = app_verify(baseline_verifier, package, trust, work,
                                                   host_caps, exec_region)
            host_category, host_fields = host_verify(runner, name, package, publisher, spki,
                                                     host_caps, exec_region)
            match = app_category == host_category == expected
            row = {
                "case": name,
                "package_sha256": sha256(package.read_bytes()),
                "expected": expected,
                "app_result": app_category,
                "host_result": host_category,
                "same_category": app_category == host_category,
                "pass": match,
            }
            if app_category == "PASS" and host_category == "PASS":
                app_caps = int(app_payload["required_host_caps"], 0)
                digest_match = (
                    app_payload["content_identity_sha256"] == host_fields.get("tbs_sha256") and
                    app_payload["native_file_sha256"] == host_fields.get("image_sha256") and
                    app_payload["publisher_key_sha256"] == host_fields.get("spki_sha256") and
                    app_caps == int(host_fields["caps"], 0)
                )
                row["digest_and_caps_match"] = digest_match
                row["tbs_sha256"] = host_fields.get("tbs_sha256")
                row["image_sha256"] = host_fields.get("image_sha256")
                row["publisher_spki_sha256"] = host_fields.get("spki_sha256")
                row["required_host_caps"] = host_fields.get("caps")
                row["pass"] = row["pass"] and digest_match
            report_rows.append(row)
            print(f"JOINT case={name} app={app_category} host={host_category} "
                  f"expected={expected} match={'PASS' if row['pass'] else 'FAIL'} "
                  f"package_sha256={row['package_sha256']}")
            if not row["pass"]:
                raise RuntimeError(f"App/Host result mismatch in {name}: {row}")

        print(f"HOST_INTEGRATION_SUITE checks={suite_checks} failures=0 "
              "source=tests/app_native_vnext/test_app_native_vnext.c")
        print(f"HOST_SESSION_SUITE checks={session_checks} failures=0 "
              "live_publish=APP_SESSION_ERR_UNAVAILABLE")

        def package_record(path: Path, publisher: str, caps: int, quotas: dict):
            data = path.read_bytes()
            trust = identity_dir / "trust-both.json"
            _, payload = app_verify(baseline_verifier, path, trust, work)
            tbs_len = 16 + struct.unpack_from("<I", data, 8)[0] + struct.unpack_from("<I", data, 12)[0]
            return {
                "file": str((GOLDENS / path.name).relative_to(ROOT)),
                "bytes": len(data),
                "package_sha256": sha256(data),
                "package_hex": data.hex(),
                "tbs_sha256": payload["content_identity_sha256"],
                "native_file_sha256": payload["native_file_sha256"],
                "publisher_id": publisher,
                "publisher_spki_sha256": payload["publisher_key_sha256"],
                "required_host_caps": f"0x{caps:03x}",
                "run_profile": payload["run_profile"],
                "quotas": quotas,
                "signature_len": len(data) - tbs_len,
            }

        report = {
            "app_base_sha": APP_BASE,
            "app_candidate_sha": app_candidate,
            "host_parser_sha": HOST_BASE,
            "host_parser_sources": {
                path: git_text(host_repo, "rev-parse", f"{HOST_BASE}:{path}")
                for path in HOST_PIN_PATHS
            },
            "goldens": {
                "live-only": package_record(live_path, "dev-publisher", 0x223, {
                    "event_max": 0, "state_quota": 0, "report_max": 0,
                    "control_max": 0, "snapshot_max": 0,
                    "live_publish_max": 9008, "live_track_max": 64,
                }),
                "enable": package_record(enable_path, "dev-publisher", 0x173, {
                    "event_max": 0, "state_quota": 4096, "report_max": 0,
                    "control_max": 256, "snapshot_max": 0,
                    "live_publish_max": 0, "live_track_max": 0,
                }),
            },
            "joint_matrix": report_rows,
            "host_integration_suite": {
                "checks": suite_checks,
                "failures": 0,
                "evidence": "pinned Host app_native_vnext suite, with App golden fixtures injected in temporary archive",
            },
            "host_session_suite": {
                "checks": session_checks,
                "failures": 0,
                "runtime_live_publish": "APP_SESSION_ERR_UNAVAILABLE",
                "source": runtime_source_path,
                "source_blob": git_text(host_repo, "rev-parse", f"{HOST_BASE}:{runtime_source_path}"),
                "evidence": "pinned Host app_host_session C suite",
            },
            "runtime_live_authorization": "APP_SESSION_ERR_UNAVAILABLE; Host #91 producer-ingest is not implemented",
            "production_keys_device_arm_install_network": "NOT_RUN",
        }
        if not args.no_report:
            report_path = EVIDENCE / "joint-interop.json"
            report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
            print(f"REPORT_WRITE {report_path.relative_to(ROOT)}")
            write_markdown_report(report)
            print("REPORT_WRITE docs/evidence/package-vnext/joint-interoperability.md")
    print(f"JOINT_INTEROP PASS cases={len(report_rows)} "
          f"host_vnext={suite_checks}/0 host_session={session_checks}/0")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"JOINT_INTEROP FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
