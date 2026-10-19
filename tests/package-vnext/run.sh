#!/usr/bin/env bash
# run.sh — one-command signed-native-vNext (.neapp v4) offline suite (App #36).
#
# Pipeline (all OFFLINE; no device, no network, no production keys):
#   [0/8] preflight (python3 + cryptography + openssl; NO toolchain build)
#   [1/8] frozen legacy vector suites UNCHANGED and byte-stable:
#         spec-v2, spec-v3, then the vNext spec suite itself
#   [2/8] NON-PRODUCTION v4 test identities (PUBLIC d=1 golden signer and
#         d=2 cross-publisher; provenance documented, keys gitignored)
#   [3/8] legacy package-tool zero-degradation reproduction (unmodified
#         v2/v3 packers+verifiers rebuild the committed #12/#19 goldens
#         byte-identically under tests/package-vnext/work/; the v1 golden
#         still verifies) — committed evidence is never rewritten
#   [4/8] controlled v4 native images (64B function table + Thumb stub)
#   [5/8] golden replica pack (d=1): byte-identical to the independent
#         spec-vnext golden (docs/evidence/package-vnext/spec/)
#   [6/8] dev-key packages: 4.0.0 / 4.1.0 upgrade / alt-image conflict /
#         ENABLE_CONTROL-shaped / LIVE_PUBLISH-shaped (track 64 @ 9008B)
#   [7/8] rejection matrix + cross-major fail-closed (v4_cases.py)
#   [8/8] structured evidence -> docs/evidence/package-vnext/artifacts.json
#
# Key discipline: only PUBLIC non-production test scalars (d=1, d=2);
# private keys live under tests/package-vnext/work/ (gitignored) and are
# never printed; a signed-format PASS never claims Host/native runtime
# admission, device capacity, floor/Enable semantics, or live delivery.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/tests/package-vnext/work"
PKG_DIR="$WORK/pkg"
IMG_DIR="$WORK/img"
LOG="$ROOT/docs/evidence/package-vnext/run.log"
PYTHON=${PYTHON:-python3}
SPEC_EVIDENCE="$ROOT/docs/evidence/package-vnext/spec"

SPKI_D1_SHA=5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3
SPKI_D2_SHA=dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba
GOLDEN_NATIVE_SHA=845e09288e0f1d876832dcda553580c6aa64ef17f08b9e529550aefa4db12cd1
GOLDEN_TBS_SHA=581e3ae98afef313de0bdf7d8bc85c2a36585a7c28e609dea183a558e599e095
GOLDEN_PKG_SHA=e6a7fedc8cda9f3900311bc077de2a3ea79002d10b23241d1690c9e28ee46e0e
V3_GOLDEN_NATIVE_SHA=aa8c3ef6e4082656c76255807bee5a7c562ad212a0c3e2a4f009a62129cdee69

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$ROOT/docs/evidence/package-vnext"
exec > >(tee "$LOG") 2>&1

step "[0/8] preflight"
command -v "$PYTHON" >/dev/null || fail "python3 missing"
"$PYTHON" -c 'import cryptography' 2>/dev/null || fail "python cryptography missing"
command -v openssl >/dev/null || fail "openssl missing"
echo "python3=$($PYTHON --version 2>&1) cryptography=$($PYTHON -c 'import cryptography; print(cryptography.__version__)') openssl=$(openssl version 2>&1 | awk '{print $1 $2}')"
rm -rf "$WORK"
mkdir -p "$PKG_DIR" "$IMG_DIR"

step "[1/8] frozen vector suites UNCHANGED (spec-v2, spec-v3) + vNext spec suite"
"$PYTHON" "$ROOT/tests/spec-v2/run_all_tests.py" >/dev/null \
    || fail "spec-v2 suite regressed"
git -C "$ROOT" diff --quiet -- docs/evidence/spec-v2 \
    || fail "spec-v2 evidence was rewritten (must stay byte-identical)"
echo "spec-v2 suite: PASS (committed evidence byte-identical)"
"$PYTHON" "$ROOT/tests/spec-v3/run_all_tests.py" >/dev/null \
    || fail "spec-v3 suite regressed"
git -C "$ROOT" diff --quiet -- docs/evidence/spec-v3 \
    || fail "spec-v3 evidence was rewritten (must stay byte-identical)"
echo "spec-v3 suite: PASS (committed evidence byte-identical)"
"$PYTHON" "$ROOT/tests/spec-vnext/run_all_tests.py"
git -C "$ROOT" diff --quiet -- docs/evidence/package-vnext/spec \
    || fail "spec-vnext evidence was rewritten non-deterministically"
echo "spec-vnext suite: PASS (committed evidence byte-identical)"

step "[2/8] NON-PRODUCTION v4 test identities (PUBLIC d=1 golden signer + d=2)"
"$PYTHON" "$ROOT/tests/package-vnext/make_test_identity.py" --out-dir "$WORK" \
    | grep -v "private keys"
[ "$(sha "$WORK/test-publisher.spki.der")" = "$(sha "$SPEC_EVIDENCE/test-publisher.spki.der")" ] \
    || fail "d=1 SPKI differs from the committed spec artifact"

step "[3/8] legacy package tools zero-degradation reproduction (UNMODIFIED v1/v2/v3)"
V2_IMAGE="$IMG_DIR/lc-v2-image.bin"
"$PYTHON" "$ROOT/tools/make_v2_test_image.py" --out "$V2_IMAGE"
V2_REPLICA="$PKG_DIR/golden-replica.neapp.v2"
"$PYTHON" "$ROOT/package/neapp_pack_v2.py" \
    --image "$V2_IMAGE" --out "$V2_REPLICA" \
    --key "$WORK/keys/d1-test-signer.pem" \
    --publisher-id test-publisher --app-id hello-app --version 1.0.0 \
    --host-caps 0x3f --event-max 2048 --state-quota 4096 --report-max 6144 \
    --source-commit "$(git -C "$ROOT" rev-parse HEAD)" >/dev/null
"$PYTHON" - "$V2_REPLICA" <<'EOF'
import struct, sys
replica = open(sys.argv[1], "rb").read()
golden_tbs = open("docs/evidence/spec-v2/golden-tbs.bin", "rb").read()
image_len = struct.unpack_from("<I", replica, 12)[0]
if replica[:16 + 192 + image_len] != golden_tbs:
    raise SystemExit("FATAL: unmodified v2 packer no longer reproduces the #12 golden TBS")
print("v2 replica TBS byte-identical to committed #12 golden "
      "(the v2 packer signs with random k; the TBS is the pinned identity)")
EOF
"$PYTHON" "$ROOT/package/neapp_verify_v2.py" --package "$V2_REPLICA" \
    --trust "$WORK/trust-d1.json" >/dev/null
echo "v2 golden replica verified PASS (unmodified neapp_verify_v2)"

V3_IMAGE="$IMG_DIR/lc-v3-image.bin"
"$PYTHON" "$ROOT/tests/package-v3/make_v3_test_image.py" --out "$V3_IMAGE" \
    --expect-sha256 "$V3_GOLDEN_NATIVE_SHA" >/dev/null
V3_REPLICA="$PKG_DIR/golden-replica.neapp.v3"
"$PYTHON" "$ROOT/package/neapp_pack_v3.py" \
    --image "$V3_IMAGE" --out "$V3_REPLICA" \
    --key "$WORK/keys/d1-test-signer.pem" \
    --publisher-id test-publisher --app-id line-crossing --version 3.0.0 \
    --host-caps 0xff --event-max 2048 --state-quota 4096 --report-max 6144 \
    --control-max 256 --snapshot-max 1024 \
    --source-commit "$(git -C "$ROOT" rev-parse HEAD)" >/dev/null
"$PYTHON" - "$V3_REPLICA" <<'EOF'
import sys
replica = open(sys.argv[1], "rb").read()
golden_pkg = open("docs/evidence/spec-v3/golden.neapp.v3", "rb").read()
golden_tbs = open("docs/evidence/spec-v3/golden-tbs.bin", "rb").read()
if replica[:244] != golden_tbs or replica != golden_pkg:
    raise SystemExit("FATAL: unmodified v3 packer no longer reproduces the #19 golden bytes")
print("v3 replica byte-identical to committed #19 golden (packer+verifier zero degradation)")
EOF
"$PYTHON" "$ROOT/package/neapp_verify_v3.py" --package "$V3_REPLICA" \
    --trust "$WORK/trust-d1.json" >/dev/null
echo "v3 golden replica verified PASS (unmodified neapp_verify_v3)"

"$PYTHON" "$ROOT/package/neapp_verify.py" \
    --package "$ROOT/docs/evidence/spec-v2/v1-golden.neapp" \
    --trust "$WORK/trust-d1.json" >/dev/null
echo "committed v1 golden verified PASS (unmodified neapp_verify)"

step "[4/8] controlled v4 native images"
GOLDEN_IMAGE="$IMG_DIR/v4-golden-image.bin"
"$PYTHON" "$ROOT/tests/package-vnext/make_v4_test_image.py" --out "$GOLDEN_IMAGE" \
    --expect-sha256 "$GOLDEN_NATIVE_SHA" >/dev/null
ALT_IMAGE="$IMG_DIR/v4-alt-image.bin"
"$PYTHON" "$ROOT/tests/package-vnext/make_v4_test_image.py" --out "$ALT_IMAGE" \
    --payload-hex 00207047 --entry-offset 0 >/dev/null
echo "golden image sha256 $(sha "$GOLDEN_IMAGE") (pinned), alt image sha256 $(sha "$ALT_IMAGE")"

step "[5/8] golden replica pack (d=1) — must equal the independent spec-vnext golden"
GOLDEN_REPLICA="$PKG_DIR/golden-replica.neapp.v4"
"$PYTHON" "$ROOT/package/vnext/neapp_pack_v4.py" \
    --image "$GOLDEN_IMAGE" --out "$GOLDEN_REPLICA" \
    --key "$WORK/keys/d1-test-signer.pem" \
    --publisher-id test-publisher --app-id line-crossing --version 4.0.0 \
    --host-caps 0x3FF --event-max 2048 --state-quota 4096 --report-max 6144 \
    --control-max 256 --snapshot-max 1024 \
    --live-publish-max 1168 --live-track-max 8 \
    --source-commit "$(git -C "$ROOT" rev-parse HEAD)" --sidecar none >/dev/null
cmp "$GOLDEN_REPLICA" "$SPEC_EVIDENCE/golden.neapp.v4" \
    || fail "packer replica differs from the independent spec-vnext golden (cross-implementation interlock)"
"$PYTHON" - "$GOLDEN_REPLICA" <<'EOF'
import hashlib, struct, sys
pkg = open(sys.argv[1], "rb").read()
image_len = struct.unpack_from("<I", pkg, 12)[0]
tbs_sha = hashlib.sha256(pkg[:224 + image_len]).hexdigest()
pkg_sha = hashlib.sha256(pkg).hexdigest()
assert tbs_sha == "581e3ae98afef313de0bdf7d8bc85c2a36585a7c28e609dea183a558e599e095", tbs_sha
assert pkg_sha == "e6a7fedc8cda9f3900311bc077de2a3ea79002d10b23241d1690c9e28ee46e0e", pkg_sha
print(f"golden replica: TBS sha {tbs_sha}")
print(f"golden replica: package sha {pkg_sha} ({len(pkg)}B, byte-identical to the "
      "independent stdlib implementation)")
EOF
"$PYTHON" "$ROOT/package/vnext/neapp_verify_v4.py" --package "$GOLDEN_REPLICA" \
    --trust "$WORK/trust-d1.json" --compact
echo "golden replica verified PASS (independent v4 verifier path)"

step "[6/8] dev-key v4 packages (d=2 cross-publisher; new-capability shapes)"
DEV_BASE=(--key "$WORK/keys/d2-test-signer.pem" --publisher-id dev-publisher
          --app-id lc-test-app --exec-base 0x93E00000
          --source-commit "$(git -C "$ROOT" rev-parse HEAD)")
DEV_PKG="$PKG_DIR/lc-test-app-4.0.0.neapp.v4"
DEV_PKG_410="$PKG_DIR/lc-test-app-4.1.0.neapp.v4"
ALT_PKG="$PKG_DIR/lc-v4-alt-4.0.0.neapp.v4"
ENABLE_PKG="$PKG_DIR/lc-test-app-enable-4.0.0.neapp.v4"
LIVE_PKG="$PKG_DIR/lc-test-app-live-4.0.0.neapp.v4"

"$PYTHON" "$ROOT/package/vnext/neapp_pack_v4.py" \
    --image "$GOLDEN_IMAGE" --out "$DEV_PKG" "${DEV_BASE[@]}" \
    --version 4.0.0 --host-caps 0x3FF --event-max 2048 --state-quota 4096 \
    --report-max 6144 --control-max 256 --snapshot-max 1024 \
    --live-publish-max 1168 --live-track-max 8 >/dev/null
"$PYTHON" "$ROOT/package/vnext/neapp_pack_v4.py" \
    --image "$GOLDEN_IMAGE" --out "$DEV_PKG_410" "${DEV_BASE[@]}" \
    --version 4.1.0 --host-caps 0x3FF --event-max 2048 --state-quota 4096 \
    --report-max 6144 --control-max 256 --snapshot-max 1024 \
    --live-publish-max 1168 --live-track-max 8 >/dev/null
"$PYTHON" "$ROOT/package/vnext/neapp_pack_v4.py" \
    --image "$ALT_IMAGE" --out "$ALT_PKG" "${DEV_BASE[@]}" \
    --version 4.0.0 --host-caps 0x63 --control-max 256 >/dev/null
"$PYTHON" "$ROOT/package/vnext/neapp_pack_v4.py" \
    --image "$GOLDEN_IMAGE" --out "$ENABLE_PKG" "${DEV_BASE[@]}" \
    --version 4.0.0 --host-caps 0x173 --state-quota 4096 --control-max 256 >/dev/null
"$PYTHON" "$ROOT/package/vnext/neapp_pack_v4.py" \
    --image "$GOLDEN_IMAGE" --out "$LIVE_PKG" "${DEV_BASE[@]}" \
    --version 4.0.0 --host-caps 0x223 --control-max 0 --snapshot-max 0 \
    --live-publish-max 9008 --live-track-max 64 >/dev/null

for pkg in "$DEV_PKG" "$DEV_PKG_410" "$ALT_PKG" "$ENABLE_PKG" "$LIVE_PKG"; do
    "$PYTHON" "$ROOT/package/vnext/neapp_verify_v4.py" --package "$pkg" \
        --trust "$WORK/trust-both.json" --compact >/dev/null
    echo "packed+verified $(basename "$pkg") sha256 $(sha "$pkg")"
done
[ "$(sha "$DEV_PKG")" != "$(sha "$DEV_PKG_410")" ] || fail "upgrade discriminator broken"

step "[7/8] rejection matrix + cross-major fail-closed"
"$PYTHON" "$ROOT/tests/package-vnext/v4_cases.py" \
    --work-dir "$WORK" \
    --image "$GOLDEN_IMAGE" \
    --golden-replica "$GOLDEN_REPLICA" \
    --key-d1 "$WORK/keys/d1-test-signer.pem" \
    --key-d2 "$WORK/keys/d2-test-signer.pem" \
    --trust-d1 "$WORK/trust-d1.json" \
    --trust-both "$WORK/trust-both.json"

step "[8/8] structured evidence"
"$PYTHON" - "$ROOT" "$WORK" <<'EOF'
import hashlib, json, subprocess, sys
from pathlib import Path

root, work = Path(sys.argv[1]), Path(sys.argv[2])
pkg = work / "pkg"

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def tool(command):
    return subprocess.run(command, capture_output=True, text=True).stdout.strip()

v4_results = json.loads((work / "v4-cases" / "v4-cases-results.json").read_text())
spec_report = json.loads((root / "docs" / "evidence" / "package-vnext" / "spec" / "report.json").read_text())

def verify_report(package: Path, trust: str) -> dict:
    out = subprocess.run([sys.executable, str(root / "package" / "vnext" / "neapp_verify_v4.py"),
                          "--package", str(package), "--trust", str(work / trust), "--compact"],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[0])

def legacy_report(verifier: str, package: Path, trust: str) -> str:
    out = subprocess.run([sys.executable, str(root / "package" / verifier),
                          "--package", str(package), "--trust", str(work / trust), "--compact"],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[0])["result"]

packages = {}
for name, trust in (("golden-replica", "trust-d1.json"),
                    ("lc-test-app-4.0.0", "trust-both.json"),
                    ("lc-test-app-4.1.0", "trust-both.json"),
                    ("lc-v4-alt-4.0.0", "trust-both.json"),
                    ("lc-test-app-enable-4.0.0", "trust-both.json"),
                    ("lc-test-app-live-4.0.0", "trust-both.json")):
    p = pkg / f"{name}.neapp.v4"
    packages[name] = {"sha256": sha(p), "verifier_report": verify_report(p, trust)}

evidence = {
    "issue": "harryhua-ai/ne30x-app#36 (signed native vNext offline tooling)",
    "boundary": (
        "OFFLINE signed-format evidence only; NOT Host admission/install/execution, "
        "NOT native runtime admission, NOT floor/Enable semantics, NOT live delivery, "
        "NOT device capacity; signing identities are PUBLIC NON-PRODUCTION test "
        "scalars and never device production trust roots"),
    "spec_authority": {
        "freeze": "harryhua-ai/ne301#104 A architecture freeze (2026-10-19, NO READY by design)",
        "f1_f4": "https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258534821",
        "f5_f7": "https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258601629",
        "f8_f10": "https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258637748",
        "host_claim_execution_base": "6357a04d509fb8e1851603d1efe0de51def9edb1",
        "host_claim_branch": "agent/104/de1fd467 (claim comment 6258843064; no v4 parser "
                             "commits pushed at packaging time — cross-repo interop NOT_RUN)",
        "app_protocol_docs": "existing docs/app-package-protocol-v{1,2-draft,3}.md untouched; "
                             "no second competing spec written in this repo",
    },
    "toolchain": {
        "python": tool([sys.executable, "--version"]),
        "python_cryptography": tool([sys.executable, "-c", "import cryptography; print(cryptography.__version__)"]),
        "openssl": tool(["openssl", "version"]),
    },
    "key_discipline": {
        "private_keys_committed": False,
        "identities": [
            {"publisher_id": "test-publisher", "scalar": "d=1 (PUBLIC test scalar, same as v1/v2/v3 goldens)",
             "spki_sha256": "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3",
             "provenance": "public textbook test scalar; reproducible by anyone; never a production anchor"},
            {"publisher_id": "dev-publisher", "scalar": "d=2 (PUBLIC test scalar)",
             "spki_sha256": "dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba",
             "provenance": "public textbook test scalar; reproducible by anyone; never a production anchor"},
        ],
        "private_key_locations": [
            "tests/package-vnext/work/keys/d1-test-signer.pem (gitignored, 0600)",
            "tests/package-vnext/work/keys/d2-test-signer.pem (gitignored, 0600)",
        ],
        "no_production_key_material": True,
    },
    "golden_consistency": {
        "golden_package_sha256": "e6a7fedc8cda9f3900311bc077de2a3ea79002d10b23241d1690c9e28ee46e0e",
        "golden_tbs_sha256": "581e3ae98afef313de0bdf7d8bc85c2a36585a7c28e609dea183a558e599e095",
        "golden_native_sha256": "845e09288e0f1d876832dcda553580c6aa64ef17f08b9e529550aefa4db12cd1",
        "independent_stdlib_rebuild": (
            "tests/spec-vnext (v4lib, from-scratch P-256/RFC-6979/DER) rebuilds the "
            "identical package bytes; run.sh asserts byte-identity"),
        "observed_package_sha256": packages["golden-replica"]["sha256"],
        "observed_tbs_sha256": packages["golden-replica"]["verifier_report"]["content_identity_sha256"],
    },
    "controlled_images": {
        "v4_golden_image": {"sha256": sha(work / "img" / "v4-golden-image.bin"),
                            "note": "64B frozen function table (SIMULATION pointers) + Thumb stub"},
        "v4_alt_image": {"sha256": sha(work / "img" / "v4-alt-image.bin")},
    },
    "packages": packages,
    "spec_suite": {
        "suite": "tests/spec-vnext/run_all_tests.py (independent stdlib-only)",
        "vectors_total": spec_report["vectors_total"],
        "vectors_passed": spec_report["vectors_passed"],
    },
    "v4_case_suite": {"cases_total": len(v4_results), "cases": v4_results},
    "zero_degradation": {
        "legacy_suites_rerun": [
            "tests/spec-v2/run_all_tests.py (exit 0, committed evidence byte-identical)",
            "tests/spec-v3/run_all_tests.py (exit 0, committed evidence byte-identical)",
        ],
        "legacy_tool_reproduction": {
            "v2_golden_tbs_rebuilt_byte_identical": True,
            "v3_golden_rebuilt_byte_identical": True,
            "v1_golden_verified_pass": legacy_report("neapp_verify.py",
                                                     root / "docs/evidence/spec-v2/v1-golden.neapp",
                                                     "trust-d1.json"),
            "verifiers": "unmodified package/neapp_pack_v2.py, neapp_pack_v3.py, "
                         "neapp_verify.py, neapp_verify_v2.py, neapp_verify_v3.py",
        },
        "cross_major_fail_closed": {
            "old_verifiers_reject_v4_golden": ["BAD_PACKAGE", "BAD_PACKAGE", "BAD_PACKAGE"],
            "v4_verifier_rejects_committed_v1_v2_v3_goldens": ["BAD_PACKAGE", "BAD_PACKAGE", "BAD_PACKAGE"],
            "nfc3_rejected_by_v4_control_parser": True,
        },
        "canonical_heavyweight_command": (
            "bash tests/package-v3/run_checks.sh (pre-existing #20 suite; transitively "
            "runs the v1/v2 chains and refreshes its own committed p6 evidence by design)"),
    },
    "pass_not_run_matrix": {
        "PASS_offline": [
            "v4 golden generation byte-identical across two independent implementations",
            "strict-DER ECDSA P-256 signing/verification (RFC-6979; OpenSSL + cryptography cross-proof)",
            "container/manifest/native/table/policy rejection matrix (tooling + spec suites)",
            "trust fail-closed (unknown publisher, fingerprint mismatch; package keys never self-trust)",
            "bit8/bit9 capability prerequisites and live quota closure (312 / 48+140*tracks)",
            "NFC4 ENABLE_SET/ENR1 receipt and LVN4 packet/GAP vector coverage (frozen bytes)",
            "legacy v1/v2/v3 suites byte-stable; cross-major fail-closed both directions",
        ],
        "NOT_RUN": [
            {"item": "cross-repo Host #104 parser/golden interop",
             "reason": "Host implementation candidate not merged: branch agent/104/de1fd467 "
                       "stands at execution_base 6357a04d509fb8e1851603d1efe0de51def9edb1 with "
                       "no v4 parser commits at packaging time; App goldens under "
                       "docs/evidence/package-vnext/spec/ are the exported black-box vectors "
                       "for that future interop (final AC3 acceptance per contract)"},
            {"item": "device flash/NVS/LittleFS, board install or execution", "reason": "no device"},
            {"item": "production keys, real issuance, production trust roots", "reason": "out of scope; non-production only"},
            {"item": "Host #104 admission/floor implementation", "reason": "Host-owned; non-goal here"},
            {"item": "App #30 Enable/Paused business semantics", "reason": "owned by #30; non-goal here"},
            {"item": "Host #91 producer-ingest / live read path, App #27 tracker", "reason": "owned by #91/#27; non-goal here"},
            {"item": "ARM target build static asserts (sizeof(void*)==4, Thumb)", "reason": "target-build proof, not offline tooling"},
            {"item": "real RAM/CPU/live-queue capacity on hardware", "reason": "device measurement"},
            {"item": "remaining #104 bytes (control/live wire final freeze beyond F5/F8/F9)", "reason": "A freeze in progress at Host #104"},
        ],
    },
}
out = root / "docs" / "evidence" / "package-vnext" / "artifacts.json"
out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"evidence -> {out}")
EOF

printf '\n== ALL PACKAGE-VNEXT CHECKS PASSED\n'
printf 'golden replica %s\n  sha256 %s\n' "$GOLDEN_REPLICA" "$(sha "$GOLDEN_REPLICA")"
printf 'evidence log   %s\n' "$LOG"
