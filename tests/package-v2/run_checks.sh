#!/usr/bin/env bash
# run_package_checks.sh — one-command P6 (Issue #13) offline v2 packaging suite.
#
# Pipeline (all OFFLINE; no device, no ne301 workspace, no network):
#   [0/8] preflight (python3 + cryptography, openssl, arm toolchain for the
#         v1 regression)
#   [1/8] v1 regression UNCHANGED: run tests/package/run_package_checks.sh
#         verbatim (packs/verifies hello-app V1/V2, adopts the frozen P2 §2.5
#         vectors, runs the 33 generated cases).  Its per-run artifact is
#         snapshotted under the P6 evidence name and the P3-owned artifact
#         file is restored, so this branch does not churn P3 evidence.
#   [2/8] #12 spec-v2 vector suite UNCHANGED: python3 tests/spec-v2/
#         run_all_tests.py (must leave docs/evidence/spec-v2 byte-identical)
#   [3/8] NON-PRODUCTION identities: per-round dev key (gen_dev_key.py) and
#         the PUBLIC spec §10.1 d=1 test signer (both gitignored, never
#         committed; trust stores generated from local SPKI material only)
#   [4/8] controlled v2-ABI native test images (tools/make_v2_test_image.py);
#         the default image must equal the #12 golden native image bytes
#   [5/8] pack the golden replica with d=1: the TBS must be byte-identical to
#         docs/evidence/spec-v2/golden-tbs.bin (SHA-256(TBS) pinned)
#   [6/8] pack the dev-key v2 packages: 1.0.0 / 2.0.0 / alt-image@1.0.0
#         (upgrade + content-conflict discriminators); each self-verified
#   [7/8] v2 rejection matrix + cross-version discrimination
#         (tests/package-v2/v2_cases.py), including the prebuilt hello-app V1
#         image as an additional v2 input (never rebuilt here)
#   [8/8] structured evidence -> docs/evidence/p6-package-artifacts.json
#
# Key discipline (AC3): private keys live only under tests/package-v2/work/
# (gitignored, owner-only) and are never printed; the d=1 scalar is the
# spec's PUBLIC non-production test key.
#
# A PASS of this suite proves offline generation/discrimination only.  It is
# NOT device install, execution, STM32/PKA verification, or power-fail
# recovery evidence (spec §12).

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/tests/package-v2/work"
PKG_DIR="$WORK/pkg"
IMG_DIR="$WORK/img"
KEYS_DIR="$WORK/keys"
LOG="$ROOT/docs/evidence/p6-package-checks.log"
PYTHON=${PYTHON:-python3}
PUBLISHER=dev-publisher
APP_ID=lc-test-app

# #12 pinned spec §10.1/§10.2 values (docs/app-package-protocol-v2-draft.md)
GOLDEN_TBS_SHA256=e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278
SPKI_SHA256=5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$ROOT/docs/evidence"
exec > >(tee "$LOG") 2>&1

step "[0/8] preflight"
command -v "$PYTHON" >/dev/null || fail "python3 missing"
"$PYTHON" -c 'import cryptography' 2>/dev/null || fail "python cryptography missing"
command -v openssl >/dev/null || fail "openssl missing"
command -v arm-none-eabi-gcc >/dev/null || fail "arm-none-eabi-gcc missing (needed by the unchanged v1 regression)"
echo "python3=$($PYTHON --version 2>&1) cryptography=$($PYTHON -c 'import cryptography; print(cryptography.__version__)') openssl=$(openssl version 2>&1 | awk '{print $1 $2}')"
rm -rf "$WORK"
mkdir -p "$PKG_DIR" "$IMG_DIR" "$KEYS_DIR"

step "[1/8] v1 regression UNCHANGED (tests/package/run_package_checks.sh)"
bash "$ROOT/tests/package/run_package_checks.sh"
cp "$ROOT/docs/evidence/p3-package-artifacts.json" "$ROOT/docs/evidence/p6-v1-regression-artifacts.json"
if git -C "$ROOT" diff --quiet -- docs/evidence/p3-package-artifacts.json; then
    echo "P3 evidence artifact unchanged (unexpected for a fresh run; keeping as-is)"
else
    git -C "$ROOT" restore -- docs/evidence/p3-package-artifacts.json
    echo "P3-owned artifact restored; this run snapshotted to docs/evidence/p6-v1-regression-artifacts.json"
fi
HELLO_V1_IMAGE="$ROOT/apps/hello-app/build/hello-app.bin"
[ -f "$HELLO_V1_IMAGE" ] || fail "hello-app V1 image missing after the v1 regression"

step "[2/8] #12 spec-v2 vector suite UNCHANGED (tests/spec-v2/run_all_tests.py)"
"$PYTHON" "$ROOT/tests/spec-v2/run_all_tests.py"
git -C "$ROOT" diff --quiet -- docs/evidence/spec-v2 \
    || fail "tests/spec-v2 run_all_tests.py rewrote the committed evidence (must be deterministic)"

step "[3/8] NON-PRODUCTION identities (dev key per round + PUBLIC spec d=1 test signer)"
"$PYTHON" "$ROOT/tests/package/gen_dev_key.py" --out-dir "$WORK" --publisher-id "$PUBLISHER"
"$PYTHON" - "$WORK" "$SPKI_SHA256" <<'EOF'
import hashlib, json, stat, sys
from pathlib import Path

work = Path(sys.argv[1])
spki_sha = sys.argv[2]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# d=1 is the PUBLIC, unsafe, non-production scalar pinned by spec §10.1.
d1 = ec.derive_private_key(1, ec.SECP256R1())
spki = d1.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
digest = hashlib.sha256(spki).hexdigest()
if digest != spki_sha:
    raise SystemExit(f"FATAL: d=1 SPKI digest {digest} != pinned {spki_sha}")
committed = (work.parents[2] / "docs" / "evidence" / "spec-v2" / "test-publisher.spki.der")
if committed.read_bytes() != spki:
    raise SystemExit("FATAL: generated d=1 SPKI differs from the committed #12 artifact")
pem = work / "keys" / "d1-test-signer.pem"
pem.write_text(
    d1.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8,
                     serialization.NoEncryption()).decode(), encoding="ascii")
pem.chmod(stat.S_IREAD | stat.S_IWRITE)
trust = {
    "version": 1,
    "comment": (
        "NON-PRODUCTION offline test trust store for the PUBLIC spec §10.1 d=1 "
        "test key; generated per test run; must never be a production trust anchor"
    ),
    "publishers": {
        "test-publisher": {"spki_der_hex": spki.hex(), "spki_sha256": digest},
    },
}
(work / "trust-d1.json").write_text(json.dumps(trust, indent=2) + "\n", encoding="utf-8")
print(f"d=1 test identity generated (PUBLIC, NON-PRODUCTION): SPKI sha256 {digest}")
print(f"  private key (gitignored): {pem}")
print(f"  trust store: {work / 'trust-d1.json'} (publisher_id 'test-publisher')")
EOF

step "[4/8] controlled v2-ABI native test images (deterministic)"
GOLDEN_NATIVE_SHA=$("$PYTHON" -c "
import hashlib
print(hashlib.sha256(open('$ROOT/docs/evidence/spec-v2/golden-tbs.bin','rb').read()[-36:]).hexdigest())")
LC_IMAGE="$IMG_DIR/lc-test-image.bin"
"$PYTHON" "$ROOT/tools/make_v2_test_image.py" --out "$LC_IMAGE" --expect-sha256 "$GOLDEN_NATIVE_SHA"
"$PYTHON" - "$LC_IMAGE" <<'EOF'
import sys
golden_native = open("docs/evidence/spec-v2/golden-tbs.bin", "rb").read()[-36:]
img = open(sys.argv[1], "rb").read()
if img != golden_native:
    raise SystemExit("FATAL: controlled test image != #12 golden native image bytes")
print("controlled image == #12 golden native image (byte-identical)")
EOF
ALT_IMAGE="$IMG_DIR/lc-test-alt-image.bin"
"$PYTHON" "$ROOT/tools/make_v2_test_image.py" --out "$ALT_IMAGE" --payload-hex 00207048

step "[5/8] golden replica pack (d=1): TBS must equal the #12 golden TBS byte-for-byte"
GOLDEN_REPLICA="$PKG_DIR/golden-replica.neapp.v2"
"$PYTHON" "$ROOT/package/neapp_pack_v2.py" \
    --image "$LC_IMAGE" --out "$GOLDEN_REPLICA" \
    --key "$KEYS_DIR/d1-test-signer.pem" \
    --publisher-id test-publisher --app-id hello-app --version 1.0.0 \
    --host-caps 0x3f --event-max 2048 --state-quota 4096 --report-max 6144 \
    --source-commit "$(git -C "$ROOT" rev-parse HEAD)"
"$PYTHON" - "$GOLDEN_REPLICA" "$GOLDEN_TBS_SHA256" <<'EOF'
import hashlib, struct, sys
pkg = open(sys.argv[1], "rb").read()
image_len = struct.unpack_from("<I", pkg, 12)[0]
tbs = pkg[:16 + 192 + image_len]
golden_tbs = open("docs/evidence/spec-v2/golden-tbs.bin", "rb").read()
if tbs != golden_tbs:
    raise SystemExit("FATAL: replica TBS differs from the #12 golden TBS")
digest = hashlib.sha256(tbs).hexdigest()
if digest != sys.argv[2]:
    raise SystemExit(f"FATAL: SHA-256(TBS) {digest} != pinned {sys.argv[2]}")
print(f"replica TBS byte-identical to #12 golden; SHA-256(TBS) {digest}")
EOF
"$PYTHON" "$ROOT/package/neapp_verify_v2.py" --package "$GOLDEN_REPLICA" --trust "$WORK/trust-d1.json"

step "[6/8] dev-key v2 packages (AC1 traceable provenance, upgrade + conflict discriminators)"
DEV_PKG="$PKG_DIR/lc-test-app-1.0.0.neapp.v2"
DEV_PKG_200="$PKG_DIR/lc-test-app-2.0.0.neapp.v2"
ALT_PKG="$PKG_DIR/lc-test-alt-1.0.0.neapp.v2"
for spec in "1.0.0:$DEV_PKG:$LC_IMAGE" "2.0.0:$DEV_PKG_200:$LC_IMAGE" "1.0.0:$ALT_PKG:$ALT_IMAGE"; do
    ver=${spec%%:*}; rest=${spec#*:}; out=${rest%%:*}; img=${rest#*:}
    "$PYTHON" "$ROOT/package/neapp_pack_v2.py" \
        --image "$img" --out "$out" \
        --key "$KEYS_DIR/dev-signer.pem" \
        --publisher-id "$PUBLISHER" --app-id "$APP_ID" --version "$ver" \
        --host-caps 0x3f --event-max 2048 --state-quota 4096 --report-max 6144 \
        --source-commit "$(git -C "$ROOT" rev-parse HEAD)"
    "$PYTHON" "$ROOT/package/neapp_verify_v2.py" --package "$out" --trust "$WORK/trust-dev.json"
done

step "[7/8] v2 rejection matrix + cross-version discrimination"
"$PYTHON" "$ROOT/tests/package-v2/v2_cases.py" \
    --work-dir "$WORK" \
    --image "$LC_IMAGE" \
    --alt-image "$ALT_IMAGE" \
    --golden-replica-package "$GOLDEN_REPLICA" \
    --dev-package "$DEV_PKG" \
    --dev-package-2-0-0 "$DEV_PKG_200" \
    --alt-image-package "$ALT_PKG" \
    --hello-image "$HELLO_V1_IMAGE"

step "[8/8] write structured evidence"
"$PYTHON" - "$ROOT" "$WORK" <<'EOF'
import hashlib, json, subprocess, sys
from pathlib import Path

root, work = Path(sys.argv[1]), Path(sys.argv[2])
pkg = work / "pkg"

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def git(*args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                          text=True, check=True).stdout.strip()

v2_results = json.loads((work / "v2-cases" / "v2-cases-results.json").read_text())
spec_v2_report = json.loads((root / "docs" / "evidence" / "spec-v2" / "report.json").read_text())
v1_snapshot = json.loads((root / "docs" / "evidence" / "p6-v1-regression-artifacts.json").read_text())

def verify_report(package: Path, trust: str) -> dict:
    out = subprocess.run([sys.executable, str(root / "package" / "neapp_verify_v2.py"),
                          "--package", str(package), "--trust", str(work / trust), "--compact"],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[0])

packages = {}
for name, trust in (("golden-replica", "trust-d1.json"),
                    ("lc-test-app-1.0.0", "trust-dev.json"),
                    ("lc-test-app-2.0.0", "trust-dev.json"),
                    ("lc-test-alt-1.0.0", "trust-dev.json")):
    p = pkg / f"{name}.neapp.v2"
    packages[name] = {"sha256": sha(p), "verifier_report": verify_report(p, trust)}

evidence = {
    "issue": "harryhua-ai/ne30x-app#13 (P6)",
    "boundary": ("OFFLINE packaging evidence only; NOT device install/execution/"
                 "STM32-PKA verification/power-fail-recovery PASS; signing identities "
                 "are NON-PRODUCTION test roots (per-round dev key + PUBLIC spec d=1)"),
    "protocol_authorities": {
        "v1": "docs/app-package-protocol-v1.md (integrated P2/#6 baseline, unchanged)",
        "v2": "docs/app-package-protocol-v2-draft.md (integrated #12 baseline)",
    },
    "source_commit": git("rev-parse", "HEAD"),
    "toolchain": {
        "python_cryptography": subprocess.run(
            [sys.executable, "-c", "import cryptography; print(cryptography.__version__)"],
            capture_output=True, text=True).stdout.strip(),
        "openssl": subprocess.run(["openssl", "version"], capture_output=True,
                                  text=True).stdout.strip(),
    },
    "v1_regression": {
        "suite": "tests/package/run_package_checks.sh (UNCHANGED, exit 0)",
        "artifact_snapshot": "docs/evidence/p6-v1-regression-artifacts.json",
        "spec_vectors": len(v1_snapshot["spec_vector_suite"]),
        "generated_cases": len(v1_snapshot["generated_case_suite"]),
        "hello_app_v1_sha256": v1_snapshot["images"]["hello_app_v1"]["sha256"],
        "hello_app_v1_reproduction": v1_snapshot["images"]["hello_app_v1"]["reproduction"],
    },
    "spec_v2_suite": {
        "suite": "tests/spec-v2/run_all_tests.py (UNCHANGED, exit 0)",
        "vectors_total": spec_v2_report["vectors_total"],
        "vectors_passed": spec_v2_report["vectors_passed"],
        "committed_evidence_unchanged": True,
    },
    "controlled_images": {
        "lc_test_image": {
            "path": "tests/package-v2/work/img/lc-test-image.bin",
            "sha256": sha(work / "img" / "lc-test-image.bin"),
            "note": "byte-identical to the #12 spec §10.1 golden native image",
        },
        "lc_test_alt_image": {
            "path": "tests/package-v2/work/img/lc-test-alt-image.bin",
            "sha256": sha(work / "img" / "lc-test-alt-image.bin"),
        },
    },
    "packages": packages,
    "golden_consistency": {
        "pinned_sha256_tbs": "e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278",
        "observed_sha256_tbs": packages["golden-replica"]["verifier_report"]["content_identity_sha256"],
        "pinned_sha256_golden_package": "3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e",
        "tbs_byte_identical": True,
        "der_identical_to_pinned": False,
        "der_note": ("the packer's cryptography RFC-6979 k differs from the #12 pure-Python "
                     "k: a DIFFERENT valid DER over the SAME SHA-256(TBS) identity (§2.2); "
                     "the pinned DER itself is independently re-verified by cryptography + "
                     "OpenSSL in v2_cases:golden_der_independent_cross"),
        "spki_sha256": "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3",
        "archive_negative_class": "RESOURCE_LIMIT",
    },
    "v2_case_suite": {
        "cases_total": len(v2_results),
        "cases": v2_results,
    },
    "key_discipline": {
        "private_keys_committed": False,
        "private_key_locations": [
            "tests/package-v2/work/keys/dev-signer.pem (per-round, gitignored, 0600)",
            "tests/package-v2/work/keys/d1-test-signer.pem (PUBLIC spec §10.1 scalar, gitignored)",
        ],
        "trust_roots": "NON-PRODUCTION dev/test identities only; no production key material",
    },
}
out = root / "docs" / "evidence" / "p6-package-artifacts.json"
out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"evidence -> {out}")
EOF

printf '\n== ALL P6 PACKAGE CHECKS PASSED\n'
printf 'controlled image %s\n  sha256 %s\n' "$LC_IMAGE" "$(sha "$LC_IMAGE")"
printf 'golden replica  %s\n  sha256 %s\n' "$GOLDEN_REPLICA" "$(sha "$GOLDEN_REPLICA")"
printf 'dev package     %s\n  sha256 %s\n' "$DEV_PKG" "$(sha "$DEV_PKG")"
printf 'evidence log    %s\n' "$LOG"
