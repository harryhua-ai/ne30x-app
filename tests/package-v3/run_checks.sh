#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/tests/package-v3/work"
PKG_DIR="$WORK/pkg"
IMG_DIR="$WORK/img"
LOG="$ROOT/docs/evidence/p6-package-v3-checks.log"
PYTHON=${PYTHON:-python3}
PUBLISHER=dev-publisher
APP_ID=lc-test-app

GOLDEN_TBS_SHA256=d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e
GOLDEN_PKG_SHA256=c74f7e468a9b63403bbaa8d36816bfd5250ffd68f66ebffc7d994440f1e22342
GOLDEN_NATIVE_SHA256=aa8c3ef6e4082656c76255807bee5a7c562ad212a0c3e2a4f009a62129cdee69
SPKI_SHA256=5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$ROOT/docs/evidence"
exec > >(tee "$LOG") 2>&1

step "[0/7] preflight"
command -v "$PYTHON" >/dev/null || fail "python3 missing"
"$PYTHON" -c 'import cryptography' 2>/dev/null || fail "python cryptography missing"
command -v openssl >/dev/null || fail "openssl missing"
command -v arm-none-eabi-gcc >/dev/null || fail "arm-none-eabi-gcc missing (needed by the unchanged v1 regression)"
echo "python3=$($PYTHON --version 2>&1) cryptography=$($PYTHON -c 'import cryptography; print(cryptography.__version__)') openssl=$(openssl version 2>&1 | awk '{print $1 $2}') arm-none-eabi-gcc=$(arm-none-eabi-gcc -dumpversion)"
rm -rf "$WORK"
mkdir -p "$PKG_DIR" "$IMG_DIR"

step "[1/7] frozen v1/v2 package-tool regression UNCHANGED (tests/package-v2/run_checks.sh)"
bash "$ROOT/tests/package-v2/run_checks.sh"
"$PYTHON" - "$ROOT" "$WORK" <<'EOF'
import json, sys
from pathlib import Path
root, work = Path(sys.argv[1]), Path(sys.argv[2])
v2_art = json.loads((root / "docs" / "evidence" / "p6-package-artifacts.json").read_text())
v1_art = json.loads((root / "docs" / "evidence" / "p6-v1-regression-artifacts.json").read_text())
snapshot = {
    "suite": "tests/package-v2/run_checks.sh (UNCHANGED, exit 0)",
    "v1_regression": {
        "suite": v2_art["v1_regression"]["suite"],
        "spec_vectors": v2_art["v1_regression"]["spec_vectors"],
        "generated_cases": v2_art["v1_regression"]["generated_cases"],
        "hello_app_v1_sha256": v2_art["v1_regression"]["hello_app_v1_sha256"],
        "hello_app_v1_reproduction": v2_art["v1_regression"]["hello_app_v1_reproduction"],
    },
    "spec_v2_suite": v2_art["spec_v2_suite"],
    "v2_case_suite_total": v2_art["v2_case_suite"]["cases_total"],
}
(work / "frozen-regression-snapshot.json").write_text(
    json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
print("frozen v1/v2 regression snapshot captured:")
print(f"  v1 spec vectors: {snapshot['v1_regression']['spec_vectors']}, "
      f"generated cases: {snapshot['v1_regression']['generated_cases']}")
print(f"  hello-app V1 sha256: {snapshot['v1_regression']['hello_app_v1_sha256']} "
      f"({snapshot['v1_regression']['hello_app_v1_reproduction']})")
print(f"  v2 cases: {snapshot['v2_case_suite_total']}")
EOF
git -C "$ROOT" restore -- docs/evidence/p6-package-checks.log \
    docs/evidence/p6-package-artifacts.json docs/evidence/p6-v1-regression-artifacts.json
git -C "$ROOT" diff --quiet -- docs/evidence/p3-package-artifacts.json docs/evidence/spec-v2 \
    || fail "frozen #12/#13 evidence files were modified by the regression run"
echo "#13-owned p6 evidence files restored unchanged (this round's results are recorded in the v3 evidence)"

HELLO_V1_IMAGE="$ROOT/apps/hello-app/build/hello-app.bin"
[ -f "$HELLO_V1_IMAGE" ] || fail "hello-app V1 image missing after the v1 regression"

step "[2/7] frozen spec suites UNCHANGED (spec-v2 then spec-v3, evidence must stay deterministic)"
"$PYTHON" "$ROOT/tests/spec-v2/run_all_tests.py" >/dev/null
git -C "$ROOT" diff --quiet -- docs/evidence/spec-v2 \
    || fail "tests/spec-v2 run_all_tests.py rewrote the committed evidence"
echo "spec-v2 suite: PASS (committed evidence byte-identical)"
"$PYTHON" "$ROOT/tests/spec-v3/run_all_tests.py" >/dev/null
git -C "$ROOT" diff --quiet -- docs/evidence/spec-v3 \
    || fail "tests/spec-v3 run_all_tests.py rewrote the committed evidence"
echo "spec-v3 suite: PASS (committed evidence byte-identical)"

step "[3/7] NON-PRODUCTION identities (dev key per round + PUBLIC spec d=1 test signer)"
"$PYTHON" "$ROOT/tests/package/gen_dev_key.py" --out-dir "$WORK" --publisher-id "$PUBLISHER"
"$PYTHON" - "$WORK" "$SPKI_SHA256" <<'EOF'
import hashlib, json, stat, sys
from pathlib import Path

work = Path(sys.argv[1])
spki_sha = sys.argv[2]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

d1 = ec.derive_private_key(1, ec.SECP256R1())
spki = d1.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
digest = hashlib.sha256(spki).hexdigest()
if digest != spki_sha:
    raise SystemExit(f"FATAL: d=1 SPKI digest {digest} != pinned {spki_sha}")
committed = work.parents[2] / "docs" / "evidence" / "spec-v3" / "test-publisher.spki.der"
if committed.read_bytes() != spki:
    raise SystemExit("FATAL: generated d=1 SPKI differs from the committed #19 artifact")
pem = work / "keys" / "d1-test-signer.pem"
pem.write_text(
    d1.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8,
                     serialization.NoEncryption()).decode(), encoding="ascii")
pem.chmod(stat.S_IREAD | stat.S_IWRITE)
trust = {
    "version": 1,
    "comment": (
        "NON-PRODUCTION offline test trust store for the PUBLIC spec §12 d=1 "
        "test key; generated per test run; must never be a production trust anchor "
        "or a device production root"
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

step "[4/7] controlled v3-ABI native test images (deterministic)"
LC_IMAGE="$IMG_DIR/lc-v3-test-image.bin"
"$PYTHON" "$ROOT/tests/package-v3/make_v3_test_image.py" --out "$LC_IMAGE" \
    --expect-sha256 "$GOLDEN_NATIVE_SHA256"
"$PYTHON" - "$LC_IMAGE" <<'EOF'
import sys
golden_native = open("docs/evidence/spec-v3/golden-tbs.bin", "rb").read()[-36:]
img = open(sys.argv[1], "rb").read()
if img != golden_native:
    raise SystemExit("FATAL: controlled test image != #19 golden native image bytes")
print("controlled image == #19 golden native image (byte-identical)")
EOF
ALT_IMAGE="$IMG_DIR/lc-v3-alt-image.bin"
"$PYTHON" "$ROOT/tests/package-v3/make_v3_test_image.py" --out "$ALT_IMAGE" --payload-hex 00207048

step "[5/7] golden replica pack (d=1): TBS and whole package must be byte-identical to #19 golden"
GOLDEN_REPLICA="$PKG_DIR/golden-replica.neapp.v3"
"$PYTHON" "$ROOT/package/neapp_pack_v3.py" \
    --image "$LC_IMAGE" --out "$GOLDEN_REPLICA" \
    --key "$WORK/keys/d1-test-signer.pem" \
    --publisher-id test-publisher --app-id line-crossing --version 3.0.0 \
    --host-caps 0xff --event-max 2048 --state-quota 4096 --report-max 6144 \
    --control-max 256 --snapshot-max 1024 \
    --source-commit "$(git -C "$ROOT" rev-parse HEAD)"
"$PYTHON" - "$GOLDEN_REPLICA" "$GOLDEN_TBS_SHA256" "$GOLDEN_PKG_SHA256" <<'EOF'
import hashlib, sys
pkg = open(sys.argv[1], "rb").read()
golden_pkg = open("docs/evidence/spec-v3/golden.neapp.v3", "rb").read()
golden_tbs = open("docs/evidence/spec-v3/golden-tbs.bin", "rb").read()
if pkg[:244] != golden_tbs:
    raise SystemExit("FATAL: replica TBS differs from the #19 golden TBS")
if hashlib.sha256(pkg[:244]).hexdigest() != sys.argv[2]:
    raise SystemExit(f"FATAL: SHA-256(TBS) {hashlib.sha256(pkg[:244]).hexdigest()} != pinned {sys.argv[2]}")
if pkg != golden_pkg:
    raise SystemExit("FATAL: replica package differs from the #19 golden package bytes")
if hashlib.sha256(pkg).hexdigest() != sys.argv[3]:
    raise SystemExit(f"FATAL: SHA-256(package) {hashlib.sha256(pkg).hexdigest()} != pinned {sys.argv[3]}")
print(f"replica TBS byte-identical; SHA-256(TBS) {sys.argv[2]}")
print(f"replica package byte-identical (314B); SHA-256(package) {sys.argv[3]}")
EOF
"$PYTHON" "$ROOT/package/neapp_verify_v3.py" --package "$GOLDEN_REPLICA" --trust "$WORK/trust-d1.json"
echo "golden replica verified PASS"

step "[6/7] dev-key v3 packages (AC1 traceable provenance, upgrade + conflict discriminators)"
DEV_PKG="$PKG_DIR/lc-test-app-1.0.0.neapp.v3"
DEV_PKG_200="$PKG_DIR/lc-test-app-2.0.0.neapp.v3"
ALT_PKG="$PKG_DIR/lc-v3-alt-1.0.0.neapp.v3"
for spec in "1.0.0:$DEV_PKG:$LC_IMAGE" "2.0.0:$DEV_PKG_200:$LC_IMAGE" "1.0.0:$ALT_PKG:$ALT_IMAGE"; do
    ver=${spec%%:*}; rest=${spec#*:}; out=${rest%%:*}; img=${rest#*:}
    "$PYTHON" "$ROOT/package/neapp_pack_v3.py" \
        --image "$img" --out "$out" \
        --key "$WORK/keys/dev-signer.pem" \
        --publisher-id "$PUBLISHER" --app-id "$APP_ID" --version "$ver" \
        --host-caps 0xff --event-max 2048 --state-quota 4096 --report-max 6144 \
        --control-max 256 --snapshot-max 1024 \
        --source-commit "$(git -C "$ROOT" rev-parse HEAD)"
    "$PYTHON" "$ROOT/package/neapp_verify_v3.py" --package "$out" --trust "$WORK/trust-dev.json" --compact
    echo "packed+verified $out"
done

step "[7/7] v3 rejection matrix + cross-version discrimination + evidence"
"$PYTHON" "$ROOT/tests/package-v3/v3_cases.py" \
    --work-dir "$WORK" \
    --image "$LC_IMAGE" \
    --alt-image "$ALT_IMAGE" \
    --golden-replica-package "$GOLDEN_REPLICA" \
    --dev-package "$DEV_PKG" \
    --dev-package-2-0-0 "$DEV_PKG_200" \
    --alt-image-package "$ALT_PKG" \
    --hello-image "$HELLO_V1_IMAGE"

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

v3_results = json.loads((work / "v3-cases" / "v3-cases-results.json").read_text())
frozen = json.loads((work / "frozen-regression-snapshot.json").read_text())
spec_v3_report = json.loads((root / "docs" / "evidence" / "spec-v3" / "report.json").read_text())
spec_v2_report = json.loads((root / "docs" / "evidence" / "spec-v2" / "report.json").read_text())

def verify_report(package: Path, trust: str) -> dict:
    out = subprocess.run([sys.executable, str(root / "package" / "neapp_verify_v3.py"),
                          "--package", str(package), "--trust", str(work / trust), "--compact"],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[0])

packages = {}
for name, trust in (("golden-replica", "trust-d1.json"),
                    ("lc-test-app-1.0.0", "trust-dev.json"),
                    ("lc-test-app-2.0.0", "trust-dev.json"),
                    ("lc-v3-alt-1.0.0", "trust-dev.json")):
    p = pkg / f"{name}.neapp.v3"
    packages[name] = {"sha256": sha(p), "verifier_report": verify_report(p, trust)}

evidence = {
    "issue": "harryhua-ai/ne30x-app#20 (P6 v3)",
    "boundary": ("OFFLINE packaging evidence only; NOT NE301 admission/install/execution/"
                 "hot-reconfiguration/STM32-PKA verification/power-fail-recovery PASS; "
                 "signing identities are NON-PRODUCTION test roots (per-round dev key + "
                 "PUBLIC spec d=1) and never device production trust roots"),
    "protocol_authorities": {
        "v1": "docs/app-package-protocol-v1.md (integrated P2/#6 baseline, unchanged)",
        "v2": "docs/app-package-protocol-v2-draft.md (integrated #12 baseline, unchanged)",
        "v3": "docs/app-package-protocol-v3.md (integrated #19 baseline)",
    },
    "source_commit": git("rev-parse", "HEAD"),
    "toolchain": {
        "python": subprocess.run([sys.executable, "--version"], capture_output=True,
                                 text=True).stdout.strip(),
        "python_cryptography": subprocess.run(
            [sys.executable, "-c", "import cryptography; print(cryptography.__version__)"],
            capture_output=True, text=True).stdout.strip(),
        "openssl": subprocess.run(["openssl", "version"], capture_output=True,
                                  text=True).stdout.strip(),
    },
    "frozen_v1_v2_regression": {
        **frozen,
        "committed_13_evidence_restored_unchanged": True,
        "note": ("the frozen v1/v2/hello-app regression was re-run this round via the "
                 "UNCHANGED tests/package-v2/run_checks.sh; the #13-owned committed "
                 "evidence files were restored byte-identical afterwards"),
    },
    "spec_suites": {
        "spec_v2": {
            "suite": "tests/spec-v2/run_all_tests.py (UNCHANGED, exit 0)",
            "vectors_total": spec_v2_report["vectors_total"],
            "vectors_passed": spec_v2_report["vectors_passed"],
            "committed_evidence_unchanged": True,
        },
        "spec_v3": {
            "suite": "tests/spec-v3/run_all_tests.py (UNCHANGED, exit 0)",
            "vectors_total": spec_v3_report.get("vectors_total", len(spec_v3_report["vectors"])),
            "vectors_passed": spec_v3_report.get("vectors_passed",
                                                 sum(1 for v in spec_v3_report["vectors"] if v["ok"])),
            "committed_evidence_unchanged": True,
        },
    },
    "controlled_images": {
        "lc_v3_test_image": {
            "path": "tests/package-v3/work/img/lc-v3-test-image.bin",
            "sha256": sha(work / "img" / "lc-v3-test-image.bin"),
            "note": "byte-identical to the #19 spec §12.1 golden native image",
        },
        "lc_v3_alt_image": {
            "path": "tests/package-v3/work/img/lc-v3-alt-image.bin",
            "sha256": sha(work / "img" / "lc-v3-alt-image.bin"),
        },
    },
    "packages": packages,
    "golden_consistency": {
        "pinned_sha256_tbs": "d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e",
        "observed_sha256_tbs": packages["golden-replica"]["verifier_report"]["content_identity_sha256"],
        "pinned_sha256_golden_package": "c74f7e468a9b63403bbaa8d36816bfd5250ffd68f66ebffc7d994440f1e22342",
        "observed_sha256_golden_package": packages["golden-replica"]["sha256"],
        "tbs_byte_identical": True,
        "package_byte_identical": True,
        "der_identical_to_pinned": True,
        "der_note": ("the packer (cryptography RFC-6979, deterministic_signing=True) and the "
                     "#19 pure-Python RFC-6979 prover produce the SAME k for d=1 over the "
                     "same SHA-256(TBS): the packed replica is byte-identical to "
                     "golden.neapp.v3, so SHA-256(package) c74f7e46… is reproduced"),
        "spki_sha256": "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3",
    },
    "v3_case_suite": {
        "cases_total": len(v3_results),
        "cases": v3_results,
    },
    "key_discipline": {
        "private_keys_committed": False,
        "private_key_locations": [
            "tests/package-v3/work/keys/dev-signer.pem (per-round, gitignored, 0600)",
            "tests/package-v3/work/keys/d1-test-signer.pem (PUBLIC spec §12 scalar, gitignored)",
        ],
        "trust_roots": "NON-PRODUCTION dev/test identities only; no production key material; "
                       "neither identity is a device production trust root",
    },
}
out = root / "docs" / "evidence" / "p6-package-v3-artifacts.json"
out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"evidence -> {out}")
EOF

printf '\n== ALL P6 v3 PACKAGE CHECKS PASSED\n'
printf 'controlled image %s\n  sha256 %s\n' "$LC_IMAGE" "$(sha "$LC_IMAGE")"
printf 'golden replica  %s\n  sha256 %s\n' "$GOLDEN_REPLICA" "$(sha "$GOLDEN_REPLICA")"
printf 'dev package     %s\n  sha256 %s\n' "$DEV_PKG" "$(sha "$DEV_PKG")"
printf 'evidence log    %s\n' "$LOG"
