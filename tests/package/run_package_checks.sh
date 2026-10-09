#!/usr/bin/env bash
# run_package_checks.sh — one-command P3 (Issue #6) offline packaging suite.
#
# Pipeline (all OFFLINE; no device, no ne301 workspace, no network except the
# sha256-locked ABI header fetch on cold builds):
#   [1/9] generate the NON-PRODUCTION dev/test signing identity (gitignored)
#   [2/9] clean-build hello-app V1 and V2 native images; V1 must reproduce the
#         historical Issue #2 bytes exactly; validate both against the pinned ABI
#   [3/9] rebuild V1 from clean again and require byte identity (reproducible)
#   [4/9] pack V1/V2 (and a content-conflict evidence package) with neapp_pack
#   [5/9] offline-verify the trusted packages with neapp_verify
#   [6/9] independently cross-verify signatures with the OpenSSL CLI
#   [7/9] adopt the P2 spec §2.5 golden + negative vectors verbatim
#         (byte-exact reconstruction, hash-asserted, expected class per vector)
#   [8/9] run the locally generated structure/DER/policy negative suite
#   [9/9] write structured evidence to docs/evidence/p3-package-artifacts.json
#
# Key discipline (AC3): the private key lives only under tests/package/work/
# (gitignored, owner-only) and is never printed; every artifact/document
# labels the dev/test identity as a NON-PRODUCTION trust root.
#
# A PASS of this suite proves offline generation/discrimination only.  It is
# NOT device install, execution, or power-fail recovery evidence.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/tests/package/work"
PKG_DIR="$WORK/pkg"
KEYS_DIR="$WORK/keys"
V1_IMAGE="$ROOT/apps/hello-app/build/hello-app.bin"
V2_IMAGE="$ROOT/apps/hello-app/build-v2/hello-app-v2.bin"
V1_ELF="$ROOT/apps/hello-app/build/hello-app.elf"
V2_ELF="$ROOT/apps/hello-app/build-v2/hello-app-v2.elf"
ABI_HEADER="$ROOT/apps/hello-app/build/cache/app_host_abi.h"
PYTHON=${PYTHON:-python3}
PUBLISHER=dev-publisher
APP_ID=hello-app

# Historical hello-app V1 image (Issue #2, docs/app-hello-poc.md §6,
# docs/evidence/build-evidence.md): 608 B, reproduced byte-exact.
HISTORICAL_V1_SHA256=d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03
# Historical v2 recorded in docs/evidence/device-evidence.md; NOT reproducible
# from committed sources and NOT claimed by this suite (we register a NEW
# experimental V2 build instead).
HISTORICAL_V2_SHA256=db1c6d60b398cab11a276e15770fdcdf9d42b9c96b4de6ef2cc93c1ecdec8744

step() { printf '\n== %s\n' "$*"; }

sha() { # portable sha256
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

step "[0/9] preflight"
command -v "$PYTHON" >/dev/null || { echo "python3 missing" >&2; exit 2; }
"$PYTHON" -c 'import cryptography' 2>/dev/null || { echo "python cryptography missing" >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl missing" >&2; exit 2; }
echo "python3=$($PYTHON --version 2>&1) cryptography=$($PYTHON -c 'import cryptography; print(cryptography.__version__)') openssl=$(openssl version 2>&1 | awk '{print $1 $2}')"
rm -rf "$WORK"
mkdir -p "$PKG_DIR"

step "[1/9] generate NON-PRODUCTION dev/test signing identity (AC3)"
"$PYTHON" "$ROOT/tests/package/gen_dev_key.py" --out-dir "$WORK" --publisher-id "$PUBLISHER"

step "[2/9] clean build hello-app V1 + V2 native images (pinned ABI, Arm GNU)"
make -C "$ROOT/apps/hello-app" cleanall all
make -C "$ROOT/apps/hello-app" clean all APP_VERSION=2
V1_SHA=$(sha "$V1_IMAGE")
V2_SHA=$(sha "$V2_IMAGE")
if [ "$V1_SHA" != "$HISTORICAL_V1_SHA256" ]; then
    echo "FAIL: rebuilt V1 $V1_SHA != historical $HISTORICAL_V1_SHA256" >&2
    exit 1
fi
echo "V1 reproduction OK: sha256 $V1_SHA (608 B, byte-identical to Issue #2 record)"
if [ "$V2_SHA" = "$V1_SHA" ] || [ "$V2_SHA" = "$HISTORICAL_V2_SHA256" ]; then
    echo "FAIL: V2 must be a distinct NEW experimental artifact" >&2
    exit 1
fi
echo "V2 new artifact: sha256 $V2_SHA ($(wc -c < "$V2_IMAGE" | tr -d ' ') B)"
echo "  (historical v2 $HISTORICAL_V2_SHA256 is NOT claimed; see docs/p3-packaging.md)"
"$PYTHON" "$ROOT/tools/validate_app_image.py" --image "$V1_IMAGE" --abi-header "$ABI_HEADER"
"$PYTHON" "$ROOT/tools/validate_app_image.py" --image "$V2_IMAGE" --abi-header "$ABI_HEADER"

step "[3/9] reproducibility: rebuild V1 from clean, require identical sha256"
make -C "$ROOT/apps/hello-app" clean all >/dev/null
V1_SHA2=$(sha "$V1_IMAGE")
if [ "$V1_SHA" != "$V1_SHA2" ]; then
    echo "FAIL: V1 rebuild not reproducible ($V1_SHA vs $V1_SHA2)" >&2
    exit 1
fi
echo "reproducible OK: sha256 $V1_SHA2"

step "[4/9] pack .neapp v1 packages (packer self-verifies before writing)"
"$PYTHON" "$ROOT/package/neapp_pack.py" \
    --image "$V1_IMAGE" --out "$PKG_DIR/hello-app-v1.neapp" \
    --key "$KEYS_DIR/dev-signer.pem" \
    --publisher-id "$PUBLISHER" --app-id "$APP_ID" --version 1.0.0 \
    --source-commit "$(git -C "$ROOT" rev-parse HEAD)"
"$PYTHON" "$ROOT/package/neapp_pack.py" \
    --image "$V2_IMAGE" --out "$PKG_DIR/hello-app-v2.neapp" \
    --key "$KEYS_DIR/dev-signer.pem" \
    --publisher-id "$PUBLISHER" --app-id "$APP_ID" --version 2.0.0 \
    --source-commit "$(git -C "$ROOT" rev-parse HEAD)"
# content-conflict evidence: V2 image labelled with version 1.0.0
"$PYTHON" "$ROOT/package/neapp_pack.py" \
    --image "$V2_IMAGE" --out "$PKG_DIR/v2-image-as-1.0.0.neapp" \
    --key "$KEYS_DIR/dev-signer.pem" \
    --publisher-id "$PUBLISHER" --app-id "$APP_ID" --version 1.0.0 \
    --source-commit "$(git -C "$ROOT" rev-parse HEAD)"

step "[5/9] offline verification of the trusted packages (must PASS)"
"$PYTHON" "$ROOT/package/neapp_verify.py" --package "$PKG_DIR/hello-app-v1.neapp" --trust "$WORK/trust-dev.json"
"$PYTHON" "$ROOT/package/neapp_verify.py" --package "$PKG_DIR/hello-app-v2.neapp" --trust "$WORK/trust-dev.json"
"$PYTHON" "$ROOT/package/neapp_verify.py" --package "$PKG_DIR/v2-image-as-1.0.0.neapp" --trust "$WORK/trust-dev.json"

step "[6/9] independent OpenSSL cross-verification of the same TBS/signatures"
openssl pkey -pubin -inform DER -in "$KEYS_DIR/dev-signer.spki.der" -out "$WORK/dev-pub.pem" 2>/dev/null
for pkg in hello-app-v1 hello-app-v2; do
    "$PYTHON" - "$PKG_DIR/$pkg.neapp" "$WORK/$pkg.tbs.bin" "$WORK/$pkg.sig.der" <<'EOF'
import struct, sys
data = open(sys.argv[1], "rb").read()
_, image_len = struct.unpack_from("<II", data, 8)
signed = 16 + 160 + image_len
open(sys.argv[2], "wb").write(data[:signed])
open(sys.argv[3], "wb").write(data[signed:])
EOF
    printf '%s: ' "$pkg"
    openssl dgst -sha256 -verify "$WORK/dev-pub.pem" \
        -signature "$WORK/$pkg.sig.der" "$WORK/$pkg.tbs.bin"
done

step "[7/9] P2 spec §2.5 vectors: byte-exact adoption + expected result classes"
"$PYTHON" "$ROOT/tests/package/spec_vectors.py" --out-dir "$WORK"

step "[8/9] locally generated structure/DER/policy cases"
"$PYTHON" "$ROOT/tests/package/generated_cases.py" \
    --work-dir "$WORK" \
    --v1-package "$PKG_DIR/hello-app-v1.neapp" \
    --v2-package "$PKG_DIR/hello-app-v2.neapp" \
    --v2-image-as-v1-package "$PKG_DIR/v2-image-as-1.0.0.neapp"

step "[9/9] write structured evidence"
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

spec_results = json.loads((work / "spec-vectors-results.json").read_text())
gen_results = json.loads((work / "generated-cases" / "generated-cases-results.json").read_text())
verify_reports = {}
for name in ("hello-app-v1", "hello-app-v2", "v2-image-as-1.0.0"):
    out = subprocess.run([sys.executable, str(root / "package" / "neapp_verify.py"),
                          "--package", str(pkg / f"{name}.neapp"),
                          "--trust", str(work / "trust-dev.json"), "--compact"],
                         capture_output=True, text=True, check=True)
    verify_reports[name] = json.loads(out.stdout.strip().splitlines()[0])

evidence = {
    "issue": "harryhua-ai/ne30x-app#6 (P3)",
    "boundary": ("OFFLINE packaging evidence only; NOT device install/execution/"
                 "power-fail-recovery PASS; signing identity is a NON-PRODUCTION test root"),
    "protocol_authority": "docs/app-package-protocol-v1.md (integrated P2 spec)",
    "source_commit": git("rev-parse", "HEAD"),
    "toolchain": {
        "arm_none_eabi_gcc": subprocess.run(
            ["arm-none-eabi-gcc", "--version"], capture_output=True, text=True
        ).stdout.splitlines()[0],
        "python_cryptography": subprocess.run(
            [sys.executable, "-c", "import cryptography; print(cryptography.__version__)"],
            capture_output=True, text=True).stdout.strip(),
    },
    "images": {
        "hello_app_v1": {
            "path": "apps/hello-app/build/hello-app.bin",
            "sha256": sha(root / "apps/hello-app/build/hello-app.bin"),
            "historical_issue2_sha256": "d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03",
            "reproduction": "byte-exact",
        },
        "hello_app_v2": {
            "path": "apps/hello-app/build-v2/hello-app-v2.bin",
            "sha256": sha(root / "apps/hello-app/build-v2/hello-app-v2.bin"),
            "note": ("NEW experimental V2 build (HELLO_APP_VERSION=2, 0x4E46); the "
                     "historical v2 db1c6d60… is not reproducible from committed "
                     "sources and is not claimed"),
        },
    },
    "packages": {
        name: {
            "sha256": sha(pkg / f"{name}.neapp"),
            "verifier_report": verify_reports[name],
        }
        for name in ("hello-app-v1", "hello-app-v2", "v2-image-as-1.0.0")
    },
    "spec_vector_suite": spec_results,
    "generated_case_suite": gen_results,
    "key_discipline": {
        "private_key_committed": False,
        "private_key_location": "tests/package/work/keys/ (gitignored, generated per run)",
        "trust_root": "NON-PRODUCTION dev/test identity; spec §2.5 d=1 key used only for spec vectors",
    },
}
out = root / "docs" / "evidence" / "p3-package-artifacts.json"
out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"evidence -> {out}")
EOF

printf '\n== ALL PACKAGE CHECKS PASSED\n'
printf 'V1 image  %s\n  sha256 %s\n' "$V1_IMAGE" "$V1_SHA"
printf 'V2 image  %s\n  sha256 %s\n' "$V2_IMAGE" "$V2_SHA"
printf 'V1 package %s\n  sha256 %s\n' "$PKG_DIR/hello-app-v1.neapp" "$(sha "$PKG_DIR/hello-app-v1.neapp")"
printf 'V2 package %s\n  sha256 %s\n' "$PKG_DIR/hello-app-v2.neapp" "$(sha "$PKG_DIR/hello-app-v2.neapp")"
