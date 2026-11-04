#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "$0")/../.." && pwd)
OUT_DIR="$ROOT_DIR/apps/line-crossing/app/build/pkg"
SOURCE_SHA=""
while [ $# -gt 0 ]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --source-sha) SOURCE_SHA="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

UI_DIR="$ROOT_DIR/tests/line-crossing-ui"
APP_DIR="$ROOT_DIR/apps/line-crossing/app"
V4_APP_VERSION=$(make -C "$APP_DIR" -s print-v4_app_version)
V5_UI_VERSION=$(make -C "$APP_DIR" -s print-v5_ui_version)
PRODUCT_VERSION=$(make -C "$APP_DIR" -s print-v5_product_version)
[ -n "$V4_APP_VERSION" ] || { echo "empty V4_APP_VERSION" >&2; exit 1; }
[ -n "$V5_UI_VERSION" ] || { echo "empty V5_UI_VERSION" >&2; exit 1; }
[ -n "$PRODUCT_VERSION" ] || { echo "empty PRODUCT_VERSION" >&2; exit 1; }
# User-facing package filename uses the product version only (issue #6).
PACKAGE="$OUT_DIR/line-crossing-$PRODUCT_VERSION.neapp"

command -v arm-none-eabi-gcc >/dev/null || { echo "arm-none-eabi-gcc not found" >&2; exit 1; }
command -v node >/dev/null || { echo "node not found" >&2; exit 1; }
command -v pnpm >/dev/null || { echo "pnpm not found" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }

if [ ! -d "$UI_DIR/node_modules" ]; then
    pnpm --dir "$UI_DIR" install --frozen-lockfile --ignore-scripts
fi
if [ ! -d "$UI_DIR/browser-runner/node_modules" ]; then
    npm ci --prefix "$UI_DIR/browser-runner" --ignore-scripts
fi

[ -n "$SOURCE_SHA" ] || SOURCE_SHA=$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
node "$UI_DIR/browser-runner/build.mjs"
make -C "$APP_DIR" clean-v4
make -C "$APP_DIR" elf-v4
make -C "$APP_DIR" neapp-v5 V5_OUT_DIR="$OUT_DIR" V5_SOURCE_COMMIT="$SOURCE_SHA"

[ -f "$PACKAGE" ] || { echo "expected package missing: $PACKAGE" >&2; exit 1; }

VERIFICATION="$OUT_DIR/line-crossing-$PRODUCT_VERSION.verification.json"
# Product-version packages require the CAP_PRODUCT_VERSION gate bit (0x400),
# so the positive check simulates a product-version-capable Host (0x7ff).
python3 "$ROOT_DIR/package/unsigned/neapp_verify_v5.py" \
    --package "$PACKAGE" --host-caps-hex 0x7ff --compact > "$VERIFICATION"
python3 - "$VERIFICATION" "$PRODUCT_VERSION" <<'PY'
import json
import sys

report = json.loads(open(sys.argv[1], encoding="utf-8").read())
expected = sys.argv[2]
if report.get("result") != "PASS":
    raise SystemExit(f"verification failed: {report.get('result')}")
if report.get("product_version") != expected:
    raise SystemExit(
        f"verified product version mismatch: {report.get('product_version')!r}")
PY

# Old-Host fail-closed gate (negative check): the default simulated Host keeps
# the current 0x3ff support mask and MUST refuse the package before install.
OLDHOST="$OUT_DIR/line-crossing-$PRODUCT_VERSION.oldhost-gate.json"
set +e
python3 "$ROOT_DIR/package/unsigned/neapp_verify_v5.py" \
    --package "$PACKAGE" --compact > "$OLDHOST" 2>/dev/null
OLDHOST_RC=$?
set -e
if [ "$OLDHOST_RC" -eq 0 ]; then
    echo "old-Host admission gate did NOT refuse the product-version package" >&2
    exit 1
fi
python3 - "$OLDHOST" <<'PY'
import json
import sys

report = json.loads(open(sys.argv[1], encoding="utf-8").read())
if report.get("result") != "ABI_INCOMPATIBLE" or "0x400" not in report.get("detail", ""):
    raise SystemExit(
        f"unexpected old-Host gate failure: {report.get('result')}: "
        f"{report.get('detail', '')}")
PY

sha256sum "$PACKAGE" | awk '{ print $1 }' > "$PACKAGE.sha256"

python3 - "$ROOT_DIR" "$OUT_DIR" "$V4_APP_VERSION" "$V5_UI_VERSION" "$PRODUCT_VERSION" "$SOURCE_SHA" "$PACKAGE" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root, out_dir, native, ui, product, source_sha, package = sys.argv[1:8]
package = Path(package)
provenance = json.loads(
    Path(str(package) + ".provenance.json").read_text(encoding="utf-8"))
verification = json.loads(
    Path(str(package).replace(".neapp", ".verification.json"))
    .read_text(encoding="utf-8"))
if provenance["app_id"] != "line-crossing":
    raise SystemExit(f"unexpected app id: {provenance['app_id']}")
if [int(x) for x in native.split(".")] != provenance["native_version"]:
    raise SystemExit("provenance native version mismatch")
if [int(x) for x in ui.split(".")] != provenance["ui_version"]:
    raise SystemExit("provenance ui version mismatch")
if provenance.get("product_version") != product:
    raise SystemExit(
        f"provenance product version mismatch: {provenance.get('product_version')!r} != {product!r}")
digest = hashlib.sha256(package.read_bytes()).hexdigest()
if digest != provenance["package"]["sha256"]:
    raise SystemExit("package sha256 mismatch against provenance")
if verification.get("result") != "PASS":
    raise SystemExit(f"verification is not PASS: {verification.get('result')}")
if verification.get("product_version") != product:
    raise SystemExit(
        f"verification product version mismatch: {verification.get('product_version')!r}")
candidate = {
    "artifact": "neapp-v5-unsigned CI candidate",
    "official_release": False,
    "repo_version_recorded_separately": True,
    "source_sha": source_sha,
    "app_id": provenance["app_id"],
    "product_version": provenance["product_version"],
    "native_version": provenance["native_version"],
    "ui_version": provenance["ui_version"],
    "package": provenance["package"],
    "package_sha256_file": package.name + ".sha256",
    "provenance_file": package.name + ".provenance.json",
    "verification_file": package.name + ".verification.json",
    "oldhost_gate_file": package.name.replace(".neapp", ".oldhost-gate.json"),
    "verification_result": verification["result"],
}
path = package.parent / "candidate.json"
path.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
print(json.dumps(candidate, indent=2, sort_keys=True))
PY
