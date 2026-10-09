#!/usr/bin/env bash
# run_build_checks.sh — one-command host-side build + static acceptance checks
# for Harry Dev Issue #2 (hello-app standalone build PoC).
#
# Steps:
#   1. fetch pinned ABI header (sha256-locked) + clean build of hello-app
#   2. validate the packed image -> must be VALID
#   3. rebuild from clean and require a byte-identical image (reproducible build)
#   4. generate corrupt-image fixtures
#   5. each fixture must be rejected for exactly its expected reason
#
# Exit non-zero on the first failed step. Device-side (AC2 / on-target AC3)
# steps are out of scope here and are executed by the coordinator.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP_DIR="$ROOT/apps/hello-app"
BUILD_DIR="$APP_DIR/build"
IMAGE="$BUILD_DIR/hello-app.bin"
ABI_HEADER="$BUILD_DIR/cache/app_host_abi.h"
BAD_DIR="$BUILD_DIR/bad-images"
PYTHON=${PYTHON:-python3}

step() { printf '\n== %s\n' "$*"; }

step "[1/5] clean build (fetches pinned ABI header)"
make -C "$APP_DIR" clean all

step "[2/5] validate packed image (must be VALID)"
"$PYTHON" "$ROOT/tools/validate_app_image.py" --image "$IMAGE" --abi-header "$ABI_HEADER"

step "[3/5] reproducibility: rebuild from clean, require identical sha256"
sha_first=$(shasum -a 256 "$IMAGE" | awk '{print $1}')
make -C "$APP_DIR" clean all >/dev/null
sha_second=$(shasum -a 256 "$IMAGE" | awk '{print $1}')
if [ "$sha_first" != "$sha_second" ]; then
    echo "FAIL: image not reproducible" >&2
    echo "  first  $sha_first" >&2
    echo "  second $sha_second" >&2
    exit 1
fi
echo "reproducible OK: sha256 $sha_second"

step "[4/5] generate corrupt-image fixtures"
"$PYTHON" "$ROOT/tools/make_bad_images.py" --good "$IMAGE" --out-dir "$BAD_DIR"

step "[5/5] every fixture must be rejected for its expected reason"
rc=0
for bad in "$BAD_DIR"/bad-*.bin; do
    name=$(basename "$bad")
    reason=${name#bad-}
    reason=${reason%.bin}
    if ! "$PYTHON" "$ROOT/tools/validate_app_image.py" \
            --image "$bad" --abi-header "$ABI_HEADER" --expect-failure "$reason"; then
        rc=1
    fi
done
if [ "$rc" -ne 0 ]; then
    echo "FAIL: at least one fixture was not rejected as expected" >&2
    exit 1
fi

printf '\n== ALL BUILD CHECKS PASSED\n'
printf 'image   %s\n' "$IMAGE"
printf 'sha256  %s\n' "$sha_second"
printf 'size    %s bytes\n' "$(wc -c < "$IMAGE" | tr -d ' ')"
