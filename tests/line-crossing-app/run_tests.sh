#!/usr/bin/env bash
# run_tests.sh — one-command offline evidence suite for the Line Crossing
# App (Harry Dev Issue #11, P7 app integration).
#
# Pipeline (fully OFFLINE; no device, no network for the default path):
#   [1/6] core library builds clean (apps/line-crossing, unmodified sources)
#   [2/6] #8 equivalence regression: tests/line-crossing/run_tests.sh verbatim
#         (upstream regression test + golden-trace diff must stay green)
#   [3/6] unit tests (arena / json writer / state blob / config parity)
#   [4/6] business scenario tests through the real business layer + stub v2
#         table (AC2: windows, totals, target switch / manual reset, counter
#         name edit, model incompatible/recovery, gaps/backpressure,
#         persistence revision semantics, accepted-vs-delivered reports)
#   [5/6] host-contract tests: the REAL app_entry driven through a stub v2
#         function table (all ten functions' call/error contracts)
#   [6/6] native v2-ABI image build (arm-none-eabi, cortex-m55) + signed
#         .neapp v2 package (per-run NON-PRODUCTION dev key, gitignored) +
#         package/neapp_verify_v2.py offline verification
#
# Evidence: docs/evidence/p7-app/ (committed).  Keys and packages stay under
# tests/line-crossing-app/work/ (gitignored, never committed).
#
# A PASS of this suite proves offline implementation + call/error contracts
# only.  It does NOT prove device install, STM32/PKA signature verification,
# sustained AI inference, MQTT/Webhook remote delivery, or power-fail
# recovery (v2 spec §12; those belong to the NE301 device tasks).

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
APP_DIR="$ROOT/apps/line-crossing"
TESTS_DIR="$ROOT/tests/line-crossing-app"
EVIDENCE_DIR="$ROOT/docs/evidence/p7-app"
CC=${CC:-cc}
CFLAGS="-Wall -Wextra -Werror -std=c11 -O2 -I$APP_DIR/include -I$APP_DIR/app -I$TESTS_DIR"

step() { printf '\n== %s\n' "$*"; }
sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$EVIDENCE_DIR"
WORK="$TESTS_DIR/work"
mkdir -p "$WORK"

APP_SRCS="$APP_DIR/app/lc_app_entry.c $APP_DIR/app/lc_bus.c $APP_DIR/app/lc_bus_config.c \
$APP_DIR/app/lc_stateblob.c $APP_DIR/app/lc_json.c $APP_DIR/app/lc_arena.c"
CORE_SRCS="$APP_DIR/src/lc_tracker.c $APP_DIR/src/lc_line_cross.c"
STUB="$TESTS_DIR/host_stub.c"

step "[1/6] core library builds clean"
make -C "$APP_DIR" clean all > "$EVIDENCE_DIR/core-build.log" 2>&1
echo "OK: build/liblinecross.a"

step "[2/6] #8 core equivalence regression (must stay green)"
bash "$ROOT/tests/line-crossing/run_tests.sh" > "$EVIDENCE_DIR/core-regression.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/core-regression.log" >&2; exit 1; }
grep -E "RESULT: PASS" "$EVIDENCE_DIR/core-regression.log" >/dev/null \
    || { echo "FAIL: core regression did not report PASS" >&2; exit 1; }
grep -E "byte-identical" "$EVIDENCE_DIR/core-regression.log" >/dev/null \
    || { echo "FAIL: golden trace diff not identical" >&2; exit 1; }
echo "OK: upstream regression + golden trace still byte-identical"

step "[3/6] unit tests"
"$CC" $CFLAGS "$TESTS_DIR/test_unit.c" \
    "$APP_DIR/app/lc_arena.c" "$APP_DIR/app/lc_json.c" \
    "$APP_DIR/app/lc_stateblob.c" "$APP_DIR/app/lc_bus_config.c" \
    -o "$WORK/test_unit"
"$WORK/test_unit" | tee "$EVIDENCE_DIR/test-unit.log"

step "[4/6] business scenario tests (AC2) via business layer + stub v2 table"
"$CC" $CFLAGS "$TESTS_DIR/test_business.c" "$STUB" $APP_SRCS $CORE_SRCS \
    -o "$WORK/test_business"
"$WORK/test_business" | tee "$EVIDENCE_DIR/test-business.log"

step "[5/6] host-contract tests: real app_entry over stub v2 table"
"$CC" $CFLAGS "$TESTS_DIR/test_contract.c" "$STUB" $APP_SRCS $CORE_SRCS \
    -o "$WORK/test_contract"
"$WORK/test_contract" | tee "$EVIDENCE_DIR/test-contract.log"

step "[6/6] native v2 image + signed package + offline verification"
if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    for d in /Applications/ArmGNUToolchain/*/arm-none-eabi/bin; do
        [ -x "$d/arm-none-eabi-gcc" ] && PATH="$d:$PATH" && break
    done
fi
command -v arm-none-eabi-gcc >/dev/null 2>&1 \
    || { echo "FAIL: arm-none-eabi-gcc not found" >&2; exit 1; }
make -C "$APP_DIR/app" clean image package > "$EVIDENCE_DIR/native-build.log" 2>&1 \
    || { tail -30 "$EVIDENCE_DIR/native-build.log" >&2; exit 1; }
grep -E "EXPECTED RESULT MATCH: PASS" "$EVIDENCE_DIR/native-build.log" >/dev/null \
    || { echo "FAIL: offline package verification did not PASS" >&2; exit 1; }
grep -E "\.data.*0\b|   text" "$EVIDENCE_DIR/native-build.log" >/dev/null || true

IMAGE="$APP_DIR/app/build/lc-line-crossing.bin"
PKG="$WORK/pkg/lc-line-crossing-1.0.0.neapp.v2"
{
    echo "native_image: $IMAGE"
    echo "native_image_sha256: $(sha "$IMAGE")"
    echo "package: $PKG"
    echo "package_sha256: $(sha "$PKG")  (per-run dev-key signature; identity, not a pinned artifact)"
    echo "signing_identity: NON-PRODUCTION per-run dev key (tests/package/gen_dev_key.py), gitignored"
    echo "verifier: package/neapp_verify_v2.py --expect PASS (see native-build.log for full report)"
    echo "boundary: offline packaging/verification only — no device install/execution (v2 spec §12)"
} > "$EVIDENCE_DIR/native-package-hashes.txt"
echo "OK: image + signed package verified offline"

step "summary"
echo "evidence written under docs/evidence/p7-app/:"
ls -1 "$EVIDENCE_DIR"
UNIT_N=$(grep -oE "pass=[0-9]+" "$EVIDENCE_DIR/test-unit.log" | head -1)
BIZ_N=$(grep -oE "pass=[0-9]+" "$EVIDENCE_DIR/test-business.log" | head -1)
CON_N=$(grep -oE "pass=[0-9]+" "$EVIDENCE_DIR/test-contract.log" | head -1)
printf '\nRESULT: PASS (%s, %s, %s)\n' "$UNIT_N" "$BIZ_N" "$CON_N"
