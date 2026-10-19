#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
APP_DIR="$ROOT/apps/line-crossing"
TESTS_DIR="$ROOT/tests/line-crossing-live"
APP_TESTS="$ROOT/tests/line-crossing-app"
EVIDENCE_DIR="$ROOT/docs/evidence/line-crossing-live"
HOST_REPO=${HOST_REPO:-/Users/harryhua/Documents/GitHub/ne301}
HOST_SHA=4c1c0d7ec5bc8ae18fae4ca5a31f0699b7c5895b
APP_BASE_SHA=a1b93322ae010356a6293421a137564fc0e23664
CC=${CC:-cc}

step() { printf '\n== %s\n' "$*"; }

mkdir -p "$EVIDENCE_DIR" "$TESTS_DIR/work"
mkdir -p "$EVIDENCE_DIR/fixtures"

CFLAGS="-Wall -Wextra -Werror -std=c11 -O2 -I$APP_DIR/include -I$APP_DIR/app -I$TESTS_DIR -I$APP_TESTS -include $TESTS_DIR/live_alloc.h"
ALLOC="-DLC_MALLOC(sz)=live_malloc(sz) -DLC_FREE(p)=live_free(p)"

CORE_SRCS="$APP_DIR/src/lc_tracker.c $APP_DIR/src/lc_line_cross.c"
BUS_SRCS="$APP_DIR/app/lc_bus.c $APP_DIR/app/lc_bus_config.c $APP_DIR/app/lc_stateblob.c $APP_DIR/app/lc_json.c $APP_DIR/app/lc_lvn4.c"
FIXTURE_SRCS="$TESTS_DIR/live_stub.c $TESTS_DIR/ref_decoder.c"

CC_ID=$("$CC" --version 2>/dev/null | head -n 1 || echo unknown)
ARM_ID=$(command -v arm-none-eabi-gcc >/dev/null 2>&1 && arm-none-eabi-gcc --version | head -n 1 || echo "arm-none-eabi-gcc not found")
APP_SHA=$(git -C "$ROOT" rev-parse HEAD)
HOST_SRC="$TESTS_DIR/work/host-$HOST_SHA"
if ! git -C "$HOST_REPO" cat-file -e "$HOST_SHA^{commit}"; then
    echo "FAIL: exact Host #91 source commit is unavailable" >&2
    exit 1
fi
mkdir -p "$HOST_SRC"
git -C "$HOST_REPO" archive --format=tar "$HOST_SHA" \
    Custom/Services/AppHost/app_host_live.c \
    Custom/Services/AppHost/app_host_live.h \
    Custom/Services/AppHost/app_admission.h \
    Custom/Common/Inc/aicam_types.h | tar -xf - -C "$HOST_SRC"
{
    echo "suite: tests/line-crossing-live"
    echo "host_cc: $CC_ID"
    echo "arm_toolchain: $ARM_ID"
    echo "app_candidate_sha: $APP_SHA"
    echo "app_accepted_base_sha: $APP_BASE_SHA"
    echo "host_parser_sha: $HOST_SHA"
    echo "host_source_mode: read-only git archive"
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$EVIDENCE_DIR/env.txt"

step "[1/5] live wire producer suite (real lc_bus + real lc_tracker fixture)"
"$CC" $CFLAGS $ALLOC "$TESTS_DIR/test_live_wire.c" $FIXTURE_SRCS $BUS_SRCS $CORE_SRCS \
    -o "$TESTS_DIR/work/test_live_wire"
"$TESTS_DIR/work/test_live_wire" | tee "$EVIDENCE_DIR/test-live-wire.log"

step "[2/5] live bus integration suite"
"$CC" $CFLAGS $ALLOC "$TESTS_DIR/test_live_bus.c" $FIXTURE_SRCS $BUS_SRCS $CORE_SRCS \
    -o "$TESTS_DIR/work/test_live_bus"
"$TESTS_DIR/work/test_live_bus" | tee "$EVIDENCE_DIR/test-live-bus.log"

step "[3/5] App producer bytes through pinned Host #91 parser and read cursor"
HOST_APP_DIR="$HOST_SRC/Custom/Services/AppHost"
HOST_COMMON_DIR="$HOST_SRC/Custom/Common/Inc"
"$CC" $CFLAGS $ALLOC \
    -I"$HOST_APP_DIR" -I"$HOST_COMMON_DIR" \
    "$TESTS_DIR/test_host_joint.c" $FIXTURE_SRCS $BUS_SRCS $CORE_SRCS \
    "$HOST_APP_DIR/app_host_live.c" \
    -o "$TESTS_DIR/work/test_host_joint"
"$TESTS_DIR/work/test_host_joint" "$EVIDENCE_DIR/fixtures" | tee "$EVIDENCE_DIR/test-host-joint.log"

step "[4/5] App #30 schema3 Paused/UNKNOWN gate with the live observer attached"
"$CC" $CFLAGS \
    "$TESTS_DIR/test_pause_gate.c" \
    "$APP_TESTS/host_stub.c" \
    "$APP_DIR/app/lc_app_entry_v4.c" \
    "$APP_DIR/app/lc_bus.c" \
    "$APP_DIR/app/lc_bus_config.c" \
    "$APP_DIR/app/lc_stateblob.c" \
    "$APP_DIR/app/lc_ctrl.c" \
    "$APP_DIR/app/lc_cfgcodec.c" \
    "$APP_DIR/app/lc_json.c" \
    "$APP_DIR/app/lc_arena.c" \
    "$APP_DIR/app/lc_lvn4.c" \
    "$APP_DIR/src/lc_tracker.c" \
    "$APP_DIR/src/lc_line_cross.c" \
    -o "$TESTS_DIR/work/test_pause_gate"
"$TESTS_DIR/work/test_pause_gate" | tee "$EVIDENCE_DIR/test-paused-gate.log"

step "[5/5] real v4 app_entry producer through current Host #91 parser"
"$CC" $CFLAGS \
    -I"$HOST_APP_DIR" -I"$HOST_COMMON_DIR" -I"$APP_TESTS" \
    "$TESTS_DIR/test_entry_activation.c" \
    "$APP_TESTS/host_stub.c" \
    "$APP_DIR/app/lc_app_entry_v4.c" \
    "$APP_DIR/app/lc_bus.c" \
    "$APP_DIR/app/lc_bus_config.c" \
    "$APP_DIR/app/lc_stateblob.c" \
    "$APP_DIR/app/lc_ctrl.c" \
    "$APP_DIR/app/lc_cfgcodec.c" \
    "$APP_DIR/app/lc_json.c" \
    "$APP_DIR/app/lc_arena.c" \
    "$APP_DIR/app/lc_lvn4.c" \
    "$APP_DIR/src/lc_tracker.c" \
    "$APP_DIR/src/lc_line_cross.c" \
    "$HOST_APP_DIR/app_host_live.c" \
    -o "$TESTS_DIR/work/test_entry_activation"
"$TESTS_DIR/work/test_entry_activation" | tee "$EVIDENCE_DIR/test-entry-host-activation.log"

python3 -c 'import hashlib,pathlib,sys; root=pathlib.Path(sys.argv[1]); rows=[(p.name,p.stat().st_size,hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.glob("*.bin"))]; print("".join(f"{digest} {size} {name}\n" for name,size,digest in rows),end="")' \
    "$EVIDENCE_DIR/fixtures" > "$EVIDENCE_DIR/fixture-sha256.txt"

step "summary"
WIRE_N=$(grep -oE "pass=[0-9]+ fail=[0-9]+" "$EVIDENCE_DIR/test-live-wire.log" | tail -1)
BUS_N=$(grep -oE "pass=[0-9]+ fail=[0-9]+" "$EVIDENCE_DIR/test-live-bus.log" | tail -1)
HOST_N=$(grep -oE "pass=[0-9]+ fail=[0-9]+" "$EVIDENCE_DIR/test-host-joint.log" | tail -1)
PAUSE_N=$(grep -oE "pass=[0-9]+ fail=[0-9]+" "$EVIDENCE_DIR/test-paused-gate.log" | tail -1)
ENTRY_N=$(grep -oE "pass=[0-9]+ fail=[0-9]+" "$EVIDENCE_DIR/test-entry-host-activation.log" | tail -1)
printf 'RESULT: PASS (%s, %s, %s, %s, %s)\n' \
    "$WIRE_N" "$BUS_N" "$HOST_N" "$PAUSE_N" "$ENTRY_N"
