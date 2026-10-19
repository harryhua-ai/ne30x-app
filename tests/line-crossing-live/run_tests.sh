#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
APP_DIR="$ROOT/apps/line-crossing"
TESTS_DIR="$ROOT/tests/line-crossing-live"
EVIDENCE_DIR="$ROOT/docs/evidence/line-crossing-live"
CC=${CC:-cc}

step() { printf '\n== %s\n' "$*"; }

mkdir -p "$EVIDENCE_DIR" "$TESTS_DIR/work"

CFLAGS="-Wall -Wextra -Werror -std=c11 -O2 -I$APP_DIR/include -I$APP_DIR/app -I$TESTS_DIR -include $TESTS_DIR/live_alloc.h"
ALLOC="-DLC_MALLOC(sz)=live_malloc(sz) -DLC_FREE(p)=live_free(p)"

CORE_SRCS="$APP_DIR/src/lc_tracker.c $APP_DIR/src/lc_line_cross.c"
BUS_SRCS="$APP_DIR/app/lc_bus.c $APP_DIR/app/lc_bus_config.c $APP_DIR/app/lc_stateblob.c $APP_DIR/app/lc_json.c $APP_DIR/app/lc_lvn4.c"
FIXTURE_SRCS="$TESTS_DIR/live_stub.c $TESTS_DIR/ref_decoder.c"

CC_ID=$("$CC" --version 2>/dev/null | head -n 1 || echo unknown)
ARM_ID=$(command -v arm-none-eabi-gcc >/dev/null 2>&1 && arm-none-eabi-gcc --version | head -n 1 || echo "arm-none-eabi-gcc not found")
{
    echo "suite: tests/line-crossing-live"
    echo "host_cc: $CC_ID"
    echo "arm_toolchain: $ARM_ID"
    echo "repo: ne30x-app agent/27/12c88d73 (base 1f48bdd)"
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$EVIDENCE_DIR/env.txt"

step "[1/2] live wire producer suite (real lc_bus + real lc_tracker fixture)"
"$CC" $CFLAGS $ALLOC "$TESTS_DIR/test_live_wire.c" $FIXTURE_SRCS $BUS_SRCS $CORE_SRCS \
    -o "$TESTS_DIR/work/test_live_wire"
"$TESTS_DIR/work/test_live_wire" | tee "$EVIDENCE_DIR/test-live-wire.log"

step "[2/2] live bus integration suite"
"$CC" $CFLAGS $ALLOC "$TESTS_DIR/test_live_bus.c" $FIXTURE_SRCS $BUS_SRCS $CORE_SRCS \
    -o "$TESTS_DIR/work/test_live_bus"
"$TESTS_DIR/work/test_live_bus" | tee "$EVIDENCE_DIR/test-live-bus.log"

step "summary"
WIRE_N=$(grep -oE "pass=[0-9]+ fail=[0-9]+" "$EVIDENCE_DIR/test-live-wire.log" | tail -1)
BUS_N=$(grep -oE "pass=[0-9]+ fail=[0-9]+" "$EVIDENCE_DIR/test-live-bus.log" | tail -1)
printf 'RESULT: PASS (%s, %s)\n' "$WIRE_N" "$BUS_N"
