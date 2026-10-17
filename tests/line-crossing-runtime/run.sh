#!/bin/sh
set -eu
TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$TEST_DIR/../.." && pwd)
cd "$TEST_DIR"
UI_TEST_DIR="$REPO_ROOT/tests/line-crossing-ui"
if [ ! -d "$UI_TEST_DIR/browser-runner/node_modules" ]; then
    npm --prefix "$UI_TEST_DIR/browser-runner" ci --offline --ignore-scripts
fi
if [ ! -d "$UI_TEST_DIR/node_modules" ]; then
    pnpm -C "$UI_TEST_DIR" install --offline --frozen-lockfile --ignore-scripts
fi
node "$UI_TEST_DIR/browser-runner/build.mjs"
node --test contract.test.mjs browser.test.mjs
