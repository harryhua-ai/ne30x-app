#!/bin/sh
set -eu
TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$TEST_DIR/../.." && pwd)
cd "$TEST_DIR"
pnpm install --offline --frozen-lockfile --ignore-scripts
npm --prefix browser-runner ci --offline --ignore-scripts
node browser-runner/build.mjs
node --test contract.test.mjs browser.test.mjs
if [ "${LC_SAVE_DIAGNOSTIC_MODE:-}" = "matrix" ]; then
    LC_SAVE_DIAGNOSTIC_PHASE=matrix node --test --test-name-pattern='line-save diagnostic matrix' browser.test.mjs
fi
sh "$REPO_ROOT/tests/line-crossing-runtime/run.sh"
