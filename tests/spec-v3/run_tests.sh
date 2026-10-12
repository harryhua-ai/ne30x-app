#!/bin/sh
set -e
cd "$(dirname "$0")/../.."
python3 tests/spec-v3/run_all_tests.py
