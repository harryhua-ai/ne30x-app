#!/usr/bin/env bash
# fetch_abi_header.sh — fetch the single versioned NE301 public Host ABI header
# from the pinned upstream commit into a build cache location, with sha256 lock.
#
# The ne30x-app repo must NOT carry a copy of the header (drift protection):
# this script is the only sanctioned way the header enters a build.
#
# Sources, in order (all verified against EXPECTED_SHA256 before use):
#   1. an already-populated, sha256-verified destination (offline rebuilds)
#   2. a local read-only checkout pinned at PINNED_SHA
#      (env NE301_PINNED_RO, default /tmp/ne301-pinned-ro)
#   3. raw.githubusercontent.com (pure network path)
#   4. `gh api` (authenticated network fallback)
#
# Usage: fetch_abi_header.sh <dest-header-path>
# Exit 0 and print the destination path on success; non-zero on any failure.

set -euo pipefail

PINNED_SHA="a5b4bf3dd25931d612680aff200e4e0ac8d8e64e"
UPSTREAM_REPO="harryhua-ai/ne301"
UPSTREAM_PATH="Custom/Common/Inc/app_host_abi.h"
EXPECTED_SHA256="9337f684893cf2a06aea6f6f8c448708d91e8f9c6c86c24905ced8a7d5df23f4"
RAW_URL="https://raw.githubusercontent.com/${UPSTREAM_REPO}/${PINNED_SHA}/${UPSTREAM_PATH}"

if [ $# -ne 1 ]; then
    echo "usage: $0 <dest-header-path>" >&2
    exit 2
fi

dest=$1
dest_dir=$(dirname "$dest")
mkdir -p "$dest_dir"

sha256_of() {
    # portable sha256 (macOS shasum / coreutils sha256sum)
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

install_verified() { # <src> <label>
    local src=$1 label=$2 got
    got=$(sha256_of "$src")
    if [ "$got" != "$EXPECTED_SHA256" ]; then
        echo "fetch_abi_header: sha256 mismatch from ${label}" >&2
        echo "  expected ${EXPECTED_SHA256}" >&2
        echo "  got      ${got}" >&2
        return 1
    fi
    cp "$src" "${dest}.tmp"
    mv "${dest}.tmp" "$dest"
    echo "fetch_abi_header: OK (${label}) -> ${dest}"
    echo "  pinned ${UPSTREAM_REPO}@${PINNED_SHA}:${UPSTREAM_PATH}"
    echo "  sha256 ${EXPECTED_SHA256}"
    return 0
}

# 1. cached destination that still matches the lock
if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "$EXPECTED_SHA256" ]; then
    echo "fetch_abi_header: cached OK -> ${dest}"
    exit 0
fi

# 2. local pinned read-only checkout (HEAD must equal the pinned SHA)
local_ro="${NE301_PINNED_RO:-/tmp/ne301-pinned-ro}"
if [ -f "${local_ro}/${UPSTREAM_PATH}" ]; then
    head_sha=$(git -C "$local_ro" rev-parse HEAD 2>/dev/null || echo "not-a-git-repo")
    if [ "$head_sha" = "$PINNED_SHA" ]; then
        if install_verified "${local_ro}/${UPSTREAM_PATH}" "local pinned checkout ${local_ro}"; then
            exit 0
        fi
    else
        echo "fetch_abi_header: ${local_ro} is at ${head_sha}, not pinned ${PINNED_SHA}; skipping" >&2
    fi
fi

# 3. pure network path (repo is public; curl with -f so HTTP errors fail)
tmp_dl="${dest}.download"
if curl -fsSL --retry 2 -o "$tmp_dl" "$RAW_URL" 2>/dev/null; then
    if install_verified "$tmp_dl" "raw.githubusercontent.com"; then
        rm -f "$tmp_dl"
        exit 0
    fi
    rm -f "$tmp_dl"
    echo "fetch_abi_header: network content does not match the pinned sha256" >&2
    exit 1
fi
rm -f "$tmp_dl"

# 4. authenticated fallback
if command -v gh >/dev/null 2>&1; then
    if gh api "repos/${UPSTREAM_REPO}/contents/${UPSTREAM_PATH}?ref=${PINNED_SHA}" \
        --jq '.content' | base64 -d > "$tmp_dl" 2>/dev/null && [ -s "$tmp_dl" ]; then
        if install_verified "$tmp_dl" "gh api"; then
            rm -f "$tmp_dl"
            exit 0
        fi
    fi
fi
rm -f "$tmp_dl"

echo "fetch_abi_header: FAILED to obtain ${UPSTREAM_REPO}@${PINNED_SHA}:${UPSTREAM_PATH}" >&2
echo "  pinned sha256 must be ${EXPECTED_SHA256}" >&2
exit 1
