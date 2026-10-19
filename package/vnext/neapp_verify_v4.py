#!/usr/bin/env python3
"""neapp_verify_v4 — offline verifier for signed .neapp v4 packages.

Consumes the frozen v4 semantics via package/vnext/neapp_v4_format.py
(self-written v4 primitives, no shared code with the v1/v2/v3 tooling), in
the normative check order inherited from the v3-major precedent and pinned
by Host #104 F1:

  1. bounded container structure (magic 4e45415050040000, manifest_len 208,
     native_file_len caps, u64-checked lengths, DER window 8..72B with the
     tail fully consumed, package cap; v1/v2/v3 majors are foreign input
     and are never negotiated)
  2. strict-DER structural decode (canonical, fully consumed)
  3. 208B NMF4 manifest unique-encoding decode ([58..59] and [192..207]
     reserved zero, required_host_abi 0x00040000, identifier charset)
  4. local trust mapping (publisher_id -> SHA-256(SPKI DER)); package
     key material never self-trusts
  5. ECDSA P-256 / SHA-256 over the exact raw TBS = file[0:224+native_file_len]
  6. signed-content cross-checks (native NEA1 header with abi_version
     0x00040000, digests, CRC-32, Thumb entry, residency floor)
  7. intrinsic manifest policy (caps within 0x000003FF, run_profile 3,
     bit8/bit9 prerequisites, live quota closure, quota/capability
     consistency, 32B control-wire minimum)
  8. target-Host admission tier (--policy JSON): board/PSRAM/ABI,
     Host-provided capability bits, capacity ceilings, loader/exec geometry

Failure classes: BAD_PACKAGE, SIGNATURE_INVALID, PUBLISHER_UNTRUSTED,
TARGET_INCOMPATIBLE, ABI_INCOMPATIBLE, RESOURCE_LIMIT.

BOUNDARY: a PASS here is signed-format tooling evidence only.  It does NOT
mean a Host admitted or installed the package, a native image ran, or that
ENABLE_CONTROL / LIVE_PUBLISH are usable — those require the actual Host
to implement and grant them (UNAVAILABLE/UNAUTHORIZED otherwise).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import neapp_v4_format as fmt4

EXPECTED_RESULTS = ("PASS",) + tuple(cls.code for cls in fmt4.ERROR_CLASSES)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--package", required=True, type=Path, help=".neapp.v4 package path")
    parser.add_argument("--trust", required=True, type=Path, help="trust store JSON")
    parser.add_argument("--policy", type=Path, default=None,
                        help="optional Host-policy JSON overrides (board/ABI/caps/loader/"
                             "quotas/live capacity)")
    parser.add_argument("--expect", choices=EXPECTED_RESULTS, default=None,
                        help="assert this exact verification result (test harness mode)")
    parser.add_argument("--intrinsic-only", action="store_true",
                        help="run the package-intrinsic tier only (no Host-admission policy); "
                             "a PASS still makes no Host or runtime claim")
    parser.add_argument("--compact", action="store_true", help="one-line JSON output")
    args = parser.parse_args()

    try:
        data = args.package.read_bytes()
        trust = fmt4.load_trust_store_v4(args.trust)
        policy_data = json.loads(args.policy.read_text(encoding="utf-8")) if args.policy else None
        policy = fmt4.DevicePolicyV4.from_json(policy_data)
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    report, err = fmt4.verify_package_v4(
        data, trust, policy, host_admission=not args.intrinsic_only)

    if report is not None:
        payload = report
        actual = "PASS"
        exit_code = 0
    else:
        actual = err.code
        payload = {
            "result": actual,
            "package_sha256": fmt4.sha256_hex(data),
            "package_len": len(data),
            "detail": err.detail,
            "boundary": "offline signed-format verification only; no Host admission, "
                        "install, execution, floor, or live-delivery claim",
        }
        exit_code = 1

    print(json.dumps(payload, sort_keys=True,
                     indent=None if args.compact else 2))

    if args.expect is not None:
        if actual != args.expect:
            print(f"FAIL: expected {args.expect}, got {actual} ({args.package})",
                  file=sys.stderr)
            return 1
        print(f"EXPECTED RESULT MATCH: {actual} — {args.package}", file=sys.stderr)
        return 0

    if exit_code != 0:
        print(f"REJECTED: {actual} — {args.package}", file=sys.stderr)
    else:
        print(f"VERIFIED: {actual} — {args.package}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
