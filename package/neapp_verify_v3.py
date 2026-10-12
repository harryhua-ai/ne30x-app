#!/usr/bin/env python3
"""neapp_verify_v3 — offline verifier for signed .neapp v3 packages.

Consumes the frozen v3 semantics via package/neapp_v3_format.py (layered on
package/neapp_format.py), in the normative order of the integrated v3 spec
(docs/app-package-protocol-v3.md §2.3 判定序):

  1. bounded container structure (v3 magic 4e45415050030000, manifest_len
     = 192, lengths, DER structure with tail fully consumed, package cap;
     unknown container versions reject — v1/v2 packages are never parsed)
  2. 192B NMF3 manifest unique-encoding decode (reserved invariants,
     required_host_abi = 0x00030000 format invariant)
  3. local trust mapping (publisher_id -> SHA-256(SPKI DER)); the package
     never self-trusts through any key material it carries
  4. ECDSA P-256 / SHA-256 verification over the exact raw TBS
  5. signed-content cross-checks (native NEA1 header, digests, CRC, entry,
     native-ABI <-> manifest-ABI binding, residency floor)
  6. Host policy: board / PSRAM / ABI, capability bits (bit8..31 reject;
     known-but-unsupported bits reject, §4.2), run_profile 2, quota/
     capability matching incl. control_max/snapshot_max, generic control-wire
     minimum 32, line-crossing-64 floors (event_max >= 1576, report_max >=
     6144), Host capacity ceilings, load region, independently known loader
     range, actual execution region

Failure classes: BAD_PACKAGE, SIGNATURE_INVALID, PUBLISHER_UNTRUSTED,
TARGET_INCOMPATIBLE, ABI_INCOMPATIBLE, RESOURCE_LIMIT (§11 mapping).

The trust store JSON supplies the trusted publisher public keys from LOCAL
configuration (the offline stand-in for the Host-built-in trust anchor);
the optional --policy JSON overrides the Host-side facts (board/ABI/caps/
loader range/quotas) — also LOCAL configuration, never package data.

BOUNDARY: a PASS here is offline packaging-layer evidence only.  It does
NOT mean NE301 admitted, installed, executed, or hot-reconfigured anything,
and does not mean an STM32/mbedTLS/PKA device verifier agrees (§14).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import neapp_format as fmt  # noqa: E402
import neapp_v3_format as fmt3  # noqa: E402

EXPECTED_RESULTS = ("PASS",) + tuple(cls.code for cls in fmt.ERROR_CLASSES)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--package", required=True, type=Path, help=".neapp.v3 package path")
    parser.add_argument("--trust", required=True, type=Path, help="trust store JSON")
    parser.add_argument("--policy", type=Path, default=None,
                        help="optional Host-policy JSON overrides (board/ABI/caps/loader/quotas)")
    parser.add_argument("--expect", choices=EXPECTED_RESULTS, default=None,
                        help="assert this exact verification result (test harness mode)")
    parser.add_argument("--compact", action="store_true", help="one-line JSON output")
    args = parser.parse_args()

    try:
        data = args.package.read_bytes()
        trust = fmt.load_trust_store(args.trust)
        policy_data = json.loads(args.policy.read_text(encoding="utf-8")) if args.policy else None
        policy = fmt3.DevicePolicyV3.from_json(policy_data)
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    report, err = fmt3.verify_package_v3(data, trust, policy)

    if report is not None:
        payload = report
        actual = "PASS"
        exit_code = 0
    else:
        actual = err.code
        payload = {
            "result": actual,
            "package_sha256": fmt.sha256_hex(data),
            "package_len": len(data),
            "detail": err.detail,
            "boundary": "offline verification only; no NE301 admission/install/execution/hot-config claim",
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
