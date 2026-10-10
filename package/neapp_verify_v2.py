#!/usr/bin/env python3
"""neapp_verify_v2 — offline verifier for signed .neapp v2 packages.

Consumes the same frozen v2 semantics as the packer via
package/neapp_v2_format.py (layered on the shared v1 primitives in
package/neapp_format.py), in the normative order of the integrated v2 spec
(docs/app-package-protocol-v2-draft.md §2.3 判定序; identical to the #12
tests/spec-v2 `full_accept` order):

  1. bounded container structure (v2 magic, manifest_len = 192, lengths,
     signature window, package cap; unknown container versions reject)
  2. strict-DER signature structural decode (tail fully consumed)
  3. 192B manifest unique-encoding decode (NMF2, reserved invariants,
     required_host_abi = 0x00020000 format invariant)
  4. local trust mapping (publisher_id -> SHA-256(SPKI DER)); the package
     never self-trusts through any key material it carries
  5. ECDSA P-256 / SHA-256 verification over the exact raw TBS
  6. signed-content cross-checks (native NEA1 header, digests, CRC, entry,
     native-ABI <-> manifest-ABI binding, residency floor)
  7. Host policy: board / PSRAM / ABI, capability bits (unknown bits reject;
     known-but-unsupported bits reject, §4.2), run_profile, quota/capability
     matching, business floors (64-detection event_min 1576, report_min 6144),
     Host capacity ceilings, load region, independently known loader range

Failure classes: BAD_PACKAGE, SIGNATURE_INVALID, PUBLISHER_UNTRUSTED,
TARGET_INCOMPATIBLE, ABI_INCOMPATIBLE, RESOURCE_LIMIT (§9 mapping).

The trust store JSON supplies the trusted publisher public keys from LOCAL
configuration (the offline stand-in for the Host-built-in trust anchor);
the optional --policy JSON overrides the Host-side facts (board/ABI/caps/
loader range/quotas) — also LOCAL configuration, never package data.

BOUNDARY: a PASS here is offline packaging-layer evidence only.  It does
NOT mean the package was installed on a device, executed, power-fail
recovered, or that an STM32/mbedTLS/PKA device verifier agrees (§12).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import neapp_format as fmt  # noqa: E402
import neapp_v2_format as fmt2  # noqa: E402

EXPECTED_RESULTS = ("PASS",) + tuple(cls.code for cls in fmt.ERROR_CLASSES)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--package", required=True, type=Path, help=".neapp.v2 package path")
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
        policy = fmt2.DevicePolicyV2.from_json(policy_data)
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    report, err = fmt2.verify_package_v2(data, trust, policy)

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
            "boundary": "offline verification only; no device install/execution/PKA claim",
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
