#!/usr/bin/env python3
"""gen_dev_key — generate the NON-PRODUCTION P-256 dev/test signing identity.

Issue #6 AC3: the development/test signing identity is generated at test
time into a gitignored work directory; the private key never enters the
repository, logs, or deliverables.  Everything printed here is public
material (SPKI DER hex and its SHA-256 fingerprint only).

The generated key is a TEST ROOT.  It must never be presented as a
production publisher trust anchor (spec §4.1).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "package"))
import neapp_format as fmt  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path,
                        help="work directory (must be gitignored)")
    parser.add_argument("--publisher-id", default="dev-test-publisher",
                        help="publisher_id the dev key will be trusted for")
    args = parser.parse_args()

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    keys_dir = args.out_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    pem_path = keys_dir / "dev-signer.pem"
    spki_path = keys_dir / "dev-signer.spki.der"

    key = ec.generate_private_key(ec.SECP256R1())
    pem_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    spki = fmt.spki_der_from_public_key(key.public_key())
    spki_path.write_bytes(spki)
    fingerprint = hashlib.sha256(spki).hexdigest()

    trust = {
        "version": 1,
        "comment": (
            "NON-PRODUCTION offline test trust store; generated per test run "
            "by tests/package/gen_dev_key.py; dev/test identity only"
        ),
        "publishers": {
            args.publisher_id: {
                "spki_der_file": str(spki_path.resolve()),
                "spki_sha256": fingerprint,
            }
        },
    }
    trust_path = args.out_dir / "trust-dev.json"
    trust_path.write_text(json.dumps(trust, indent=2) + "\n", encoding="utf-8")

    # chmod the private key down to owner-only as basic hygiene.
    pem_path.chmod(0o600)

    print(f"dev signing identity generated (NON-PRODUCTION TEST ROOT)")
    print(f"  private key (gitignored, owner-only): {pem_path}")
    print(f"  signer SPKI DER: {spki_path} ({len(spki)} B)")
    print(f"  SHA-256(SPKI DER): {fingerprint}")
    print(f"  trust store: {trust_path} (publisher_id {args.publisher_id!r})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
