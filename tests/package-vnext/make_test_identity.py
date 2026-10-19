#!/usr/bin/env python3
"""make_test_identity — materialize the NON-PRODUCTION v4 test identities.

Two PUBLIC, fully reproducible P-256 scalars (never production trust
roots, never committed as private keys):

  d=1  publisher "test-publisher" — the same PUBLIC non-production test
       scalar the v1/v2/v3 goldens use; SPKI SHA-256
       5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3.
       Key provenance: textbook public test scalar; anyone can reproduce
       the private key from d=1, which is exactly why it must never be a
       production anchor.
  d=2  publisher "dev-publisher" — second public test scalar for
       cross-publisher negatives; SPKI SHA-256
       dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba.

Writes PEM private keys (gitignored work dir, 0600) plus trust-store JSON
files whose SPKI material is validated against the pinned fingerprints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spec-vnext"))

import v4lib as V

D1_SPKI_SHA = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
D2_SPKI_SHA = "dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba"

IDENTITIES = (
    (1, "test-publisher", D1_SPKI_SHA),
    (2, "dev-publisher", D2_SPKI_SHA),
)


def write_private_key_pem(d: int, path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.derive_private_key(d, ec.SECP256R1())
    path.write_text(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
        encoding="ascii",
    )
    path.chmod(stat.S_IREAD | stat.S_IWRITE)


def trust_entry(spki: bytes) -> dict:
    return {
        "spki_der_hex": spki.hex(),
        "spki_sha256": hashlib.sha256(spki).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out-dir", required=True, type=Path,
                        help="output directory (gitignored work dir)")
    args = parser.parse_args()

    keys_dir = args.out_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    spkis = {}
    for d, publisher, pinned_sha in IDENTITIES:
        spki = V.spki_der_for_scalar(d)
        digest = hashlib.sha256(spki).hexdigest()
        if digest != pinned_sha:
            print(f"FATAL: d={d} SPKI sha256 {digest} != pinned {pinned_sha}", file=sys.stderr)
            return 2
        write_private_key_pem(d, keys_dir / f"d{d}-test-signer.pem")
        (args.out_dir / f"{publisher}.spki.der").write_bytes(spki)
        spkis[publisher] = (spki, digest)
        print(f"d={d} identity materialized (PUBLIC, NON-PRODUCTION): publisher "
              f"{publisher!r}, SPKI sha256 {digest}")

    single = {
        "version": 1,
        "comment": (
            "NON-PRODUCTION offline test trust store for the PUBLIC d=1 v4 test "
            "signer; regenerated per run; must never be a production trust anchor "
            "or a device production root"
        ),
        "publishers": {"test-publisher": trust_entry(spkis["test-publisher"][0])},
    }
    (args.out_dir / "trust-d1.json").write_text(json.dumps(single, indent=2) + "\n",
                                                encoding="utf-8")

    both = {
        "version": 1,
        "comment": (
            "NON-PRODUCTION offline test trust store with both PUBLIC v4 test "
            "publishers (d=1 golden signer and d=2 cross-publisher); never a "
            "production trust anchor"
        ),
        "publishers": {
            "test-publisher": trust_entry(spkis["test-publisher"][0]),
            "dev-publisher": trust_entry(spkis["dev-publisher"][0]),
        },
    }
    (args.out_dir / "trust-both.json").write_text(json.dumps(both, indent=2) + "\n",
                                                  encoding="utf-8")

    committed = Path(__file__).resolve().parents[2] / "docs" / "evidence" / "package-vnext" / "spec" / "test-publisher.spki.der"
    if committed.exists() and committed.read_bytes() != spkis["test-publisher"][0]:
        print("FATAL: generated d=1 SPKI differs from the committed spec artifact",
              file=sys.stderr)
        return 2

    print(f"trust stores -> {args.out_dir / 'trust-d1.json'}, {args.out_dir / 'trust-both.json'}")
    print(f"private keys (gitignored): {keys_dir}/d1-test-signer.pem, {keys_dir}/d2-test-signer.pem")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
