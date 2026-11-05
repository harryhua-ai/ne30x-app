from __future__ import annotations

"""Trusted product-version metadata carried inside an unsigned NEAPP v5 package.

The product version (the single user-facing 1.0.x line) travels as an ordinary
normalized UI asset, ``product-version.json``, so it is covered by the existing
v5 trust chain without any container/format/reserved-slot change:

- the packer's ``collect_assets()`` includes it like any other UI resource and
  the UI manifest records its length and SHA-256;
- the v5 verifier recomputes every asset SHA-256 (neapp_v5_format.py), and the
  UI manifest stays bound to the exact native member bytes.

Trust rules:
- A package claims product metadata ONLY by setting the ``CAP_PRODUCT_VERSION``
  capability bit (bit 10, 0x400) in the native manifest ``required_host_caps``.
  Hosts that predate the product-version metadata support only the 0x3ff mask
  and fail closed on that bit BEFORE install (existing unknown-bit and
  unsupported-bit admission refusals), so old Hosts can never silently install
  a package whose display semantics they do not understand.
- Verifiers must parse and strictly validate the carrier asset only for
  packages that require the capability bit. Packages without the bit keep
  their historical byte-for-byte verification behavior; a stray
  ``product-version.json`` there is just an opaque hashed asset and must not
  be trusted as product metadata (Host admission design: only trust the
  product version when the bit is set and admission accepted it).
- The encoding is canonical: exactly one JSON object with exactly one key
  ``product_version`` mapping to a ``MAJOR.MINOR.PATCH`` string (major >= 1,
  no leading zeros, ASCII digits only), serialized as
  ``{"product_version":"M.m.p"}`` with no whitespace, no extra fields, and no
  duplicate keys. Canonical bytes make Host-side extraction and equality
  checks deterministic.

Monotonicity (upgrade/downgrade/refusal rules) is a Host admission decision
and is intentionally NOT computed here; this module only validates the carrier
shape.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import neapp_v5_native as v4

PRODUCT_VERSION_ASSET_PATH = "product-version.json"

# Product version is MAJOR.MINOR.PATCH: major >= 1, no leading zeros.
PRODUCT_VERSION_RE = re.compile(r"^([1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

MIN_ASSET_LEN = 1
MAX_ASSET_LEN = 128


def parse_product_version(value: str) -> str:
    """Validate a product version string (the declared/requested form)."""
    if not isinstance(value, str) or PRODUCT_VERSION_RE.match(value) is None:
        raise ValueError(
            f"product version must be MAJOR.MINOR.PATCH with major >= 1 and "
            f"no leading zeros: got {value!r}")
    if int(value.split(".", 1)[0]) < 1:
        raise ValueError(f"product version major must be >= 1: got {value!r}")
    return value


def _reject_duplicate_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"duplicate JSON keys: {keys}")
    return dict(pairs)


def _reject_non_json_constant(value):
    raise ValueError(f"non-JSON constant {value!r} is not allowed")


def parse_product_version_asset(blob: bytes) -> str:
    """Strictly parse the canonical product-version carrier bytes."""
    if not isinstance(blob, bytes):
        raise v4.BadPackage("product-version asset payload must be raw bytes")
    if not MIN_ASSET_LEN <= len(blob) <= MAX_ASSET_LEN:
        raise v4.BadPackage(
            f"product-version asset is {len(blob)} bytes, outside the "
            f"{MIN_ASSET_LEN}..{MAX_ASSET_LEN}-byte carrier limit")
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as error:
        raise v4.BadPackage(
            f"product-version asset is not valid UTF-8: {error}") from error
    try:
        obj = json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                         parse_constant=_reject_non_json_constant)
    except ValueError as error:
        raise v4.BadPackage(
            f"product-version asset is not a strict JSON object: {error}") from error
    if not isinstance(obj, dict) or set(obj.keys()) != {"product_version"}:
        raise v4.BadPackage(
            "product-version asset must be a JSON object with exactly one key "
            "'product_version' and no extra fields")
    value = obj["product_version"]
    if not isinstance(value, str):
        raise v4.BadPackage("product_version must be a JSON string")
    try:
        parse_product_version(value)
    except ValueError as error:
        raise v4.BadPackage(str(error)) from error
    canonical = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    if text != canonical:
        raise v4.BadPackage(
            "product-version asset is not in the canonical encoding "
            f"{canonical!r}; whitespace/key-order variants are rejected so "
            "Host-side extraction stays byte-deterministic")
    return value


def extract_product_version(ui_manifest, ui_payload: bytes) -> str:
    """Locate and parse the carrier asset inside a verified v5 UI member.

    ``ui_manifest`` is a parsed ``neapp_v5_format.UiManifestV5`` whose records
    and payload have already passed the per-asset SHA-256 checks, so the
    returned string is bound to the exact verified package bytes.
    """
    cursor = 0
    for record in ui_manifest.records:
        if record.path == PRODUCT_VERSION_ASSET_PATH:
            blob = ui_payload[cursor:cursor + record.file_len]
            return parse_product_version_asset(blob)
        cursor += record.file_len
    raise v4.BadPackage(
        "package requires the product-version capability bit (0x400) but its "
        f"UI asset tree has no {PRODUCT_VERSION_ASSET_PATH!r} carrier asset")
