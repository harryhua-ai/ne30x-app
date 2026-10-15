#!/usr/bin/env python3
"""make_neui_fixture — deterministic NON-PRODUCTION asset-tree fixtures for
NEUI UI-Sidecar v1 offline tests (Issue #26 AC3).

Variants (pure functions of the variant name — same bytes on every host):
  base  four small assets (index.html, css/style.css, js/app.js,
        assets/data.txt) used for the golden positive vectors
  alt   same four paths with different bytes, used for the
        content-conflict / upgrade discriminator vectors

These fixtures are synthetic offline test material.  They are NOT the real
counting UI (ne301 counting@de25a6f1), never a production UI payload, and
carry no product claim.
"""

from __future__ import annotations

import argparse
from pathlib import Path

BASE_FILES = {
    "index.html": (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\"><title>NEUI fixture</title>"
        "<link rel=\"stylesheet\" href=\"css/style.css\"></head>\n"
        "<body>\n"
        "<h1>NEUI sidecar v1 offline test fixture</h1>\n"
        "<p>NON-PRODUCTION fixture; not the real counting UI.</p>\n"
        "<script src=\"js/app.js\"></script>\n"
        "</body>\n"
        "</html>\n"
    ),
    "css/style.css": (
        "body { font-family: sans-serif; margin: 2rem; }\n"
        "h1 { color: #036; }\n"
    ),
    "js/app.js": (
        "document.addEventListener('DOMContentLoaded', function () {\n"
        "  document.body.setAttribute('data-fixture', 'neui-sidecar-v1');\n"
        "});\n"
    ),
    "assets/data.txt": (
        "neui sidecar v1 fixture payload\n"
        "line 02\nline 03\nline 04\n"
    ),
}

ALT_FILES = {
    "index.html": (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\"><title>NEUI fixture alt</title>"
        "<link rel=\"stylesheet\" href=\"css/style.css\"></head>\n"
        "<body>\n"
        "<h1>NEUI sidecar v1 offline test fixture (alt content)</h1>\n"
        "<p>NON-PRODUCTION fixture; not the real counting UI.</p>\n"
        "<script src=\"js/app.js\"></script>\n"
        "</body>\n"
        "</html>\n"
    ),
    "css/style.css": (
        "body { font-family: serif; margin: 1rem; }\n"
        "h1 { color: #603; }\n"
    ),
    "js/app.js": (
        "document.addEventListener('DOMContentLoaded', function () {\n"
        "  document.body.setAttribute('data-fixture', 'neui-sidecar-v1-alt');\n"
        "});\n"
    ),
    "assets/data.txt": (
        "neui sidecar v1 fixture payload (alt)\n"
        "line 02 altered\nline 03 altered\n"
    ),
}

VARIANTS = {"base": BASE_FILES, "alt": ALT_FILES}


def write_fixture(out_dir: Path, variant: str) -> Path:
    files = VARIANTS[variant]
    root = out_dir / variant
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path,
                        help="output directory (must be gitignored)")
    parser.add_argument("--variant", choices=sorted(VARIANTS), default="base")
    args = parser.parse_args()
    root = write_fixture(args.out_dir, args.variant)
    print(f"fixture '{args.variant}' -> {root}")
    for rel in sorted(VARIANTS[args.variant]):
        print(f"  {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
