# Signed NEPK release path: abandoned

The standalone per-App digital signing scheme (NEPK v1.1 native/UI/Pair
three-signature packages, publisher SPKI trust anchors, the production signing
key, the protected `production` Environment gates, and the
`nepk-production-sequence-ledger` release-sequence ledger) is **abandoned** as
the App packaging premise per ne301 issue #136 (2026-10-23). The one-click
signed production release workflow and its scripts were removed from this
repository.

This is a policy decision recorded in code, not a claim about repository
back-end state: the GitHub Environment, its secrets/variables, and any existing
ledger ref may still exist and are left for a repository administrator to
review separately. Nothing here asserts those back-end settings were deleted.

## What replaces it

Packaging and verification now use the unsigned single-file `.neapp` v5 format
([app-package-unsigned-v5.md](app-package-unsigned-v5.md)):

- CI verification workflow: `.github/workflows/neapp-unsigned.yml` builds the
  real Line Crossing native v4 ELF plus the production UI and independently
  verifies the resulting `line-crossing-<version>.neapp`. It requires no key,
  SPKI, signature, Environment, or sequence ledger input.
- Local reproduction: `make -C apps/line-crossing/app neapp-v5` after building
  the UI assets.
- Legacy signed formats (neapp v1/v2/v3/v4, NEUI sidecar v1, NEPK v1.1) are
  still parsed far enough to be identified and are rejected with
  `LEGACY_SIGNED_FORMAT`; they are never mis-parsed as unsigned packages. Their
  format libraries and unit tests remain in the repository as the legacy
  detection reference.

SHA-256 digests in the unsigned format check file and member consistency only.
They do not prove publisher authenticity and do not provide a trusted
anti-rollback guarantee: anyone allowed to modify a package can recompute the
digests. Administrator accountability for installed native code replaces
publisher verification; original-vendor firmware signing and Host-side
administrator authorization are unchanged.
