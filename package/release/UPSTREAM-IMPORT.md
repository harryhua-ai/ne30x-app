# Upstream import plan (camthink-ai/ne30x-app)

Constraints for the initial public import: **zero `docs/**` files** and
**exactly one `.neapp`-oriented workflow**.

## Include

- `apps/line-crossing/` (app, UI, tests)
- `common/`, `platform/`, `tools/`
- `package/unsigned/`, `package/release/` (incl. `known-limitations.md` —
  the release pipeline's only limitations input, no `docs/` dependency)
- `tests/line-crossing*/`, `tests/unsigned/`, `tests/release/`,
  `tests/fixtures/`
- `README.md`, `LICENSE`
- `.github/workflows/neapp.yml` — single combined workflow: the `candidate`
  job from `neapp-unsigned.yml` (push/PR/dispatch, `contents: read`, uploads
  the verified CI artifact) plus the `release` job from `release-app.yml`
  (`workflow_dispatch` on `refs/heads/main` only, `contents: write`,
  draft-only). Both jobs are copied verbatim; no behavior changes.

## Exclude

- `docs/**` (all internal design/study records)
- `.github/workflows/ght-*.yml` (governance tooling)
- `.ght/`, `.worktree/`, `.agents/`, internal study/test directories not
  required to build, test, package, and release the app

## Notes

- The release pipeline (`build_neapp.sh`, `release_tool.py`, both workflow
  jobs) references no `docs/**` path.
- Internal workflows may keep evolving in the development repository; they
  are not copied upstream automatically.
