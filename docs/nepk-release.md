# NEPK v1.1 verification and production release

## Ordinary pull request verification

`.github/workflows/nepk_v1_1.yml` remains the pull request and main branch verification workflow. It builds Line Crossing native v4 and the production UI, runs the offline acceptance suites, and verifies a transient `TEST ONLY` package. The private test key and `.neapp` stay on the runner; the workflow does not use the production key, create a release sequence, or upload a test package. `GITHUB_RUN_NUMBER` is not a release sequence.

## One-click release

After the administrator setup below, an authorized maintainer can run the production workflow:

1. Open **Actions → NEPK v1.1 Production Release → Run workflow** and select `main`.
2. Enter one required input, `version`, in canonical `vMAJOR.MINOR.PATCH` form. The first release is `v1.0.0`.
3. Wait for a required reviewer to approve the protected `production` Environment.

One run checks the exact current `main` commit and its latest successful NEPK v1.1 verification, builds the native ELF and production UI, reads the native version from `apps/line-crossing/app/Makefile` and the UI package version from `tests/line-crossing-ui/package.sh`, reserves a sequence in the persistent ledger, signs the native/UI/Pair artifacts, runs independent verification, and fixes the package SHA-256. It creates the immutable version tag and a private Draft, reads back the tag, full Notes, asset list, and package bytes, records the signed and published states in the ledger, then publishes the Release.

The tag is `v<version without the leading v>`, and the asset is `line-crossing-<version without the leading v>.neapp`. Notes include the native version, NEUI version, release sequence, publisher SPKI SHA-256, package SHA-256, source SHA, and Host compatibility statement. No Packages or GHCR publication is configured.

A complete same-version Release with matching package bytes is read-only idempotent. Reusing a version with another source, build input, signature, or package digest is refused. An incomplete private Draft can be resumed by rerunning the same version when the authorized inputs still reproduce the recorded bytes. A published tag or asset is never replaced. Missing ledger, key, or protected configuration fails closed with an actionable error.

The sequence ledger is stored as `sequence-ledger.json` on `refs/heads/nepk-production-sequence-ledger`. Each write is a hash-chained JSON event and a Git commit whose parent is the ledger head read by that writer. The GitHub Git refs API updates the branch with `force: false`; a concurrent stale writer loses the compare-and-swap and retries from the new head. A workflow concurrency group also serializes production runs. Workflow run numbers are recorded as audit metadata only and never determine `release_seq`.

## Administrator one-time setup

Complete these steps before any production dispatch. The setup does not generate a signing identity or change the Host trust root.

1. In repository settings, create or verify the `production` Environment. Require at least one non-self reviewer and allow deployments from exactly the protected `main` branch. The workflow checks these rules before and after approval.
2. Add the existing production signing private key as the Environment secret `NEPK_PRODUCTION_ISSUER_KEY`. Its public SPKI must be the identity already trusted by the target Host.
3. Add these non-secret values to the same Environment:

   | Variable | Value |
   | --- | --- |
   | `NEPK_PRODUCTION_PUBLISHER_ID` | Existing production publisher identifier |
   | `NEPK_PRODUCTION_SPKI_DER_HEX` | Existing production SPKI DER bytes as lowercase hex |
   | `NEPK_PRODUCTION_SPKI_SHA256` | SHA-256 of those DER bytes and the private key's public SPKI |

4. Calculate the deterministic genesis fingerprint using the exact production publisher and existing Host SPKI fingerprint:

   ```sh
   python scripts/nepk_v1_1_production_release.py genesis-sha256 \
     --publisher-id "$NEPK_PRODUCTION_PUBLISHER_ID" \
     --spki-sha256 "$NEPK_PRODUCTION_SPKI_SHA256"
   ```

   Add the printed value as the Environment variable `NEPK_PRODUCTION_SEQUENCE_LEDGER_GENESIS_SHA256`. This value pins the one allowed empty genesis ledger.

5. With a GitHub token that can write repository contents, run the one-time initializer from a trusted administrator workstation. Set the local `NEPK_PRODUCTION_SEQUENCE_LEDGER_GENESIS_SHA256` value to the exact Environment value first. The command refuses a mismatch and refuses to replace an existing ledger ref:

   ```sh
   export NEPK_PRODUCTION_SEQUENCE_LEDGER_GENESIS_SHA256='<the configured Environment value>'
   export GH_TOKEN="$(gh auth token)"
   python scripts/nepk_v1_1_production_release.py initialize-ledger \
     --repository harryhua-ai/ne30x-app \
     --publisher-id "$NEPK_PRODUCTION_PUBLISHER_ID" \
     --spki-sha256 "$NEPK_PRODUCTION_SPKI_SHA256" \
     --expected-genesis-sha256 "$NEPK_PRODUCTION_SEQUENCE_LEDGER_GENESIS_SHA256"
   ```

   Verify the command reports `INITIALIZED` and record the returned ledger ref and commit SHA. Initialization creates only the genesis ref with sequence zero. It never allocates release sequence one; the first authorized release reserves sequence one through the normal compare-and-swap path. If the ledger is absent after initialization, stop and review repository state; a release run will not recreate it.

The workflow requires `contents: write` to create the version tag, Draft, asset, and non-force ledger commits. Do not allow force updates to the ledger ref. Keep the production key and Host trust root out of the repository and ordinary pull request workflow.

## Failure recovery and evidence

The ledger binds each version to the source SHA and a fingerprint of the built ELF, UI assets, publisher identity, and pinned toolchain versions. Retrying the same version with those exact inputs reuses its reservation and package identity. A changed input or signature conflicts with the existing record and requires an administrator to investigate; do not edit or reset ledger history to make a retry pass.

If publication fails after Draft creation, the Draft remains private. Rerun the same version after resolving the transient cause. The workflow verifies the existing tag, release notes, and any uploaded asset before uploading a missing asset or publishing. Byte mismatches, unexpected or duplicate assets, public Releases with missing assets, and tag conflicts are rejected. If publication succeeded but ledger finalization did not, rerunning verifies the published bytes and completes the ledger state without replacing the public Release.

The Actions evidence artifact contains the source SHA, ledger head and genesis fingerprint, publisher SPKI fingerprint, versions, sequence, package SHA-256, independent verification report, provenance, complete Release Notes, and GitHub Release result. It contains no private key. A `REJECTED` evidence file records actionable pre-publication failures when the script starts. Production Environment setup, ledger initialization, production signing, workflow dispatch, and public Release creation are administrator operations and have not been performed as part of this code change.
