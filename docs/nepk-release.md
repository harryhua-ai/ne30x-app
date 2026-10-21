# NEPK v1.1 verification and release

## Verification workflow

`.github/workflows/nepk-v1_1.yml` runs for pull requests to `main`, pushes to `main`, and manual verification dispatches. It builds the real Line Crossing v4 ELF and production UI, runs the browser/H.264, runtime, bridge, and NEPK positive and negative suites, then makes and independently verifies a transient `TEST ONLY` package with a per-run test key.

The transient `.neapp` and private test key stay under the runner temporary directory. The uploaded Actions artifact contains only test logs, JSON verification reports, hashes, and run metadata; it never contains a `.neapp`. The test package uses a fixed test sequence value and is not an issuance or release sequence. `GITHUB_RUN_NUMBER` is not used as a release sequence.

The browser test records capability timestamps and freshness, edit/dirty/write state, pointer events, the trusted save click, and apply-wait samples at 1, 5, and 10 seconds plus the final outcome. `LC_SAVE_DIAGNOSTIC_MODE=matrix` runs controlled freshness, fixture-observation, and pointer-sequence injections after the normal H.264 browser suite; `LC_SAVE_EVIDENCE_PATH` writes the observations as JSON for the Actions artifact. The injected pointer sequence that omits movement deliberately exercises the unchanged 30-second wait. The investigation and evidence boundary are recorded in [the save-flake report](evidence/line-crossing-ui/save-flake-r2.md). No product freshness, write policy, H.264 coverage, or timeout was changed.

## Production workflow gates

`.github/workflows/nepk-v1_1-release.yml` is a manual capability for a separately authorized production issuance and Release action. Its preflight requires all of the following:

- Dispatch targets the current `main` SHA.
- The latest completed `NEPK v1.1 Verification` run for that exact SHA succeeded.
- The existing `production` Environment has a required reviewer, blocks self-review, and allows only the exact `main` branch policy.
- The release request action, source SHA, ledger structure, selected sequence records, and per-App identity are consistent.

Preflight reads the Environment and branch policies through GitHub's read-only API and fails when the Environment is missing or does not match. The workflow does not create or configure the Environment. At this implementation snapshot, the Environment query returned 404; authorized maintainers must configure it before production dispatch can pass.

After preflight succeeds, GitHub applies the `production` Environment gate before the signing job starts. That job rechecks the main SHA, verification run, Environment rules, and the protected ledger pin after approval. Missing or inconsistent production settings fail before key use. The job requires the secret `NEPK_PRODUCTION_ISSUER_KEY` and these non-secret Environment variables:

| Name | Required value |
| --- | --- |
| `NEPK_PRODUCTION_PUBLISHER_ID` | Authorized production publisher ID; known test publisher IDs are rejected |
| `NEPK_PRODUCTION_SPKI_DER_HEX` | Production issuer SubjectPublicKeyInfo DER, lowercase hex |
| `NEPK_PRODUCTION_SPKI_SHA256` | SHA-256 of the configured DER and exact signing key public key |
| `NEPK_PRODUCTION_SEQUENCE_LEDGER_SHA256` | SHA-256 pin of the authorized sequence ledger JSON |

The workflow references the environment secret only in the protected production job. The packer rejects the Host TEST ONLY key and the documented public `test-publisher` and `dev-publisher` keys. It checks the private key's SPKI against the configured production fingerprint and requires a private key file mode of `0600` or stricter. The key is written to a temporary file, omitted from provenance, and removed when the job exits.

## Release request

The manual `release_request_json` input must be JSON with this structure. This shape example omits the required authorized ledger record and is not a dispatchable request:

```json
{
  "version": 1,
  "action": "draft",
  "batch_version": "2.14.0",
  "source_sha": "<full lowercase main commit SHA>",
  "authorization": {
    "request_id": "<authorized request ID>",
    "authorization_ref": "https://<authorization-record>",
    "source_sha": "<same full SHA>",
    "action": "draft"
  },
  "sequence_ledger": {
    "version": 1,
    "records": []
  },
  "apps": [
    {
      "app_id": "line-crossing",
      "publisher_id": "<production publisher ID>",
      "native_version": "4.0.1",
      "ui_version": "1.0.1",
      "release_seq": 1,
      "sequence_record_id": "<authorized ledger record ID>",
      "compatibility": "<Host and UI ABI compatibility statement>"
    }
  ]
}
```

The `authorization_ref` must be an HTTPS reference without credentials, query parameters, or fragments. The `publish` request uses the same batch, source, app versions, package bytes, sequence records, and authorization request identity as the completed draft, with `action` changed to `publish` in both the request and authorization object. The sequence ledger is canonicalized and must match the protected SHA pin. Its selected record must be `authorized`, bind the exact source, publisher, app, native/UI versions, nonzero sequence and previous high-water mark, and include the expected native, UI, pair, and complete package digests. Sequence allocation and ledger recording remain owned by the authorized release responsible; Actions run numbers are never used for them.

The current production builder accepts one real app, `line-crossing`. The release planner and Release API tests cover one or multiple apps, duplicate IDs, asset collisions, incorrect app identity, sequence reuse, and partial asset sets with synthetic signed fixtures. Other apps are refused until they have an explicit real build recipe.

## Release behavior and evidence boundary

The production job builds the selected app from the accepted SHA, signs with the protected issuer, independently verifies the resulting NEPK bytes, checks the package and provenance against the pinned authorized record, and fixes the package SHA-256 before upload. Assets use `<app-id>-<batch-version>.neapp` names on one GitHub Release tag `v<batch-version>`. Release notes list each app asset, native and UI versions, `release_seq`, package digest, publisher SPKI fingerprint, source SHA, authorization request ID, and compatibility limits. No Packages or GHCR publication is configured.

The Release client creates a draft first, checks the tag target and complete asset bytes, and publishes only after all assets match the verified plan. Existing tags without a matching Release, conflicting versions or bytes, partial assets, and unauthorized actions fail closed. A complete matching publication is idempotent. An already public Release is never changed by a draft request.

Release Actions evidence contains only hashes, verification reports, provenance, request identity, and the Release API result. No release package is uploaded as a workflow artifact. A production workflow dispatch, production signature, draft, public Release, Environment configuration, and device operation have not been performed for this task. Those states remain `NOT_RUN` until separately authorized.
