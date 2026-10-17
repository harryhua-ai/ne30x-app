# Line Crossing runtime bridge (App #32)

Authoritative inputs: ne301 #84 comment 6229932486 (frozen browser-level typed
MessagePort bridge v1, shared with the Host implementation) and the App #32
`ght-contract`. This document is the App-owned HOW for that frozen WHAT: the
production signed counting UI consumes Host-granted capabilities only through
this adapter and fails closed on every deviation. It does not re-freeze wire
semantics, grant Host API passthrough, or claim any device/cross-site property
that has not been executed.

## Production entry

`apps/line-crossing/ui/src/main.tsx`:

- top-level document (`window.parent === window`) or opaque origin
  (`self.origin === 'null'`): `unavailableCapabilities`; the adapter is not
  armed at all;
- framed document: `createRuntimeCapabilities(connectHostBridge())` passed to
  the unchanged `LineCountingModule` from App #25.

The test fixture entry (`tests/line-crossing-ui/src/test-main.tsx`) keeps its
own `createTestCapabilities` injection. The production entry never imports test
code and never defines `__lineCrossingTest`; the UI suite asserts this against
the production build output.

## Bridge v1 usage (App side)

- Handshake: exactly one `HELLO` on `ne301.sidecar.bridge.v1`, accepted only
  from `event.source === window.parent`, trusted event, non-opaque sender
  origin, exactly one `MessageChannel` port, exact channel field. The App
  never treats its own URL, `app_id` strings, or a nonce as authorization;
  real admission stays with Host #83/#84.
- Envelope: `protocol/type/seq/grant_id/identity` on every message; strict
  exact-field validation for `HELLO/GRANT/REQUEST/RESULT/EVENT/REVOKE`;
  `identity` is the full 10-field tuple; `app_id` must equal
  `line-crossing` before any grant is adopted.
- Requests: `request_id:u32` + `seq:u32` strictly increasing, ops restricted
  to the GRANT whitelist
  (`snapshot.read, config.read, config.apply, counters.reset,
  report-policy.read, report-policy.apply, video.open, video.close,
  enable.read, enable.apply, live.subscribe, live.unsubscribe`), at most 4
  concurrent pending, 10 s deadline, 16 KiB encoded-size bound in both
  directions. Timeouts resolve `UNKNOWN`; late `RESULT`s for expired requests
  are dropped; nothing is committed without a cross-checked `APPLIED`.
- Inbound discipline: inbound `seq` must strictly increase; replays/duplicates
  are dropped; identity or grant_id mismatch, malformed envelopes, oversized
  messages and unknown types revoke the session (`REVOKE` is final; the port
  is closed; a new session requires an iframe reload).
- Events: `EVENT` payloads carry `stream/stream_seq` plus optional
  `GAP/STALE/REVOKE` status; a sequence rollback or gap marks live
  capabilities unavailable until a Host resync; live data is bounded
  (<= 100 events / 100 tracks / 64 points per track) and strictly validated.
- Grant lifecycle: a GRANT with `expires_at_ms <= Date.now()` is rejected.
  The active grant is checked again immediately before a REQUEST is sent and
  when each RESULT or EVENT is consumed. An expired request is not sent and
  returns `UNAVAILABLE`; a pending request whose RESULT arrives after expiry
  resolves `UNKNOWN`; an EVENT after expiry is dropped. Expiry clears the
  active grant, resolves other pending requests as `UNKNOWN`, and marks the UI
  unavailable while keeping the channel ready for a fresh GRANT. A fresh GRANT
  with the same handshake identity and a newer sequence can restore
  authorization; stale sequences are dropped and identity changes revoke.

## App-side payload schemas

Result payloads are validated field-by-field; any deviation fails closed for
that capability instead of partial rendering:

- `snapshot.read` APPLIED: `{ session_generation, config_generation, config
  (schema-1 candidate), status, stats? }` → `app` + `stats` capabilities.
  Missing `stats` stays honestly unavailable.
- `report-policy.read/apply` APPLIED: `{ session_generation, generation,
  config { mqtt_enabled, webhook_enabled, backlog_capacity } }` →
  `hostPolicy` (camelCase `sessionGeneration` on the UI side).
- `enable.read` APPLIED: `{ session_generation, value }` → `businessEnable`;
  `UNAVAILABLE` is surfaced verbatim as a real unavailable (App #30 producer
  is not implemented and must never appear enabled).
- `video.open` APPLIED: `{ url (ws:/wss: only), session_generation,
  expires_at_ms, grant_id }` → bounded media grant; `release()` is App-local,
  emits unavailable and fires `video.close`.
- Writes carry the current generation (`expected_config_generation`,
  `expected_generation`) and commit only when the echoed session/generation
  reconcile with the request; otherwise the UI shows `UNKNOWN`/`CONFLICT` and
  never optimistic-commits.

## Isolation position (software-verifiable part)

The runtime browser fixture embeds the production build in
`sandbox="allow-scripts allow-same-origin"` with Host at
`host.example.test:<port>` and App at `app.other.test:<port>`. Chrome maps both
`.test` names to loopback with `--host-resolver-rules`; the sites are distinct
without relying on device DNS. The cross-site case runs the bridge v1 flow,
both App-origin Workers and MSE/H264 playback. It also verifies that the
HttpOnly `SameSite=Strict` Host cookie is absent from the App's credentialed
admin POST, the write is not committed, and parent DOM/storage access raises
`SecurityError`. A same-origin control confirms that DOM/storage are exposed
when the sandbox is widened to the Host origin. A same-site, different-port
control confirms that the Host cookie is sent and the admin write succeeds;
TCP port separation is not cookie isolation.

These are software lab results for the fixture's cookie and admin endpoint,
not claims about target Host policy. The UI contract test verifies the
committed signed NEUI asset paths, lengths and hashes against the rebuilt
production files served by the browser fixture. Opaque-origin embedding still
fails closed (the App asset CSP blocks scripts there).

## Evidence and reproduction

From the repository root, offline:

```sh
bash tests/line-crossing-ui/run.sh
```

runs, in order: offline dependency install, the vite production + fixture
builds, the UI offline browser suite (Google Chrome via Playwright,
`--offline`), then the runtime suite `tests/line-crossing-runtime/run.sh`:

- `tests/line-crossing-runtime/contract.test.mjs` — Node-only protocol and
  adapter tests (validation, seq/replay, pending cap, deadlines, revocation,
  payload fail-closed, generation cross-checks);
- `tests/line-crossing-runtime/browser.test.mjs` — real-Chrome fixture with a
  Host broker page, the signed-equivalent production build in the sandboxed
  App iframe and a hostile sibling iframe; covers authorized use (writes,
  counters reset, media open/close under revocation), absent/wrong/limited
  grants, opaque origin, seq rollback, oversize, late-ACK after revoke,
  stale-session echo, sibling forgery, cross-site cookie/DOM/storage/admin
  denial, same-origin widening and the same-site port-only cookie leak.

`docs/evidence/line-crossing-runtime/runtime-fixture-evidence.json` pins the
executed case list; the suite re-verifies it on every run (`WRITE_EVIDENCE=1`
regenerates it after an intentional case change).

Signed bundle reproduction (NEUI v1, test identity only):

```sh
git status --porcelain   # must be clean on apps/line-crossing/ui and tests/line-crossing-ui
bash tests/line-crossing-ui/package.sh
```

`package.sh` rebuilds `tests/line-crossing-ui/.build/production` content into
`docs/evidence/line-crossing-ui/line-crossing.neui` via
`package/sidecar/neui_pack_v1.py` (invoked, never modified), offline-verifies
it with `neui_verify_v1.py` against `docs/evidence/spec-v3/golden.neapp.v3`,
and rewrites the verification/provenance sidecars with `source_commit`.
`tests/line-crossing-ui/contract.test.mjs` then asserts per-asset byte
equality between the committed signed bundle and the rebuilt production build.

Executed with: Node v22.22.3, Google Chrome 155.0.8059.80 (headless, Playwright
chromium.launch), ffmpeg-generated baseline H264 fixture.

## Explicit NOT_RUN / unavailable by design

- Host #84 real resource service, permission granting and broker (the fixture
  broker is test code in this repository, not Host production code).
- #88/#101 Host policy engine, App #30 native Enable producer, Host #91 /
  App #27 live tracks/events producers — always answered `UNAVAILABLE`,
  never faked as available.
- Real camera/stream, target-board memory/network/flash/integration, device
  acceptance, production signing keys, production downloads/recording export
  (signed FileSaver `saveAs` remains failed; the anchor fallback requires a
  Host download token, and no recording download PASS is claimed).
- Target deployment DNS/TLS, camera and Host site topology; the `.test` resolver
  mapping is local to this Chrome fixture. Opaque-origin positive operation
  (Worker/importScripts/H264 under opaque origin).
