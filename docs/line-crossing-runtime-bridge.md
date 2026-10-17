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
- Grant lifecycle: `expires_at_ms` expiry marks everything unavailable;
  grant refresh requires the same identity; identity change revokes.

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
`sandbox="allow-scripts allow-same-origin"` on a distinct origin (distinct TCP
port). Per the #84 freeze this combination is only admissible when the App
document is truly cross-origin and cross-site from the Host admin origin; the
fixture satisfies cross-origin but NOT cross-site, so it proves bridge
semantics, workers, MSE/H264 and resource loading — it does NOT prove Host
cookie/storage isolation. Opaque-origin embedding fails closed (and in this
fixture the app asset CSP `script-src 'self'` blocks scripts outright).
Real cross-site deployment, DNS/TLS and the production App-site origin set
remain Host #84/#40/#48/#58 work and are NOT_RUN here.

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
  Host broker page, the production build in the sandboxed cross-origin iframe
  and a hostile sibling iframe; covers authorized end-to-end use (writes,
  counters reset, media open/close under revocation), absent/wrong/limited
  grants, opaque origin, seq rollback, oversize, late-ACK after revoke,
  stale-session echo and sibling forgery attempts.

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
  (FileSaver anchor fallback stays as delivered by App #25; its gated
  `allow-downloads` path is not exercised here).
- Cross-site App origin vs Host admin origin, Host admin cookie isolation,
  opaque-origin positive operation (Worker/importScripts/H264 under opaque
  origin).
