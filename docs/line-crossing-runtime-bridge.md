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

## App #27 — LVN4 native live producer (line crossing tracks/events)

Scope of this section: the App-native producer side of Host #104 F8–F10
([freeze comment 6258637748](https://github.com/harryhua-ai/ne301/issues/104#issuecomment-6258637748),
the only wire authority; F1–F4/F5–F7 remain the container/capability and
control/floor context). The producer converts the real `lc_tracker`/`lc_bus`
crossing facts into ordered `live_publish` packets and preserves
source-accurate GAP accounting; it does not re-freeze any wire bytes, does not
implement the Host consumer, and does not touch the v3 window report, business
totals, `report_seq`, or the queued MQTT/Webhook history.

### Production path (App-owned files)

- `apps/line-crossing/include/lc_tracker.h`, `src/lc_tracker.c` — `lc_cross_evt_t`
  gained the observed crossing position (`pos`), and `lc_tracker_for_each_active`
  enumerates the full active-track set for kind2 snapshots. Golden-trace-neutral:
  the equivalence harness prints only id/ts/direction.
- `apps/line-crossing/app/lc_bus.{h,c}` — minimal orthogonal seam for the
  shared source: one additive `lcbus_live_facts_t` observer
  (`lcbus_set_live_observer`) notified once per valid bus event with the exact
  per-frame crossing delta (`frame_in+frame_out`), the encoded `evts[16]`
  records, frame-complete/dropped flags and GAP/lost-unknown markers. No
  business flow is altered; this is the single observation point of the real
  crossing facts (`lc_line_cross_check` mutates track dedupe state, so facts
  cannot be re-derived outside `process_frame`).
- `apps/line-crossing/app/lc_lvn4.{h,c}` — the producer core: strict F8 48B
  header (LE, no padding, magic `4c 56 4e 34`, header_version 1, kinds 1/2,
  packet_seq nonzero monotonic +1, watermark triple
  `event_through_seq`/`cumulative_event_total`/`cumulative_source_gap`,
  nonzero `config_generation`, flags bit0/bit1/bit2 only, reserved 0), F9 kind1
  16B event records (seq strictly increasing and <= through_seq, direction
  1/2, flags bit0-only, x/y q8 visualization-only from the observed crossing
  position) and F9 kind2 full-replacement track records (12B header + 8B per
  point, unique nonzero track ids, point_count 0..16, class from the trusted
  binding or 0xFFFF, state 1, flags 0, points ordered oldest→newest q16).
- Conservation per F10: `delta = Δ(win_in+win_out)` per frame;
  `evts[16]` truncation and publish failures advance `through_seq` and add
  exactly to `cumulative_source_gap` (never re-sent as new crossings); GAP or
  dropped-frame stretches latch `SOURCE_LOSS_UNKNOWN` instead of pretending a
  precise zero; 0-track snapshots are legal full clears; u32 exhaustion,
  packet_seq exhaustion and active-tracks > granted `live_track_max` fail
  closed into explicit unavailable states with no silent wrap and no partial
  "complete" snapshot.
- Authority gate (AC1/AC3): packets exist only while armed with a validated
  grant (session nonzero, `live_publish_max >= 312` AND >= the kind2 closure
  `48 + live_track_max × 140` in u64, `live_track_max` 1..64, publish fn
  present) and the gate is OPEN. `LC_LVN4_GATE_PAUSED`/`GATE_UNKNOWN` stop all
  publishing; crossings observed despite a closed gate are still accounted
  (total/through/gap) so nothing silently disappears, and the gate re-open
  marks the next packet `RESYNC_REQUIRED` so a resumed cursor is never treated
  as continuous across the break. Session identity reuse is rejected; a new
  session generation restarts all watermarks at zero per F8.

### Parallel-line coordination (App #30)

The #30 branch (NFC4 Enable/Paused) owns `lc_ctrl`/`lc_stateblob` and its
`lc_bus` integration points; its in-flight branch `agent/30/cab8a664` was
admission-checked before touching shared hunks (branch tip still at base
`1f48bdd`; its worktree carries uncommitted modifications to `lc_bus.{c,h}`,
`lc_ctrl.*`, `lc_stateblob.*`, `lc_app_abi_v4.*`, `app/Makefile`,
`tests/line-crossing-app/host_stub.*`, `tests/line-crossing-enable/`). The #27
change deliberately avoids every file in that set: the only shared-file
increment is the additive `lcbus_live_facts_t` observer described above (two
new struct fields appended at the end of `lcbus_t`, one setter, one
notification call in `lcbus_on_event`, one out-param in `process_frame`), which
is semantically orthogonal to the Enable/Paused state machine and renamed
nothing. File-name collision with #30's `lc_app_abi_v4.h`/`lc_app_entry_v4.*`
was avoided by placing the producer in `lc_lvn4.{h,c}`. The joint assertion
"trusted Paused state blocks new live facts" is implemented at the producer
gate and exercised directly; the end-to-end joint test with #30's real v4
Enable path remains NOT_RUN until that branch lands (see matrix).

### Verification matrix (executed on this branch)

Reproduction (from the repo root, offline):

```sh
bash tests/line-crossing-live/run_tests.sh   # LVN4 producer suites
bash tests/line-crossing/run_tests.sh        # core equivalence + golden trace
bash tests/line-crossing-app/run_tests.sh    # v2 unit/business/contract + image
bash tests/line-crossing-v3/run_tests.sh     # v3 unit/ctrl/snapshot + image
bash tests/sidecar/run_checks.sh             # NEUI sidecar v1
bash tests/line-crossing-runtime/run.sh      # runtime bridge contract+browser
```

| Check | Result |
| --- | --- |
| `tests/line-crossing-live` wire suite (F8/F9 byte goldens incl. hand-computed 48B headers, 0/1/16/17-crossing frames, 64 tracks × 16 points = 9008B closure, truncation gap, gap/loss-unknown flags, rebind + config-generation, gate paused/unknown, publish-failure gap, u32/packet_seq exhaustion, capacity fail-closed, session reuse, independent ref_decoder positive/negative cases) | PASS (1486 checks, 0 fail) |
| `tests/line-crossing-live` bus suite (real lc_bus+lc_tracker end-to-end ordering, unarmed byte-identical business regression, GAP events, allocator-fault dropped frames, idle/window regression, v3 report byte-equality armed vs unarmed, target-change clear view, malformed frame isolation) | PASS (100 checks, 0 fail) |
| both live suites under `-fsanitize=address,undefined` | PASS |
| `tests/line-crossing` core regression + byte-identical golden trace | PASS |
| `tests/line-crossing-app` unit/business/contract | PASS (50 / 214 / 52) |
| `tests/line-crossing-v3` unit/txn/snapshot/contract + v2 regression | PASS (68 / 267 / 52 / 49) |
| `tests/sidecar` | PASS |
| `tests/line-crossing-runtime` contract + browser | PASS (47/47) |

Per-run evidence logs live in `docs/evidence/line-crossing-live/`
(`env.txt`, `test-live-wire.log`, `test-live-bus.log`).

### NOT_RUN (honest gaps, not claimed)

- Host #91 cross-repo golden-byte reconciliation with an independent trusted
  unpacker: NOT_RUN — Host #91's in-flight branch
  (`agent/91/1a7bfe00`) still returns `UNAVAILABLE` from
  `sess_api_live_publish` and contains no LVN4 parser; reconciliation inside
  this repo is covered by the independent `ref_decoder.c` second
  implementation only.
- #30 joint Enable/Paused producer gate test with the real v4 `ENABLE_SET`
  path: NOT_RUN — App #30 is unmerged and provides no real v4 Enable yet; the
  producer gate semantics are verified directly at the gate API.
- Real signed v4 package/caps admission (`live_publish` fn delivered by a v4
  function table), actual NPU frame feed, target RAM/CPU/stack budget for the
  9008B packet buffer and per-frame publishing cadence, device run, production
  keys: NOT_RUN.
- Slow-reader/ring-drop Host-owned GAP: NOT_RUN on the Host side by design
  (F10 keeps Host-owned loss separate); the App side only asserts its own
  watermarks stay exact.
