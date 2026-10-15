# NE301 Line Crossing UI port

## Scope and source

This port lives at `apps/line-crossing/ui/` and carries the source behavior from `ne301` branch `counting` at `de25a6f1f431a631a37ff1cda87f616e293e8836`. The complete target-to-source blob map is in [provenance.md](evidence/line-crossing-ui/provenance.md): 33 upstream-backed target files and 3 new App-owned entry/adapter files.

The migrated screen retains the source Realtime, Configuration, and Advanced tab order, model class selector, line drawing, direction switch, stats/events/tracks, H264 preview, and the source confirmation/undo/reset journey. The line preview keeps the source video aspect ratio. The source did not bind pointer dragging to its line endpoints; this port adds pointer capture and dragging for both endpoints and updates the outside/direction point with the line. There is no uninstall or delete control in the Sidecar; uninstall remains in the Host management page.

The source tests were reviewed. `Web/src/test/lineCountingApi.test.ts` asserts the legacy `/api/v1/apps/line-counting` client; `lineCountingNavigation.test.tsx` and `lineCountingPage.test.tsx` stub that client and `deviceTool`. They do not assert the v3 capability/generation contract, so they are replaced by the offline browser and bundle contract tests under `tests/line-crossing-ui/`.

## Capability boundary and v3 mapping

Production mounts `unavailableCapabilities`. It performs no fetch, cookie lookup, Host admin call, or placeholder-data generation. A future trusted Host integration must provide `LineCrossingCapabilities` and supply observed snapshots plus write/video grants. If those capabilities are absent, stale, expired, or revoked, the UI reports unavailable/stale and disables the dependent action.

| Source UI value | App candidate field | Conversion |
|---|---|---|
| `counter_name` | `counter_name` | unchanged |
| `target_class` | `target_class_name` | unchanged |
| line endpoints and outside/direction point | `line.{x1,y1,x2,y2,outside_x,outside_y}` | integer permille, unchanged |
| `confidence_threshold` | `conf_threshold_permille` | multiply by 1000 |
| `tracking.association_distance` | `max_dist_permille` | multiply by 1000 |
| history / missed / confirmation values | `track_history_k` / `max_miss` / `k_confirm` | unchanged |
| track/heat reporting toggles | `tracks_report_enable` / `heat_grid_enable` | unchanged |
| `window_minutes` | `window_minutes` | unchanged |
| fixed schema version | `schema` | `1` |

`enable`, MQTT, Webhook, and backlog are Host policy/strategy values. They are not included in the App candidate and are never submitted through `CONFIG_APPLY`. Advanced presents App-owned and Host-owned groups with independent Save results. The Host group stays read-only when its trusted capability is unavailable.

Every App apply carries the observed `sessionGeneration` and `expectedConfigGeneration`; the adapter accepts success only when the returned outcome is `APPLIED` and both returned generations match the new snapshot. `CONFLICT` asks the operator to reload the current snapshot. `UNKNOWN` is displayed without retry or replay. Writes are blocked for stale snapshots (10 seconds), lost permission, invalid lines, or a changed session. Stats reset is separately permission-gated and confirmation-protected.

A video grant is bound to its App session and explicit expiry. `Live` requires video playback; the WebSocket worker reports reconnect transitions, and the UI reaches `Unavailable` on grant expiry/revocation or worker failure. Existing source reconnect/backoff policy remains in the WebSocket and H264 workers.

## Adaptation record

1. **Sidecar assets:** `/libs/FileSaver.min.js` is now a Vite `?url` import. `/libs/jmuxer.min.js` is now `new URL('./jmuxer.min.js', self.location.href)` from the emitted worker. Both assets are bundled under `assets/` with relative paths; there are no root `/libs` requests.
2. **Legacy management API removal:** the old `/api/v1/apps/line-counting` JSON API and `deviceTool` stream-control API are removed from the migrated tree. The semantic v3 typed adapter contains no wire encoding or transport implementation; native-owned 144-byte config bytes remain outside the UI.
3. **Unavailable data:** production does not fabricate a false Enable value, zero stats, empty events, or pretend Host policy. Missing values render unavailable/read-only states.
4. **Endpoint dragging:** pointer handlers were added because the pinned upstream endpoint circles did not have a drag handler. Dragging changes the draft; saving still requires the source finish/save action and the normal v3 generation checks.
5. **Video connection state:** source H264/MSE workers remain the decoder and reconnect path. The UI adds Live/Reconnecting/Unavailable presentation and checks the grant session/expiry. `wv_work` returning to connected marks an already playing video Live after reconnect.
6. **Local diagnostics:** source logging called the shared request service, which is outside the App capability boundary. `streamLog.ts` now emits a local `line-crossing-media-diagnostic` event without exposing the stream URL or issuing a request.
7. **Utility closure:** only the source `sleep` helper is extracted; the broader utility index also imports unrelated route/storage concerns. Unused `tw-animate-css` is removed from the source stylesheet import because no migrated component uses it.
8. **Comments:** explanatory comments and lint/type suppression comments were removed from copied non-vendor code as required. FileSaver's MIT license banner is retained.

## Reproduction

With the pinned dependencies cached, one command builds the production bundle and browser fixture, then runs the offline suite:

```sh
bash tests/line-crossing-ui/run.sh
```

The script uses `pnpm install --offline --ignore-scripts`, `npm ci --offline --ignore-scripts`, and the local Vite build. Browser tests require Google Chrome at `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` and `ffmpeg`. The fixture generates an H264 Baseline Annex-B stream locally and serves HTTP/WebSocket only on `127.0.0.1`; its CSP permits only same-origin resources and that loopback WebSocket. Test-only capabilities are compiled only from `tests/line-crossing-ui/src/test-main.tsx`; the production entry does not import them.

The suite exercises production unavailable/read-only presentation; actual H264 MSE/JMuxer playback and natural dimensions; line dragging with discard and APPLIED save; candidate field exclusion; class-change confirmation; independent App/Host saves; permission revocation; reconnect and video grant revocation; unknown result/no replay; stale snapshot blocking; session-generation races; and worker-load failure. Contract checks enforce the NEUI v1 asset envelope and reject legacy admin/root media paths.

## NEUI and evidence boundary

`package/sidecar/neui_pack_v1.py` and `neui_verify_v1.py` are invoked read-only. The App UI assets are signed with the public, non-production P-256 `d=1` test identity used by the native v3 golden; the packer verifies the native v3 package and binds the NEUI manifest to its verified TBS. The private test scalar is generated outside the repository and is not committed. Run `bash tests/line-crossing-ui/package.sh` after the suite to package and independently verify the NEUI artifact. It creates the public d=1 development key only in a temporary directory and removes it on exit. The resulting `.neui`, provenance JSON, and verifier report are stored under `docs/evidence/line-crossing-ui/`. The bundle is offline format/signature evidence only; it does not prove Host admission or installation, production video access, device behavior, or product acceptance.

The generated artifact is [line-crossing.neui](evidence/line-crossing-ui/line-crossing.neui), 421,221 bytes with 7 assets. Bundle SHA-256 is `4ff1f15c91e22308e2aeaa4c8d3adcc161c384b17ca368d77bab3006c5334177`; signed UI TBS SHA-256 is `b5f0334b1cd92645606a8f5c2485cec354cb23471d65508a304dd68d6352673e`. Offline verification is `PASS`, with `native_binding_trusted=true`; bound verified native TBS SHA-256 is `d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e`. The packer's provenance records source commit `81ed4c4dd02f5190ec4131a72da35ca0fd11e234`. The full verifier result and per-asset SHA-256 list are in [neui-verification.json](evidence/line-crossing-ui/neui-verification.json) and [line-crossing.neui.provenance.json](evidence/line-crossing-ui/line-crossing.neui.provenance.json).

## Execution boundary record

One initial dependency-install invocation used `pnpm install --offline --frozen-lockfile` without disabling lifecycle scripts. Tailwind's platform package lifecycle attempted and completed a request to `registry.npmjs.org`. This crossed the task's no-network boundary. After identifying it, all further dependency/build/test operations were run offline with lifecycle scripts disabled. No device, flash, production key, native binding, Host endpoint, firmware, algorithm, `package/neapp_*`, `package/sidecar/*`, `.github`, or `scripts` files were changed.

Software completion is not M1/M2 product PASS. Host end-to-end integration remains with #83/#84/#27/#30/#88/#48/#58.
