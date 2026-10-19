# App #27 regression evidence

## Source pins

- App code revision under test: `c06fdedc5c7422b88d24a1e07d018dd07ff41567`
- Accepted App #30 base: `a1b93322ae010356a6293421a137564fc0e23664`
- Host #91 delivered candidate: `4c1c0d7ec5bc8ae18fae4ca5a31f0699b7c5895b`
- The test runner records the App source SHA, accepted base SHA, Host SHA,
  compiler, and UTC time in `env.txt`.
- The exact documentation Candidate SHA is bound by the PR #39 `ght deliver`
  snapshot after commit; it cannot be embedded in the same commit's evidence.

## Results

| Command | Result |
| --- | --- |
| `bash tests/line-crossing-live/run_tests.sh` | PASS: wire 1502/0, bus 100/0, Host parser/read/cursor 610/0, schema3 Paused/UNKNOWN 19/0, v4 entry activation 79/0 |
| `bash tests/package-vnext/run.sh` | PASS: v2/v3 evidence byte-identical, vNext vectors 117/117, rejection matrix 50/50, signed App/Host interop 12/12, Host suites 77/0 and 592/0 |
| `bash tests/line-crossing-enable/run_tests.sh` | PASS: Enable 204/0, v4 entry 15/0 |
| `bash tests/line-crossing-enable/run_joint_matrix.sh` | PASS: Host package 77/0, Host session 592/0, cross-owner 67/0, Enable 204/0, v4 entry 15/0; complete AC4 production gate NOT_RUN |
| `bash tests/enable-persistence-study/run.sh` | PASS: 65 checks |
| `bash tests/line-crossing/run_tests.sh` | PASS: upstream engine regression and ported golden trace identical; SHA-256 `9d5751d675a61444e0c9db9932b1cd1aa5fd766559182f2e0f78091f1e2aa0c0` |
| `bash tests/line-crossing-app/run_tests.sh` | PASS: unit 50/0, business 214/0, contract 52/0; native v2 package verified |
| `bash tests/line-crossing-v3/run_tests.sh` | PASS: unit 68/0, transaction 267/0, snapshot 52/0, contract 49/0; v2 regression and signed v3 package verified |
| `bash tests/sidecar/run_checks.sh` | PASS: all 94 expectations matched |
| `bash tests/line-crossing-runtime/run.sh` | PASS: 47/47 browser and contract cases |
| `make -C apps/line-crossing/app elf-v4` | PASS: v4 ELF linked with `lc_lvn4.c`; linker emitted an RWX LOAD-segment warning |

The live wire suite covers known and unknown GAP, 17-crossing truncation and
`through_seq`, 64 × 16 track closure, zero-track replacement, packet and u32
exhaustion, rebind/resync, gate pause/resume, disarm/session reuse, track
capacity, and callback capability loss. The Host joint test marks old tracks
STALE after 10001 ms and verifies the later zero-track replacement clears the
snapshot. The bus regression checks idle/window behavior and byte-identical
v3 report output with and without the live observer.

## Test boundary distinction

- The independent signed-package/Host admission checks run under
  `bash tests/package-vnext/run.sh`. They exercise offline signed-format and
  Host parser/admission behavior with non-production test identities; they do
  not execute the App #27 entry/tracker callback path. Its Host session suite
  reports `APP_SESSION_ERR_UNAVAILABLE` for runtime live publish, so it does
  not establish a production Host session grant.
- `test-entry-host-activation.log` records 79/0 for the real v4 `app_entry`
  producer routed through `live_publish` and the pinned Host parser/read. Its
  fixture simulates Host admission with local test values and a callback hook;
  it is not a signed production grant or a production Host session.
- `test-host-joint.log` separately records 610/0 for producer bytes through
  the pinned Host parser/read/cursor using fixture identity and capacity values.
  It is not the signed-Host admission suite.

## Evidence boundary

- The Host parser test compiles source archived read-only from the delivered
  Host candidate. Host #91 is not ACCEPTED; final Host-side same-byte
  reconciliation remains NOT_RUN.
- Test owner/capability values are local fixtures. They do not prove signed
  production admission or a production Host session grant.
- The independent package-vnext Host session suite reports
  `APP_SESSION_ERR_UNAVAILABLE` for runtime live publish. This is a Host
  session limitation and does not negate the App entry's armed producer path.
- The production v4 App entry arms the producer with a bounded local entry
  epoch and 9008/64 profile and routes packets through `live_publish`. The
  entry fixture exercises this callback path with simulated Host admission;
  it does not prove signed production admission or a production device result.
- Web/UI #108/#113, target hardware, NPU frame feed, and production device
  acceptance are NOT_RUN.
