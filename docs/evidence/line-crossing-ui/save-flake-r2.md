# Line-save timeout investigation, r2

## Finding

The instrumented Linux rerun captured the missing-draft branch behind the 30-second wait failure signature. Before the narrow test correction, the save boundary had `editMode=true`, `dirty=false`, `writeAllowed=true`, a fresh App capability, and zero App writer calls. Its pointer sequence never targeted `lc-line-endpoint`. With no draft to apply, the finish handler returned without calling the fixture; the test then reached `Timeout 30000ms exceeded`. A controlled pointer-down/up sequence with movement omitted reproduces that exact wait timeout.

The coordinate-only test drag was not reliably starting on the endpoint in Linux. The test now uses Playwright locator hover to target the endpoint and reads the stage bounds afterward before moving. The existing pre-save assertions verify the endpoint receives pointer down/move/up and that the draft is dirty before Apply. This is a test-only correction; product behavior and timing policy are unchanged.

The original baseline failure has no pre-save trace, so its exact event sequence cannot be recovered. Route (a) is supported by the observed same-test Linux failure branch, the controlled reproduction of its exact timeout, and the narrow test correction. The evidence establishes the reproduced mechanism; it does not claim to reconstruct the missing historical trace byte-for-byte.

## Historical and instrumented Linux evidence

The baseline [Linux run 39543677797, attempt 2](https://github.com/harryhua-ai/ne30x-app/actions/runs/39543677797/attempts/2) used SHA `1e8b74136752d99f330f1ce53d4cb992c3fa86d6`. Its log records `page.waitForFunction: Timeout 30000ms exceeded` at `tests/line-crossing-ui/browser.test.mjs:277`; the prior r1 review also recorded zero App writer calls. That attempt did not collect edit mode, draft dirtiness, capability timestamps, write eligibility, save click, or pointer events. The Playwright FFmpeg DNS errors in setup have no demonstrated connection to the missing App call and are not treated as causal evidence.

The instrumented pre-correction Linux run [39578495884, attempt 2](https://github.com/harryhua-ai/ne30x-app/actions/runs/39578495884/attempts/2), on SHA `5b00122a9407034432ed2606c08096427637b860`, failed at the new pre-save assertion. Its `LC_SAVE_BEFORE` record showed a fresh capability (age 1,047 ms), edit mode active, `dirty=false`, writes allowed, and zero App writer calls. Every recorded drag event had `targetTestId=null`, including the down/move/up sequence. This localizes that Linux failure to the no-draft branch before the save wait.

## Diagnostic mode and bounded matrix

Set `LC_SAVE_DIAGNOSTIC_MODE=matrix` to run the matrix after the normal real H.264 browser scenario. Set `LC_SAVE_EVIDENCE_PATH` to persist JSON boundary records. The normal browser test also records the pre-save boundary. Each record includes capability/snapshot/config observation timestamps, age and expiry, edit/dirty/write state, control disabled state, trusted Apply click, pointer sequence and target, and App writer call count. The unchanged apply wait samples at 1, 5, and 10 seconds and at completion or timeout.

| Injection | Observation | Result |
| --- | --- | --- |
| Normal pointer sequence | Fresh capability; endpoint receives down/move/up; edit mode and dirty draft true; writes allowed. | Control passes and fixture receives one call. |
| App capability aged beyond 10 seconds before Apply | Capability and snapshot age exceed `FRESH_FOR_MS`; writes disallowed and toolbar disabled. | Rejected before the apply wait; no App call. |
| Fixture observation not refreshed | `observedAtMs` stays fixed until age exceeds 10 seconds; the UI marks the capability stale and disables writes. | Rejected before the apply wait; no App call. |
| Pointer down/up with no movement after down | Endpoint receives down/up, no movement occurs, draft stays clean while capability is fresh and writes remain allowed. | Finish handler makes no App call; unchanged wait ends with `Timeout 30000ms exceeded` at about 30 seconds. This matches the wait-failure signature. |
| Pointer cancel before movement | Endpoint receives down/cancel/up; draft stays clean. | No App call during the bounded post-click observation. |

The production `FRESH_FOR_MS` remains 10,000 ms. No production freshness, write policy, UI, permission, H.264 coverage, or timeout was changed.

## Narrow correction and verification

The test now uses locator hover for endpoint targeting, refreshes the stage bounds after hover, and retains assertions that require a dirty draft, fresh write capability, and endpoint-targeted pointer down/move/up before waiting for the App call. The controlled no-movement injection remains in the diagnostic matrix so the no-draft branch continues to reproduce and identify the unchanged wait signature.

Local verification on 2026-10-21 passed the browser/H.264 suite (10 passed, 1 matrix test skipped in the normal phase), the separately enabled diagnostic matrix (1 passed, including the intentional 30-second expected-timeout injection), and runtime/bridge (47 passed). The normal save recorded `dirty=true`, endpoint-targeted down/move/up, and one App writer call; the matrix recorded the injected timeout at 30,005 ms with zero calls.

Post-correction local and repeated Linux CI results will be recorded in the Candidate Snapshot and execution report for the exact candidate SHA. CI evidence must include at least three successful full workflow attempts on that same SHA, with diagnostic artifacts retaining both the normal control and injected cases.

## Acceptance boundary

AC2–AC4 remain CLOSED per A's review of `38051418e1ffa0186ea58b7c35dc45b742d21d48`; this change only supplies the missing AC1 diagnostic evidence and test correction. A remains the exact-Candidate acceptance authority. This report does not claim A's acceptance or a production release decision.
