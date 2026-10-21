# Line-save timeout isolation, r2

## Finding

The historical AC1 root cause remains unproven. The bounded matrix shows that an omitted effective pointer movement can produce the same externally observed failure signature, while capability expiry and a fixture observation that is not refreshed take a different path and disable the save control. The failed historical run contains no pre-save state or pointer trace, so it cannot establish which path occurred. This follows route (b): record the observability boundary and escalate the AC1 root-cause decision to A/User.

## Historical evidence and limit

The failed [Linux run 39543677797, attempt 2](https://github.com/harryhua-ai/ne30x-app/actions/runs/39543677797/attempts/2) is on baseline SHA `1e8b74136752d99f330f1ce53d4cb992c3fa86d6`. Its job log records `page.waitForFunction: Timeout 30000ms exceeded` at `tests/line-crossing-ui/browser.test.mjs:277`. The prior r1 review evidence also recorded that the fixture's App write-call recorder saw no call. The failed attempt did not record edit mode, draft dirtiness, capability timestamps, write eligibility, the save click, or pointer events before the wait. There is no historical trace that can distinguish a missing/ineffective drag from another route that omitted the fixture call.

The same job log contains Playwright FFmpeg download DNS errors during dependency setup. No evidence connects those setup messages to the missing App call; they are not treated as the cause.

## Controlled matrix

The diagnostic mode uses the real browser bundle and live local H.264 fixture. `LC_SAVE_DIAGNOSTIC_MODE=matrix` runs after the full UI/H.264 suite; `LC_SAVE_EVIDENCE_PATH` stores each boundary and wait-stage sample as JSON. The apply wait remains 30,000 ms and records state at 1, 5, and 10 seconds, then at completion or timeout.

| Injection | Observation | Relation to historical signature |
| --- | --- | --- |
| Normal pointer sequence | Fresh capabilities, edit mode and dirty draft true, write allowed; recorder saw one call within 2 ms. | Control passes. |
| App capability forced past 10 seconds before apply | App capability age 11,004 ms; write disallowed, toolbar disabled, recorder stayed at zero. | Does not enter the apply wait. |
| Fixture App observation left unchanged | `observedAtMs` stayed constant; at age 10,255 ms the UI marked App state stale, ended edit mode, cleared the draft and disabled writes. | Does not enter the apply wait. |
| Pointer down/up with no movement after down | Edit mode true, dirty false, capability fresh and write allowed; trusted finish click succeeded, but `handleFinishDraw` exited without calling the fixture. The unchanged wait timed out at 30,003 ms with `Timeout 30000ms exceeded` and zero App calls. | Reproduces the same test-visible wait failure, but does not prove that the historical run had this event sequence. |
| Pointer cancel before movement | `pointercancel` was observed, draft stayed clean, and no call occurred during the bounded post-click observation. | Confirms a second no-draft event path; the full 30-second wait was not repeated for this case. |

The source path is consistent with these outcomes: `handleFinishDraw` exits without applying when the draft is not dirty or the line is invalid. The production `FRESH_FOR_MS` remains 10,000 ms. No product UI, permission, or freshness logic changed.

## Test change and evidence

The normal browser test now records the save boundary before and after the click and asserts that edit mode, a dirty draft, a fresh write capability, and endpoint pointer down/move/up events exist before starting the App-call wait. A failure at that boundary will report the missing condition directly. During the wait, diagnostic runs capture capability ages, control state, click and pointer history, and App-call count at 1, 5, and 10 seconds. These changes improve localization; they do not establish or claim the historical cause.

Local verification on 2026-10-21 passed the UI/H.264/browser suite (10 passed), the diagnostic matrix (1 passed, including the intentional expected-timeout injection), and runtime/bridge (47 passed). The full H.264 test remained enabled and reported live playback.

## AC1 decision request

AC1's repeated Linux PASS evidence remains valid as repeatability evidence. The matrix identifies one mechanism capable of producing the historical test signature, but the historical attempt did not record the state required to attribute that mechanism. Keep the original root-cause item **unresolved** and explicitly request A/User to decide whether this route (b) evidence is sufficient for AC1 or whether a new historical-equivalent trace is required. Do not convert the unknown original cause into PASS.
