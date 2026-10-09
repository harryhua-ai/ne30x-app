<!-- harry-dev:agents-managed begin v1 -->
## Harry Dev engineering / review boundary

- The current Task Contract (the active Issue's `ght-contract`) owns the task's WHAT, BOUNDARY, and DONE.
- This AGENTS.md is durable project engineering/review guidance only; it grants no READY, execution, acceptance, merge, scheduling, or release authority.
- Review what is consequential: correctness, regressions, Contract/scope violations, weak or missing tests, and security/data-integrity where material; avoid cosmetic or speculative churn better owned by deterministic tooling.
- Compare implementation behavior with the current Task Contract; passing tests and author-checked acceptance criteria are evidence, not proof.
- When a changed surface makes a negative path consequential, verify the test actually constructs the failure, race, permission, or partial-state condition it claims to exercise.
- The independent steward agent (A) remains the exact-Candidate acceptance/integration authority; User-owned product and release decisions remain User-owned.
<!-- harry-dev:agents-managed end v1 -->
