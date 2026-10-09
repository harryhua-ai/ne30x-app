#!/bin/sh
# Minimal repo-local event/branch resolver for the ght completion workflow
# (Harry Dev downstream thin-caller model, harry-dev docs/adoption.md). This is
# the ONLY completion-path logic that lives in this repository: it
# derives the merged Candidate's (issue, pr) identity from the GitHub
# Actions event metadata BEFORE the attempt-bound runtime can be selected,
# and owns NO completion semantics — every durable completion predicate
# stays in the attempt-bound capsule and is reached through
# scripts/ght/ght-gha-adapter.sh (which materializes that exact capsule
# and execs its canonical completion glue). No canonical Harry Dev glue is
# copied into this repository.
#
# Applicability boundary: only merged ght Candidate PRs (head branch
# agent/<issue>/<id>) are applicable. A head ref outside that namespace
# (A-owned docs/release/other work) resolves not-applicable — the workflow
# ends as an explicit no-op success. A ref that ENTERS the agent/
# namespace but is not exactly canonical, or contradictory event
# metadata, is untrusted and fails closed; there is deliberately no
# guessing, no retry, and no fallback.
#
# Usage:
#   ght-gha-resolve.sh            # emits applicable=/issue=/pr= lines
#
# Environment (set by the repo-local workflow):
#   GHA_EVENT_NAME     pull_request | workflow_dispatch
#   GHA_PR_NUMBER      pull_request event: the merged PR number
#   GHA_HEAD_REF       pull_request event: the PR head branch
#                      (canonical claim branch: agent/<issue>/<id>)
#   GHA_DISPATCH_ISSUE / GHA_DISPATCH_PR   workflow_dispatch inputs
set -eu

die() {
    echo "ght-gha-resolve: $1" >&2
    exit 1
}

require_digits() {
    case "$1" in
        ''|*[!0-9]*) die "expected a numeric $2, got '$1'; refusing to guess — fail closed" ;;
    esac
}

[ $# -eq 0 ] || die "usage: ght-gha-resolve.sh (no arguments; identity comes from the GHA_* event environment)"

case "${GHA_EVENT_NAME:-}" in
    pull_request)
        [ -n "${GHA_PR_NUMBER:-}" ] || die "pull_request event without a PR number — fail closed"
        require_digits "$GHA_PR_NUMBER" "PR number"
        [ -n "${GHA_HEAD_REF:-}" ] || die "pull_request event without a head ref; metadata is contradictory — fail closed"
        case "$GHA_HEAD_REF" in
            agent/[0-9]*/*)
                rest=${GHA_HEAD_REF#agent/}
                issue=${rest%%/*}
                id=${rest#*/}
                require_digits "$issue" "issue number derived from head ref"
                case "$id" in
                    */*) die "head ref '${GHA_HEAD_REF}' is not the canonical agent/<issue>/<id> shape; the Candidate identity is untrusted — fail closed" ;;
                    "") die "head ref '${GHA_HEAD_REF}' carries no attempt id; the Candidate identity is untrusted — fail closed" ;;
                esac
                echo "applicable=true"
                echo "issue=$issue"
                echo "pr=$GHA_PR_NUMBER"
                ;;
            agent/*)
                die "head ref '${GHA_HEAD_REF}' entered the ght attempt-branch namespace but is not the canonical agent/<issue>/<id> shape; the Candidate identity is untrusted — fail closed"
                ;;
            *)
                echo "ght-gha-resolve: head ref '${GHA_HEAD_REF}' is not a ght attempt branch; PR #${GHA_PR_NUMBER} is not applicable — completion skipped (no-op success)" >&2
                echo "applicable=false"
                ;;
        esac
        ;;
    workflow_dispatch)
        [ -n "${GHA_DISPATCH_ISSUE:-}" ] || die "workflow_dispatch requires an explicit issue input — fail closed"
        [ -n "${GHA_DISPATCH_PR:-}" ] || die "workflow_dispatch requires an explicit pr input — fail closed"
        require_digits "$GHA_DISPATCH_ISSUE" "issue input"
        require_digits "$GHA_DISPATCH_PR" "pr input"
        echo "applicable=true"
        echo "issue=$GHA_DISPATCH_ISSUE"
        echo "pr=$GHA_DISPATCH_PR"
        ;;
    *)
        die "unsupported event '${GHA_EVENT_NAME:-}'; only pull_request (merged) and workflow_dispatch are handled — fail closed"
        ;;
esac
