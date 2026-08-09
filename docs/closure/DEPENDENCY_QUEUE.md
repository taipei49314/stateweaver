# DEPENDENCY_QUEUE — stateweaver 2026-08-07

> **HISTORICAL / SUPERSEDED.** The live queue is now empty. This file preserves the 2026-08-07
> inspection only and is not current candidate evidence.

| Field | Value |
|---|---|
| Status | **DEPENDENCY_QUEUE_CLOSED** |
| Meaning | Every then-open Dependabot PR was inspected one-at-a-time with a local rebase onto `origin/main` (`5df5f57…`) and a recorded verdict. |
| Cursor merges | **none** |
| Cursor closes | **none** |
| Detail | [DEPENDENCY_PR_VERDICTS.md](DEPENDENCY_PR_VERDICTS.md) |
| Owner next | [OWNER_ACTIONS.md](OWNER_ACTIONS.md) |

## Queue snapshot (open on inspection)

| PR | Branch | Verdict |
|---|---|---|
| #1 | `dependabot/github_actions/astral-sh/setup-uv-9.0.0` | MERGE_CANDIDATE |
| #4 | `dependabot/github_actions/actions/upload-artifact-7.0.1` | MERGE_CANDIDATE |
| #3 | `dependabot/github_actions/actions/download-artifact-8.0.1` | MERGE_CANDIDATE |
| #2 | `dependabot/pip/mypy-gte-1.15-and-lt-3` | CLOSE_WITH_REASON |
| #5 | `dependabot/npm_and_yarn/apps/web/typescript-7.0.2` | CLOSE_WITH_REASON |

Historical recommended order was #1 → #4/#3 together → then stop. It has already been resolved.
