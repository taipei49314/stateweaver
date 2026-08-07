# DEPENDENCY_PR_VERDICTS — stateweaver 2026-08-07

Inspected open Dependabot PRs on `main` tip `5df5f57`. Cursor does **not** merge these PRs.

| PR | Change | CI snapshot (as of inspection) | Verdict | Reason |
|---|---|---|---|---|
| #1 | `astral-sh/setup-uv` 6.8.0 → 9.0.0 | Py3.12 SUCCESS; Py3.13 FAILURE; Web SUCCESS | **BLOCKED** | Major action bump; Py3.13 job red on PR. Re-test after Py3.13 baseline fixed on main or accept scoped merge after isolated green. |
| #3 | `actions/download-artifact` 4.3.0 → 8.0.1 | Py3.12 SUCCESS; Py3.13 FAILURE; Web SUCCESS | **BLOCKED** | Same Py3.13 redness; major artifact action. Do not batch with others. |
| #4 | `actions/upload-artifact` 4.6.2 → 7.0.1 | Py3.12 SUCCESS; Py3.13 FAILURE; Web SUCCESS | **BLOCKED** | Pair with #3 after isolated re-test; Py3.13 failure blocks MERGE_CANDIDATE. |
| #2 | mypy `<2,>=1.15` → `>=1.15,<3` | Py3.12 FAILURE; Py3.13 FAILURE; Web SUCCESS | **CLOSE_WITH_REASON** or keep open as blocked | Type-checker ceiling expansion failed Python jobs — not merge-ready. |
| #5 | TypeScript 6.0.3 → 7.0.2 (`apps/web`) | Py3.12 SUCCESS; Py3.13 FAILURE; Web **FAILURE** | **CLOSE_WITH_REASON** (scope freeze) | Major TS upgrade expands frontend scope; Web public experience failed. Prefer freeze until Monday GPT milestone wording / frontend owner scope. |

Recommended owner order (unchanged from workpack): #1 tooling → #3/#4 artifacts → #2 mypy → #5 TS last.

## Source-only pre-alpha note

Current `main` remains **source-only pre-alpha**. Do **not** claim: live-provider support, trusted Reality Broker, M6 clean-machine certification, PyPI production readiness, or general production readiness. Final milestone wording reserved for GPT Monday.
