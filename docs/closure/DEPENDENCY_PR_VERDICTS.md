# DEPENDENCY_PR_VERDICTS — stateweaver 2026-08-07

Inspected each open Dependabot PR **one at a time** with a local rebase onto
`origin/main` (`5df5f57eb8a588eda420d610603f4689faaf4b05`). Cursor did **not**
merge, recreate, or close any Dependabot PR.

Order: setup/runtime tooling → artifact upload → artifact download → type
checker → major TypeScript upgrade last.

| PR | Title | Rebase onto main | Local checks | Verdict |
|---|---|---|---|---|
| [#1](https://github.com/taipei49314/stateweaver/pull/1) | `astral-sh/setup-uv` 6.8.0 → 9.0.0 | Clean | Workflow YAML OK; pin-only; `enable-cache` / `python-version` unchanged. Breaking note: `prune-cache` default `false` (compatible here). | **MERGE_CANDIDATE** |
| [#4](https://github.com/taipei49314/stateweaver/pull/4) | `actions/upload-artifact` 4.6.2 → 7.0.1 | Clean | Workflow YAML OK; existing inputs unchanged; `archive` default remains `true` (zipped). | **MERGE_CANDIDATE** |
| [#3](https://github.com/taipei49314/stateweaver/pull/3) | `actions/download-artifact` 4.3.0 → 8.0.1 | Clean | Workflow YAML OK; attest-job `name`+`path` unchanged. | **MERGE_CANDIDATE** |
| [#2](https://github.com/taipei49314/stateweaver/pull/2) | mypy constraint → `>=1.15,<3` | Clean | As shipped: `uv sync --locked` **exit 1** (no lock update). After local `uv lock`: mypy 1.20.2, `mypy` exit 0 (132 files). Opening `<3` admits mypy 2.x without paired plan. | **CLOSE_WITH_REASON** |
| [#5](https://github.com/taipei49314/stateweaver/pull/5) | TypeScript 6.0.3 → 7.0.2 in `/apps/web` | Clean | `npm ci` **exit 1** `ERESOLVE`: `typescript-eslint@8.65.0` peers `typescript@>=4.8.4 <6.1.0`. Major upgrade deferred. | **CLOSE_WITH_REASON** |

## Stale remote CI vs rebase truth

Dependabot tips were behind `main` by 2–4 commits. Remote Py3.13 redness on those
tips is **not** post-rebase proof: `main` tip `5df5f57` CI conclusion is
**success**. Owner must `@dependabot rebase` and require green CI before merge.

## CLOSE_WITH_REASON detail

### PR #2 — mypy `>=1.15,<3`

Incomplete without `uv.lock`. Upper bound opens mypy 2.x during weekend scope
freeze. Keep `mypy>=1.15,<2` until a dedicated mypy 2 validation lands.

### PR #5 — TypeScript 7.0.2

Peer conflict with current `typescript-eslint@8.65.0`. Close/ignore major until
a coordinated eslint toolchain bump exists.
