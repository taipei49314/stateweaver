# Dependency PR verdicts — 2026-08-07

Inspected one PR at a time on local rebases onto `origin/main`
(`5df5f57eb8a588eda420d610603f4689faaf4b05`). Cursor did **not** merge,
recreate, or close any Dependabot PR.

Order used: setup/runtime tooling → artifact upload → artifact download →
type checker → major TypeScript upgrade last.

| PR | Title | Rebase onto main | Local checks | Verdict |
|---|---|---|---|---|
| [#1](https://github.com/taipei49314/stateweaver/pull/1) | Bump `astral-sh/setup-uv` 6.8.0 → 9.0.0 | Clean | Workflow YAML parse OK; pin-only; `enable-cache` / `python-version` inputs unchanged. Breaking note: `prune-cache` default now `false` (compatible with current workflows). | **MERGE_CANDIDATE** |
| [#4](https://github.com/taipei49314/stateweaver/pull/4) | Bump `actions/upload-artifact` 4.6.2 → 7.0.1 | Clean | Workflow YAML parse OK; existing `name`/`path`/`if-no-files-found`/`retention-days` inputs unchanged; `archive` left at default `true` (zipped, backward compatible). | **MERGE_CANDIDATE** |
| [#3](https://github.com/taipei49314/stateweaver/pull/3) | Bump `actions/download-artifact` 4.3.0 → 8.0.1 | Clean | Workflow YAML parse OK; single attest-job download keeps `name` + `path`. Zipped artifacts remain the path used here. | **MERGE_CANDIDATE** |
| [#2](https://github.com/taipei49314/stateweaver/pull/2) | Update mypy constraint to `>=1.15,<3` | Clean | As shipped: `uv sync --locked` **fails** (lockfile not updated). After local `uv lock`: still resolves mypy 1.20.2; `mypy` exit 0 on 132 files. Opening `<3` admits mypy 2.x without a paired upgrade plan. | **CLOSE_WITH_REASON** |
| [#5](https://github.com/taipei49314/stateweaver/pull/5) | Bump TypeScript 6.0.3 → 7.0.2 in `/apps/web` | Clean | `npm ci` **fails** with `ERESOLVE`: `typescript-eslint@8.65.0` peers `typescript@>=4.8.4 <6.1.0`. Major upgrade expands web toolchain scope. | **CLOSE_WITH_REASON** |

## Notes for the owner

1. Remote CI on the Dependabot tips is stale (tips are behind `main` by 2–4
   commits). Failures observed there are not treated as post-rebase proof.
2. Before merging any `MERGE_CANDIDATE`, rebase onto current `main` and require
   green CI on that tip. Prefer landing #4 and #3 close together so upload and
   download majors stay paired in practice.
3. Cursor must not merge these PRs. Closing #2 / #5 is an owner Dependabot
   action (`@dependabot ignore this major version` or manual close).

## CLOSE_WITH_REASON detail

### PR #2 — mypy `>=1.15,<3`

- Incomplete as shipped: CI uses `uv sync --locked`; constraint change without
  `uv.lock` update fails immediately.
- Even after a lock refresh, the upper bound opens mypy 2.x. Weekend closure
  freezes that major typing-tool expansion; keep `mypy>=1.15,<2` until a
  dedicated mypy 2 validation pass lands with lock + CI.

### PR #5 — TypeScript 7.0.2

- Peer conflict with current `typescript-eslint@8.65.0`.
- Major TypeScript upgrade is deferred for scope freeze; green is not required
  to close. Revisit only with a coordinated eslint/typescript-eslint bump.
