# OWNER_ACTIONS — stateweaver dependency queue / source-only candidate

> **HISTORICAL / COMPLETED.** PR #7 and the accepted dependency updates were merged. These are not
> current owner instructions; current blockers are tracked in the repository-root `BLOCKERS.md`.

Cursor branch: `closure/stateweaver-20260807`  
Cursor must **not** merge Dependabot PRs, force-push, rewrite tags, publish a
Release, or change the default branch.

## Required

1. Review/merge the closure-branch docs onto `main` when ready
   ([PR #7](https://github.com/taipei49314/stateweaver/pull/7) or successor).
2. For **MERGE_CANDIDATE** PRs (#1, #4, #3):
   - `@dependabot rebase` onto current `main` (already green at `5df5f57`).
   - Merge only after CI is green on the rebased tip.
   - Prefer landing #4 and #3 in the same window after #1.
3. For **CLOSE_WITH_REASON** PRs (#2, #5): close without merge or
   `@dependabot ignore this major version`.
4. Keep public claims inside
   [SOURCE_ONLY_PREALPHA_CANDIDATE.md](SOURCE_ONLY_PREALPHA_CANDIDATE.md).
   Final milestone wording is reserved for GPT Monday.

## Note on Python 3.13

Do **not** treat unrebased Dependabot Py3.13 failures as a main-baseline
blocker. Main CI at `5df5f57` is green; rebase first.
