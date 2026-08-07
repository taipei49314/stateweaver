# Owner actions — stateweaver dependency queue / source-only candidate

Cursor branch: `closure/stateweaver-20260807`  
Cursor must **not** merge Dependabot PRs, force-push, rewrite tags, publish a
Release, or change the default branch.

## Required

1. Review and merge (or cherry-pick) the closure-branch docs commit onto `main`
   when ready.
2. For Dependabot PRs marked **MERGE_CANDIDATE** (#1, #4, #3):
   - Comment `@dependabot rebase` (or recreate) onto current `main`.
   - Merge only after CI is green on the rebased tip.
   - Prefer landing upload (#4) and download (#3) in the same window.
3. For PRs marked **CLOSE_WITH_REASON** (#2, #5):
   - Close without merge, or `@dependabot ignore this major version`.
4. Keep public claims within the source-only / pre-alpha boundary in
   [SOURCE_ONLY_PREALPHA_CANDIDATE.md](SOURCE_ONLY_PREALPHA_CANDIDATE.md).
   Final milestone wording is reserved for GPT Monday.

## Forbidden for Cursor (already observed)

- Merging own or Dependabot PRs
- Force-push
- Tag delete/rewrite
- Publishing GitHub Release or PyPI
- Claiming live-provider, trusted Reality Broker, M6 clean-machine
  certification, PyPI production readiness, or general production readiness
