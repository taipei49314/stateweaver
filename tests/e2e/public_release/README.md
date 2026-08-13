# Public release journey tests

The Python journey connects the deterministic foundation, equal-budget synthetic holdout, and the
four read-only public-experience payloads without opening a socket or accepting a target.

`m8_public_ux.spec.ts` adds a real Chromium gate against only the fixed loopback UI and API. It
covers desktop, mobile, keyboard navigation, WCAG A/AA checks, console health, loading, fixed API
failure, empty filters, and fail-closed digest substitution. It does not accept a caller-provided
URL, a public target, credentials, or provider traffic. These checks remain synthetic acceptance
evidence; they do not replace external accessibility review or release qualification.
