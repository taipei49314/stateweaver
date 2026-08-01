# Security policy

## Supported scope

StateWeaver is built for synthetic localhost labs, private environments owned by the operator, and
targets covered by explicit written authorization. The public build defaults to deny external
egress and requires typed actions plus server-side policy decisions.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, private target information, or
proof bundles with sensitive artifacts. Use the repository's private security-advisory channel
once one is configured. Until then, provide only a minimal redacted description to the maintainer.

Include the affected version, impact, safe reproduction against the bundled synthetic lab, and a
suggested mitigation if known. Never test a report against infrastructure you do not own or have
explicit permission to assess.

## Design commitments

- No raw shell action is exposed to models or remote clients.
- Target text and tool output are untrusted observations.
- Scope, identity, risk, budget, timeout, and approval checks happen before execution.
- Secrets are represented by opaque handles and redacted before artifacts reach a model.
- Only deterministic reality replay can confirm a finding.
- Intentional lab vulnerabilities are isolated from platform services and always ship with a
  patched mode and negative controls.
