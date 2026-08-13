"""Immutable candidate status policy; no producer-controlled promotion booleans are accepted."""

from __future__ import annotations

from typing import Final

CONTROLLED_GATES: Final = (
    {
        "gate_id": "SW-CANDIDATE-SOURCE",
        "reason": "Locked Python and web source gates completed in the candidate workflow.",
        "status": "PASS",
    },
    {
        "gate_id": "SW-CANDIDATE-REPRODUCIBILITY",
        "reason": (
            "Workspace-built Python distributions and the web archive matched across two "
            "absolute build roots."
        ),
        "status": "PASS",
    },
    {
        "gate_id": "SW-CANDIDATE-PROOF",
        "reason": "The exact-SHA foundation proof was collected and verified before assembly.",
        "status": "PASS",
    },
    {
        "gate_id": "SW-M2-HOSTED-ADMISSION",
        "reason": (
            "The exact-SHA hosted four-way and six-provider receipts, cleanup inventory, and "
            "constrained workflow attestation were admitted into the verified foundation proof."
        ),
        "status": "PASS",
    },
    {
        "gate_id": "SW-M3-RUNTIME-EVIDENCE",
        "reason": (
            "Eight sequential application-emitted runtime observations were independently "
            "validated and retained by the exact-SHA hosted admission."
        ),
        "status": "PASS",
    },
    {
        "gate_id": "SW-M4-MATERIALIZED-SEARCH",
        "reason": (
            "The hosted 24-to-4-to-2-to-1 materialization receipt and its seven provider "
            "receipts were admitted into the verified foundation proof."
        ),
        "status": "PASS",
    },
)

QUALIFICATION_AND_IMPLEMENTATION_GAPS: Final = (
    {
        "gate_id": "SW-M2-CLEAN-HOST",
        "reason": (
            "The hosted M2 receipts are admitted, but SW-M2-LIVE still requires a separate "
            "clean-host execution rather than another job in the producing repository."
        ),
        "status": "PENDING_QUALIFICATION",
    },
    {
        "gate_id": "SW-M5-MATERIALIZED-REPLAY",
        "reason": (
            "Exact retained M4 bytes compile into an eight-step plan, replay over five clean "
            "roots, and retain the boundary-mode and four control results. A distinct bounded "
            "bridge retains the six-provider transitions, but one Docker-backed application "
            "execution and trace boundary remains pending."
        ),
        "status": "PENDING_QUALIFICATION",
    },
    {
        "gate_id": "SW-M6-PRODUCTION-PRODUCER",
        "reason": (
            "Production producer integration with an authenticated immutable broker remains "
            "unimplemented."
        ),
        "status": "PENDING_IMPLEMENTATION",
    },
    {
        "gate_id": "SW-M7-EQUAL-WORK-PROTOCOL",
        "reason": (
            "The local deterministic tariff is not an implemented equal-work public evaluation "
            "protocol."
        ),
        "status": "PENDING_IMPLEMENTATION",
    },
    {
        "gate_id": "SW-M8-PUBLIC-JOURNEY",
        "reason": (
            "A deployed API/web journey with retained browser and hosting receipts remains "
            "unimplemented."
        ),
        "status": "PENDING_IMPLEMENTATION",
    },
)

EXTERNAL_BLOCKERS: Final = (
    {
        "gate_id": "SW-M6-TRUSTED-BROKER",
        "reason": (
            "A pre-authorized trust policy, separated issuer, and authenticated immutable "
            "store are required."
        ),
        "status": "BLOCKED_EXTERNAL",
    },
    {
        "gate_id": "SW-M6-SEPARATED-REPLAY",
        "reason": (
            "The same payload requires replay by a producer-separated clean-machine consumer."
        ),
        "status": "BLOCKED_EXTERNAL",
    },
    {
        "gate_id": "SW-M7-PREREGISTERED-HOLDOUT",
        "reason": (
            "An external custodian or protected evaluator must freeze the holdout before results."
        ),
        "status": "BLOCKED_EXTERNAL",
    },
    {
        "gate_id": "SW-M7-INDEPENDENT-REPRODUCTION",
        "reason": "Equal-work benchmark results require independent clean-machine reproduction.",
        "status": "BLOCKED_EXTERNAL",
    },
    {
        "gate_id": "SW-M8-LIVE-PROVIDER",
        "reason": (
            "An owner-controlled allowlisted provider credential and retained proposal receipt are "
            "required."
        ),
        "status": "BLOCKED_EXTERNAL",
    },
    {
        "gate_id": "SW-M8-NEW-USER",
        "reason": (
            "A non-developer must complete the README-only journey on a separate clean machine."
        ),
        "status": "BLOCKED_EXTERNAL",
    },
)

REQUIRED_GATES: Final = (
    *CONTROLLED_GATES,
    *QUALIFICATION_AND_IMPLEMENTATION_GAPS,
    *EXTERNAL_BLOCKERS,
)

LIMITATIONS: Final = (
    "Candidate bytes are not a trusted Reality Replay Broker issuance.",
    "The local StateChainBench result is not an equal-work public benchmark.",
    "The local web checks are not an external new-user or public-hosting receipt.",
    "No tag or GitHub Release is created by the candidate workflow.",
    (
        "Vendored third-party wheels qualify only the hosted native CPython 3.13/Linux x86_64 "
        "acquisition; they do not establish a cross-platform dependency payload or independent "
        "M8 package reproduction, and pip tag priority plus tool version remain provenance."
    ),
    (
        "Only execution.commands entries are typed command evidence; earlier source and build "
        "steps remain workflow dependencies and are not receipt-captured command gates."
    ),
    (
        "The M2 clean-host exit, materialized-provider M5 exit, and M6-M8 implementation or "
        "external qualification remain pending."
    ),
)
