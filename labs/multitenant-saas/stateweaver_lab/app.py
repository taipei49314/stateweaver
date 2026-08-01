"""FastAPI surface for the deterministic, in-process StateWeaver lab."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import cast

from fastapi import Depends, FastAPI, Request, Response, Security
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .models import (
    ActionReceipt,
    AdvanceClockRequest,
    ChainStateResponse,
    ClaimReferenceRequest,
    ClockResponse,
    DelayQueueRequest,
    DocumentId,
    DocumentResponse,
    EvidenceListResponse,
    HealthResponse,
    LabMode,
    LayeredStateCapture,
    MaskedDocumentResponse,
    MockPolicyResponse,
    OracleResultResponse,
    PrimeAuthorizationCacheRequest,
    PublishReferenceRequest,
    ReferenceResponse,
    ResetLabRequest,
    RetainSessionRequest,
    RoleDowngradeRequest,
    RoleDowngradeResponse,
    StateDigestResponse,
)
from .state import AuthContext, LabActionError, LabState

bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="SyntheticFixtureBearer",
    description="Public synthetic fixture ID; never use a real credential.",
)


def _state(request: Request) -> LabState:
    return cast(LabState, request.app.state.lab)


def require_session(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> AuthContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail={"code": "synthetic_bearer_required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    context = _state(request).authenticate(credentials.credentials)
    if context is None:
        # The supplied value is intentionally never interpolated into the error.
        raise HTTPException(
            status_code=401,
            detail={"code": "unknown_or_expired_fixture"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    return context


def require_admin(
    request: Request,
    context: AuthContext = Depends(require_session),
) -> AuthContext:
    _state(request).require_admin(context)
    return context


def create_app(mode: str | LabMode) -> FastAPI:
    """Create an isolated vulnerable or patched lab instance.

    No module-global state is shared between app instances, which makes clean
    reset and sibling-world isolation deterministic.
    """

    try:
        selected_mode = mode if isinstance(mode, LabMode) else LabMode(mode)
    except ValueError as error:
        raise ValueError("mode must be 'vulnerable' or 'patched'") from error

    app = FastAPI(
        title="StateWeaver deterministic multi-tenant SaaS lab",
        summary="Local synthetic target with a machine-checkable oracle",
        version="0.1.0",
        debug=False,
        servers=[{"url": "http://localhost", "description": "localhost only"}],
    )
    app.state.lab = LabState.canonical(selected_mode)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["testserver", "localhost", "127.0.0.1", "lab"],
    )

    @app.middleware("http")
    async def add_local_security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(LabActionError)
    async def handle_lab_action_error(request: Request, error: LabActionError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={"detail": {"code": error.code}},
        )

    @app.get("/healthz", response_model=HealthResponse, tags=["meta"])
    def health(request: Request) -> HealthResponse:
        return HealthResponse(mode=_state(request).mode)

    @app.post(
        "/v1/lab/session/retain",
        response_model=ActionReceipt,
        tags=["chain actions"],
    )
    def retain_session(
        payload: RetainSessionRequest,
        request: Request,
        context: AuthContext = Depends(require_session),
    ) -> ActionReceipt:
        del payload
        return _state(request).retain_old_session(context)

    @app.post(
        "/v1/lab/authorization-cache/prime",
        response_model=ActionReceipt,
        tags=["chain actions"],
    )
    def prime_cache(
        payload: PrimeAuthorizationCacheRequest,
        request: Request,
        context: AuthContext = Depends(require_session),
    ) -> ActionReceipt:
        return _state(request).prime_authorization_cache(context, payload.document_id)

    @app.post(
        "/v1/lab/admin/role-downgrade",
        response_model=RoleDowngradeResponse,
        tags=["chain actions"],
    )
    def downgrade_role(
        payload: RoleDowngradeRequest,
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> RoleDowngradeResponse:
        return _state(request).downgrade_role(context, payload.principal_id, payload.new_role)

    @app.post(
        "/v1/lab/admin/queue/defer",
        response_model=ActionReceipt,
        tags=["chain actions"],
    )
    def defer_queue_job(
        payload: DelayQueueRequest,
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> ActionReceipt:
        return _state(request).delay_queue_job(context, payload.job_id, payload.delay_seconds)

    @app.post(
        "/v1/lab/references/publish",
        response_model=ReferenceResponse,
        tags=["chain actions"],
    )
    def publish_reference(
        payload: PublishReferenceRequest,
        request: Request,
        context: AuthContext = Depends(require_session),
    ) -> ReferenceResponse:
        return _state(request).publish_reference(context, payload.document_id, payload.recipient_id)

    @app.post(
        "/v1/lab/references/claim",
        response_model=ReferenceResponse,
        tags=["chain actions"],
    )
    def claim_reference(
        payload: ClaimReferenceRequest,
        request: Request,
        context: AuthContext = Depends(require_session),
    ) -> ReferenceResponse:
        return _state(request).claim_reference(context, payload.reference_id)

    @app.post(
        "/v1/lab/admin/clock/advance",
        response_model=ClockResponse,
        tags=["chain actions"],
    )
    def advance_clock(
        payload: AdvanceClockRequest,
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> ClockResponse:
        return _state(request).advance_clock(context, payload.seconds)

    @app.get(
        "/v1/lab/documents/{document_id}",
        response_model=DocumentResponse,
        tags=["replay"],
    )
    def read_document(
        document_id: DocumentId,
        request: Request,
        context: AuthContext = Depends(require_session),
    ) -> DocumentResponse:
        return _state(request).read_document(context, document_id)

    @app.get(
        "/v1/lab/decoys/masked/{document_id}",
        response_model=MaskedDocumentResponse,
        tags=["negative controls"],
    )
    def masked_decoy(
        document_id: DocumentId,
        request: Request,
        context: AuthContext = Depends(require_session),
    ) -> MaskedDocumentResponse:
        return _state(request).masked_decoy(context, document_id)

    @app.get(
        "/v1/lab/decoys/mock-policy/{document_id}",
        response_model=MockPolicyResponse,
        tags=["negative controls"],
    )
    def mock_policy_decoy(
        document_id: DocumentId,
        request: Request,
        context: AuthContext = Depends(require_session),
    ) -> MockPolicyResponse:
        return _state(request).mock_policy_decoy(context, document_id)

    @app.get(
        "/v1/lab/chain-state",
        response_model=ChainStateResponse,
        tags=["oracle"],
    )
    def chain_state(
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> ChainStateResponse:
        del context
        return _state(request).chain_state()

    @app.get(
        "/v1/lab/oracle",
        response_model=OracleResultResponse,
        tags=["oracle"],
    )
    def oracle(
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> OracleResultResponse:
        del context
        return _state(request).oracle_result()

    @app.get(
        "/v1/lab/evidence",
        response_model=EvidenceListResponse,
        tags=["oracle"],
    )
    def evidence(
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> EvidenceListResponse:
        del context
        return _state(request).evidence()

    @app.get(
        "/v1/lab/state",
        response_model=StateDigestResponse,
        tags=["meta"],
    )
    def state_digest(
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> StateDigestResponse:
        del context
        return _state(request).state_digest()

    @app.get(
        "/v1/lab/state/layers",
        response_model=LayeredStateCapture,
        tags=["meta"],
    )
    def layered_state_capture(
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> LayeredStateCapture:
        del context
        return _state(request).capture_layers()

    @app.post(
        "/v1/lab/reset",
        response_model=StateDigestResponse,
        tags=["meta"],
    )
    def reset_lab(
        payload: ResetLabRequest,
        request: Request,
        context: AuthContext = Depends(require_admin),
    ) -> StateDigestResponse:
        del payload, context
        current_mode = _state(request).mode
        request.app.state.lab = LabState.canonical(current_mode)
        return _state(request).state_digest()

    return app
