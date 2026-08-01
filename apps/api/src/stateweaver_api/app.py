"""The deliberately narrow, read-only public demo API."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from stateweaver_api.fixture import DEMO_HEALTH, DEMO_OVERVIEW, DEMO_REPLAY, DEMO_TWIN, DEMO_WORLDS
from stateweaver_api.models import (
    HealthResponse,
    OverviewResponse,
    ReplayResponse,
    TwinResponse,
    WorldsResponse,
)

LOCAL_DEV_ORIGINS = ("http://localhost:3000", "http://127.0.0.1:3000")

app = FastAPI(
    title="StateWeaver Synthetic Local Lab API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=LOCAL_DEV_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=[],
)


@app.middleware("http")
async def reject_get_input(request: Request, call_next: RequestResponseEndpoint) -> Response:
    """Keep the presentation API a literal zero-input surface."""
    if request.method == "GET" and (request.url.query or await request.body()):
        return JSONResponse(
            {"detail": "demo GET endpoints accept no query parameters or request body"},
            status_code=400,
        )
    return await call_next(request)


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    """Return the API's fixed read-only state."""
    return DEMO_HEALTH


@app.get("/v1/demo/overview", response_model=OverviewResponse)
def demo_overview() -> OverviewResponse:
    """Return the saved Experiment Overview presentation data."""
    return DEMO_OVERVIEW


@app.get("/v1/demo/worlds", response_model=WorldsResponse)
def demo_worlds() -> WorldsResponse:
    """Return the saved World DAG presentation data."""
    return DEMO_WORLDS


@app.get("/v1/demo/twin", response_model=TwinResponse)
def demo_twin() -> TwinResponse:
    """Return the saved Twin Inspector presentation data."""
    return DEMO_TWIN


@app.get("/v1/demo/replay", response_model=ReplayResponse)
def demo_replay() -> ReplayResponse:
    """Return the saved Replay and Evidence Viewer presentation data."""
    return DEMO_REPLAY
