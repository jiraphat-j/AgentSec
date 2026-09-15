"""Optional loopback-only Phase 5 dashboard HTTP adapter."""

from __future__ import annotations

import asyncio
from importlib.resources import files
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .constants import MAX_DASHBOARD_QUERY_BYTES, MAX_DASHBOARD_RESPONSE_BYTES
from .dashboard_catalog import (
    DashboardCatalog,
    DashboardInputError,
    DashboardResourceLimitExceeded,
    encode_safe_projection,
)
from .dashboard_models import ArtifactKind
from .dashboard_service import DashboardNotFoundError, DashboardQueryError, DashboardService

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
}


def _json(value: object, status_code: int = 200) -> JSONResponse:
    try:
        encoded = encode_safe_projection(value)
    except DashboardInputError:
        return JSONResponse(
            {"error": {"code": "unsafe_projection_rejected"}},
            status_code=503,
            headers=_SECURITY_HEADERS,
        )
    if len(encoded) > MAX_DASHBOARD_RESPONSE_BYTES:
        return JSONResponse(
            {"error": {"code": "response_limit_exceeded"}},
            status_code=503,
            headers=_SECURITY_HEADERS,
        )
    return JSONResponse(value, status_code=status_code, headers=_SECURITY_HEADERS)


def _asset(name: str, media_type: str) -> Response:
    data = files("agentsec.resources").joinpath("dashboard", name).read_bytes()
    if len(data) > MAX_DASHBOARD_RESPONSE_BYTES:
        return _json({"error": {"code": "response_limit_exceeded"}}, 503)
    return Response(data, media_type=media_type, headers=_SECURITY_HEADERS)


def create_dashboard_app(catalog: DashboardCatalog, *, port: int = 8765) -> FastAPI:
    if not 1 <= port <= 65535:
        raise ValueError("dashboard port must be between 1 and 65535")
    app = FastAPI(
        title="AgentSec Lab dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1"], www_redirect=False)
    service = DashboardService(catalog)
    active = 0
    active_lock = asyncio.Lock()
    allowed_origin = f"http://127.0.0.1:{port}"

    @app.middleware("http")
    async def enforce_request_boundary(request: Request, call_next: Any) -> Response:
        nonlocal active
        if len(request.url.query.encode("utf-8")) > MAX_DASHBOARD_QUERY_BYTES:
            return _json({"error": {"code": "invalid_query"}}, 422)
        if request.method not in {"GET", "HEAD"}:
            return _json({"error": {"code": "method_not_allowed"}}, 405)
        origin = request.headers.get("origin")
        if origin is not None and origin != allowed_origin:
            return _json({"error": {"code": "cross_site_request_rejected"}}, 403)
        fetch_site = request.headers.get("sec-fetch-site")
        if fetch_site not in {None, "none", "same-origin"}:
            return _json({"error": {"code": "cross_site_request_rejected"}}, 403)
        async with active_lock:
            if active >= 8:
                return _json({"error": {"code": "request_limit_exceeded"}}, 503)
            active += 1
        try:
            response = await call_next(request)
        finally:
            async with active_lock:
                active -= 1
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _error: RequestValidationError) -> JSONResponse:
        return _json({"error": {"code": "invalid_query"}}, 422)

    @app.exception_handler(DashboardNotFoundError)
    async def missing(_request: Request, _error: DashboardNotFoundError) -> JSONResponse:
        return _json({"error": {"code": "not_found"}}, 404)

    @app.exception_handler(DashboardQueryError)
    async def invalid_query(_request: Request, _error: DashboardQueryError) -> JSONResponse:
        return _json({"error": {"code": "invalid_query"}}, 422)

    @app.exception_handler(DashboardResourceLimitExceeded)
    async def resource_limit(
        _request: Request, _error: DashboardResourceLimitExceeded
    ) -> JSONResponse:
        return _json({"error": {"code": "resource_limit_exceeded"}}, 503)

    @app.get("/", include_in_schema=False)
    async def index() -> Response:
        return _asset("index.html", "text/html")

    @app.get("/assets/styles.css", include_in_schema=False)
    async def styles() -> Response:
        return _asset("styles.css", "text/css")

    @app.get("/assets/app.js", include_in_schema=False)
    async def script() -> Response:
        return _asset("app.js", "text/javascript")

    def page(offset: int, limit: int) -> tuple[int, int]:
        return offset, limit

    @app.get("/api/v1/catalog")
    async def catalog_route(
        offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)
    ) -> JSONResponse:
        return _json(service.catalog(*page(offset, limit)))

    route_kinds: dict[str, tuple[ArtifactKind, ...]] = {
        "runs": (ArtifactKind.EVENT_SOURCE, ArtifactKind.RUN_REPORT),
        "investigations": (ArtifactKind.INVESTIGATION,),
        "comparisons": (ArtifactKind.COMPARISON,),
        "evaluations": (ArtifactKind.EVALUATION,),
        "rules": (ArtifactKind.RULE,),
        "rule-tests": (ArtifactKind.RULE_TEST,),
    }

    @app.get("/api/v1/{collection}")
    async def list_records(
        collection: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
    ) -> JSONResponse:
        kinds = route_kinds.get(collection)
        if kinds is None:
            raise DashboardNotFoundError("collection not found")
        return _json(service.list_kind(kinds, offset, limit))

    @app.get("/api/v1/{collection}/{item_id}")
    async def record_detail(collection: str, item_id: str) -> JSONResponse:
        kinds = route_kinds.get(collection)
        if kinds is None:
            raise DashboardNotFoundError("collection not found")
        return _json(service.detail(item_id, kinds))

    @app.get("/api/v1/runs/{item_id}/events")
    async def events_route(
        item_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
        trace_id: str | None = None,
        event_type: str | None = None,
    ) -> JSONResponse:
        return _json(
            service.events(item_id, offset, limit, trace_id=trace_id, event_type=event_type)
        )

    @app.get("/api/v1/runs/{item_id}/events/{event_id}")
    async def event_route(item_id: str, event_id: str) -> JSONResponse:
        return _json(service.event(item_id, event_id))

    @app.get("/api/v1/investigations/{item_id}/alerts/{alert_id}")
    async def alert_route(item_id: str, alert_id: str) -> JSONResponse:
        return _json(service.investigation_child(item_id, "alerts", alert_id))

    @app.get("/api/v1/investigations/{item_id}/incidents/{incident_id}")
    async def incident_route(item_id: str, incident_id: str) -> JSONResponse:
        return _json(service.investigation_child(item_id, "incidents", incident_id))

    @app.get("/api/v1/{collection}/{item_id}/{nested_collection}")
    async def nested_route(
        collection: str,
        item_id: str,
        nested_collection: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
    ) -> JSONResponse:
        if collection not in {"investigations", "evaluations"}:
            raise DashboardNotFoundError("nested collection not found")
        return _json(service.nested(item_id, nested_collection, offset, limit))

    return app
