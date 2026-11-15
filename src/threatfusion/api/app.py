"""FastAPI application: loopback-only, same-origin, no CORS, no API docs.

Requests are refused unless the Host header names a loopback address (DNS
rebinding defence shared with the Streamlit workspace). State-changing
requests additionally need a loopback Origin, a same-origin fetch and a JSON
body, so another website open in the same browser cannot change marks.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from ..request_guard import host_header_name, is_allowed_host
from .i18n import Language, ui_strings
from .review import Mark, UnknownItem, review_response, set_mark
from .settings import ApiSettings, resolve_settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)


class MarkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=1024)
    mark: Mark | None


def _origin_allowed(origin: str | None, environment: Mapping[str, str]) -> bool:
    if not origin:
        return False
    scheme, separator, rest = origin.partition("://")
    if scheme not in {"http", "https"} or not separator or "/" in rest:
        return False
    return host_header_name(rest) is not None and is_allowed_host(rest, environment)


def create_app(
    settings_provider: Callable[[], ApiSettings] = resolve_settings,
    *,
    static_dir: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> FastAPI:
    environment = os.environ if environment is None else environment
    app = FastAPI(title="ThreatFusion local API", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if not is_allowed_host(request.headers.get("host"), environment):
            return JSONResponse({"detail": "Only requests addressed to 127.0.0.1 or localhost are accepted."},
                                status_code=403)
        if request.method not in SAFE_METHODS:
            content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if (not _origin_allowed(request.headers.get("origin"), environment)
                    or request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}
                    or content_type != "application/json"):
                return JSONResponse({"detail": "Cross-site request refused."}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def settings() -> ApiSettings:
        try:
            return settings_provider()
        except (OSError, ValueError, TypeError):
            raise HTTPException(500, "Application configuration is invalid. Check runtime paths "
                                     "and private file permissions.") from None

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/api/i18n")
    def strings(lang: Literal["en", "tr"] = "en") -> dict:
        return ui_strings(lang)

    @app.get("/api/review")
    def review(lang: Language = Query("en"), resolved: ApiSettings = Depends(settings)) -> dict:
        return review_response(resolved, lang)

    @app.put("/api/review/marks", status_code=204)
    def mark(body: MarkRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        try:
            set_mark(resolved, body.key, body.mark)
        except UnknownItem:
            raise HTTPException(404, "This item is not in the current list. Refresh and retry.") from None
        except FileNotFoundError:
            raise HTTPException(404, "No collector snapshot yet.") from None
        except (OSError, ValueError, TypeError, KeyError):
            raise HTTPException(409, "Could not save. Check the folder permissions.") from None
        return Response(status_code=204)

    if static_dir is not None and (static_dir / "index.html").is_file():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="web")
    return app
