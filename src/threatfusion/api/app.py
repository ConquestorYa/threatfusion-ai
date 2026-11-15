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

from ..request_guard import LOOPBACK_HOSTNAMES, host_header_name, is_allowed_host
from . import details as details_module
from . import lookup as lookup_module
from . import setup as setup_module
from .i18n import Language, ui_strings
from .review import Mark, UnknownItem, review_response, set_mark
from .settings import ApiSettings, resolve_settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)


class LookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(max_length=4096)  # quick_lookup.MAX_LOOKUP_INPUT_CHARS


class DomainAgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1, max_length=253)


class ModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["cti-only", "demo"]


class ScheduleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    automatic: bool
    interval_hours: Literal[6, 12, 24]


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force: bool = False


class MarkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=1024)
    mark: Mark | None


DEFAULT_STREAMLIT_URL = "http://127.0.0.1:8501"


def streamlit_url(environment: Mapping[str, str]) -> str:
    """Where the Streamlit workspace runs; only a loopback http address is linked."""
    value = environment.get("THREATFUSION_STREAMLIT_URL", "").strip().rstrip("/")
    scheme, separator, rest = value.partition("://")
    if scheme == "http" and separator and "/" not in rest and host_header_name(rest) in LOOPBACK_HOSTNAMES:
        return value
    return DEFAULT_STREAMLIT_URL


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
        if (request.url.path.startswith("/api/details/download/")
                and request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}):
            # Downloads carry sensitive telemetry: same-origin navigation only.
            return JSONResponse({"detail": "Cross-site request refused."}, status_code=403)
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

    @app.get("/api/app")
    def app_info(resolved: ApiSettings = Depends(settings)) -> dict:
        from ..ui_local_settings import needs_first_setup

        root = resolved.local_root
        try:
            first = root is not None and needs_first_setup(root)
        except (OSError, ValueError, TypeError):
            first = False
        # Same screen rules as Streamlit: Setup only for a managed installation,
        # and it opens first until real CTI has been downloaded once.
        return {"streamlit_url": streamlit_url(environment), "setup_available": root is not None,
                "first_setup": first}

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

    @app.get("/api/details")
    def details(lang: Language = Query("en"), local_ips: bool = True, reviews_only: bool = True,
                include_expected: bool = False, dns_observations: bool = False,
                resolved: ApiSettings = Depends(settings)) -> dict:
        return details_module.details_response(resolved, lang, local_ips=local_ips, reviews_only=reviews_only,
                                               include_expected=include_expected, dns_observations=dns_observations)

    def _timeline(builder, resolved: ApiSettings, lang: Language, group: int, local_ips: bool) -> dict:
        try:
            return builder(resolved, lang, group, local_ips=local_ips)
        except (details_module.NotAvailable, FileNotFoundError):
            raise HTTPException(404, "This group is not in the current snapshot. Refresh and retry.") from None
        except (OSError, ValueError, TypeError, AttributeError, KeyError):
            raise HTTPException(409, "Collector snapshot could not be read.") from None

    @app.get("/api/details/connection-timeline")
    def connection_timeline(group: int = Query(ge=0), lang: Language = Query("en"), local_ips: bool = True,
                            resolved: ApiSettings = Depends(settings)) -> dict:
        return _timeline(details_module.connection_timeline, resolved, lang, group, local_ips)

    @app.get("/api/details/dns-timeline")
    def dns_timeline(group: int = Query(ge=0), lang: Language = Query("en"), local_ips: bool = True,
                     resolved: ApiSettings = Depends(settings)) -> dict:
        return _timeline(details_module.dns_timeline, resolved, lang, group, local_ips)

    @app.get("/api/details/download/snapshot")
    def download_snapshot(resolved: ApiSettings = Depends(settings)) -> Response:
        try:
            body, name = details_module.snapshot_download(resolved)
        except (details_module.NotAvailable, FileNotFoundError):
            raise HTTPException(404, "No collector snapshot yet.") from None
        except (OSError, ValueError, TypeError, KeyError):
            raise HTTPException(409, "Collector snapshot could not be read.") from None
        return Response(body, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/details/download/full")
    def download_full(resolved: ApiSettings = Depends(settings)) -> Response:
        try:
            body = details_module.full_download(resolved)
        except (details_module.NotAvailable, FileNotFoundError):
            raise HTTPException(404, "No full report for this snapshot.") from None
        except (OSError, ValueError, TypeError, KeyError):
            raise HTTPException(409, "Full report changed or is unavailable. Refresh this page and retry; "
                                     "no unverified archive is served.") from None
        return Response(body, media_type="application/gzip", headers={
            "Content-Disposition": 'attachment; filename="threatfusion_collected_connections.full.json.gz"'})

    @app.get("/api/lookup/status")
    def lookup_status(lang: Language = Query("en"), resolved: ApiSettings = Depends(settings)) -> dict:
        return lookup_module.status(resolved, lang)

    @app.post("/api/lookup")
    def lookup(body: LookupRequest, lang: Language = Query("en"), resolved: ApiSettings = Depends(settings)) -> dict:
        try:
            return lookup_module.lookup(resolved, lang, body.value)
        except lookup_module.LookupUnavailable:
            raise HTTPException(409, "The local ML artifact is not ready.") from None

    @app.post("/api/lookup/domain-age")
    def domain_age(body: DomainAgeRequest, lang: Language = Query("en"),
                   resolved: ApiSettings = Depends(settings)) -> dict:
        try:
            return lookup_module.domain_age(resolved, lang, body.domain)
        except lookup_module.LookupUnavailable:
            raise HTTPException(409, "Registry lookups are not available in this mode.") from None
        except ValueError:
            raise HTTPException(422, "Site age is not available for this name.") from None

    def _setup_write(action) -> Response:
        try:
            action()
        except setup_module.NotManaged:
            raise HTTPException(404, "Setup is available in a managed installation in real CTI mode.") from None
        except (OSError, ValueError, TypeError):
            raise HTTPException(409, "Local settings could not be read. Check private file permissions.") from None
        return Response(status_code=204)

    @app.get("/api/setup")
    def setup(lang: Language = Query("en"), resolved: ApiSettings = Depends(settings)) -> dict:
        try:
            return setup_module.setup_state(resolved, lang)
        except (OSError, ValueError, TypeError):
            return {"state": "unreadable"}

    @app.put("/api/setup/mode", status_code=204)
    def setup_mode(body: ModeRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        return _setup_write(lambda: setup_module.change_mode(resolved, body.mode))

    @app.put("/api/setup/schedule", status_code=204)
    def setup_schedule(body: ScheduleRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        return _setup_write(lambda: setup_module.save_schedule(resolved, body.automatic, body.interval_hours))

    @app.post("/api/setup/refresh")
    def setup_refresh(body: RefreshRequest, resolved: ApiSettings = Depends(settings)) -> dict:
        try:
            return {"started": setup_module.start_refresh(resolved, body.force)}
        except setup_module.NotManaged:
            raise HTTPException(404, "Setup is available in a managed installation in real CTI mode.") from None
        except (OSError, ValueError, TypeError):
            raise HTTPException(409, "Local settings could not be read. Check private file permissions.") from None

    if static_dir is not None and (static_dir / "index.html").is_file():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="web")
    return app
