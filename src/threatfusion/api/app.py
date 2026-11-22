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
from . import analyze as analyze_module
from . import behavior as behavior_module
from . import details as details_module
from . import evaluation as evaluation_module
from . import history as history_module
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


class KeysRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threatfox: str = Field(default="", max_length=512)
    urlhaus: str = Field(default="", max_length=512)


class EmptyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force: bool = False


FeedbackLabel = Literal["Confirmed Threat", "Benign", "Uncertain"]


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1, max_length=1024)
    label: FeedbackLabel
    note: str = Field(default="", max_length=500)


class BulkFeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domains: list[str] = Field(min_length=1, max_length=10_000)
    label: FeedbackLabel
    note: str = Field(default="", max_length=500)
    confirm: Literal[True]


class ConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: Literal[True]


class RetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keep_latest: int = Field(ge=1, le=1000)
    confirm: Literal[True]


class SuppressionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1, max_length=1024)
    reason: str = Field(max_length=300)
    expiry_days: int = Field(default=0, ge=0, le=3650)


class ExpectedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str | None = Field(default=None, max_length=65_536)  # expected_connections.MAX_RULE_BYTES


class DomainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1, max_length=1024)


class MarkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=1024)
    mark: Mark | None


def streamlit_url(environment: Mapping[str, str]) -> str | None:
    """A Streamlit workspace running beside this one, or None (DEC-109).

    Every screen has moved, so the header links to Streamlit only when it is
    explicitly configured (developers running both, ``web/README.md``); the
    launcher's React mode does not start Streamlit. Only a loopback ``http``
    address is ever linked; anything else means no link.
    """
    value = environment.get("THREATFUSION_STREAMLIT_URL", "").strip().rstrip("/")
    scheme, separator, rest = value.partition("://")
    if scheme == "http" and separator and "/" not in rest and host_header_name(rest) in LOOPBACK_HOSTNAMES:
        return value
    return None


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
        if ("/download/" in request.url.path and request.url.path.startswith("/api/")
                and request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}):
            # Downloads carry sensitive telemetry: same-origin navigation only.
            return JSONResponse({"detail": "Cross-site request refused."}, status_code=403)
        if request.method not in SAFE_METHODS:
            content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
            # Uploads send raw bytes; that type is not "simple" either, so a
            # cross-site page cannot send it without a CORS preflight we never allow.
            allowed = {"application/json"} | ({"application/octet-stream"} if request.url.path == "/api/analyze" else set())
            if (not _origin_allowed(request.headers.get("origin"), environment)
                    or request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}
                    or content_type not in allowed):
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
                "first_setup": first, "evaluation_available": evaluation_module.available(resolved),
                "history_available": resolved.history_enabled}

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

    @app.get("/api/behavior")
    def behavior(lang: Language = Query("en"), resolved: ApiSettings = Depends(settings)) -> dict:
        return behavior_module.behavior_response(resolved, lang)

    @app.put("/api/behavior/marks", status_code=204)
    def behavior_mark(body: MarkRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        try:
            behavior_module.set_mark(resolved, body.key, body.mark)
        except behavior_module.UnknownCard:
            raise HTTPException(404, "This item is not in the current list. Refresh and retry.") from None
        except (OSError, ValueError, TypeError, KeyError):
            raise HTTPException(409, "Could not save. Check the folder permissions.") from None
        return Response(status_code=204)

    @app.get("/api/evaluation")
    def evaluation(lang: Language = Query("en"), resolved: ApiSettings = Depends(settings)) -> dict:
        return evaluation_module.evaluation_response(resolved, lang)

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

    @app.put("/api/setup/keys", status_code=204)
    def setup_keys(body: KeysRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        # Keys are never logged or returned; a bad format saves nothing.
        try:
            setup_module.save_keys(resolved, body.threatfox, body.urlhaus)
        except setup_module.NotManaged:
            raise HTTPException(404, "Setup is available in a managed installation in real CTI mode.") from None
        except ValueError:
            raise HTTPException(422, "Invalid API key format. No credentials were saved.") from None
        except (OSError, TypeError):
            raise HTTPException(409, "Local settings could not be read. Check private file permissions.") from None
        return Response(status_code=204)

    @app.post("/api/setup/keys/forget", status_code=204)
    def setup_forget_keys(_body: EmptyRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        return _setup_write(lambda: setup_module.forget_keys(resolved))

    @app.post("/api/setup/refresh")
    def setup_refresh(body: RefreshRequest, resolved: ApiSettings = Depends(settings)) -> dict:
        try:
            return {"started": setup_module.start_refresh(resolved, body.force)}
        except setup_module.NotManaged:
            raise HTTPException(404, "Setup is available in a managed installation in real CTI mode.") from None
        except (OSError, ValueError, TypeError):
            raise HTTPException(409, "Local settings could not be read. Check private file permissions.") from None

    @app.post("/api/app/stop")
    def stop_application(_body: EmptyRequest, resolved: ApiSettings = Depends(settings)) -> dict:
        try:
            return {"stopping": setup_module.stop_application(resolved)}
        except setup_module.NotManaged:
            raise HTTPException(404, "Setup is available in a managed installation in real CTI mode.") from None
        except (OSError, ValueError, TypeError):
            raise HTTPException(409, "Local settings could not be read. Check private file permissions.") from None

    @app.get("/api/analyze/status")
    def analyze_status(lang: Language = Query("en"), resolved: ApiSettings = Depends(settings)) -> dict:
        return analyze_module.status(resolved, lang)

    @app.post("/api/analyze")
    async def analyze_upload(request: Request, format: str = Query(max_length=64), name: str = Query(max_length=255),
                             lang: Language = Query("en"), resolved: ApiSettings = Depends(settings)) -> dict:
        from starlette.concurrency import run_in_threadpool

        declared = request.headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > analyze_module.MAX_UPLOAD_BYTES):
            raise HTTPException(413, analyze_module.translate("Uploaded telemetry exceeds the 100 MB application limit.", lang))
        body = bytearray()
        async for chunk in request.stream():  # hard cap even if the length header lies
            body.extend(chunk)
            if len(body) > analyze_module.MAX_UPLOAD_BYTES:
                raise HTTPException(413, analyze_module.translate("Uploaded telemetry exceeds the 100 MB application limit.", lang))
        try:
            return await run_in_threadpool(analyze_module.analyze, resolved, lang, format, name, bytes(body))
        except analyze_module.UploadRejected as error:
            raise HTTPException(error.status, str(error)) from None

    def _analysis(analysis_id: str):
        try:
            return analyze_module.current(analysis_id)
        except analyze_module.NoAnalysis:
            raise HTTPException(404, "This analysis is no longer available. Upload the file again.") from None

    @app.get("/api/analyze/{analysis_id}")
    def analysis_overview(analysis_id: str, lang: Language = Query("en"), include_suppressed: bool = False,
                          resolved: ApiSettings = Depends(settings)) -> dict:
        return analyze_module.overview(_analysis(analysis_id), lang, resolved, include_suppressed=include_suppressed)

    @app.get("/api/analyze/{analysis_id}/domain")
    def analysis_domain(analysis_id: str, name: str = Query(max_length=1024), lang: Language = Query("en"),
                        resolved: ApiSettings = Depends(settings)) -> dict:
        try:
            return analyze_module.domain_detail(_analysis(analysis_id), lang, name, resolved)
        except analyze_module.NoAnalysis:
            raise HTTPException(404, "This domain is not in the analysis.") from None

    def _history(action):
        try:
            return action()
        except history_module.HistoryDisabled:
            raise HTTPException(404, "Analysis history is disabled in this mode.") from None
        except history_module.UnknownRun:
            raise HTTPException(404, "The selected saved run no longer exists.") from None
        except (TypeError, ValueError) as error:
            raise HTTPException(422, str(error)) from None
        except OSError:
            raise HTTPException(409, "Local settings could not be read. Check private file permissions.") from None

    @app.post("/api/analyze/{analysis_id}/save")
    def analysis_save(analysis_id: str, _body: EmptyRequest, lang: Language = Query("en"),
                      resolved: ApiSettings = Depends(settings)) -> dict:
        analysis = _analysis(analysis_id)
        return {"message": _history(lambda: history_module.save_analysis(resolved, analysis, lang))}

    @app.put("/api/analyze/suppression", status_code=204)
    def analysis_suppress(body: SuppressionRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        _history(lambda: history_module.suppress(resolved, body.domain, body.reason, body.expiry_days))
        return Response(status_code=204)

    @app.post("/api/analyze/suppression/remove", status_code=204)
    def analysis_unsuppress(body: DomainRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        _history(lambda: history_module.unsuppress(resolved, body.domain))
        return Response(status_code=204)

    @app.get("/api/history")
    def history(lang: Language = Query("en"), run: int | None = Query(None, ge=1),
                resolved: ApiSettings = Depends(settings)) -> dict:
        return history_module.history_response(resolved, lang, run)

    @app.put("/api/history/{run_id}/feedback", status_code=204)
    def history_feedback(run_id: int, body: FeedbackRequest, resolved: ApiSettings = Depends(settings)) -> Response:
        _history(lambda: history_module.save_feedback(resolved, run_id, body.domain, body.label, body.note))
        return Response(status_code=204)

    @app.put("/api/history/{run_id}/feedback/bulk")
    def history_bulk_feedback(run_id: int, body: BulkFeedbackRequest, resolved: ApiSettings = Depends(settings)) -> dict:
        return {"count": _history(lambda: history_module.save_bulk_feedback(resolved, run_id, body.domains,
                                                                             body.label, body.note))}

    @app.post("/api/history/{run_id}/delete")
    def history_delete(run_id: int, _body: ConfirmRequest, resolved: ApiSettings = Depends(settings)) -> dict:
        return {"deleted": _history(lambda: history_module.delete_run(resolved, run_id))}

    @app.post("/api/history/retention")
    def history_retention(body: RetentionRequest, lang: Language = Query("en"),
                          resolved: ApiSettings = Depends(settings)) -> dict:
        return {"message": _history(lambda: history_module.apply_retention(resolved, body.keep_latest, lang))}

    @app.get("/api/analyze/{analysis_id}/devices")
    def analysis_devices(analysis_id: str, lang: Language = Query("en"), include_ips: bool = False,
                         include_observe: bool = False, resolved: ApiSettings = Depends(settings)) -> dict:
        return analyze_module.devices(_analysis(analysis_id), lang, include_ips=include_ips,
                                      include_observe=include_observe, public_mode=resolved.public_mode)

    @app.get("/api/analyze/{analysis_id}/device-timeline")
    def analysis_device_timeline(analysis_id: str, group: int = Query(ge=0), lang: Language = Query("en")) -> dict:
        try:
            return analyze_module.device_timeline(_analysis(analysis_id), lang, group)
        except analyze_module.NoAnalysis:
            raise HTTPException(404, "This group is not in the current view. Refresh and retry.") from None

    @app.get("/api/analyze/{analysis_id}/connections")
    def analysis_connections(analysis_id: str, lang: Language = Query("en"), include_ips: bool = False,
                             reviews_only: bool = True, include_expected: bool = False,
                             resolved: ApiSettings = Depends(settings)) -> dict:
        return analyze_module.connections(_analysis(analysis_id), lang, include_ips=include_ips,
                                          reviews_only=reviews_only, public_mode=resolved.public_mode,
                                          include_expected=include_expected)

    @app.put("/api/analyze/{analysis_id}/expected")
    def analysis_expected(analysis_id: str, body: ExpectedRequest, lang: Language = Query("en"),
                          resolved: ApiSettings = Depends(settings)) -> dict:
        if resolved.public_mode:
            raise HTTPException(404, "Expected-connection declarations are not available in this mode.")
        try:
            return {"rules": analyze_module.set_expected(_analysis(analysis_id), body.content)}
        except ValueError:
            raise HTTPException(422, analyze_module.translate(
                "Invalid expected-connection file. No declarations applied.", lang)) from None

    @app.get("/api/analyze/{analysis_id}/connection-timeline")
    def analysis_connection_timeline(analysis_id: str, group: int = Query(ge=0), lang: Language = Query("en")) -> dict:
        try:
            return analyze_module.connection_timeline(_analysis(analysis_id), lang, group)
        except analyze_module.NoAnalysis:
            raise HTTPException(404, "This group is not in the current view. Refresh and retry.") from None

    @app.get("/api/analyze/{analysis_id}/download/{kind}")
    def analysis_download(analysis_id: str, kind: Literal["json", "csv", "devices", "connections"],
                          include_ips: bool = False, resolved: ApiSettings = Depends(settings)) -> Response:
        body, filename, media = analyze_module.download(_analysis(analysis_id), kind, include_ips=include_ips,
                                                        public_mode=resolved.public_mode)
        return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    if static_dir is not None and (static_dir / "index.html").is_file():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="web")
    return app
