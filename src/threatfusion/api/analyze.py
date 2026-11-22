"""Analyze telemetry (upload) as JSON, using the existing analysis functions.

Mirrors the "Analyze telemetry" page of ``streamlit_app`` and its tabs
(priority findings, overview, domain findings, device triage, connection
activity, domain investigation, IOC evidence, related activity, export).
Parsing and analysis are the ``runtime_analysis`` functions; rows come from
``dashboard``; reports from ``reporting``.

Upload safety: the body is read with a hard 100 MB cap (Streamlit's limit),
the file name's extension must match the chosen format (Streamlit's upload
types), text formats must be UTF-8, and the bytes are analysed in memory only:
nothing is written to disk or sent anywhere. Like Streamlit's session state,
the last result is kept in this process's memory (one at a time) so the tabs
and downloads can be rendered; a new upload replaces it.

History-only parts (saving aggregate history, previous analyst review,
local suppressions) come from ``history`` and exist only when
``history_enabled``, as in Streamlit. The optional expected-connection JSON
of Connection activity is parsed by ``parse_expected_connections`` and kept
with the analysis in memory only (Streamlit: "local session only"). Not
mirrored: the verdict and related-activity charts (their numbers are shown as
tables).
"""
from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from pathlib import PurePath

from .details import _attempts, _block, _joined, _table, connection_timeline_payload, dns_timeline_payload
from .i18n import Language, evidence, short_time, translate
from .settings import ApiSettings

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # streamlit_app.MAX_UPLOAD_BYTES
MAX_ROWS = 500

# streamlit_app: format choices with their caption, requirement, label, types and help.
FORMATS = {
    "Auto-detect": {
        "caption": "Auto-detect · CSV/TSV/TXT/XLSX/XLS/PCAP/Zeek/Suricata/Pi-hole/AdGuard · max 100 MB",
        "required": "No manual mapping required. ThreatFusion detects the file type, delimiter, text encoding, DNS columns, packet captures, Zeek logs and supported network telemetry automatically.",
        "label": "Upload telemetry",
        "types": ("csv", "tsv", "txt", "log", "json", "xlsx", "xls", "db", "sqlite", "sqlite3", "pcap", "pcapng",
                  "cap", "capinfos", "dnstop"),
        "help": "Upload a DNS telemetry file. ThreatFusion detects CSV/TSV delimiters, common text encodings, Excel worksheets, common DNS column names, Zeek dns.log/conn.log, PCAP/PCAPNG DNS, Pi-hole FTL SQLite, Suricata EVE, dnstop, and AdGuard Home query logs automatically.",
    },
    "Generic DNS CSV": {
        "caption": "Generic DNS CSV · UTF-8 · max 100 MB",
        "required": "query_name; all other fields are optional",
        "label": "Upload DNS CSV",
        "types": ("csv",),
        "help": "Expected columns: timestamp, client_ip, query_name, query_type, response_ip. Only query_name is required.",
    },
    "Zeek dns.log": {
        "caption": "Zeek dns.log text export · max 100 MB",
        "required": "Zeek #fields header with query",
        "label": "Upload Zeek dns.log",
        "types": ("log", "txt"),
        "help": "Expected Zeek dns.log text with a #fields header. query, ts, id.orig_h, qtype_name, and answers are used when available.",
    },
    "Pi-hole FTL database": {
        "caption": "Pi-hole FTL SQLite database · max 100 MB",
        "required": "queries view with standard Pi-hole fields",
        "label": "Upload Pi-hole FTL database",
        "types": ("db", "sqlite", "sqlite3"),
        "help": "Expected a Pi-hole FTL SQLite query database containing the standard queries view. The database is deserialized into memory; the upstream forward field is not treated as a DNS response IP.",
    },
    "AdGuard Home query log": {
        "caption": "AdGuard Home JSON query log · max 100 MB",
        "required": "query-log JSON with host and timestamp fields",
        "label": "Upload AdGuard Home query log",
        "types": ("json", "log", "txt"),
        "help": "Expected AdGuard Home query-log JSON. Both the on-disk querylog.json record shape and exported query-log API objects are accepted.",
    },
}


class UploadRejected(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class NoAnalysis(LookupError):
    """The id is not the current analysis (replaced, or the API restarted)."""


@dataclass
class _Analysis:
    id: str
    result: object
    diagnostics: object
    detection: object
    artifact: object
    format: str
    name: str
    extra: dict = field(default_factory=dict)


_CURRENT: dict[str, _Analysis] = {}
_LOCK = threading.Lock()


def current(analysis_id: str) -> _Analysis:
    with _LOCK:
        analysis = _CURRENT.get("last")
    if analysis is None or not secrets.compare_digest(analysis.id, analysis_id):
        raise NoAnalysis(analysis_id)
    return analysis


def _artifact(settings: ApiSettings):
    from .lookup import LookupUnavailable, _artifact as load

    try:
        return load(settings)
    except LookupUnavailable:
        raise UploadRejected(409, "The local ML artifact is not ready. Set up a trusted artifact to analyze telemetry.") from None


def status(settings: ApiSettings, language: Language) -> dict:
    """What the page shows before an upload (format choices, limits, notices)."""
    from ..cti_cache import load_ioc_records

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    notices = []
    try:
        artifact = _artifact(settings)
    except UploadRejected as error:
        return {"ready": False, "notices": [_block("warning", t(str(error)))]}
    if artifact is not None and getattr(artifact.metadata, "evaluation_status", None) == "demo_only_synthetic":
        notices.append(_block("warning", t("Demo ML artifact active. It uses synthetic training data only to exercise the interface and must not be interpreted as measured model performance.")))
    try:
        empty = not load_ioc_records(settings.cti_db_path) if settings.cti_db_path else True
    except Exception:  # noqa: BLE001 - unreadable cache behaves as empty, as in Streamlit
        empty = True
    if empty:
        notices.append(_block("warning", t(
            "CTI cache is empty. Results can include DNS behavior only; known-indicator matching and ML are unavailable."
            if settings.cti_only else
            "CTI cache is empty. Analysis can still use ML and DNS behavior, but known-threat matching will be unavailable. Run scripts/refresh_cti_cache.py to populate the cache.")))
    return {
        "ready": True,
        "notices": notices,
        "intake": t("Choose the format, upload a file, then analyze. Supported: delimited tables, Zeek DNS/connection logs, DNS packet captures, Suricata EVE, Pi-hole and AdGuard."),
        "format_label": t("Telemetry format"),
        "formats": [{"value": name, "label": t(name), "caption": t(spec["caption"]), "required": t(spec["required"]),
                     "upload": t(spec["label"]), "types": list(spec["types"]), "help": t(spec["help"])}
                    for name, spec in FORMATS.items()],
        "requirements_title": t("Input requirements"),
        "requirements_note": t("Optional fields enrich the evidence. Missing values are handled by the existing parser."),
        "privacy": t("Processed in memory. Raw DNS rows and client IPs are not saved. Reports and optional history contain aggregate findings only."),
        "analyze": t("Analyze"),
        "max_bytes": MAX_UPLOAD_BYTES,
        "too_large": t("Uploaded telemetry exceeds the 100 MB application limit."),
        "empty_title": t("Your findings will appear here"),
        "empty_text": t("Choose a source and upload a file to build your priority queue. Then select a domain to inspect the evidence."),
    }


def analyze(settings: ApiSettings, language: Language, telemetry_format: str, name: str, content: bytes) -> dict:
    """Run the same analyzer Streamlit runs for the chosen format; keep the result in memory."""
    from ..cti_cache import load_ioc_records
    from ..runtime_analysis import (
        analyze_adguard_query_log_with_diagnostics,
        analyze_dns_csv_with_diagnostics,
        analyze_dns_upload_with_diagnostics,
        analyze_pihole_query_db_with_diagnostics,
        analyze_zeek_dns_log_with_diagnostics,
    )

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    spec = FORMATS.get(telemetry_format)
    if spec is None:
        raise UploadRejected(422, t("Choose a telemetry format."))
    base = PurePath(name.replace("\\", "/")).name[:255]
    if not base or "." not in base or base.rsplit(".", 1)[1].lower() not in spec["types"]:
        raise UploadRejected(415, t("This file type is not accepted for the selected format."))
    if len(content) > MAX_UPLOAD_BYTES:
        raise UploadRejected(413, t("Uploaded telemetry exceeds the 100 MB application limit."))
    text = None
    if telemetry_format not in {"Auto-detect", "Pi-hole FTL database"}:
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise UploadRejected(422, t("Telemetry input must use UTF-8 encoding.")) from None
    artifact = _artifact(settings)
    indicators = load_ioc_records(settings.cti_db_path) if settings.cti_db_path else []
    try:
        if telemetry_format == "Auto-detect":
            result, diagnostics, detection = analyze_dns_upload_with_diagnostics(content, base, indicators, artifact)
        elif telemetry_format == "Pi-hole FTL database":
            result, diagnostics = analyze_pihole_query_db_with_diagnostics(content, indicators, artifact)
            detection = None
        else:
            analyzer = {"Generic DNS CSV": analyze_dns_csv_with_diagnostics,
                        "Zeek dns.log": analyze_zeek_dns_log_with_diagnostics,
                        "AdGuard Home query log": analyze_adguard_query_log_with_diagnostics}[telemetry_format]
            result, diagnostics = analyzer(text, indicators, artifact)
            detection = None
    except ValueError as error:
        raise UploadRejected(422, t("DNS telemetry could not be analyzed: {error}", error=t(str(error)))) from None
    from .history import capture_audit

    analysis = _Analysis(secrets.token_hex(16), result, diagnostics, detection, artifact, telemetry_format, base)
    if settings.history_enabled:
        analysis.extra["audit"] = capture_audit(settings, artifact)
    with _LOCK:
        _CURRENT["last"] = analysis  # replaces the previous result, like a new Streamlit upload
    return overview(analysis, language, settings)


def _translated_rows(rows: list[dict], language: Language) -> list[dict]:
    """Evidence labels one by one; comma-joined scopes part by part."""
    out = []
    for row in rows:
        row = dict(row)
        if row.get("Evidence"):
            row["Evidence"] = evidence(row["Evidence"], language)
        for key in ("Evidence scope", "Match scope", "Evidence scopes"):
            if isinstance(row.get(key), str) and row[key]:
                row[key] = ", ".join(translate(part.strip(), language) for part in row[key].split(","))
        out.append(row)
    return out


def overview(analysis: _Analysis, language: Language, settings: ApiSettings | None = None, *,
             include_suppressed: bool = False) -> dict:
    from ..dashboard import (
        assessment_rows,
        cluster_rows,
        ioc_corroboration_rows,
        match_rows,
        priority_assessment_rows,
        relationship_rows,
        summarize_runtime_result,
    )
    from ..campaign import find_related_activity

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    result, diagnostics, detection = analysis.result, analysis.diagnostics, analysis.detection
    quality = []
    if detection is not None:
        encoding = f" · {detection.encoding}" if detection.encoding else ""
        detail = detection.detail
        detail = t("worksheet: {sheet}", sheet=detail.split(": ", 1)[1]) if detail.startswith("worksheet: ") else t(detail)
        quality.append(t("Detected input: {format} · {detail}{encoding}", format=t(detection.format_name),
                         detail=detail, encoding=encoding))
    quality.append(t("Input quality: {accepted}/{total} rows accepted; {missing} missing query names; {timestamps} invalid timestamps; {ips} invalid response IPs.",
                     accepted=diagnostics.accepted_rows, total=diagnostics.total_rows,
                     missing=diagnostics.skipped_missing_query_name, timestamps=diagnostics.invalid_timestamps,
                     ips=diagnostics.invalid_response_ips))
    if diagnostics.packet_dns_queries or diagnostics.packet_response_only:
        quality.append(t("Packet DNS: {queries} query observations; {paired} paired replies; {orphan} response-only observations. Unpaired replies remain separate; queries without replies have no response code.",
                         queries=diagnostics.packet_dns_queries, paired=diagnostics.packet_paired_queries,
                         orphan=diagnostics.packet_response_only))

    from .history import policy

    history = settings is not None and settings.history_enabled
    if history and "audit" in analysis.extra and analysis.extra["audit"] is None:
        quality.append(t("Analysis completed, but reproducibility metadata could not be captured. Re-run the analysis before saving history."))
    _feedback, suppressions = policy(settings, [a.domain for a in result.assessments]) if history else ({}, {})
    summary = summarize_runtime_result(result)
    all_priority = priority_assessment_rows(result)
    suppressed = sum(row["Domain"] in suppressions for row in all_priority)
    priority = [{"domain": row["Domain"], "verdict": row["Verdict"], "verdict_label": t(row["Verdict"]),
                 "events": row.get("DNS events", 0),
                 "sources": str(row.get("Known CTI sources") or t("No cached CTI match")),
                 "evidence": evidence(row.get("Evidence"), language) if row.get("Evidence") else t("No strong signal summary")}
                for row in all_priority if include_suppressed or row["Domain"] not in suppressions]
    rows = assessment_rows(result)
    corroboration, matches = ioc_corroboration_rows(result), match_rows(result)
    try:
        related = find_related_activity(result)
        related_error = None
    except ValueError as error:
        related, related_error = None, str(error)
    if related_error is not None:
        related_block = {"notices": [_block("warning", t("Related-activity visualization was skipped because the candidate set was too large: {error}", error=related_error))]}
    elif related is not None and related.clusters:
        related_block = {
            "notices": [_block("info", t("These groups show possible related suspicious activity based on weighted local DNS and CTI context. High-fan-out shared infrastructure is down-weighted or filtered. The groups do not prove one malware campaign."))],
            "clusters_title": t("Possible related-activity groups"),
            "clusters": _table(_translated_rows(cluster_rows(related), language), language),
            "relationships_title": t("Relationship evidence and noise adjustments"),
            "relationships": _table(_translated_rows(relationship_rows(related), language), language),
            "relationships_caption": t("Raw client IP values are not shown. Strength is a local evidence score, not an attribution probability. Relationship rows expose aggregate counts and explainable noise adjustments only."),
        }
    else:
        related_block = {"notices": [_block("info", t("No possible related-activity groups were found among Known Threat, High Risk, or Review domains."))]}

    findings = _table(_translated_rows(rows, language), language)
    return {
        "id": analysis.id,
        "file": analysis.name,
        "input_quality_title": t("Input quality"),
        "input_quality": quality,
        "priority_title": t("Priority findings"),
        "priority_caption": t("Start with the highest-priority domains, then open Domain investigation for the evidence."),
        "priority": priority[:5],
        "priority_more": t("{count} additional priority finding(s) are available in Domain findings.", count=len(priority) - 5)
        if len(priority) > 5 else None,
        "priority_empty": t("All current priority findings are locally suppressed. Enable the checkbox above to include them.")
        if all_priority and suppressed and not priority else t("No Known Threat, High Risk, or Review findings."),
        "suppressed_label": t("Include {count} locally suppressed finding(s)", count=suppressed) if suppressed else None,
        "distribution_title": t("Verdict distribution"),
        "overview_title": t("Analysis overview"),
        "metrics": [
            {"label": t("DNS events"), "value": summary.event_count, "tone": None},
            {"label": t("Unique domains"), "value": summary.domain_count, "tone": None},
            {"label": t("Known Threat"), "value": summary.known_threat_count, "tone": "threat"},
            {"label": t("High Risk"), "value": summary.high_risk_count, "tone": "high"},
            {"label": t("Review"), "value": summary.review_count, "tone": "review"},
            {"label": t("Low"), "value": summary.low_count, "tone": "low"},
        ],
        "metrics_caption": t("Verdicts are assigned per unique domain; DNS events count individual telemetry rows."),
        "tabs": {"findings": t("Domain findings"), "devices": t("Device triage"), "connections": t("Connection activity"),
                 "investigation": t("Domain investigation"), "ioc": t("IOC evidence"), "related": t("Related activity"),
                 "export": t("Export & save")},
        "findings": {
            **findings,
            "verdicts": [row["Verdict"] for row in rows],
            "sources": [[part.strip() for part in str(row.get("Known CTI sources") or "").split(",") if part.strip()] for row in rows],
            "domains": [row["Domain"] for row in rows],
            "search_label": t("Search domains"), "search_placeholder": t("Domain or part of a hostname"),
            "verdict_label": t("Verdict"), "source_label": t("CTI source"), "all": t("All"),
            "verdict_options": [{"value": v, "label": t(v)} for v in ("Known Threat", "High Risk", "Review", "Low")],
            "empty_title": t("No domain findings"), "empty_text": t("This analysis did not produce any domain assessments."),
        },
        "ioc": {
            "corroboration_title": t("Source corroboration"),
            "corroboration_caption": t("Multiple cached CTI sources strengthen analyst context. Corroboration does not override evidence-scope rules."),
            "corroboration": _table(_translated_rows(corroboration, language), language) if corroboration else None,
            "matches_title": t("IOC evidence"),
            "matches": _table(_translated_rows(matches, language), language) if matches else None,
            "empty": t("No cached IOC matches were found."),
        },
        "related": related_block,
        "investigation": {"label": t("Inspect a domain"), "domains": [row["Domain"] for row in rows],
                          "empty_title": t("No domains to investigate"), "empty_text": t("Upload telemetry to begin.")},
        "export": {
            "include_ips_label": t("Include literal IP targets in aggregate exports"),
            "json": t("Download JSON report"), "csv": t("Download CSV findings"),
            "caption": t("Exports contain aggregate/per-domain findings only. Raw DNS rows, client IP values, and response IP values are not included."),
            "save": t("Save aggregate analysis history") if history else None,
        },
    }


def domain_detail(analysis: _Analysis, language: Language, domain: str, settings: ApiSettings | None = None) -> dict:
    """``ui_investigation._show_domain_detail``; the analyst policy only when history is enabled."""
    from ..dashboard import assessment_detail, domain_match_rows

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    assessment = next((item for item in analysis.result.assessments if item.domain == domain), None)
    if assessment is None:
        raise NoAnalysis(domain)
    detail = assessment_detail(assessment)
    evidence_rows = domain_match_rows(analysis.result, domain)

    def fmt(value, pattern):
        return pattern.format(value) if value is not None else "N/A"

    primary = None
    if evidence_rows:
        row = evidence_rows[0]
        primary = {
            "title": t("Primary CTI evidence"),
            "summary": f"{t(str(row['Evidence scope']))} · {row['Source']}" + (f" · {row['Threat type']}" if row["Threat type"] else ""),
            "metrics": [
                {"label": t("First seen"), "value": short_time(row["First seen"]) if row["First seen"] else t("Unknown")},
                {"label": t("Last seen"), "value": short_time(row["Last seen"]) if row["Last seen"] else t("Unknown")},
                {"label": t("Confidence"), "value": f"{row['Confidence']:.2f}" if row["Confidence"] is not None else t("Unknown")},
                {"label": t("Tags"), "value": row["Tags"] or t("None")},
            ],
            "all_title": t("Show all IOC evidence ({count})", count=len(evidence_rows)),
            "all": _table(_translated_rows(evidence_rows, language), language),
        }
    from .history import domain_policy

    codes = ", ".join(f"{code}:{count}" for code, count in detail["response_code_counts"])
    return {
        "policy": domain_policy(settings, detail["domain"], language) if settings is not None else None,
        "title": t("Domain investigation"),
        "domain": detail["domain"],
        "verdict": detail["verdict"],
        "verdict_label": t(str(detail["verdict"])),
        "why_title": t("Why this verdict?"),
        "why": [t(item) for item in detail["evidence"]],
        "why_empty": t("No strong CTI, ML-tier, or DNS-behavior signal was recorded."),
        "known_note": t("Known Threat is reserved for an exact known-domain IOC match. URL-hostname and response-IP matches are contextual CTI evidence and do not prove the queried domain is malicious.")
        if detail["verdict"] == "Known Threat" else None,
        "primary": primary,
        "no_evidence": t("No cached IOC evidence is associated with this domain."),
        "context_title": t("Detection context"),
        "context": [
            {"label": t("ML score"), "value": f"{detail['ml_score']:.4f}" if detail["ml_score"] is not None else t("Not scored")},
            {"label": t("ML tier"), "value": t(str(detail["ml_tier"]))},
            {"label": t("DNS events"), "value": detail["event_count"]},
            {"label": t("Unique clients"), "value": detail["client_count"]},
            {"label": t("Response IPs"), "value": detail["response_ip_count"]},
        ],
        "behavior_title": t("DNS behavior details"),
        "behavior": [
            t("Query types") + ": " + (", ".join(detail["query_types"]) or t("None")),
            t("Response codes") + f": {codes or t('None')}",
            t("NXDOMAIN ratio") + ": " + fmt(detail["nxdomain_ratio"], "{:.2f}"),
            t("Label count / subdomain depth") + ": " + f"{detail['label_count']} / {detail['subdomain_depth']}",
            t("Numeric ratio / entropy") + ": " + fmt(detail["numeric_character_ratio"], "{:.2f}") + " / " + fmt(detail["hostname_entropy"], "{:.2f}"),
            t("Response-IP churn rate") + ": " + fmt(detail["response_ip_churn_rate"], "{:.2f}"),
            t("Periodicity score / interval") + ": " + fmt(detail["periodicity_score"], "{:.2f}") + " / "
            + fmt(detail["periodic_interval_seconds"], "{:.1f}s"),
        ],
    }


def devices(analysis: _Analysis, language: Language, *, include_ips: bool, include_observe: bool, public_mode: bool) -> dict:
    """``ui_device_triage.render_device_triage``."""
    import json

    from ..dashboard import device_finding_rows
    from ..reporting import build_device_report

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    include_ips = include_ips and not public_mode
    rows = device_finding_rows(analysis.result.device_findings, include_client_ips=include_ips)
    visible = rows if include_observe else [row for row in rows if row["Queue priority"] != "Observe"]
    display = [dict(row) for row in visible[:MAX_ROWS]]
    for row in display:
        if str(row["Device"]).startswith("Device "):
            row["Device"] = t("Device {number}", number=str(row["Device"])[7:])
        row["Evidence"] = evidence(row.get("Evidence"), language)
        row["Coverage limits"] = _joined(row["Coverage limits"], language)
    report = json.loads(build_device_report(analysis.result, include_client_ips=include_ips))
    analysis.extra["device_timelines"] = report["timelines"]
    analysis.extra["device_rows"] = visible[:MAX_ROWS]
    shown = visible[:MAX_ROWS]
    has_groups = bool(shown) and all("Group" in row for row in shown)
    device_names = list(dict.fromkeys(row["Device"] for row in shown)) if has_groups else []
    return {
        "captions": [t("Client/domain observations are assessed separately. Queue priority is not proof of compromise."),
                     t("DNS shows queries, not confirmed connections or downloads. A client address may belong to a resolver or NAT.")],
        "include_ips_label": None if public_mode else t("Show observed client and IP target addresses in this view and device export"),
        "include_observe_label": t("Include observations without review priority"),
        **_table(display, language),
        "empty": t("No device observations currently require review."),
        "footer": t("Sustained periodic DNS enters Review after at least 20 distinct, fully timestamped observations over 30 minutes. Legitimate updates may also qualify."),
        "more": t("Showing the first 500 device groups. The device download contains all groups.") if len(visible) > MAX_ROWS else None,
        "investigation": None if not shown else {
            "title": t("Device DNS investigation"),
            "missing": None if has_groups else t("Restart the updated collector to generate DNS timelines."),
            "devices": [{"value": d, "label": t("Device {number}", number=str(d)[7:]) if str(d).startswith("Device ") else d}
                        for d in device_names],
            "domains": [{"group": row["Group"], "device": row["Device"], "target": str(row.get("Target", ""))}
                        for row in shown] if has_groups else [],
        },
        "download": t("Download device triage JSON"),
        "download_caption": t("Device aliases apply only to this report. Domains and timestamps remain sensitive telemetry; keep this export local."),
    }


def device_timeline(analysis: _Analysis, language: Language, group: int) -> dict:
    rows = analysis.extra.get("device_rows") or []
    row = next((row for row in rows if row.get("Group") == group), None)
    if row is None:
        raise NoAnalysis(group)
    return dns_timeline_payload(row, analysis.extra.get("device_timelines") or {}, language, analysis.id)


def set_expected(analysis: _Analysis, content: str | None) -> int:
    """The optional expected-connection JSON for this analysis (None clears it); invalid input applies nothing."""
    from ..expected_connections import MAX_RULE_BYTES, parse_expected_connections

    if content is None:
        analysis.extra.pop("expected_rules", None)
        return 0
    analysis.extra.pop("expected_rules", None)  # an invalid file applies nothing, as in Streamlit
    data = content.encode()
    if len(data) > MAX_RULE_BYTES:
        raise ValueError("Expected-connection file exceeds 64 KiB")
    rules = parse_expected_connections(data)
    analysis.extra["expected_rules"] = rules
    return len(rules)


def connections(analysis: _Analysis, language: Language, *, include_ips: bool, reviews_only: bool, public_mode: bool,
                include_expected: bool = False) -> dict:
    """``ui_connections.render_connections``, including the optional expected-connection declarations."""
    from datetime import datetime, timezone

    from ..collector_reports import review_counts
    from ..connection_attempts import attempt_report
    from ..connection_timeline import timeline_report
    from ..dashboard import contextual_connection_rows

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    result = analysis.result
    captions = [t("Connection timing, duration and byte counts are review context. They do not prove malware or downloads."),
                t("Direction means originator to responder. Hostnames and inbound/outbound direction are not inferred.")]
    if not result.connection_findings:
        return {"captions": captions, "missing": t("Upload a Zeek conn.log to inspect connection activity.")}
    include_ips = include_ips and not public_mode
    rules = () if public_mode else analysis.extra.get("expected_rules", ())
    rows = contextual_connection_rows(result, rules, include_ips=include_ips, evaluated_at=datetime.now(timezone.utc))
    show_expected = include_expected if rules else True
    visible = [row for row in rows if (not reviews_only or row["Queue priority"] == "Review" or row["CTI match"])
               and (show_expected or not row["Declared expected"] or row["CTI match"])]
    display = [dict(row) for row in visible[:MAX_ROWS]]
    for row in display:
        for key in ("Originator", "Responder"):
            if str(row[key]).startswith("Host "):
                row[key] = t("Host {number}", number=str(row[key])[5:])
        row["Evidence"] = evidence(row["Evidence"], language)
        for key in ("Coverage limits", "Analyst context", "Context reason"):
            row[key] = _joined(row[key], language)
    analysis.extra["connection_rows"] = visible[:MAX_ROWS]
    analysis.extra["connection_timelines"] = timeline_report(result.connection_timelines, len(rows))
    summary = review_counts(rows)
    return {
        "captions": captions,
        "include_ips_label": None if public_mode else t("Show connection endpoint IPs in this view and export"),
        "reviews_only_label": t("Show only connection reviews"),
        "expected": None if public_mode else {
            "caption": t("Expected activity is your declaration, not verified software identity. Exact endpoints, traffic limits and expiry are required; CTI conflicts stay visible."),
            "label": t("Optional expected-connection JSON (local session only)"),
            "invalid": t("Invalid expected-connection file. No declarations applied."),
            "rules": len(rules),
            "include_label": t("Include declared expected activity") if rules else None,
        },
        "summary": {"metrics": [{"label": t(label), "value": value} for label, value in summary.items()],
                    "captions": [t("Before filters: {count} retained TCP groups. CTI groups are included in the unexplained queue even without a behavior Review; counts overlap. DNS and attempt queues are separate.", count=len(rows)),
                                 t("Declarations change review context, not original priority. Reveal expected activity with the checkbox; exports retain all groups.")]},
        **_table(display, language),
        "empty": t("No unexplained connection reviews in this view." if rules else "No connection groups currently require review."),
        "more": t("Showing the first 500 groups. The download contains all retained groups.") if len(visible) > MAX_ROWS else None,
        "investigation_title": t("Connection investigation"),
        "select_label": t("Select a connection group"),
        "groups": [{"group": row["Group"], "label": f"{row['Group']}: {row['Originator'] if not str(row['Originator']).startswith('Host ') else t('Host {number}', number=str(row['Originator'])[5:])} → "
                    f"{row['Responder'] if not str(row['Responder']).startswith('Host ') else t('Host {number}', number=str(row['Responder'])[5:])}:{row.get('Responder port')} / {row.get('Protocol')}"}
                   for row in visible[:MAX_ROWS] if "Group" in row],
        "attempts": _attempts(attempt_report(result.connection_attempts, result.connection_findings, include_ips=include_ips), language),
        "download": t("Download connection review JSON"),
        "download_caption": t("Connection exports remain sensitive telemetry. Host aliases apply only to this report."),
    }


def connection_timeline(analysis: _Analysis, language: Language, group: int) -> dict:
    rows = analysis.extra.get("connection_rows") or []
    row = next((row for row in rows if row.get("Group") == group), None)
    if row is None:
        raise NoAnalysis(group)
    return connection_timeline_payload(row, analysis.extra.get("connection_timelines") or {}, language, analysis.id)


def download(analysis: _Analysis, kind: str, *, include_ips: bool, public_mode: bool) -> tuple[bytes, str, str]:
    """The same report bytes Streamlit offers for download."""
    from datetime import datetime, timezone

    from ..reporting import build_analysis_report, build_connection_report, build_device_report

    include_ips = include_ips and not public_mode
    if kind in {"json", "csv"}:
        report = build_analysis_report(
            analysis.result,
            model_name=analysis.artifact.metadata.model_name if analysis.artifact else "cti_only_ml_disabled",
            include_target_ips=include_ips)
        if kind == "json":
            return report.json_text.encode(), "threatfusion_analysis.json", "application/json"
        return report.csv_text.encode(), "threatfusion_findings.csv", "text/csv"
    if kind == "devices":
        import json

        report = json.loads(build_device_report(analysis.result, include_client_ips=include_ips))
        return json.dumps(report, indent=2).encode(), "threatfusion_device_triage.json", "application/json"
    if kind == "connections":
        rules = () if public_mode else analysis.extra.get("expected_rules", ())
        body = build_connection_report(analysis.result, include_ips=include_ips, expected_rules=rules,
                                       evaluated_at=datetime.now(timezone.utc))
        return body.encode() if isinstance(body, str) else body, "threatfusion_connections.json", "application/json"
    raise NoAnalysis(kind)

