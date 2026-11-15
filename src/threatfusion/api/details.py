"""The collector "Details" tab and its timelines as JSON.

Mirrors ``ui_collector._render_details`` and the shared timeline, attempt and
DNS renderers block by block, in the same order and with the same wording.
Evidence, filters and validation come from the existing functions; this
module only turns each Streamlit element into a typed block for the browser.
The "Behavior score (ML)" column of the DNS table is not produced here: the
experimental model stays in Streamlit (DEC-102) and its scoring also trains.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..i18n import _COLUMN_TR, _TR, _VALUE_TR
from .i18n import Language, evidence, short_time, translate
from .settings import ApiSettings

MAX_ROWS = 500


class NotAvailable(LookupError):
    """No collector, no snapshot, or the requested group is not in it."""


def _host(value, language: Language) -> str:
    text = str(value)
    if text.startswith("Host "):
        return translate("Host {number}", language, number=text[5:])
    return text


def _device(value, language: Language) -> str:
    text = str(value)
    if text.startswith("Device "):
        return translate("Device {number}", language, number=text[7:])
    return text


def _joined(value, language: Language) -> str:
    return "; ".join(translate(part, language) for part in str(value).split("; "))


def _table(rows: list[dict], language: Language) -> dict:
    """``translate_dataframe``: translated column names and categorical values."""
    columns = list(dict.fromkeys(key for row in rows for key in row))

    def cell(value):
        if language == "tr" and isinstance(value, str):
            return _VALUE_TR.get(value, _TR.get(value, value))  # exact matches only; data stays as is
        return value

    return {
        # Column names: the table dictionary first, then the general one.
        "columns": [_COLUMN_TR.get(column, _TR.get(column, column)) if language == "tr" else column for column in columns],
        "rows": [[cell(row.get(column)) for column in columns] for row in rows],
    }


def _block(kind: str, text: str) -> dict:
    return {"kind": kind, "text": text}


def _read(settings: ApiSettings):
    from ..ui_collector import _local_view, read_snapshot

    if not settings.collector_available or settings.state_dir is None:
        raise NotAvailable("not_configured")
    payload = read_snapshot(settings.state_dir)
    return payload, _local_view(settings.state_dir, payload)


def _state(settings: ApiSettings):
    """(payload, local view) or a state dict for the same cases as the review list."""
    try:
        return _read(settings), None
    except NotAvailable:
        return None, {"state": "not_configured"}
    except FileNotFoundError:
        return None, {"state": "no_snapshot"}
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return None, {"state": "unreadable"}


def _connection_rows(view: dict, reviews_only: bool, include_expected: bool) -> list[dict]:
    return [dict(row) for row in view["findings"]
            if (not reviews_only or row["Queue priority"] == "Review" or row["CTI match"])
            and (include_expected or not row["Declared expected"] or row["CTI match"])]


def details_response(settings: ApiSettings, language: Language, *, local_ips: bool = True,
                     reviews_only: bool = True, include_expected: bool = False,
                     dns_observations: bool = False) -> dict:
    from ..collector_reports import review_counts
    from ..ui_collector import COLLECTOR_GUIDE

    loaded, state = _state(settings)
    if state:
        return state
    payload, local_view = loaded
    status, counts = payload["collector"], payload["collector"]["counts"]
    t = lambda text, **values: translate(text, language, **values)  # noqa: E731

    notices: list[dict] = []
    if status.get("capacity_coverage_loss"):
        notices.append(_block("warning", t("The collector reached its record limit. Coverage is incomplete and expected-activity filtering is disabled temporarily.")))
    if counts["rejected_files"]:
        notices.append(_block("warning", t("Some logs were rejected. Check source format, completion and limits before trusting coverage.")))
    if status.get("input_coverage_loss"):
        notices.append(_block("warning", t("Input coverage is incomplete. Rejected, quarantined or pending records prevent expected-activity filtering.")))
    if status.get("preparation", {}).get("bundles"):
        prepared = status["preparation"]
        notices.append(_block("caption", t("Prepared source rows: {total}; eligible: {accepted}; quarantined DNS rows: {quarantined}; pending files: {pending}.",
                                           total=prepared["source_rows"], accepted=prepared["accepted_rows"],
                                           quarantined=prepared["quarantined_rows"], pending=prepared["pending_files"])))
    if "scan" in status:
        scan = status["scan"]
        notices.append(_block("caption", t("Last scan: {seconds} s; changed files checked: {checked}; candidates: {candidates}.",
                                           seconds=f"{scan['analysis_elapsed_seconds']:.2f}", checked=scan["attempted_files"],
                                           candidates=scan["candidate_files"])))
        if scan["remaining_candidates"]:
            notices.append(_block("warning", t("{count} candidate files await checking because the scan budget was reached. They may be open or unchanged; this is not a count of ready logs.",
                                               count=scan["remaining_candidates"])))
        labels = {"format_or_limits": "Format or safety limits", "access": "File access",
                  "archive": "Invalid archive", "encoding": "Text encoding"}
        rejected = [f"{t(labels[name])}: {count}" for name, count in scan["rejections"].items() if count]
        if rejected:
            notices.append(_block("caption", t("Rejected input types: {types}", types=", ".join(rejected))))
    if status.get("cti_reload_deferred"):
        notices.append(_block("warning", t("The CTI cache was busy during this scan. Results use the previously loaded indicators; recent CTI changes appear on a later scan.")))
    if not status["cti_indicators"]:
        notices.append(_block("info", t("Collector CTI is empty or disabled. These are behavior observations only.")))
    coverage = payload.get("connection_coverage")
    if coverage:
        notices.append(_block("warning", t("Connection snapshot shows {shown} of {total} retained groups. Omitted: {omitted}; omitted reviews: {reviews}; omitted CTI groups: {cti}. The full gzip report retains every group.",
                                           shown=coverage["snapshot_groups"], total=coverage["total_groups"],
                                           omitted=coverage["omitted_groups"], reviews=coverage["omitted_review_groups"],
                                           cti=coverage["omitted_cti_groups"])))

    summary = coverage["review_counts"] if coverage else review_counts(payload["findings"])
    review_summary = {
        "metrics": [{"label": t(label), "value": value} for label, value in summary.items()],
        "captions": [
            t("Before filters: {count} retained TCP groups. CTI groups are included in the unexplained queue even without a behavior Review; counts overlap. DNS and attempt queues are separate.",
              count=coverage["total_groups"] if coverage else len(payload["findings"])),
            t("Full gzip report retains all retained groups; snapshot JSON contains the bounded view only.") if coverage
            else t("Declarations change review context, not original priority. Reveal expected activity with the checkbox; exports retain all groups."),
        ],
    }

    view, identity_warning = payload, None
    if local_ips:
        if local_view is not None:
            view = local_view
        else:
            identity_warning = t("Private identity mapping is unavailable or changed. Restart the updated collector; aliases remain visible.")
    rows = _connection_rows(view, reviews_only, include_expected)
    display = [dict(row) for row in rows[:MAX_ROWS]]
    for row in display:
        for key in ("Originator", "Responder"):
            row[key] = _host(row[key], language)
        row["Evidence"] = evidence(row["Evidence"], language)
        for key in ("Coverage limits", "Analyst context", "Context reason"):
            row[key] = _joined(row[key], language)
    if len(rows) > MAX_ROWS:
        more = (t("Showing the first 500 filtered snapshot groups. Use the full gzip report for all retained groups.") if coverage
                else t("Showing the first 500 groups. The download contains all retained groups."))
    else:
        more = None
    groups = [{"group": row["Group"],
               "label": f"{row['Group']}: {_host(row.get('Originator', ''), language)} → "
                        f"{_host(row.get('Responder', ''), language)}:{row.get('Responder port')} / {row.get('Protocol')}"}
              for row in rows[:MAX_ROWS] if "Group" in row]

    full = None
    if coverage:
        reference = payload["full_report"]
        full = {"generated_at": reference["generated_at"],
                "caption": t("Full retained report generated at: {time}. Unchanged evidence reuses its verified archive.",
                             time=short_time(reference["generated_at"])),
                "label": t("Download full retained connection JSON.gz")}

    return {
        "state": "ok",
        "revision": status.get("selection_revision", status["updated_at"]),
        "guide": t(COLLECTOR_GUIDE),
        "captions": [
            t("Completed Zeek logs are collected automatically. This view refreshes every 10 seconds; active files wait for rotation."),
            t("Collector snapshot: {time}", time=short_time(status["updated_at"])),
        ],
        "metrics": [
            {"label": t("Retained connections"), "value": counts["retained_records"]},
            {"label": t("Connection reviews"), "value": counts["review_groups"]},
            {"label": t("Rejected files"), "value": counts["rejected_files"]},
            {"label": t("Attempt review patterns"), "value": counts.get("attempt_review_groups", 0)},
        ],
        "notices": notices,
        "review_summary": review_summary,
        "identity_warning": identity_warning,
        "connections": {
            **_table(display, language),
            "total": len(rows),
            "more": more,
            "empty": t("No unexplained connection reviews in this view."),
            "groups": groups,
            "timeline_missing": None if groups or not rows else t("Restart the collector to generate connection timelines."),
        },
        "attempts": _attempts(view.get("attempts"), language),
        "dns": _dns(view.get("dns"), language, dns_observations),
        "downloads": {
            "full": full,
            "snapshot": {"label": t("Download visible connection snapshot JSON") if coverage else t("Download collected connection JSON"),
                         "file": "threatfusion_collected_connections.snapshot.json" if coverage
                         else "threatfusion_collected_connections.json"},
            "caption": t("Collector history is bounded. Aliases are report-local and exports remain sensitive telemetry."),
        },
    }


def _attempts(block, language: Language):
    """``ui_connection_attempts.render_attempts``."""
    if not block or not (block.get("eligible_records") or block.get("excluded_tcp_records")):
        return None
    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    notices = [
        _block("caption", t("These patterns can come from inventory scans, blocked services or outages. Review observed behavior before deciding its cause.")),
        _block("caption", t("Sliding window: 5 minutes; at least 20 failed ports/hosts, or 30 repeated failures with at least 90% failures. Expected declarations do not hide this queue.")),
    ]
    if block["excluded_tcp_records"]:
        notices.append(_block("warning", t("{count} TCP records lack comparable evidence. Retry ratios require complete source-window coverage; observed port/host diversity can still appear with coverage limits.",
                                           count=block["excluded_tcp_records"])))
    if block["omitted_findings"]:
        notices.append(_block("warning", t("{count} additional attempt reviews exceed the 500-finding limit.",
                                           count=block["omitted_findings"])))
    rows = [dict(row) for row in block["findings"]]
    for row in rows:
        for field in ("Originator", "Responder"):
            value = str(row[field])
            row[field] = _host(value, language) if value.startswith("Host ") else t(value)
        row["Pattern"] = t(row["Pattern"])
    return {"title": t("TCP attempt reviews"), "notices": notices, **_table(rows, language),
            "empty": t("No TCP attempt pattern crossed these review gates. Check capture coverage before interpreting this result.")}


def _dns(block, language: Language, observations: bool):
    """``ui_collected_dns.render_collected_dns`` without the experimental ML column."""
    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    if block is None:
        return {"title": t("Collected DNS observations"), "missing": t("Restart the updated collector to include DNS logs.")}
    coverage = block["coverage"]
    if not coverage["retained_records"]:
        return {"title": t("Collected DNS observations"),
                "empty_window": t("No completed DNS records in the retained window. This does not prove absence of DNS traffic.")}
    # Streamlit shows the legacy warning above the metrics and the rest below the captions.
    before, notices = [], []
    if coverage.get("legacy_first_answer_events"):
        before.append(_block("warning", t("{count} retained DNS events were parsed by an older collector; additional answer IPs cannot be recovered without the original logs.",
                                           count=coverage["legacy_first_answer_events"])))
    captions = [
        t("DNS shows queries, not confirmed connections or downloads. A client address may belong to a resolver or NAT."),
        t("DNS device aliases and connection host aliases are independent within this snapshot."),
    ]
    if coverage["conflicting_transactions"]:
        notices.append(_block("warning", t("Conflicting DNS transaction records were excluded. Check source integrity before trusting coverage.")))
    if block["omitted_findings"]:
        notices.append(_block("warning", t("DNS snapshot contains at most 1,000 prioritized groups. Omitted groups: {count}.",
                                           count=block["omitted_findings"])))
    rows = [dict(row) for row in block["report"]["findings"] if observations or row["Queue priority"] != "Observe"]
    display = [dict(row) for row in rows[:MAX_ROWS]]
    for row in display:
        row["Device"] = _device(row["Device"], language)
        row["Evidence"] = evidence(row["Evidence"], language)
        row["Coverage limits"] = _joined(row["Coverage limits"], language)
    shown = rows[:MAX_ROWS]
    timelines = block["report"].get("timelines")
    has_groups = bool(shown) and all("Group" in row for row in shown)
    devices = list(dict.fromkeys(row["Device"] for row in shown)) if has_groups else []
    return {
        "title": t("Collected DNS observations"),
        "metrics": [
            {"label": t("Analyzed DNS transactions"), "value": coverage["analyzed_events"]},
            {"label": t("DNS transport: UDP / TCP"), "value": f"{coverage['transports']['udp']} / {coverage['transports']['tcp']}"},
            {"label": t("Excluded DNS records"), "value": coverage["excluded_records"]},
        ],
        "captions": captions,
        "notices_before": before,
        "notices": notices,
        "observations_label": t("Include observations without review priority"),
        **_table(display, language),
        "total": len(rows),
        "empty": t("No device observations currently require review."),
        "more": t("Showing the first 500 DNS groups. Download includes all snapshot groups, subject to the 1,000-group cap.")
        if len(rows) > MAX_ROWS else None,
        "investigation": None if not shown else {
            "title": t("Device DNS investigation"),
            "missing": None if (timelines and has_groups) else t("Restart the updated collector to generate DNS timelines."),
            "devices": [{"value": device, "label": _device(device, language)} for device in devices],
            "domains": [{"group": row["Group"], "device": row["Device"], "target": str(row.get("Target", ""))}
                        for row in shown] if has_groups else [],
        },
        "footer": t("Sustained periodic DNS enters Review after at least 20 distinct, fully timestamped observations over 30 minutes. Legitimate updates may also qualify."),
    }


def _guidance_connection(row, language: Language) -> list[dict]:
    """``ui_review_guidance.render_connection_guidance``."""
    from ..ui_review_guidance import connection_steps

    if "Queue priority" not in row:
        return []
    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    blocks = [_block("heading", t("Review guidance")),
              _block("caption", t("Original queue priority: {priority}", priority=t(str(row["Queue priority"]))))]
    evidence_text = evidence(row.get("Evidence", ""), language) if row.get("Evidence") else ""
    if evidence_text:
        blocks.append(_block("text", t("Observed evidence: {evidence}", evidence=evidence_text)))
    else:
        blocks.append(_block("caption", t("No TCP behavior review gate crossed. Check CTI and coverage separately.")))
    if row.get("CTI match") is True:
        blocks.append(_block("warning", t("Destination CTI evidence takes precedence over expected activity. Review this group.")))
    elif row.get("Declared expected") is True:
        blocks.append(_block("info", t("Declared expected activity; software identity is unverified and the original finding is retained.")))
    if row.get("Coverage limits"):
        blocks.append(_block("caption", t("Evidence limits: {limits}", limits=_joined(row["Coverage limits"], language))))
    blocks += [_block("text", t(step)) for step in connection_steps(row)]
    return blocks


def connection_timeline(settings: ApiSettings, language: Language, group: int, *, local_ips: bool = True) -> dict:
    """``ui_connection_timeline.render_timeline`` for one selected group."""
    payload, local_view = _read(settings)
    view = local_view if local_ips and local_view is not None else payload
    row = next((row for row in view["findings"] if row.get("Group") == group), None)
    if row is None:
        raise NotAvailable(group)
    revision = payload["collector"].get("selection_revision", payload["collector"]["updated_at"])
    return connection_timeline_payload(row, payload.get("timelines", {}), language, revision)


def connection_timeline_payload(row: dict, timelines: dict, language: Language, revision: str) -> dict:
    """Guidance, chart and bucket table for one connection group (shared with uploads)."""
    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    group = row["Group"]
    result = {"revision": revision, "group": group, "guidance": _guidance_connection(row, language), "notices": []}
    timeline = next((item for item in timelines.get("groups", []) if item["group"] == group), None)
    if timeline is None:
        result["notices"].append(_block("info", t("No timeline for this group. Timelines cover the first 200 groups, with Review groups first; the full findings remain available.")))
        return result
    result["notices"] += [
        _block("caption", t("UTC buckets: {seconds} seconds. Counts, bytes and states are assigned to connection start time, not transfer time.", seconds=timeline["bucket_seconds"])),
        _block("caption", t("A zero bucket means no retained connection starts, not proof that the network was idle. States describe Zeek observations, not malware verdicts.")),
    ]
    if timeline["untimed_connections"]:
        result["notices"].append(_block("warning", t("{count} connections have missing or ambiguous time and are excluded from the chart.", count=timeline["untimed_connections"])))
    buckets = timeline["buckets"]
    if not buckets:
        result["notices"].append(_block("info", t("No comparable timestamps for this connection group.")))
        return result
    result["chart"] = {"kind": "line", "x_title": t("UTC bucket start"), "y_title": t("Connection starts"),
                       "points": [{"t": b["start_utc"], "v": b["connections"]} for b in buckets]}
    result["table"] = _table([{"UTC bucket start": b["start_utc"], "Connection starts": b["connections"],
                               "Known originator bytes": b["originator_bytes"],
                               "Unknown originator byte counts": b["originator_bytes_unknown"],
                               "Known responder bytes": b["responder_bytes"],
                               "Unknown responder byte counts": b["responder_bytes_unknown"],
                               "Zeek states": "; ".join(f"{state}: {count}" for state, count in b["states"].items())}
                              for b in buckets], language)
    result["footer"] = t("Known bytes are partial sums when byte counts are missing. Duplicate and conflicting UIDs are excluded as in the connection findings.")
    return result


def dns_timeline(settings: ApiSettings, language: Language, group: int, *, local_ips: bool = True) -> dict:
    """``ui_dns_timeline.render_dns_timeline`` for one selected device/domain group."""
    payload, local_view = _read(settings)
    view = local_view if local_ips and local_view is not None else payload
    block = view.get("dns") or {}
    row = next((row for row in block.get("report", {}).get("findings", []) if row.get("Group") == group), None)
    if row is None:
        raise NotAvailable(group)
    revision = payload["collector"].get("selection_revision", payload["collector"]["updated_at"])
    return dns_timeline_payload(row, block.get("report", {}).get("timelines") or {}, language, revision)


def dns_timeline_payload(row: dict, payload_timelines: dict, language: Language, revision: str) -> dict:
    """Guidance, chart and bucket table for one device/domain group (shared with uploads)."""
    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    group = row["Group"]
    guidance = [_block("caption", t("Selected query evidence: {evidence}", evidence=evidence(row["Evidence"], language))),
                _block("heading", t("Review guidance")),
                _block("caption", t("Original queue priority: {priority}", priority=t(str(row["Queue priority"])))),
                _block("text", t("Confirm whether the observed address is an endpoint, shared resolver or NAT using network inventory and resolver logs. Do not attribute a shared resolver's queries to individual machines."))]
    if row.get("Known CTI sources"):
        guidance.append(_block("text", t("Check the indicator source and freshness in CTI evidence, then correlate the query time with local connection or endpoint logs.")))
    else:
        guidance.append(_block("text", t("Check distinct query times, observed span and response codes. Updates and retries can resemble periodic activity; cached DNS can hide repeated connections.")))
    if row.get("Coverage limits"):
        guidance.append(_block("caption", t("Evidence limits: {limits}", limits=_joined(row["Coverage limits"], language))))
    guidance.append(_block("caption", t("A DNS query does not prove a connection, download or execution. Device and connection aliases cannot be joined by their numbers.")))
    result = {"revision": revision, "group": group, "guidance": guidance, "notices": []}
    item = next((item for item in payload_timelines.get("groups", []) if item["group"] == group), None)
    if item is None:
        result["notices"].append(_block("info", t("No DNS timeline for this group. At most 200 eligible client/domain groups are charted; unknown clients and IP fallback targets are excluded.")))
        return result
    result["notices"] += [
        _block("caption", t("UTC query buckets: {seconds} seconds. Queries do not prove connections, downloads or execution.", seconds=item["bucket_seconds"])),
        _block("caption", t("Zero buckets mean no retained query records, not proof that DNS traffic was absent.")),
    ]
    if item["untimed_queries"]:
        result["notices"].append(_block("warning", t("{count} queries have missing or ambiguous time and are excluded from the chart.", count=item["untimed_queries"])))
    buckets = item["buckets"]
    if not buckets:
        result["notices"].append(_block("info", t("No comparable query timestamps for this group.")))
        return result
    result["chart"] = {"kind": "bar", "x_title": t("UTC bucket start"), "y_title": t("DNS queries"),
                       "points": [{"t": b["start_utc"], "v": b["queries"]} for b in buckets]}
    result["table"] = _table([{"UTC bucket start": b["start_utc"], "DNS queries": b["queries"],
                               "DNS response categories": "; ".join(f"{name}: {count}" for name, count in b["responses"].items())}
                              for b in buckets], language)
    return result


def snapshot_download(settings: ApiSettings) -> tuple[bytes, str]:
    """Same bytes as Streamlit's snapshot download (aliases; the payload, not the local view)."""
    payload, _ = _read(settings)
    name = ("threatfusion_collected_connections.snapshot.json" if payload.get("connection_coverage")
            else "threatfusion_collected_connections.json")
    return json.dumps(payload, indent=2).encode(), name


def full_download(settings: ApiSettings) -> bytes:
    """The verified full gzip report; only when the snapshot is bounded."""
    from ..collector_reports import read_archive

    payload, _ = _read(settings)
    if not payload.get("connection_coverage"):
        raise NotAvailable("full report")
    return read_archive(Path(settings.state_dir), dict(payload["full_report"]))
