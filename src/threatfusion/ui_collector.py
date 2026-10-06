"""Read the private atomic collector snapshot without accessing its raw DB."""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from .i18n import tr, translate_dataframe
from .ui_connection_timeline import render_timeline
from .connection_timeline import validate_timeline_report
from .connection_attempts import validate_attempt_report
from .ui_connection_attempts import render_attempts
from .dns_collection import validate_dns_snapshot
from .ui_collected_dns import render_collected_dns
from .collector_health import validate_collector_health
from .ui_review_guidance import render_review_summary
from .collector_reports import read_archive, validate_projection

MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


def read_snapshot(root: Path):
    info = root.lstat()
    if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("Snapshot requires a private directory")
    fd = os.open(root / "connections.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_size > MAX_SNAPSHOT_BYTES):
            raise ValueError("Snapshot requires a bounded private file")
        raw = file.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot is too large")
    try:
        payload = json.loads(raw)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("Invalid collector snapshot") from None
    if (not isinstance(payload, dict) or payload.get("schema_version") != 2
        or not isinstance(payload.get("privacy"), dict)
        or not isinstance(payload.get("collector"), dict)
        or payload.get("privacy", {}).get("endpoint_ips_included") is not False
        or not isinstance(payload.get("findings"), list) or len(payload["findings"]) > 100_000
        or payload.get("collector", {}).get("policy") not in ("closed-zeek-collector-v1", "closed-zeek-collector-v2")):
        raise ValueError("Unsupported collector snapshot")
    status = payload["collector"]
    if not isinstance(status.get("counts"), dict) or type(status.get("cti_indicators")) is not int:
        raise ValueError("Invalid collector status")
    if not isinstance(status.get("updated_at"), str):
        raise ValueError("Invalid collector timestamp")
    timestamp = datetime.fromisoformat(status["updated_at"])
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Collector snapshot requires aware time")
    for key in ("retained_records", "review_groups", "rejected_files"):
        value = status["counts"].get(key)
        if type(value) is not int or not 0 <= value <= 100_000:
            raise ValueError("Invalid collector counts")
    required = {"Originator", "Responder", "Queue priority", "CTI match", "Declared expected",
                "Evidence", "Coverage limits", "Analyst context", "Context reason"}
    if any(not isinstance(row, dict) or not required.issubset(row) for row in payload["findings"]):
        raise ValueError("Invalid collected findings")
    if "timelines" in payload:
        validate_timeline_report(payload["timelines"], payload["findings"])
    if "attempts" in payload:
        validate_attempt_report(payload["attempts"])
    if status["policy"] == "closed-zeek-collector-v2" and "dns" not in payload:
        raise ValueError("Missing collected DNS coverage")
    if "dns" in payload:
        validate_dns_snapshot(payload["dns"])
        for key in ("retained_total_records", "retained_dns_records", "analyzed_dns_events", "dns_review_groups", "dns_omitted_groups"):
            value = status["counts"].get(key)
            if type(value) is not int or not 0 <= value <= 100_000:
                raise ValueError("Invalid collected DNS counts")
        coverage = payload["dns"]["coverage"]
        if (status["counts"]["retained_total_records"] != status["counts"]["retained_records"] + coverage["retained_records"]
            or status["counts"]["retained_dns_records"] != coverage["retained_records"]
            or status["counts"]["analyzed_dns_events"] != coverage["analyzed_events"]
            or status["counts"]["dns_omitted_groups"] != payload["dns"]["omitted_findings"]
            or status["counts"]["dns_review_groups"] != sum(row["Queue priority"] != "Observe" for row in payload["dns"]["report"]["findings"])):
            raise ValueError("Inconsistent collected DNS counts")
    validate_collector_health(status)
    validate_projection(payload)
    return payload


@st.fragment(run_every="10s")
def render_collector(state_dir: Path | None, *, public_mode: bool):
    if public_mode:
        return
    st.caption(tr("Completed Zeek logs are collected automatically. This view refreshes every 10 seconds; active files wait for rotation."))
    if state_dir is None:
        st.info(tr("Configure a local collector to show automatically collected connections."))
        st.code("threatfusion-ai collect --input-dir /path/to/zeek/logs", language="shell")
        return
    try:
        payload = read_snapshot(state_dir)
    except FileNotFoundError:
        st.info(tr("No collector snapshot yet. Start the local collector."))
        return
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        st.error(tr("Collector snapshot could not be read. Check private permissions and supported schema."))
        return
    status = payload["collector"]
    counts = status["counts"]
    st.caption(tr("Collector snapshot: {time}", time=status["updated_at"]))
    if (datetime.now(timezone.utc) - datetime.fromisoformat(status["updated_at"])).total_seconds() > 60:
        st.warning(tr("This snapshot is older than one minute. Check whether the collector is still running."))
    columns = st.columns(4)
    columns[0].metric(tr("Retained connections"), counts["retained_records"])
    columns[1].metric(tr("Connection reviews"), counts["review_groups"])
    columns[2].metric(tr("Rejected files"), counts["rejected_files"])
    columns[3].metric(tr("Attempt review patterns"), counts.get("attempt_review_groups", 0))
    if status.get("capacity_coverage_loss"):
        st.warning(tr("The collector reached its record limit. Coverage is incomplete and expected-activity filtering is disabled temporarily."))
    if counts["rejected_files"]:
        st.warning(tr("Some logs were rejected. Check source format, completion and limits before trusting coverage."))
    if status.get("input_coverage_loss"):
        st.warning(tr("Input coverage is incomplete. Rejected, quarantined or pending records prevent expected-activity filtering."))
    if status.get("preparation", {}).get("bundles"):
        prepared = status["preparation"]
        st.caption(tr("Prepared source rows: {total}; eligible: {accepted}; quarantined DNS rows: {quarantined}; pending files: {pending}.",
                      total=prepared["source_rows"], accepted=prepared["accepted_rows"], quarantined=prepared["quarantined_rows"], pending=prepared["pending_files"]))
    if "scan" in status:
        scan = status["scan"]
        st.caption(tr("Last scan: {seconds} s; changed files checked: {checked}; candidates: {candidates}.",
                      seconds=scan["analysis_elapsed_seconds"], checked=scan["attempted_files"], candidates=scan["candidate_files"]))
        if scan["remaining_candidates"]:
            st.warning(tr("{count} candidate files await checking because the scan budget was reached. They may be open or unchanged; this is not a count of ready logs.", count=scan["remaining_candidates"]))
        labels = {"format_or_limits": "Format or safety limits", "access": "File access",
                  "archive": "Invalid archive", "encoding": "Text encoding"}
        details = [f"{tr(labels[name])}: {count}" for name, count in scan["rejections"].items() if count]
        if details:
            st.caption(tr("Rejected input types: {types}", types=", ".join(details)))
    if status.get("cti_reload_deferred"):
        st.warning(tr("The CTI cache was busy during this scan. Results use the previously loaded indicators; recent CTI changes appear on a later scan."))
    if not status["cti_indicators"]:
        st.info(tr("Collector CTI is empty or disabled. These are behavior observations only."))
    coverage = payload.get("connection_coverage")
    if coverage:
        st.warning(tr("Connection snapshot shows {shown} of {total} retained groups. Omitted: {omitted}; omitted reviews: {reviews}; omitted CTI groups: {cti}. The full gzip report retains every group.",
                      shown=coverage["snapshot_groups"], total=coverage["total_groups"], omitted=coverage["omitted_groups"],
                      reviews=coverage["omitted_review_groups"], cti=coverage["omitted_cti_groups"]))
    render_review_summary(payload["findings"], coverage)
    view = payload
    if st.checkbox(tr("Show observed endpoint IPs locally; downloads keep aliases"), value=False, key="collector_local_ips"):
        from .collector_identity import local_identity_view
        try:
            view = local_identity_view(state_dir, payload)
        except (OSError, ValueError, TypeError, KeyError):
            st.warning(tr("Private identity mapping is unavailable or changed. Restart the updated collector; aliases remain visible."))
    reviews = st.checkbox(tr("Show only connection reviews"), value=True, key="collector_reviews_only")
    expected = st.checkbox(tr("Include declared expected activity"), value=False, key="collector_show_expected")
    rows = [dict(row) for row in view["findings"] if (not reviews or row["Queue priority"] == "Review" or row["CTI match"])
            and (expected or not row["Declared expected"] or row["CTI match"])]
    display = [dict(row) for row in rows[:500]]
    for row in display:
        for key in ("Originator", "Responder"):
            if str(row[key]).startswith("Host "):
                row[key] = tr("Host {number}", number=str(row[key])[5:])
        for key in ("Evidence", "Coverage limits", "Analyst context", "Context reason"):
            row[key] = "; ".join(tr(value) for value in str(row[key]).split("; "))
    if rows:
        st.dataframe(translate_dataframe(pd.DataFrame(display)), hide_index=True, width="stretch")
    else:
        st.info(tr("No unexplained connection reviews in this view."))
    if len(rows) > 500:
        st.caption(tr("Showing the first 500 filtered snapshot groups. Use the full gzip report for all retained groups.") if coverage
                   else tr("Showing the first 500 groups. The download contains all retained groups."))
    revision = status.get("selection_revision", status["updated_at"])
    render_timeline(rows[:500], payload.get("timelines", {}), key="collector", revision=revision)
    render_attempts(view.get("attempts"))
    render_collected_dns(view.get("dns"), revision=revision)
    if coverage:
        reference = dict(payload["full_report"])
        failure_message = tr("Full report changed or is unavailable. Refresh this page and retry; no unverified archive is served.")
        def download_full():
            try:
                return read_archive(state_dir, reference)
            except (OSError, ValueError, TypeError):
                raise RuntimeError(failure_message) from None
        st.caption(tr("Full retained report generated at: {time}. Unchanged evidence reuses its verified archive.", time=reference["generated_at"]))
        st.download_button(tr("Download full retained connection JSON.gz"), data=download_full,
                           file_name="threatfusion_collected_connections.full.json.gz", mime="application/gzip",
                           key="collector_full_" + reference["sha256"], on_click="ignore")
    st.download_button(tr("Download visible connection snapshot JSON") if coverage else tr("Download collected connection JSON"),
                       data=json.dumps(payload, indent=2), file_name="threatfusion_collected_connections.snapshot.json" if coverage else "threatfusion_collected_connections.json",
                       mime="application/json")
    st.caption(tr("Collector history is bounded. Aliases are report-local and exports remain sensitive telemetry."))
