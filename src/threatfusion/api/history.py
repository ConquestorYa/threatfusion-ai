"""The "Analysis history" page and the history-only parts of Analyze telemetry as JSON.

Mirrors ``ui_history._show_history`` (saved runs, reproducibility metadata,
comparison with the previous run, findings with analyst feedback, single and
bulk review, deletion and retention) and, in Analyze telemetry, the
history-only analyst policy of ``streamlit_app``/``ui_investigation``
(previous analyst review, local suppressions, "Save aggregate analysis
history"). Everything reads and writes through ``persistence``; rows come
from ``dashboard``. Like Streamlit, nothing here exists unless
``AppConfig.history_enabled`` (a trusted model, not CTI-only, not public).
Only aggregate findings are stored; raw DNS rows and client IPs never are.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from .i18n import Language, short_time, translate
from .settings import ApiSettings

FEEDBACK_OPTIONS = {"Confirmed Threat": "confirmed_threat", "Benign": "benign", "Uncertain": "uncertain"}
REVIEW_FILTERS = ("All", "Unreviewed", "Reviewed", "Confirmed Threat", "Benign", "Uncertain")
COMPACT_COLUMNS = ("Domain", "Verdict", "ML score", "ML tier", "DNS events", "Known CTI sources", "Analyst feedback")
RUN_COLUMNS = ("Run ID", "Created at", "Domains", "Known Threat", "High Risk", "Review")

_WRITE_LOCK = threading.Lock()


class HistoryDisabled(LookupError):
    """History is off in this mode (CTI-only, public, or disabled by configuration)."""


class UnknownRun(LookupError):
    """The run does not exist (deleted, or never saved)."""


def _db(settings: ApiSettings):
    if not settings.history_enabled or settings.cti_db_path is None:
        raise HistoryDisabled()
    return settings.cti_db_path


def _table(rows: list[dict], language: Language) -> dict:
    from .details import _table as table

    return table(rows, language)


def _metadata(summary, language: Language) -> dict:
    from ..dashboard import format_timestamp

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    if summary.audit_captured_at is None:
        return {"legacy": t("This is a legacy saved run created before audit metadata was added.")}
    unknown = t("Unknown")
    thresholds = None
    if None not in (summary.high_threshold, summary.medium_threshold, summary.low_threshold):
        thresholds = (f"{t('Frozen thresholds')}: {t('High')} {summary.high_threshold:.6f} · "
                      f"{t('Medium')} {summary.medium_threshold:.6f} · {t('Low')} {summary.low_threshold:.6f}")
    sources = None
    if summary.cti_sources:
        sources = {"title": t("CTI snapshot context"), **_table([
            {"Source": item.source, "Refreshed at": format_timestamp(item.refreshed_at), "Records": item.record_count,
             "Status": item.freshness.title()} for item in summary.cti_sources], language)}
    return {
        "captured": f"{t('Audit captured')}: {short_time(summary.audit_captured_at)}",
        "artifact": f"{t('Artifact')}: {summary.model_name or unknown}",
        "checksum": summary.artifact_checksum or unknown,
        "schemas": t("Artifact SHA-256 checksum · artifact schema {artifact_schema} · audit schema {audit_schema}",
                     artifact_schema=summary.artifact_schema_version or unknown,
                     audit_schema=summary.audit_schema_version or unknown),
        "thresholds": thresholds,
        "sources": sources,
        "no_sources": None if sources else t("No CTI source refresh metadata was captured."),
    }


def _comparison(db, run_id: int, language: Language) -> dict:
    from ..persistence import compare_analysis_runs

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    comparison = compare_analysis_runs(db, run_id)
    caption = (t("No earlier saved analysis exists. Every domain in this run is new relative to saved history.")
               if comparison.previous_run_id is None else
               t("Comparing run #{run_id} with previous run #{previous_run_id}.", run_id=run_id,
                 previous_run_id=comparison.previous_run_id))
    return {
        "title": t("Compare with previous analysis"),
        "caption": caption,
        "metrics": [{"label": t("New domains"), "value": len(comparison.new_domains)},
                    {"label": t("No longer present"), "value": len(comparison.removed_domains)},
                    {"label": t("Verdict changes"), "value": len(comparison.verdict_changes)}],
        "new": {"title": t("New since previous analysis"), **_table([{"Domain": d} for d in comparison.new_domains], language)}
        if comparison.new_domains else None,
        "removed": {"title": t("No longer present"), **_table([{"Domain": d} for d in comparison.removed_domains], language)}
        if comparison.removed_domains else None,
        "changes": {"title": t("Verdict changes"), **_table([
            {"Domain": item.domain, "Previous verdict": item.previous_verdict, "Current verdict": item.current_verdict}
            for item in comparison.verdict_changes], language)} if comparison.verdict_changes else None,
    }


def history_response(settings: ApiSettings, language: Language, run_id: int | None = None) -> dict:
    from ..dashboard import feedback_label, history_rows, persisted_assessment_rows
    from ..persistence import get_analysis_assessments, get_analyst_feedback, list_analysis_runs

    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    try:
        db = _db(settings)
    except HistoryDisabled:
        return {"state": "disabled"}
    summaries = list_analysis_runs(db)
    head = {"subtitle": t("Revisit saved runs, compare changes and record analyst decisions.")}
    if not summaries:
        return {"state": "empty", **head, "title": t("No saved analyses yet"),
                "text": t("Analyze telemetry, then choose Save aggregate analysis history under Export & save. "
                          "Only aggregate findings are saved.")}
    all_rows = history_rows(summaries)
    selected = next((summary for summary in summaries if summary.id == run_id), summaries[0])
    assessments = get_analysis_assessments(db, selected.id)
    feedback = {item.domain: item for item in get_analyst_feedback(db, selected.id)}
    rows = persisted_assessment_rows(assessments)
    for row in rows:
        row["ML score"] = f"{row['ML score']:.4f}" if row["ML score"] is not None else ""
        item = feedback.get(row["Domain"])
        row["Analyst feedback"] = feedback_label(item.label if item else None)
        row["Analyst note"] = item.note or "" if item else ""
    compact = [{column: row[column] for column in COMPACT_COLUMNS} for row in rows]
    sources = sorted({source.strip() for row in rows for source in str(row["Known CTI sources"]).split(",")
                      if source.strip()})
    option = lambda value: {"value": value, "label": t(value)}  # noqa: E731
    return {
        "state": "ok",
        **head,
        "runs": _table([{column: row[column] for column in RUN_COLUMNS} for row in all_rows], language),
        "all_runs_title": t("All run statistics"),
        "all_runs": _table(all_rows, language),
        "run_label": t("Inspect saved run"),
        "run_ids": [summary.id for summary in summaries],
        "run": selected.id,
        "metadata_title": t("Reproducibility metadata"),
        "metadata": _metadata(selected, language),
        "comparison": _comparison(db, selected.id, language),
        "findings": {
            **_table(compact, language),
            "domains": [row["Domain"] for row in rows],
            "verdicts": [row["Verdict"] for row in rows],
            "feedback": [row["Analyst feedback"] for row in rows],
            "sources": [[s.strip() for s in str(row["Known CTI sources"]).split(",") if s.strip()] for row in rows],
            "verdict_label": t("Verdict"),
            "verdict_options": [option("All"), *(option(v) for v in sorted({row["Verdict"] for row in rows}))],
            "review_label": t("Review state"),
            "review_options": [option(value) for value in REVIEW_FILTERS],
            "source_label": t("CTI source"),
            "source_options": [option("All"), *({"value": s, "label": s} for s in sources)],
            "empty": t("No saved findings match the current triage filters."),
        },
        "review": {
            "title": t("Analyst review"),
            "caption": t("Feedback is local analyst context only. It does not change the original verdict, retrain "
                         "the model, or alter frozen evaluation."),
            "options": [option(label) for label in FEEDBACK_OPTIONS],
            "current": {domain: {"label": feedback_label(item.label), "note": item.note or ""}
                        for domain, item in feedback.items()},
            "bulk_title": t("Bulk review selected findings"),
            "bulk_domains_label": t("Findings to review"),
            "bulk_label": t("Bulk analyst label"),
            "bulk_note_label": t("Optional bulk analyst note"),
            "bulk_confirm": t("Apply this label only to the selected findings."),
            "bulk_button": t("Apply bulk review"),
            "domain_label": t("Finding to review"),
            "label": t("Analyst label"),
            "note_label": t("Optional analyst note"),
            "button": t("Save analyst feedback"),
            "saved": t("Analyst feedback saved. The original ThreatFusion verdict was not changed."),
            "bulk_saved": t("Saved analyst feedback for {count} selected findings. Detector verdicts were not changed.",
                            count="{count}"),
        },
        "retention": {
            "title": t("History retention and deletion"),
            "warning": t("These controls permanently delete local saved history. Detector logic and the current "
                         "in-memory analysis are unchanged."),
            "delete_confirm": t("I understand run #{run_id} will be permanently deleted.", run_id=selected.id),
            "delete_button": t("Delete saved run #{run_id}", run_id=selected.id),
            "deleted": t("Saved run #{run_id} was deleted.", run_id=selected.id),
            "keep_label": t("Retention: keep latest N saved runs"),
            "keep_default": min(max(len(summaries), 1), 25),
            "keep_confirm": t("I understand older saved runs beyond this limit will be permanently deleted."),
            "keep_button": t("Apply retention cleanup"),
            "kept_none": t("No saved runs were old enough to delete."),
        },
    }


def _run_exists(db, run_id: int) -> None:
    from ..persistence import list_analysis_runs

    if run_id not in {summary.id for summary in list_analysis_runs(db)}:
        raise UnknownRun(run_id)


def save_feedback(settings: ApiSettings, run_id: int, domain: str, label: str, note: str) -> None:
    from ..persistence import save_analyst_feedback

    db = _db(settings)
    _run_exists(db, run_id)
    with _WRITE_LOCK:
        save_analyst_feedback(db, run_id, domain, FEEDBACK_OPTIONS[label], note=note)


def save_bulk_feedback(settings: ApiSettings, run_id: int, domains: list[str], label: str, note: str) -> int:
    from ..persistence import save_bulk_analyst_feedback

    db = _db(settings)
    _run_exists(db, run_id)
    with _WRITE_LOCK:
        return len(save_bulk_analyst_feedback(db, run_id, domains, FEEDBACK_OPTIONS[label], note=note))


def delete_run(settings: ApiSettings, run_id: int) -> bool:
    from ..persistence import delete_analysis_run

    with _WRITE_LOCK:
        return delete_analysis_run(_db(settings), run_id)


def apply_retention(settings: ApiSettings, keep_latest: int, language: Language) -> str:
    from ..persistence import apply_history_retention

    with _WRITE_LOCK:
        deleted = apply_history_retention(_db(settings), keep_latest=keep_latest)
    if deleted:
        return translate("Deleted older saved runs: {runs}", language, runs=", ".join(f"#{item}" for item in deleted))
    return translate("No saved runs were old enough to delete.", language)


# ---- Analyze telemetry: history-only analyst policy and saving ----

def capture_audit(settings: ApiSettings, artifact):
    """``capture_analysis_audit_metadata`` at analysis time (None when history is off or it fails)."""
    from ..audit import capture_analysis_audit_metadata
    from ..cti_cache import list_cti_cache_status

    if not settings.history_enabled or artifact is None or settings.model_dir is None:
        return None
    try:
        return capture_analysis_audit_metadata(
            settings.model_dir, artifact, list_cti_cache_status(settings.cti_db_path),
            stale_after_by_source={source: timedelta(hours=hours) for source, hours in settings.cti_stale_hours_by_source})
    except OSError:
        return None


def policy(settings: ApiSettings, domains: list[str]) -> tuple[dict, dict]:
    """(latest analyst feedback, active suppressions) by domain; empty without history."""
    from ..persistence import get_active_analyst_suppressions, get_latest_analyst_feedback_for_domains

    if not settings.history_enabled or settings.cti_db_path is None:
        return {}, {}
    return (get_latest_analyst_feedback_for_domains(settings.cti_db_path, domains),
            get_active_analyst_suppressions(settings.cti_db_path, domains))


def domain_policy(settings: ApiSettings, domain: str, language: Language) -> dict | None:
    """``ui_investigation._show_domain_detail``: previous review, suppression and its controls."""
    from ..dashboard import feedback_label, format_timestamp

    if not settings.history_enabled or settings.cti_db_path is None:
        return None
    t = lambda text, **values: translate(text, language, **values)  # noqa: E731
    feedback, suppressions = policy(settings, [domain])
    prior, suppression = feedback.get(domain), suppressions.get(domain)
    return {
        "previous": (f"{t('Previous analyst review')}: {t(feedback_label(prior.label))} · "
                     f"{short_time(format_timestamp(prior.updated_at))}" + (f" · {prior.note}" if prior.note else ""))
        if prior else None,
        "suppressed": (f"{t('Locally suppressed from the priority queue')} · {suppression.reason} · "
                       + (short_time(format_timestamp(suppression.expires_at)) if suppression.expires_at
                          else t("No expiry"))) if suppression else None,
        "title": t("Local analyst policy"),
        "remove": t("Remove local suppression"),
        "suppress_title": t("Suppress from priority triage"),
        "reason_label": t("Suppression reason"),
        "expiry_label": t("Expiry in days (0 = no expiry)"),
        "save": t("Save local suppression"),
        "saved": t("Local suppression saved. Detector output was not changed."),
    }


def suppress(settings: ApiSettings, domain: str, reason: str, expiry_days: int) -> None:
    from ..persistence import save_analyst_suppression

    db = _db(settings)
    expires = datetime.now(timezone.utc) + timedelta(days=expiry_days) if expiry_days else None
    with _WRITE_LOCK:
        save_analyst_suppression(db, domain, reason, expires_at=expires)


def unsuppress(settings: ApiSettings, domain: str) -> None:
    from ..persistence import remove_analyst_suppression

    with _WRITE_LOCK:
        remove_analyst_suppression(_db(settings), domain)


def save_analysis(settings: ApiSettings, analysis, language: Language) -> str:
    """"Save aggregate analysis history": aggregate findings and reproducibility metadata only."""
    from ..persistence import save_runtime_analysis

    db = _db(settings)
    audit = analysis.extra.get("audit")
    if audit is None or analysis.artifact is None:
        raise ValueError(translate("Re-run the analysis before saving so model, threshold, and CTI audit metadata can "
                                   "be captured.", language))
    with _WRITE_LOCK:
        run_id = save_runtime_analysis(db, analysis.result, model_name=analysis.artifact.metadata.model_name,
                                       audit_metadata=audit)
    return translate("Analysis #{run_id} saved with reproducibility metadata. Raw DNS rows and client IPs were not "
                     "stored.", language, run_id=run_id)
