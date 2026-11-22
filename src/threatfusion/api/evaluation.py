"""The "Model evaluation" page as JSON.

Same visibility and content rule as ``streamlit_app``: the page exists unless
the app runs in CTI-only mode without the on-device behavior model. In
CTI-only mode with a local behavior model it shows that model's report
(``ui_behavior.render_behavior_evaluation``); otherwise the frozen lexical
holdout report (``ui_evaluation._show_model_evaluation``). Values come from
the model file, ``ml_evaluation_report.read_frozen_holdout_report`` and the
``evaluation_dashboard`` row builders; nothing is trained or scored here.
"""
from __future__ import annotations

from pathlib import Path

from .. import i18n
from .lookup import in_language
from .settings import ApiSettings

HOLDOUT_COMMAND = ("python scripts/evaluate_ml_final_holdout.py --artifact-dir data/models/lexical "
                   "--development-snapshot-dir data/snapshots/development "
                   "--holdout-snapshot-dir data/snapshots/holdout --json-output data/evaluation/final_holdout.json")


def _install_dir(settings: ApiSettings) -> Path | None:
    return Path(settings.local_root) if settings.local_root is not None else None


def available(settings: ApiSettings) -> bool:
    """``streamlit_app.main``: hidden in CTI-only mode unless the local behavior model exists."""
    from ..ui_behavior import model_path

    if not settings.cti_only:
        return True
    root = _install_dir(settings)
    return root is not None and model_path(root).exists()


def _table(rows: list[dict], language: str) -> dict:
    from .details import _table as table

    return table(rows, language)


def _behavior(root: Path, language: str) -> dict:
    """``ui_behavior.render_behavior_evaluation``."""
    from ..ui_behavior import (
        FEATURE_NAMES,
        FEATURE_NAMES_TR,
        LIMITS,
        TESTS,
        _guide,
        _load_model,
        _percent,
        model_path,
    )
    from .behavior import model_caption

    tr = i18n.tr
    path = model_path(root)
    try:
        model = _load_model(str(path), path.stat().st_mtime)
    except (OSError, ValueError, KeyError, TypeError):
        return {"kind": "behavior", "state": "unreadable", "warning": tr("The behavior model could not be read.")}
    report = model.evaluation
    test, dev = report.get("eval", {}), report.get("dev", {})
    checks, tests = report.get("checks", {}), report.get("tests", {})
    verdict = None
    if checks:
        verdict = ({"kind": "success", "text": tr("Passed its declared test: at least half of never-seen malware "
                                                  "recordings caught, at most one false flag per computer per day.")}
                   if report.get("pass") else
                   {"kind": "warning", "text": tr("Did not pass every declared test; treat its hints with extra care.")})
    declared = None
    if tests and checks:
        # declared_test_rows without its emoji: the page shows Yes/No.
        declared = {"title": tr("Declared tests (fixed before the results were seen)"),
                    **_table([{"Test": tr(title), "Result": result(tests), "Limit": limit,
                               "Passed": bool(checks.get(key))}
                              for key, title, result, limit in TESTS if key in checks], language)}
    data = [{"Data": title, "Malware recordings": values.get("malware_captures"),
             "Caught": _percent(values.get("malware_capture_recall")),
             "Normal computer-days": values.get("normal_unit_days"),
             "False flags per day": values.get("normal_flagged_per_unit_day")}
            for title, values in ((tr("Never-seen test recordings"), test), (tr("Development recordings"), dev)) if values]
    names = FEATURE_NAMES_TR if language == "tr" else FEATURE_NAMES
    importance = report.get("importance") or []
    return {
        "kind": "behavior",
        "state": "ok",
        "title": tr("Experimental behavior model"),
        "caption": model_caption(model),
        "metrics": [
            {"label": tr("Caught in testing"), "value": _percent(test.get("malware_capture_recall"))},
            {"label": tr("Malicious connections caught"), "value": _percent(test.get("malware_group_recall"))},
            {"label": tr("False flags per day (test)"), "value": test.get("normal_flagged_per_unit_day", "–")},
            {"label": tr("Score line"), "value": round(model.threshold * 100)},
        ],
        "verdict": verdict,
        "declared": declared,
        "data": _table(data, language),
        "importance": {"title": tr("What the model looks at most"),
                       "bars": [{"label": names.get(feature, feature), "value": value}
                                for feature, value in importance[:10]],
                       **_table([{"Feature": names.get(feature, feature), "Importance": value}
                                 for feature, value in importance[:10]], language)} if importance else None,
        "limits_title": tr("Limits"),
        "limits": tr(LIMITS),
        "guide_title": tr("What is this?"),
        "guide": _guide(),
    }


def _percent(value) -> str:
    return f"{value:.2%}"


def _lexical(report_path: Path | None, language: str) -> dict:
    """``ui_evaluation._show_model_evaluation``."""
    from ..evaluation_dashboard import operating_point_rows, source_metric_rows, summarize_holdout_report
    from ..ml_evaluation_report import read_frozen_holdout_report
    from ..ui_evaluation import EVALUATION_GUIDE

    tr = i18n.tr
    base = {"kind": "lexical", "guide_title": tr("What does this page do?"), "guide": tr(EVALUATION_GUIDE)}
    if report_path is None or not Path(report_path).is_file():
        return base | {"state": "not_evaluated", "guide_open": True,
                       "title": tr("Final holdout not evaluated"),
                       "text": tr("The frozen development model has not yet been measured on the separately "
                                  "collected fresh disjoint holdout."),
                       "caption": tr("Until that report exists, ThreatFusion intentionally keeps the model in "
                                     "development status."),
                       "command_title": tr("Show final-evaluation command"), "command": HOLDOUT_COMMAND}
    try:
        report = read_frozen_holdout_report(Path(report_path))
    except (OSError, TypeError, ValueError) as error:
        return base | {"state": "unreadable", "guide_open": False,
                       "error": tr("The final holdout report could not be loaded."), "caption": type(error).__name__}
    summary = summarize_holdout_report(report)
    rows = operating_point_rows(report)
    shown = [{**row, **{column: _percent(row[column]) for column in ("Precision", "Recall", "F1", "False-positive rate")},
              "Threshold": f"{row['Threshold']:.6f}", "Operating point": row["Operating point"]} for row in rows]
    sources = []
    for row in source_metric_rows(report):
        sources.append({**row, **{column: "n/a" if row[column] is None else _percent(row[column])
                                  for column in ("High recall", "High FPR", "Medium recall", "Medium FPR",
                                                 "Low recall", "Low FPR")}})
    protocol = (
        [tr("Protocol: fresh-collection disjoint holdout. Development domains are excluded, but malicious IOC "
            "first_seen is not filtered. This report does not establish strict temporal separation.")]
        if report.malicious_first_seen_after is None else
        [tr("Protocol: fresh-collection disjoint holdout with malicious first_seen filtering. Development domains "
            "and records without usable timing are excluded. The cutoff must match the artifact freeze to support a "
            "post-freeze claim; campaign/source-family leakage can remain."),
         f"{tr('Malicious first_seen cutoff')}: {report.malicious_first_seen_after}",
         f"{tr('Missing timing removed')}: {report.malicious_missing_first_seen_removed:,} · "
         f"{tr('At or before cutoff removed')}: {report.malicious_not_after_cutoff_removed:,}"])
    return base | {
        "state": "ok",
        "guide_open": False,
        "loaded": tr("Frozen-model holdout report loaded. No retraining or threshold tuning was performed on this holdout."),
        "model": f"{tr('Model')}: {summary.model_name}",
        "artifact": f"{tr('Evaluated artifact SHA-256')}: {report.artifact_sha256}" if report.artifact_sha256
        else tr("Legacy report: evaluated artifact identity is unavailable."),
        "scope": tr("This report describes the evaluated artifact. Loading it does not promote that artifact or "
                    "establish the runtime model's performance."),
        "dates": f"{tr('Snapshot dates')}: {tr('development')} {summary.development_snapshot_date} → "
                 f"{tr('holdout')} {summary.holdout_snapshot_date}",
        "metrics": [{"label": tr(label), "value": value} for label, value in (
            ("Input samples", summary.input_count), ("Overlap removed", summary.overlap_removed),
            ("Retained", summary.retained_count), ("Malicious", summary.malicious_count),
            ("Benign", summary.benign_count))],
        "operating_title": tr("Frozen operating points"),
        "operating": _table(shown, language),
        "chart": {"title": tr("Final holdout recall vs false-positive rate"),
                  "series": [tr("Recall"), tr("False-positive rate")],
                  "groups": [{"label": tr(row["Operating point"]),
                              "values": [row["Recall"], row["False-positive rate"]]} for row in rows]},
        "sources": {"title": tr("Source-aware holdout diagnostics"), **_table(sources, language),
                    "caption": tr("Recall is shown for malicious samples and false-positive rate for benign samples. "
                                  "A source with no samples for one class shows n/a for that class-specific rate.")}
        if sources else None,
        "ppv": tr("Dataset precision is not the same as operational positive predictive value (PPV). Real DNS traffic "
                  "may contain a much lower malicious base rate, so even a small false-positive rate can produce many "
                  "benign alerts."),
        "protocol": protocol,
    }


def evaluation_response(settings: ApiSettings, language: str) -> dict:
    if not available(settings):
        return {"state": "hidden"}
    with in_language(language):
        root = _install_dir(settings)
        report = (_behavior(root, language) if settings.cti_only and root is not None
                  else _lexical(settings.evaluation_report_path, language))
        return {"state": "ok", "subtitle": i18n.tr("Inspect the frozen model's measured performance and its limits."),
                "report": report}
