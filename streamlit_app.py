from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.cti_cache import (
    list_cti_cache_status,
    load_ioc_records,
)
from threatfusion.dashboard import (
    assessment_detail,
    assessment_rows,
    cti_status_rows,
    history_rows,
    match_rows,
    persisted_assessment_rows,
    summarize_runtime_result,
)
from threatfusion.ml_artifact import load_trusted_ml_artifact
from threatfusion.persistence import (
    get_analysis_assessments,
    list_analysis_runs,
    save_runtime_analysis,
)
from threatfusion.runtime_analysis import analyze_dns_csv

DEFAULT_DB_PATH = Path("data/threatfusion.sqlite")
DEFAULT_MODEL_DIR = Path("data/models/development-001")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


@st.cache_resource
def _load_artifact(path_text: str):
    return load_trusted_ml_artifact(Path(path_text))


def _verdict_chart(summary) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "verdict": [
                "Known Threat",
                "High Risk",
                "Review",
                "Low",
            ],
            "count": [
                summary.known_threat_count,
                summary.high_risk_count,
                summary.review_count,
                summary.low_count,
            ],
        }
    )


def _show_system_status(db_path: Path, model_dir: Path) -> None:
    st.sidebar.header("System status")

    model_path = model_dir / "model.joblib"
    metadata_path = model_dir / "metadata.json"
    if model_path.exists() and metadata_path.exists():
        st.sidebar.success("ML model artifact available")
    else:
        st.sidebar.error("ML model artifact missing")

    statuses = list_cti_cache_status(db_path)
    if statuses:
        st.sidebar.success("CTI cache available")
        st.sidebar.dataframe(
            pd.DataFrame(cti_status_rows(statuses)),
            hide_index=True,
            width="stretch",
        )
    else:
        st.sidebar.warning("CTI cache is empty")


def _show_domain_detail(result, domain: str) -> None:
    assessment = next(
        item for item in result.assessments if item.domain == domain
    )
    detail = assessment_detail(assessment)

    st.markdown(f"#### Domain detail: {detail['domain']}")

    columns = st.columns(4)
    columns[0].metric("Verdict", detail["verdict"])
    ml_score = detail["ml_score"]
    columns[1].metric(
        "ML score",
        f"{ml_score:.4f}" if ml_score is not None else "N/A",
    )
    columns[2].metric("ML tier", detail["ml_tier"])
    columns[3].metric("DNS events", detail["event_count"])

    behavior_columns = st.columns(3)
    behavior_columns[0].metric("Unique clients", detail["client_count"])
    behavior_columns[1].metric(
        "Unique response IPs",
        detail["response_ip_count"],
    )
    behavior_columns[2].metric(
        "Query types",
        ", ".join(detail["query_types"]) or "None",
    )

    sources = detail["known_sources"]
    if sources:
        st.write("**Known CTI sources:** " + ", ".join(sources))
    else:
        st.write("**Known CTI sources:** No cached IOC match")

    evidence = detail["evidence"]
    st.write("**Why this verdict?**")
    if evidence:
        for item in evidence:
            st.markdown(f"- {item}")
    else:
        st.caption("No strong CTI, ML-tier, or DNS-behavior signal was recorded.")


def _show_analysis_result(result, artifact, db_path: Path) -> None:
    summary = summarize_runtime_result(result)

    st.subheader("Analysis summary")
    columns = st.columns(6)
    columns[0].metric("DNS events", summary.event_count)
    columns[1].metric("Unique domains", summary.domain_count)
    columns[2].metric("Known threat", summary.known_threat_count)
    columns[3].metric("High risk", summary.high_risk_count)
    columns[4].metric("Review", summary.review_count)
    columns[5].metric("Low", summary.low_count)

    st.caption(
        "Verdicts are assigned per unique domain; DNS events count individual "
        "telemetry rows."
    )

    chart_data = _verdict_chart(summary)
    figure = px.bar(
        chart_data,
        x="verdict",
        y="count",
        title="Domain verdict distribution",
        text_auto=True,
        labels={"verdict": "Verdict", "count": "Domains"},
    )
    st.plotly_chart(figure, width="stretch")

    findings_tab, matches_tab = st.tabs(
        ["Domain findings", "Known IOC evidence"]
    )

    with findings_tab:
        rows = assessment_rows(result)
        if rows:
            frame = pd.DataFrame(rows)
            frame["ML score"] = frame["ML score"].map(
                lambda value: (
                    f"{value:.4f}" if value is not None else ""
                )
            )
            st.dataframe(
                frame,
                hide_index=True,
                width="stretch",
            )

            selected_domain = st.selectbox(
                "Inspect a domain",
                [row["Domain"] for row in rows],
                key="live_domain_detail",
            )
            _show_domain_detail(result, selected_domain)
        else:
            st.info("No domain assessments were produced.")

        st.caption(
            "ML score is a model decision score, not a literal probability "
            "that a domain is malware."
        )

    with matches_tab:
        rows = match_rows(result)
        if rows:
            st.dataframe(
                pd.DataFrame(rows),
                hide_index=True,
                width="stretch",
            )
        else:
            st.info("No cached IOC matches were found.")

    if st.button("Save aggregate analysis history"):
        run_id = save_runtime_analysis(
            db_path,
            result,
            model_name=artifact.metadata.model_name,
        )
        st.success(
            f"Analysis #{run_id} saved. Raw DNS rows and client IPs were not stored."
        )


def _show_history(db_path: Path) -> None:
    st.subheader("Saved analysis history")
    summaries = list_analysis_runs(db_path)
    if not summaries:
        st.info("No saved analyses yet.")
        return

    st.dataframe(
        pd.DataFrame(history_rows(summaries)),
        hide_index=True,
        width="stretch",
    )

    selected_id = st.selectbox(
        "Inspect saved run",
        [summary.id for summary in summaries],
    )
    assessments = get_analysis_assessments(db_path, int(selected_id))
    rows = persisted_assessment_rows(assessments)
    if rows:
        frame = pd.DataFrame(rows)
        frame["ML score"] = frame["ML score"].map(
            lambda value: (
                f"{value:.4f}" if value is not None else ""
            )
        )
        st.dataframe(
            frame,
            hide_index=True,
            width="stretch",
        )


def main() -> None:
    st.set_page_config(
        page_title="ThreatFusion AI",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("ThreatFusion AI")
    st.write(
        "Multi-source cyber threat intelligence, malicious-domain ML, "
        "and DNS behavior analysis in one explainable workflow."
    )

    db_path = DEFAULT_DB_PATH
    model_dir = DEFAULT_MODEL_DIR
    _show_system_status(db_path, model_dir)

    analysis_tab, history_tab = st.tabs(
        ["Analyze DNS telemetry", "Analysis history"]
    )

    with analysis_tab:
        st.info(
            "Uploaded DNS data is processed in memory. Raw DNS rows and "
            "client IP values are not stored unless future functionality "
            "explicitly changes that policy."
        )

        try:
            artifact = _load_artifact(str(model_dir))
        except (OSError, TypeError, ValueError) as error:
            st.error(
                "The trusted local ML artifact could not be loaded. "
                "Run scripts/train_ml_artifact.py first."
            )
            st.caption(type(error).__name__)
            return

        indicators = load_ioc_records(db_path)
        if not indicators:
            st.warning(
                "CTI cache is empty. Analysis can still use ML and DNS "
                "behavior, but known-threat matching will be unavailable. "
                "Run scripts/refresh_cti_cache.py to populate the cache."
            )

        uploaded = st.file_uploader(
            "Upload DNS CSV",
            type=["csv"],
            help=(
                "Expected columns: timestamp, client_ip, query_name, "
                "query_type, response_ip. Only query_name is required."
            ),
        )

        if uploaded is not None:
            content_bytes = uploaded.getvalue()

            if len(content_bytes) > MAX_UPLOAD_BYTES:
                st.error("Uploaded CSV exceeds the 10 MB application limit.")
            else:
                try:
                    content = content_bytes.decode("utf-8-sig")
                except UnicodeDecodeError:
                    st.error("CSV must use UTF-8 encoding.")
                else:
                    if st.button("Analyze", type="primary"):
                        try:
                            result = analyze_dns_csv(
                                content,
                                indicators,
                                artifact,
                            )
                        except ValueError as error:
                            st.error(f"DNS CSV could not be analyzed: {error}")
                        else:
                            st.session_state["analysis_result"] = result

        result = st.session_state.get("analysis_result")
        if result is not None:
            _show_analysis_result(result, artifact, db_path)

    with history_tab:
        _show_history(db_path)


if __name__ == "__main__":
    main()
