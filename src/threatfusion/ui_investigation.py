"""Evidence-first investigation; detector and analyst policy calls are unchanged."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from .dashboard import (
    assessment_detail,
    domain_match_rows,
    feedback_label,
    format_timestamp,
)
from .persistence import (
    AnalystFeedback,
    AnalystSuppression,
    remove_analyst_suppression,
    save_analyst_suppression,
)
from .ui_theme import metric_card, safe_text, section_label, verdict_badge


def _show_domain_detail(
    result,
    domain: str,
    *,
    prior_feedback: AnalystFeedback | None = None,
    suppression: AnalystSuppression | None = None,
    db_path: Path | None = None,
    analyst_policy_enabled: bool = False,
) -> None:
    assessment = next(item for item in result.assessments if item.domain == domain)
    detail = assessment_detail(assessment)
    evidence_rows = domain_match_rows(result, domain)

    with st.container(border=True):
        st.markdown(
            f"""
            <div class="tf-investigation-head">
                <div>
                    <div class="tf-eyebrow">Domain investigation</div>
                    <div class="tf-domain-name">{safe_text(detail["domain"])}</div>
                </div>
                <div>{verdict_badge(str(detail["verdict"]))}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if prior_feedback is not None:
            st.info(
                "Previous analyst review: "
                f"{feedback_label(prior_feedback.label)} · "
                f"{format_timestamp(prior_feedback.updated_at)}"
                + (f" · {prior_feedback.note}" if prior_feedback.note else "")
            )

        if suppression is not None:
            expiry_text = (
                format_timestamp(suppression.expires_at)
                if suppression.expires_at is not None
                else "No expiry"
            )
            st.warning(
                "Locally suppressed from the priority queue · "
                f"{suppression.reason} · {expiry_text}"
            )

        evidence = detail["evidence"]
        section_label("Why this verdict?")
        if evidence:
            for item in evidence:
                st.markdown(f"- {item}")
        else:
            st.caption("No strong CTI, ML-tier, or DNS-behavior signal was recorded.")

        if detail["verdict"] == "Known Threat":
            st.caption(
                "Known Threat is reserved for an exact known-domain IOC match. "
                "URL-hostname and response-IP matches are contextual CTI "
                "evidence and do not prove the queried domain is malicious."
            )

        if evidence_rows:
            section_label("Primary CTI evidence")
            primary = evidence_rows[0]
            st.write(
                f"{primary['Evidence scope']} · {primary['Source']}"
                + (f" · {primary['Threat type']}" if primary["Threat type"] else "")
            )
            metadata_columns = st.columns(4)
            metric_card(
                metadata_columns[0],
                "First seen",
                primary["First seen"] or "Unknown",
                accent="neutral",
            )
            metric_card(
                metadata_columns[1],
                "Last seen",
                primary["Last seen"] or "Unknown",
                accent="neutral",
            )
            metric_card(
                metadata_columns[2],
                "Confidence",
                (
                    f"{primary['Confidence']:.2f}"
                    if primary["Confidence"] is not None
                    else "Unknown"
                ),
                accent="neutral",
            )
            metric_card(
                metadata_columns[3],
                "Tags",
                primary["Tags"] or "None",
                accent="neutral",
            )

            if evidence_rows:
                with st.expander(
                    f"Show all IOC evidence ({len(evidence_rows)})",
                    expanded=False,
                ):
                    st.dataframe(
                        pd.DataFrame(evidence_rows),
                        hide_index=True,
                        width="stretch",
                    )
        else:
            st.caption("No cached IOC evidence is associated with this domain.")

        section_label("Detection context")
        context_columns = st.columns(5)
        ml_score = detail["ml_score"]
        metric_card(
            context_columns[0],
            "ML score",
            f"{ml_score:.4f}" if ml_score is not None else "Not scored",
            accent="neutral",
        )
        metric_card(
            context_columns[1],
            "ML tier",
            detail["ml_tier"],
            accent="neutral",
        )
        metric_card(
            context_columns[2],
            "DNS events",
            detail["event_count"],
            accent="neutral",
        )
        metric_card(
            context_columns[3],
            "Unique clients",
            detail["client_count"],
            accent="neutral",
        )
        metric_card(
            context_columns[4],
            "Response IPs",
            detail["response_ip_count"],
            accent="neutral",
        )
        with st.expander("DNS behavior details", expanded=False):
            st.caption("Query types: " + (", ".join(detail["query_types"]) or "None"))
            response_codes = ", ".join(
                f"{code}:{count}" for code, count in detail["response_code_counts"]
            )
            st.caption(f"Response codes: {response_codes or 'None'}")
            st.caption(
                "NXDOMAIN ratio: "
                + (
                    f"{detail['nxdomain_ratio']:.2f}"
                    if detail["nxdomain_ratio"] is not None
                    else "N/A"
                )
            )
            st.caption(
                "Label count / subdomain depth: "
                + f"{detail['label_count']} / {detail['subdomain_depth']}"
            )
            st.caption(
                "Numeric ratio / entropy: "
                + (
                    f"{detail['numeric_character_ratio']:.2f}"
                    if detail["numeric_character_ratio"] is not None
                    else "N/A"
                )
                + " / "
                + (
                    f"{detail['hostname_entropy']:.2f}"
                    if detail["hostname_entropy"] is not None
                    else "N/A"
                )
            )
            st.caption(
                "Response-IP churn rate: "
                + (
                    f"{detail['response_ip_churn_rate']:.2f}"
                    if detail["response_ip_churn_rate"] is not None
                    else "N/A"
                )
            )
            periodicity = (
                f"{detail['periodicity_score']:.2f}"
                if detail["periodicity_score"] is not None
                else "N/A"
            )
            interval = (
                f"{detail['periodic_interval_seconds']:.1f}s"
                if detail["periodic_interval_seconds"] is not None
                else "N/A"
            )
            st.caption("Periodicity score / interval: " + f"{periodicity} / {interval}")

        if analyst_policy_enabled and db_path is not None:
            st.markdown("**Local analyst policy**")
            if suppression is not None:
                if st.button(
                    "Remove local suppression",
                    key=f"remove_suppression_{detail['domain']}",
                ):
                    remove_analyst_suppression(db_path, detail["domain"])
                    st.rerun()
            else:
                with st.expander(
                    "Suppress from priority triage",
                    expanded=False,
                ):
                    with st.form(f"suppress_{detail['domain']}"):
                        reason = st.text_input(
                            "Suppression reason",
                            max_chars=300,
                        )
                        expiry_days = st.number_input(
                            "Expiry in days (0 = no expiry)",
                            min_value=0,
                            max_value=3650,
                            value=0,
                            step=1,
                        )
                        submitted = st.form_submit_button("Save local suppression")
                    if submitted:
                        expires_at = (
                            datetime.now(timezone.utc)
                            + timedelta(days=int(expiry_days))
                            if expiry_days
                            else None
                        )
                        try:
                            save_analyst_suppression(
                                db_path,
                                detail["domain"],
                                reason,
                                expires_at=expires_at,
                            )
                        except (TypeError, ValueError) as error:
                            st.error(f"Suppression could not be saved: {error}")
                        else:
                            st.success(
                                "Local suppression saved. Detector output was "
                                "not changed."
                            )
                            st.rerun()
