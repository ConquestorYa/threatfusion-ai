"""The historical C4 report must not mark lexical C4 final as complete."""

from dataclasses import replace

from threatfusion.ml_evaluation_report import FrozenHoldoutReport
from threatfusion.ml_final_provenance import (
    FinalProvenance,
    LEXICAL_C4_ARTIFACT_SHA256,
    LEXICAL_C4_FREEZE_CUTOFF,
)
from threatfusion.ui_evaluation import _is_current_lexical_final_report


def test_current_lexical_final_requires_matching_provenance() -> None:
    import runpy
    from pathlib import Path

    fixture = runpy.run_path(str(Path(__file__).with_name("test_evaluation_dashboard.py")))
    historical: FrozenHoldoutReport = fixture["report"]()
    assert not _is_current_lexical_final_report(historical)

    lexical_without_provenance = replace(
        historical, model_name="lr_char_2_6_plus_lexical_c4"
    )
    assert not _is_current_lexical_final_report(lexical_without_provenance)

    lexical_final = replace(
        lexical_without_provenance,
        protocol="fresh_collection_disjoint_first_seen_filtered",
        malicious_first_seen_after=LEXICAL_C4_FREEZE_CUTOFF,
        provenance=FinalProvenance(
            schema_version=1,
            protocol="post_freeze_temporal_malicious_plus_confirmed_benign_dns",
            model_name="lr_char_2_6_plus_lexical_c4",
            artifact_sha256=LEXICAL_C4_ARTIFACT_SHA256,
            development_snapshot_sha256="a" * 64,
            holdout_snapshot_sha256="b" * 64,
            cutoff=LEXICAL_C4_FREEZE_CUTOFF,
        ),
    )
    assert _is_current_lexical_final_report(lexical_final)
