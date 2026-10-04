import pytest
from types import SimpleNamespace

from scripts.lab import evaluate_iot23 as module
from scripts.lab.evaluate_iot23 import acquisition_plan, strip_labels
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics


def test_official_label_layout_is_stripped_before_detector_and_plan_is_fixed(tmp_path, monkeypatch):
    content = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\tmissed_bytes\ttunnel_parents   label   detailed-label\n1791072000\tC1\t192.0.2.1\t50000\t198.51.100.1\t443\ttcp\t4000\t100\t200\tSF\t0\t-   Benign   -\n"
    clean, labels = strip_labels(content)
    changed, changed_labels = strip_labels(content.replace("Benign   -", "Malicious   C&C"))
    assert clean == changed and labels != changed_labels
    assert "label" not in clean and "Malicious" not in clean
    result, _ = analyze_zeek_conn_log_with_diagnostics(clean, [], None)
    assert result.connection_findings[0].priority == "review"
    assert len(acquisition_plan()["captures"]) == 4
    with pytest.raises(ValueError):
        strip_labels(content.replace("#separator \\x09", "#separator ,"))
    module.verify_frozen_code()
    changed_source = tmp_path / "connections.py"
    changed_source.write_text("# changed detector\n")
    monkeypatch.setattr(module.importlib.util, "find_spec", lambda name: SimpleNamespace(origin=str(changed_source)))
    with pytest.raises(ValueError, match="Frozen evaluation code changed"):
        module.verify_frozen_code()
