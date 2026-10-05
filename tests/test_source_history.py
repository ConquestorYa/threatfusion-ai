import pytest

from scripts.lab.audit_source_history import HISTORY, audit, identity
from scripts.lab.independent_replay import declared_plan


def test_prior_log_capture_cannot_be_relabelled_fresh_by_acquiring_packets():
    with pytest.raises(ValueError, match="8-1"):
        audit(declared_plan(), prior_only=True)
    rows = audit(declared_plan(), prior_only=True, allow_known=["CTU-IoT-Malware-Capture-8-1"])
    assert [r["case"] for r in rows if r["history"] == "known_replay"] == ["malware-8"]


def test_current_acquisitions_are_also_known_for_future_protocols():
    with pytest.raises(ValueError, match="Normal-20"):
        audit(declared_plan())


def test_capture_identity_ignores_file_type_and_hash_changes():
    base = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/"
    assert identity(base + "bro/conn.log.labeled") == identity(base + "2018.pcap")
    assert identity(base + "bro/conn.log.labeled") in HISTORY


def test_somfy_variants_do_not_share_a_capture_identity():
    base = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Honeypot-Capture-7-1/"
    assert identity(base + "Somfy-01/a.pcap") != identity(base + "Somfy-02/b.pcap")
    with pytest.raises(ValueError, match="specific Somfy"):
        identity(base + "capture.pcap")


def test_unknown_or_unused_allowance_cannot_silently_bypass_history():
    with pytest.raises(ValueError, match="Unused"):
        audit({"sources": []}, allow_known=["typo"])
    with pytest.raises(ValueError, match="origin"):
        identity("https://other.example/CTU-Normal-20/a.pcap")
