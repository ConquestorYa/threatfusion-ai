"""Source integrity/privacy gates, independent of any detector outcome."""
from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.lab import independent_replay as module
from scripts.lab.evaluate_review_workload import validate_pcap


def test_published_source_plan_is_exact_and_reserves_unacquired_sources():
    text = json.dumps(module.declared_plan(), indent=2) + "\n"
    assert hashlib.sha256(text.encode()).hexdigest() == module.PLAN_SHA
    plan = module.declared_plan()
    assert len(plan["sources"]) == 4
    assert len(plan["reserved_unacquired"]) == 2
    assert all(s["head_bytes"] <= plan["max_pcap_bytes"] for s in plan["sources"])


@pytest.mark.parametrize("url", ["http://mcfp.felk.cvut.cz/x", "https://other.example/x",
                                 "https://mcfp.felk.cvut.cz:444/x", "https://user:pass@mcfp.felk.cvut.cz/x"])
def test_official_redirect_gate_blocks_before_opening_untrusted_origin(url):
    assert not module.allowed_url(url)
    with pytest.raises(ValueError, match="Redirect outside"):
        module.OfficialRedirects().redirect_request(None, None, 302, None, {}, url)


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="Private Unix lab directory")
@pytest.mark.parametrize("filename", ["plan.json", "runtime-freeze.json", "method-freeze.json"])
def test_changed_plan_runtime_or_method_aborts_before_network(tmp_path, monkeypatch, filename):
    root = tmp_path / "private"
    module.prepare(root)
    before = (root / "plan.json").read_bytes()
    with pytest.raises(FileExistsError):
        module.prepare(root)
    assert (root / "plan.json").read_bytes() == before
    data = json.loads((root / filename).read_text())
    data[next(iter(data))] = "changed"
    (root / filename).write_text(json.dumps(data))
    monkeypatch.setattr(module, "build_opener", lambda *a: pytest.fail("Network reached after fingerprint mismatch"))
    with pytest.raises(ValueError, match="changed"):
        module.acquire(root)
    assert not (root / "normal-20").exists()


@pytest.mark.parametrize("broken", [False, True])
def test_streamed_acquisition_never_scores_a_truncated_prefix_or_overwrites(tmp_path, monkeypatch, broken):
    raw = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    raw += struct.pack("<IIII", 1, 0, 2, 2) + b"xx"
    if broken:
        raw = raw[:-1]
    source = dict(name="sample", url="https://mcfp.felk.cvut.cz/sample.pcap", head_bytes=len(raw), provider_intent="fixture")
    class Response:
        status = 200
        headers = {}
        def __enter__(self):
            self.position = 0
            return self
        def __exit__(self, *args):
            return False
        def geturl(self):
            return source["url"]
        def read(self, size):
            # Small chunks exercise bounded streaming rather than one huge read.
            block = raw[self.position:self.position + 7]
            self.position += len(block)
            return block
    monkeypatch.setattr(module, "build_opener", lambda *a: SimpleNamespace(open=lambda *a, **kw: Response()))
    status = module.acquire_case(tmp_path, source)
    assert status["status"] == ("excluded" if broken else "complete")
    root = tmp_path / "sample"
    assert (root / "scenario.pcap").read_bytes() == raw
    if hasattr(os, "getuid"):
        assert (root / "acquisition.json").stat().st_mode & 0o077 == 0
    if broken:
        assert "Truncated" in status["reason"]
    with pytest.raises(FileExistsError):
        module.acquire_case(tmp_path, source)
    assert (root / "scenario.pcap").read_bytes() == raw


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="Private Unix replay evaluator")
def test_excluded_acquisition_never_reaches_private_detector_evaluation(tmp_path, monkeypatch):
    root = tmp_path / "sample"
    root.mkdir(mode=0o700)
    module.write_new(root / "acquisition.json", {"status": "excluded", "reason": "Truncated capture", "sha256": "fixture"})
    monkeypatch.setattr(module, "analyze_zeek_conn_log_with_diagnostics", lambda *a: pytest.fail("Excluded data scored"))
    result = module.evaluate_case(tmp_path, {"name": "sample"}, {})
    assert result["status"] == "excluded" and "tcp_review_groups" not in result


def test_acquisition_bound_is_separate_from_complete_packet_structure(tmp_path):
    path = tmp_path / "tiny.pcap"
    path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    with pytest.raises(ValueError, match="bound"):
        validate_pcap(path, max_bytes=23)
    assert validate_pcap(path, max_bytes=24) == 0


def test_frozen_paths_cannot_escape_comparison_root(tmp_path):
    from scripts.lab.evaluate_review_workload import verify_hashes
    with pytest.raises(ValueError, match="escapes"):
        verify_hashes(tmp_path, {str(Path(tmp_path.anchor) / "outside"): "unused"})


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="Private Unix lab directory")
def test_explicit_format_revision_preserves_first_receipt_and_cannot_follow_outcomes(tmp_path, monkeypatch):
    from tests.test_pcap_structure import interface, packet, section
    raw = section() + interface() + packet()
    plan = module.declared_plan()
    for source in plan["sources"]:
        source["head_bytes"] = len(raw)
    monkeypatch.setattr(module, "declared_plan", lambda: plan)
    monkeypatch.setattr(module, "PLAN_SHA", hashlib.sha256((json.dumps(plan, indent=2) + "\n").encode()).hexdigest())
    root = tmp_path / "private"
    module.prepare(root)
    first_method = (root / "method-freeze.json").read_bytes()
    for source in plan["sources"]:
        directory = root / source["name"]
        directory.mkdir(mode=0o700)
        (directory / "scenario.pcap").write_bytes(raw)
        module.write_new(directory / "acquisition.json", dict(source, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                         status="excluded", reason="Invalid classic PCAP header"))
    first_receipt = (root / "normal-21/acquisition.json").read_bytes()
    module.qualify(root)
    assert (root / "method-freeze.json").read_bytes() == first_method
    assert (root / "normal-21/acquisition.json").read_bytes() == first_receipt
    assert module.effective_receipt(root / "normal-21")["status"] == "complete"
    module.verify_method(root)
    with pytest.raises(FileExistsError, match="precede"):
        module.qualify(root)
    (root / "normal-21/format-qualification.json").write_text("{}")
    with pytest.raises(ValueError, match="Frozen input changed"):
        module.verify_method(root)


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="Private Unix lab directory")
def test_format_revision_refuses_prior_native_outcome(tmp_path):
    root = tmp_path / "private"
    module.prepare(root)
    module.write_new(root / "pre-analysis.json", {})
    with pytest.raises(FileExistsError, match="precede"):
        module.qualify(root)
