"""Tests for the patcher and Arm A."""
import pytest

from devsecagent import arm_a, config, patcher
from devsecagent.schema import Finding


def test_confidence_is_weighted():
    full = {"correctness": 1, "completeness": 1, "safety": 1, "consistency": 1}
    assert patcher.confidence(full) == 1.0
    assert patcher.confidence({}) == 0.0


def test_decide_routes_on_thresholds():
    assert patcher.decide(0.90) == "auto"
    assert patcher.decide(0.70) == "review"
    assert patcher.decide(0.50) == "manual"


def test_parse_json_extracts_object():
    assert patcher.parse_json('noise {"a": 1} trailing') == {"a": 1}
    assert patcher.parse_json("no json here") == {}


@pytest.mark.skipif(not config.AZURE_OPENAI_API_KEY, reason="Azure not configured")
def test_arm_a_patches_pyyaml():
    finding = Finding(cve="CVE-2020-14343", package="PyYAML", version="5.3.1",
                      fixed_version="5.4", severity="CRITICAL", ecosystem="pip", source="trivy")
    patch = arm_a.run(finding)
    assert patch.to_version
    assert patch.attempts == 1
    assert patch.decision in ("auto", "review", "manual")
