"""Tests for the scan layer."""
import shutil
from pathlib import Path

import pytest

from devsecagent import scan
from devsecagent.schema import Finding

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "vuln_python"

TRIVY_JSON = """
{
  "Results": [
    {
      "Type": "pip",
      "Target": "requirements.txt",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2020-14343",
          "PkgName": "PyYAML",
          "InstalledVersion": "5.3.1",
          "FixedVersion": "5.4",
          "Severity": "CRITICAL"
        }
      ]
    }
  ]
}
"""


def test_parse_trivy_reads_fields():
    findings = scan.parse_trivy(TRIVY_JSON)
    assert len(findings) == 1
    f = findings[0]
    assert f.cve == "CVE-2020-14343"
    assert f.package == "PyYAML"
    assert f.fixed_version == "5.4"
    assert f.severity == "CRITICAL"
    assert f.source == "trivy"


def test_parse_trivy_bad_json():
    assert scan.parse_trivy("not json") == []


@pytest.mark.skipif(not shutil.which("trivy"), reason="trivy not installed")
def test_trivy_scans_sample():
    findings = scan.trivy_scan(str(SAMPLE))
    assert len(findings) > 0
    assert all(isinstance(f, Finding) for f in findings)
    assert any(f.package == "PyYAML" for f in findings)
