"""Scan a project folder for known CVEs in its dependencies.

Trivy runs locally with no account, so it is the default. Snyk is also used if it
is installed and logged in. Both results are turned into a list of Finding.
"""
import json
import shutil
import subprocess

from devsecagent.schema import Finding


def scan(path):
    """Run every available scanner on path and return findings without duplicates."""
    findings = trivy_scan(path) + snyk_scan(path)
    unique = {}
    for f in findings:
        unique[(f.cve, f.package)] = f
    return list(unique.values())


def trivy_scan(path):
    if not shutil.which("trivy"):
        return []
    out = subprocess.run(
        ["trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "json", path],
        capture_output=True, text=True,
    ).stdout
    return parse_trivy(out)


def parse_trivy(raw):
    """Read Trivy JSON text into Finding objects."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    findings = []
    for result in data.get("Results", []):
        ecosystem = result.get("Type", "")
        for v in result.get("Vulnerabilities") or []:
            findings.append(Finding(
                cve=v.get("VulnerabilityID", ""),
                package=v.get("PkgName", ""),
                version=v.get("InstalledVersion", ""),
                fixed_version=v.get("FixedVersion", ""),
                severity=v.get("Severity", "UNKNOWN").upper(),
                ecosystem=ecosystem,
                source="trivy",
            ))
    return findings


def snyk_scan(path):
    if not shutil.which("snyk"):
        return []
    out = subprocess.run(
        ["snyk", "test", "--json", path],
        capture_output=True, text=True,
    ).stdout
    return parse_snyk(out)


def parse_snyk(raw):
    """Read Snyk JSON text into Finding objects."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    findings = []
    for v in data.get("vulnerabilities", []):
        cve = (v.get("identifiers", {}).get("CVE") or [""])[0]
        fixed = (v.get("fixedIn") or [""])[0]
        findings.append(Finding(
            cve=cve,
            package=v.get("packageName", ""),
            version=v.get("version", ""),
            fixed_version=fixed,
            severity=v.get("severity", "unknown").upper(),
            ecosystem=v.get("language", ""),
            source="snyk",
        ))
    return findings
