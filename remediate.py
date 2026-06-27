"""Arm A remediation, run by the CI/CD workflow inside GitHub Actions.

For each CVE the scanner finds, the Arm A baseline generates one patch and verifies it on
the four checks: a single generate-verify pass, no retry. The patch is applied and tested
in a clean Docker container; if it installs it is kept, otherwise it is rolled back and
left for a human. The workflow then opens a pull request with the kept fixes. This is the
baseline path that runs in GitHub Actions, not on a developer machine.
"""
import sys

from devsecagent import deployer, patcher, scan
from devsecagent.versions import at_least


def group_by_package(findings):
    """One target per package, set to the highest fixed version its CVEs need, so a
    package with several CVEs is upgraded once instead of patched repeatedly."""
    groups = {}
    for f in findings:
        g = groups.get(f.package.lower())
        if g is None:
            groups[f.package.lower()] = {"finding": f, "cves": [f.cve]}
        else:
            g["cves"].append(f.cve)
            if at_least(f.fixed_version, g["finding"].fixed_version):
                g["finding"] = f
    return list(groups.values())


def remediate_one(project_dir, finding):
    """Arm A: one generate-verify pass, applied and tested once. Returns (status, patch)."""
    data = patcher.generate_patch(finding)
    conf = patcher.verify_patch(finding, data)
    patch = patcher.make_patch(finding, data, conf, attempts=1)
    result = deployer.deploy(project_dir, patch)   # apply -> Docker install test -> promote/rollback
    return ("fixed" if result.tests_passed else "review"), patch


def main(project_dir, limit=5):
    print(f"== Scan stage ({project_dir}) ==")
    findings = scan.scan(project_dir)
    if not findings:
        print("no vulnerabilities found")
        return
    print(f"scanner found {len(findings)} CVEs:")
    for f in findings:
        print(f"  {f.cve:18s} {f.package:12s} {f.version:10s} -> "
              f"{f.fixed_version:10s} [{f.severity}] (via {f.source})")

    groups = group_by_package(findings)[:limit]
    print(f"\n== Remediation stage (Arm A, single pass; {len(groups)} packages) ==")
    fixed = review = 0
    for g in groups:
        finding, cves = g["finding"], g["cves"]
        label = f"{len(cves)} CVEs" if len(cves) > 1 else cves[0]
        status, patch = remediate_one(project_dir, finding)
        if status == "fixed":
            fixed += 1
            print(f"FIXED  {finding.package} {finding.version} -> {patch.to_version} ({label})")
        else:
            review += 1
            print(f"REVIEW {finding.package} ({label}) - routed {patch.decision} "
                  f"or the proposed version did not install")
    print(f"\nsummary: {fixed} fixed, {review} left for review, of "
          f"{len(groups)} packages ({len(findings)} CVEs)")


if __name__ == "__main__":
    project = sys.argv[1] if len(sys.argv) > 1 else "samples/vuln_python"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    main(project, n)
