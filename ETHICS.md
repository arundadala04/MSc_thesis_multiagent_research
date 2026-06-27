# Ethical Considerations

DevSecAgent is a defensive security tool: it automatically upgrades vulnerable software
dependencies to their fixed versions inside a CI/CD pipeline.

## Dual-use
The agent only responds to CVE-specific remediation prompts (upgrade a flagged dependency
to a non-vulnerable version). It does not generate exploits, attack code, or offensive
payloads. A patch is never applied without passing an install/build test, and any change
that breaks the build is rolled back automatically, so the agent cannot silently degrade a
system.

## Data
- The CVE knowledge base and the seed evaluation cases are built from public vulnerability
  records (CVE / OSV open data). No personal data and no human subjects are involved, so
  GDPR does not apply.
- The sample project is a deliberately vulnerable manifest used only as a scan target.

## Reporting
Patch outcomes are reported across difficulty and severity tiers so that performance is not
hidden behind a single average.

## Licence
Released under the MIT licence for defensive DevSecOps use and reproducible research.
