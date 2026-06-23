"""The evaluation dataset.

Each case carries the finding the system sees and the true fixed version (ground
truth), so a patch is correct when it reaches at least that version.

Two difficulties, both from real CVEs:
- easy: a pure-python package whose fixed version installs on any Python.
- hard: a compiled package whose minimum fixed version has no wheel for this Python,
  so the naive "upgrade to the minimum fix" does not actually install. A single pass
  gets stuck; a retry loop that reads the install error can recover a later compatible
  version. The no-wheel status of each minimum fix was verified with pip.
"""
from dataclasses import dataclass

from devsecagent.schema import Finding


@dataclass
class EvalCase:
    finding: Finding     # what the system sees (scanner reports the minimum fix)
    true_fix: str        # ground-truth fixed version, for scoring
    difficulty: str      # easy / hard


# (cve, package, current version, minimum fixed version, severity)
EASY_ROWS = [
    ("CVE-2018-18074", "requests", "2.19.1", "2.20.0", "HIGH"),
    ("CVE-2023-32681", "requests", "2.27.0", "2.31.0", "MEDIUM"),
    ("CVE-2021-33503", "urllib3", "1.26.4", "1.26.5", "HIGH"),
    ("CVE-2020-28493", "Jinja2", "2.11.2", "2.11.3", "MEDIUM"),
    ("CVE-2023-30861", "Flask", "2.2.0", "2.3.2", "HIGH"),
    ("CVE-2023-25577", "Werkzeug", "2.2.2", "2.2.3", "HIGH"),
    ("CVE-2023-37920", "certifi", "2022.12.7", "2023.7.22", "HIGH"),
    ("CVE-2024-3651", "idna", "3.6", "3.7", "MEDIUM"),
    ("CVE-2022-40897", "setuptools", "65.5.0", "65.5.1", "HIGH"),
    ("CVE-2023-30608", "sqlparse", "0.4.3", "0.4.4", "MEDIUM"),
]

# minimum fixed version has NO Python 3.12 wheel (verified with pip download)
HARD_ROWS = [
    ("CVE-2020-14343", "PyYAML", "5.3.1", "5.4", "CRITICAL"),
    ("CVE-2021-25287", "Pillow", "8.1.0", "8.2.0", "HIGH"),
    ("CVE-2022-22817", "Pillow", "8.3.2", "9.0.0", "CRITICAL"),
    ("CVE-2021-23437", "Pillow", "8.2.0", "8.3.2", "HIGH"),
    ("CVE-2020-36242", "cryptography", "3.2", "3.3.2", "HIGH"),
    ("CVE-2020-25659", "cryptography", "2.9", "3.2", "MEDIUM"),
    ("CVE-2021-28957", "lxml", "4.6.2", "4.6.3", "MEDIUM"),
    ("CVE-2022-2309", "lxml", "4.9.0", "4.9.1", "HIGH"),
    ("CVE-2021-21330", "aiohttp", "3.7.3", "3.7.4", "MEDIUM"),
    ("CVE-2021-34141", "numpy", "1.21.0", "1.22.0", "MEDIUM"),
]


def _case(row, difficulty):
    cve, pkg, cur, fix, sev = row
    return EvalCase(Finding(cve, pkg, cur, fix, sev, "pip", "seed"), fix, difficulty)


EASY = [_case(r, "easy") for r in EASY_ROWS]
HARD = [_case(r, "hard") for r in HARD_ROWS]


def load():
    return EASY + HARD


def easy():
    return list(EASY)


def hard():
    return list(HARD)
