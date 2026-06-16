"""The data types passed between the stages."""
from dataclasses import dataclass


@dataclass
class Finding:
    cve: str
    package: str
    version: str
    fixed_version: str
    severity: str
    ecosystem: str
    source: str


@dataclass
class Patch:
    cve: str
    package: str
    from_version: str
    to_version: str
    change: str          # the new manifest line, e.g. "PyYAML==5.4"
    explanation: str
    confidence: float
    decision: str        # auto / review / manual
    attempts: int        # how many generate-verify passes were used


@dataclass
class DeployResult:
    status: str          # promoted / rolled_back
    tests_passed: bool
    output: str
