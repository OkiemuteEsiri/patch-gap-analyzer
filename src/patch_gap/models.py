"""Domain models for patch-gap analysis."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import date
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass(frozen=True)
class PatchRecord:
    asset_id: str
    cve: str
    severity: Severity
    cvss: float
    patch_available: date
    detected: date
    installed: date | None
    internet_exposed: bool
    kev: bool
    criticality: int
    owner: str
    exception_until: date | None = None

    def __post_init__(self) -> None:
        if not self.asset_id or not self.cve.startswith("CVE-"):
            raise ValueError("asset_id and valid CVE identifier are required")
        if not 0 <= self.cvss <= 10:
            raise ValueError("cvss must be between 0 and 10")
        if not 1 <= self.criticality <= 5:
            raise ValueError("criticality must be between 1 and 5")
        if self.installed and self.installed < self.patch_available:
            raise ValueError("installed date cannot predate patch availability")

@dataclass(frozen=True)
class Finding:
    finding_id: str
    asset_id: str
    cve: str
    risk_score: int
    priority: str
    gap_days: int
    reason: str
    remediation: str
    validation: str
