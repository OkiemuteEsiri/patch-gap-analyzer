"""Deterministic patch-gap assessment engine."""
from __future__ import annotations
from datetime import date
from hashlib import sha1
from .models import Finding, PatchRecord

WEIGHTS = {"critical": 34, "high": 26, "medium": 16, "low": 8}

def _priority(score: int) -> str:
    if score >= 80: return "P0"
    if score >= 60: return "P1"
    if score >= 40: return "P2"
    return "P3"

def assess(records: list[PatchRecord], as_of: date | None = None) -> list[Finding]:
    now = as_of or date.today()
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for r in records:
        key = (r.asset_id, r.cve)
        if key in seen:
            raise ValueError(f"duplicate record: {r.asset_id}/{r.cve}")
        seen.add(key)
        if r.installed is not None and r.installed <= now:
            continue
        gap_days = max(0, (now - r.patch_available).days)
        exception_active = bool(r.exception_until and r.exception_until >= now)
        score = WEIGHTS[r.severity.value]
        score += min(20, gap_days // 15)
        score += (r.criticality - 1) * 5
        score += 12 if r.internet_exposed else 0
        score += 18 if r.kev else 0
        score -= 12 if exception_active else 0
        score = max(0, min(100, score))
        factors = [f"{gap_days}d patch gap", f"criticality {r.criticality}/5"]
        if r.kev: factors.append("CISA KEV context")
        if r.internet_exposed: factors.append("internet exposed")
        if exception_active: factors.append("active exception lowers urgency but not visibility")
        fid = "PG-" + sha1(f"{r.asset_id}|{r.cve}".encode()).hexdigest()[:10].upper()
        findings.append(Finding(
            finding_id=fid, asset_id=r.asset_id, cve=r.cve,
            risk_score=score, priority=_priority(score), gap_days=gap_days,
            reason="; ".join(factors),
            remediation=f"Validate applicability, deploy the approved fix for {r.cve}, and confirm owner {r.owner} closes the gap.",
            validation="Re-ingest inventory after deployment and verify installed date is present and affected version is no longer observed."
        ))
    return sorted(findings, key=lambda x: (-x.risk_score, -x.gap_days, x.asset_id, x.cve))
