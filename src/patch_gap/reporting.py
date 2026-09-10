"""JSON ingestion and Markdown reporting."""
from __future__ import annotations
import json
from datetime import date
from pathlib import Path
from .models import PatchRecord, Severity


def load_records(path: str | Path) -> list[PatchRecord]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    records: list[PatchRecord] = []
    for item in raw:
        records.append(PatchRecord(
            asset_id=item["asset_id"], cve=item["cve"], severity=Severity(item["severity"]),
            cvss=float(item["cvss"]), patch_available=date.fromisoformat(item["patch_available"]),
            detected=date.fromisoformat(item["detected"]),
            installed=date.fromisoformat(item["installed"]) if item.get("installed") else None,
            internet_exposed=bool(item["internet_exposed"]), kev=bool(item["kev"]),
            criticality=int(item["criticality"]), owner=item["owner"],
            exception_until=date.fromisoformat(item["exception_until"]) if item.get("exception_until") else None,
        ))
    return records


def render_markdown(findings) -> str:
    total = len(findings)
    p0 = sum(f.priority == "P0" for f in findings)
    p1 = sum(f.priority == "P1" for f in findings)
    lines = ["# Patch Gap Assessment", "", f"Open patch gaps: **{total}**", f"P0: **{p0}** | P1: **{p1}**", "",
             "| Priority | Score | Asset | CVE | Gap | Rationale |", "|---|---:|---|---|---:|---|"]
    for f in findings:
        lines.append(f"| {f.priority} | {f.risk_score} | {f.asset_id} | {f.cve} | {f.gap_days}d | {f.reason} |")
    lines += ["", "## Validation", "", "A finding closes only after refreshed inventory confirms the approved fix is installed and the affected version is no longer observed."]
    return "\n".join(lines) + "\n"
