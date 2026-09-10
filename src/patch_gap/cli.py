"""CLI entry point."""
from __future__ import annotations
import argparse
from datetime import date
from pathlib import Path
from .analyzer import assess
from .reporting import load_records, render_markdown


def main() -> int:
    p = argparse.ArgumentParser(description="Risk-based patch gap analyzer")
    p.add_argument("inventory")
    p.add_argument("--as-of", help="Assessment date (YYYY-MM-DD)")
    p.add_argument("--output", default="patch-gap-report.md")
    args = p.parse_args()
    as_of = date.fromisoformat(args.as_of) if args.as_of else None
    findings = assess(load_records(args.inventory), as_of=as_of)
    Path(args.output).write_text(render_markdown(findings), encoding="utf-8")
    print(f"wrote {len(findings)} findings to {args.output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
