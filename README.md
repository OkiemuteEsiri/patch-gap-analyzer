# Patch Gap Analyzer

A defensive, vendor-neutral **Vulnerability Management / Exposure Engineering** project for identifying systems where a security fix is available but remediation has not yet been evidenced across the affected estate.

The project focuses on the operational problem behind patch compliance: a vulnerability can remain exploitable even when a vendor fix exists, because the affected asset has not received the approved update, an exception remains open, ownership is unclear, or remediation evidence has not been refreshed.

## What this project demonstrates

- risk-based vulnerability prioritization rather than CVSS-only sorting;
- patch-age and remediation-gap analysis;
- business criticality and internet-exposure context;
- CISA KEV-aware prioritization;
- explicit, time-bound exception handling without hiding exposure;
- deterministic P0–P3 queues and bounded 0–100 risk scoring;
- evidence-based closure and remediation validation;
- defensive MITRE ATT&CK mapping;
- tested Python engineering and CI quality controls.

## Architecture

```text
Normalized scanner / CMDB export
             |
             v
      JSON ingestion layer
             |
             v
    Validated domain models
             |
             v
 Risk + patch-gap assessment
 severity | age | criticality | exposure | KEV | exception
             |
             v
      P0-P3 prioritization
             |
             v
 Markdown assessment / remediation validation
```

See [`docs/architecture.md`](docs/architecture.md) for design decisions and extension points.

## Risk model

The engine starts with technical severity, then adds context that changes operational urgency:

| Factor | Effect |
|---|---|
| Critical/high severity | Higher base risk |
| Longer time since patch availability | Increasing remediation debt |
| Asset criticality 1–5 | Higher business impact |
| Internet exposure | Higher exploitability/reachability context |
| CISA KEV indicator | Stronger evidence of real-world exploitation context |
| Active approved exception | Reduces urgency but never suppresses the finding |

Scores are bounded to **0–100** and mapped to **P0–P3**. The model is intentionally transparent and deterministic so a reviewer can explain why one remediation item ranks above another.

## Project structure

```text
.github/workflows/security-quality.yml
src/patch_gap/
  __init__.py
  models.py
  analyzer.py
  reporting.py
  cli.py
tests/test_analyzer.py
data/sample_inventory.json
docs/architecture.md
docs/methodology.md
reports/example-assessment.md
pyproject.toml
```

## Run locally

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m patch_gap.cli data/sample_inventory.json \
  --as-of 2026-09-01 \
  --output patch-gap-report.md
```

The supplied dataset is synthetic and safe for demonstration.

## Implemented controls

The current specialist build includes:

- schema validation for CVE identifiers, CVSS range, criticality, and patch dates;
- duplicate asset/CVE rejection to prevent double counting;
- exclusion of records only when installation evidence confirms remediation;
- patch-gap aging from vendor fix availability;
- business criticality weighting;
- internet-exposure weighting;
- KEV context weighting;
- exception-aware governance that preserves visibility;
- stable deterministic finding identifiers;
- remediation and revalidation instructions for every finding;
- Markdown executive/technical reporting.

## Remediation workflow

1. Validate that the scanner finding and vendor patch apply to the installed product/version.
2. Check supersedence/cumulative-update information and maintenance constraints.
3. Confirm business owner, exposure, criticality, and any approved exception.
4. Prioritize KEV and internet-facing critical systems first.
5. Deploy the approved fix through normal change governance.
6. Refresh scanner, endpoint, or CMDB evidence.
7. Close only after the affected version is no longer observed and patch installation is evidenced.

Full methodology: [`docs/methodology.md`](docs/methodology.md).

## MITRE ATT&CK context

- **T1190 – Exploit Public-Facing Application**: supports greater urgency for internet-facing vulnerable applications.
- **T1210 – Exploitation of Remote Services**: supports prioritizing vulnerable remotely reachable infrastructure.

These mappings are used only as defensive threat-model context. They do not claim that exploitation occurred.

## Tests

The unit suite covers open/closed gaps, KEV weighting, exposure weighting, exception visibility, duplicate rejection, maximum score bounding, priority mapping, and invalid CVSS handling.

GitHub Actions additionally performs source compilation, complete unit-test discovery, a CLI smoke test, and generated-report validation with read-only repository permissions.

## Example assessment

[`reports/example-assessment.md`](reports/example-assessment.md) shows how findings can be communicated to stakeholders without exposing real infrastructure or confidential data.

## Security and ethical boundaries

This repository contains **no production asset inventory, employer/client data, credentials, exploit payloads, scanner secrets, live targeting, or claims of compromise**. It is an offline defensive engineering project using synthetic data.

## Limitations

The sample implementation does not contact vendor APIs, scanners, CISA, ticketing systems, or production endpoints. KEV and exposure flags are assumed to be normalized upstream. Production integrations would also need richer package/version applicability, patch supersedence, maintenance windows, compensating controls, and workflow authorization.

## Roadmap

- add EPSS enrichment and configurable enterprise scoring policies;
- model patch supersedence/cumulative updates;
- add SLA breach and trend analytics;
- support CSV and normalized scanner adapters;
- produce JSON/SARIF-style machine-readable findings;
- add exception expiry alerts and owner-level KPI summaries;
- integrate remediation validation evidence as a first-class object.

## Skills demonstrated

Python, vulnerability management, exposure engineering, risk prioritization, patch governance, remediation validation, data normalization, deterministic scoring, defensive threat modeling, automated testing, CI/CD security hygiene, and stakeholder-oriented reporting.
