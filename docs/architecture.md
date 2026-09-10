# Architecture

`patch-gap-analyzer` is an offline, deterministic vulnerability-management utility. It intentionally separates data ingestion, domain validation, risk evaluation, and reporting so each layer can be tested independently.

## Flow

1. **Inventory ingestion** reads a normalized JSON export from a scanner/CMDB integration boundary.
2. **Domain validation** rejects malformed CVEs, impossible CVSS values, duplicate asset/CVE observations, and invalid dates.
3. **Assessment engine** calculates an explainable 0–100 score from technical severity, patch age, asset criticality, internet exposure, KEV context, and approved exception state.
4. **Prioritization** maps the score to P0–P3 queues.
5. **Reporting** produces a portable Markdown assessment with evidence and revalidation criteria.

## Design decisions

- No network calls are required; the sample project is safe to execute locally.
- Active risk acceptance never suppresses a finding. It reduces urgency while retaining visibility.
- Installed patches are excluded only when the inventory supplies a confirmed installation date.
- Scoring is bounded and deterministic to make decisions reproducible and reviewable.
- The engine is intentionally vendor-neutral so Tenable, Qualys, Defender, CrowdStrike, CMDB, or custom exports can be normalized upstream without coupling the risk model to one product.

## Extension points

Production integrations could add EPSS, vendor supersedence metadata, maintenance windows, application ownership, business service dependencies, compensating controls, and ServiceNow/Jira workflows while retaining the same assessment interface.
