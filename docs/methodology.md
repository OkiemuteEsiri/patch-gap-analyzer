# Assessment Methodology

## Objective

Identify systems for which an applicable security fix is available but the estate has not yet demonstrated successful deployment, then prioritize those gaps using business and threat context.

## Required evidence

Each normalized record contains asset identity, CVE, severity/CVSS, patch publication date, detection date, installation state, exposure, KEV indicator, business criticality, remediation owner, and optional exception expiry.

## Risk classification

The model uses additive, bounded scoring. Base technical severity is increased by patch age, asset criticality, internet exposure, and KEV status. A currently approved exception reduces urgency but never removes the finding. Scores map to P0 (80–100), P1 (60–79), P2 (40–59), and P3 (<40).

## Triage workflow

1. Confirm the scanner finding is current and the patch is applicable to the installed product/version.
2. Check whether the vendor fix has been superseded or replaced by a cumulative update.
3. Confirm asset owner, service criticality, exposure, maintenance constraints, and approved exceptions.
4. Prioritize KEV and internet-facing critical systems before lower-context backlog.
5. Deploy through the normal change/patch process; do not bypass change controls.
6. Re-scan or refresh endpoint/CMDB telemetry after deployment.
7. Close only when evidence shows the affected version is absent and the approved fix is installed.

## Remediation quality gates

A ticket is not complete merely because a patch was scheduled. Closure evidence should include the refreshed asset state, installation/build evidence, vulnerability re-scan result where available, and exception closure or update.

## ATT&CK context

- **T1190 – Exploit Public-Facing Application:** supports higher urgency for internet-exposed vulnerable applications.
- **T1210 – Exploitation of Remote Services:** supports prioritizing vulnerable remotely reachable infrastructure.

These mappings are defensive threat-model context, not evidence that exploitation occurred.
