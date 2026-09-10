# Example Patch Gap Assessment

Assessment date: **2026-09-01**  
Dataset: synthetic demonstration inventory only

## Executive summary

The sample estate contains three unresolved patch gaps and one remediated endpoint. The highest-priority condition is an internet-facing, business-critical web asset associated with KEV context and a patch available for more than two months. The API asset is also externally exposed and should follow immediately. A database finding has an active exception; the exception preserves governance context but does not remove the underlying exposure.

## Priority view

| Priority | Asset | Condition | Recommended action |
|---|---|---|---|
| P0 | web-01 | Critical, internet exposed, KEV, criticality 5 | Validate applicability and deploy the approved vendor fix through emergency/accelerated patch governance. |
| P1 | api-03 | High severity, internet exposed, criticality 4 | Patch in the next approved maintenance window and re-scan. |
| P1/P2 | db-02 | High severity, criticality 5, active time-bound exception | Reconfirm compensating controls, patch before exception expiry, and obtain refreshed closure evidence. |

## Validation evidence expected

- approved change or patch record;
- new installed build/package evidence;
- refreshed scanner or endpoint telemetry;
- vulnerable version no longer observed;
- exception updated/closed where applicable.

This report is illustrative and contains no production asset data or claim of exploitation.
