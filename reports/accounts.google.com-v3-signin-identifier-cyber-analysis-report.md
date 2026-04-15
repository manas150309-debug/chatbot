# Cyber Analysis Report

- URL: https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fdrive.google.com%2Fdrive%2Fhome&dsh=S-29558870%3A1774798657803040&followup=https%3A%2F%2Fdrive.google.com%2Fdrive%2Fhome&osid=1&passive=1209600&service=wise&flowName=WebLiteSignIn&flowEntry=ServiceLogin&ifkv=AT1y2_X5LsrhmK0RvwayoCorROAv3KgMnKh-kt6s_EYbYko1DZi9ov5zOTCwj9bfrcx38EUMc9_PMQ
- Scan type: openvas-local-passive
- Severity: Low
- Threat score: 23/100
- Protection score: 77/100
- HTTP status: 200

## Threat Graph

- Website protection: [#########-] 90/100
- Connection safety: [##########] 100/100
- Certificate health: [########--] 75/100
- Privacy exposure: [########--] 82/100

## Findings

- [MEDIUM] Server Fingerprint Exposed: Server header is exposed as `ESF`.
- [LOW] Missing Referrer Policy: No Referrer-Policy header was observed.
- [MEDIUM] Cookie Flags Need Review: 1 observed cookie definitions lacked Secure or HttpOnly markers in the visible response headers.
- [LOW] Cookie SameSite Not Visible: 2 observed cookie definitions did not visibly include SameSite.

## Offline CVE Hints

- CVE-2021-34527: PrintNightmare

## Raw Summary

Cyber Analysis Report: https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fdrive.google.com%2Fdrive%2Fhome&dsh=S-29558870%3A1774798657803040&followup=https%3A%2F%2Fdrive.google.com%2Fdrive%2Fhome&osid=1&passive=1209600&service=wise&flowName=WebLiteSignIn&flowEntry=ServiceLogin&ifkv=AT1y2_X5LsrhmK0RvwayoCorROAv3KgMnKh-kt6s_EYbYko1DZi9ov5zOTCwj9bfrcx38EUMc9_PMQ
Severity: Low
Threat score: 23/100
Protection score: 77/100

Easy summary:
This passive scan found only limited visible exposure on the public website surface.

Threat graph:
- Website protection   [#########-] 90/100
- Connection safety    [##########] 100/100
- Certificate health   [########--] 75/100
- Privacy exposure     [########--] 82/100

Key findings:
- [MEDIUM] Server Fingerprint Exposed: Server header is exposed as `ESF`.
- [LOW] Missing Referrer Policy: No Referrer-Policy header was observed.
- [MEDIUM] Cookie Flags Need Review: 1 observed cookie definitions lacked Secure or HttpOnly markers in the visible response headers.
- [LOW] Cookie SameSite Not Visible: 2 observed cookie definitions did not visibly include SameSite.

TLS days remaining: 63

Learned assessment:
- Model label: Low
- Confidence: 92%
- Models used: mlp, lstm, gnn

CVE bug context:
- CVE-2021-34527 [Critical]: Vulnerable spooler behavior can allow remote code execution or privilege escalation.
  Fix: patch Windows, disable spooler on systems that do not need it, and monitor driver installation events.

Limit:
- This is a passive local assessment, not an intrusive vulnerability exploit scan.
