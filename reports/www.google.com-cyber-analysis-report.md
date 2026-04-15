# Cyber Analysis Report

- URL: https://www.google.com/
- Scan type: openvas-local-passive
- Severity: Medium
- Threat score: 45/100
- Protection score: 55/100
- HTTP status: 200

## Threat Graph

- Header hardening: [####------] 35/100
- Transport security: [##########] 100/100
- TLS hygiene: [########--] 75/100
- Disclosure control: [########--] 82/100

## Findings

- [MEDIUM] Server Fingerprint Exposed: Server header is exposed as `gws`.
- [MEDIUM] Missing HSTS: HTTPS is used, but HSTS was not observed.
- [MEDIUM] Missing CSP: No Content-Security-Policy header was observed.
- [LOW] Missing MIME-Sniffing Protection: No X-Content-Type-Options header was observed.
- [LOW] Missing Referrer Policy: No Referrer-Policy header was observed.
- [MEDIUM] Cookie Flags Need Review: 1 observed cookie definitions lacked Secure or HttpOnly markers in the visible response headers.
- [LOW] Cookie SameSite Not Visible: 2 observed cookie definitions did not visibly include SameSite.

## Offline CVE Hints

- None found from visible fingerprints.

## Raw Summary

Cyber Analysis Report: https://www.google.com/
Severity: Medium
Threat score: 45/100
Protection score: 55/100

Easy summary:
This passive scan found visible web-security gaps that deserve review.

Threat graph:
- Header hardening      [####------] 35/100
- Transport security   [##########] 100/100
- TLS hygiene          [########--] 75/100
- Disclosure control   [########--] 82/100

Key findings:
- [MEDIUM] Server Fingerprint Exposed: Server header is exposed as `gws`.
- [MEDIUM] Missing HSTS: HTTPS is used, but HSTS was not observed.
- [MEDIUM] Missing CSP: No Content-Security-Policy header was observed.
- [LOW] Missing MIME-Sniffing Protection: No X-Content-Type-Options header was observed.
- [LOW] Missing Referrer Policy: No Referrer-Policy header was observed.
- [MEDIUM] Cookie Flags Need Review: 1 observed cookie definitions lacked Secure or HttpOnly markers in the visible response headers.
- [LOW] Cookie SameSite Not Visible: 2 observed cookie definitions did not visibly include SameSite.

TLS days remaining: 66

Learned assessment:
- Model label: Medium
- Confidence: 100%
- Models used: mlp, lstm, gnn

Offline CVE hints:
- No direct offline CVE hint was mapped from the visible host and header fingerprints.

Limit:
- This is a passive local assessment, not an intrusive vulnerability exploit scan.
