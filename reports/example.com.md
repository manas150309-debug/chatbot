# URL Threat Report

- URL: https://example.com
- Severity: Medium
- Threat score: 31/100
- Protection score: 69/100
- HTTP status: 200

## Threat Graph

- Header hardening: [##--------] 20/100
- Transport security: [##########] 100/100
- TLS hygiene: [########--] 75/100
- Disclosure control: [########--] 82/100

## Findings

- Missing HSTS header.
- Missing Content-Security-Policy header.
- Missing X-Content-Type-Options header.
- Missing Referrer-Policy header.
- Neither X-Frame-Options nor CSP frame-ancestors is present.
- Server header exposed: cloudflare

## Raw Summary

URL Threat Report: https://example.com
Severity: Medium
Threat score: 31/100
Protection score: 69/100

Easy summary:
This site shows some visible web-security gaps in the local checks and should be reviewed.

Threat graph:
- Header hardening      [##--------] 20/100
- Transport security   [##########] 100/100
- TLS hygiene          [########--] 75/100
- Disclosure control   [########--] 82/100

Main findings:
- Missing HSTS header.
- Missing Content-Security-Policy header.
- Missing X-Content-Type-Options header.
- Missing Referrer-Policy header.
- Neither X-Frame-Options nor CSP frame-ancestors is present.
- Server header exposed: cloudflare

TLS days remaining: 50

CVE note:
- No direct offline CVE mapping was found for this domain or product name.
