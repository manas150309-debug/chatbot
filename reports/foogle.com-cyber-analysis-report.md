# Cyber Analysis Report

- URL: https://foogle.com
- Scan type: openvas-local-passive
- Severity: Medium
- Threat score: 44/100
- Protection score: 56/100
- HTTP status: 200

## Threat Graph

- Header hardening: [##--------] 20/100
- Transport security: [##########] 100/100
- TLS hygiene: [########--] 75/100
- Disclosure control: [########--] 82/100

## Findings

- [MEDIUM] Server Fingerprint Exposed: Server header is exposed as `Apache`.
- [MEDIUM] Missing HSTS: HTTPS is used, but HSTS was not observed.
- [MEDIUM] Missing CSP: No Content-Security-Policy header was observed.
- [LOW] Missing MIME-Sniffing Protection: No X-Content-Type-Options header was observed.
- [LOW] Missing Referrer Policy: No Referrer-Policy header was observed.
- [MEDIUM] Weak Clickjacking Protection: Neither X-Frame-Options nor CSP frame controls were observed.

## Offline CVE Hints

- CVE-PLAYBOOK-APACHE-KAFKA-LOGGING-EXPOSURE-0080: CVE Triage Playbook: Apache Kafka Logging Exposure
- CVE-PLAYBOOK-APACHE-KAFKA-REDIRECT-ABUSE-0079: CVE Triage Playbook: Apache Kafka Redirect Abuse
- CVE-PLAYBOOK-APACHE-KAFKA-SESSION-RISK-0078: CVE Triage Playbook: Apache Kafka Session Risk

## Raw Summary

Cyber Analysis Report: https://foogle.com
Severity: Medium
Threat score: 44/100
Protection score: 56/100

Easy summary:
This passive scan found visible web-security gaps that deserve review.

Threat graph:
- Header hardening      [##--------] 20/100
- Transport security   [##########] 100/100
- TLS hygiene          [########--] 75/100
- Disclosure control   [########--] 82/100

Key findings:
- [MEDIUM] Server Fingerprint Exposed: Server header is exposed as `Apache`.
- [MEDIUM] Missing HSTS: HTTPS is used, but HSTS was not observed.
- [MEDIUM] Missing CSP: No Content-Security-Policy header was observed.
- [LOW] Missing MIME-Sniffing Protection: No X-Content-Type-Options header was observed.
- [LOW] Missing Referrer Policy: No Referrer-Policy header was observed.
- [MEDIUM] Weak Clickjacking Protection: Neither X-Frame-Options nor CSP frame controls were observed.

TLS days remaining: 72

Learned assessment:
- Model label: Medium
- Confidence: 100%
- Models used: mlp, lstm, gnn

Offline CVE hints:
- CVE-PLAYBOOK-APACHE-KAFKA-LOGGING-EXPOSURE-0080: CVE Triage Playbook: Apache Kafka Logging Exposure
- CVE-PLAYBOOK-APACHE-KAFKA-REDIRECT-ABUSE-0079: CVE Triage Playbook: Apache Kafka Redirect Abuse
- CVE-PLAYBOOK-APACHE-KAFKA-SESSION-RISK-0078: CVE Triage Playbook: Apache Kafka Session Risk

Limit:
- This is a passive local assessment, not an intrusive vulnerability exploit scan.
