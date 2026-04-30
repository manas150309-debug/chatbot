"""
DarkTraceX demo module for copyright and patent support.

Copyright (c) 2026 Manas.
All rights reserved.

Patent notice:
This file is a technical demonstration artifact for the DarkTraceX
cyber-analysis workflow. Replace this notice with your real filing number
or "Patent Pending" text if you have already filed.

This file is not legal advice. It is a compact code sample that shows
how DarkTraceX maps passive observations into a user-readable report card.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PassiveWebsiteSnapshot:
    domain: str
    server_header: str
    has_hsts: bool
    has_enforced_csp: bool
    has_referrer_policy: bool
    cookie_samesite_visible: bool
    tls_days_remaining: int


@dataclass
class ThreatReportCard:
    severity: str
    threat_score: int
    protection_score: int
    website_protection: int
    connection_safety: int
    certificate_health: int
    privacy_exposure: int
    executive_summary: str


def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def score_snapshot(snapshot: PassiveWebsiteSnapshot) -> ThreatReportCard:
    threat_score = 0
    website_protection = 100
    connection_safety = 100
    certificate_health = 100
    privacy_exposure = 100

    if snapshot.server_header:
        threat_score += 8
        website_protection -= 12
        privacy_exposure -= 10

    if not snapshot.has_hsts:
        threat_score += 12
        website_protection -= 20

    if not snapshot.has_enforced_csp:
        threat_score += 10
        website_protection -= 15

    if not snapshot.has_referrer_policy:
        threat_score += 6
        privacy_exposure -= 12

    if not snapshot.cookie_samesite_visible:
        threat_score += 5
        privacy_exposure -= 10

    if snapshot.tls_days_remaining < 15:
        threat_score += 10
        certificate_health -= 35
    elif snapshot.tls_days_remaining < 45:
        threat_score += 5
        certificate_health -= 20
    else:
        certificate_health -= 5

    threat_score = clamp(threat_score)
    website_protection = clamp(website_protection)
    connection_safety = clamp(connection_safety)
    certificate_health = clamp(certificate_health)
    privacy_exposure = clamp(privacy_exposure)
    protection_score = clamp(
        round(
            (
                website_protection
                + connection_safety
                + certificate_health
                + privacy_exposure
            )
            / 4
        )
    )

    if threat_score >= 70:
        severity = "High"
    elif threat_score >= 35:
        severity = "Medium"
    else:
        severity = "Low"

    executive_summary = (
        f"DarkTraceX scored {snapshot.domain} as {severity.lower()} risk based on "
        "passive web-surface indicators and converted the result into a user-facing "
        "report card."
    )

    return ThreatReportCard(
        severity=severity,
        threat_score=threat_score,
        protection_score=protection_score,
        website_protection=website_protection,
        connection_safety=connection_safety,
        certificate_health=certificate_health,
        privacy_exposure=privacy_exposure,
        executive_summary=executive_summary,
    )


def render_ascii_bar(label: str, value: int) -> str:
    filled = round(value / 10)
    bar = "#" * filled + "-" * (10 - filled)
    return f"{label:<22} [{bar}] {value}/100"


def demo() -> str:
    snapshot = PassiveWebsiteSnapshot(
        domain="example-company.com",
        server_header="gws",
        has_hsts=False,
        has_enforced_csp=False,
        has_referrer_policy=False,
        cookie_samesite_visible=False,
        tls_days_remaining=28,
    )
    report = score_snapshot(snapshot)
    lines = [
        "Cyber Analysis Report Demo",
        f"Target: {snapshot.domain}",
        f"Severity: {report.severity}",
        f"Threat score: {report.threat_score}/100",
        f"Protection score: {report.protection_score}/100",
        "",
        "Executive Summary:",
        report.executive_summary,
        "",
        "Risk View:",
        render_ascii_bar("Website protection", report.website_protection),
        render_ascii_bar("Connection safety", report.connection_safety),
        render_ascii_bar("Certificate health", report.certificate_health),
        render_ascii_bar("Privacy exposure", report.privacy_exposure),
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(demo())
