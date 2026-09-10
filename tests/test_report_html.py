"""Tests for `SecurityReport.to_html()` — synthetic, DVAS-independent.

Finding text ultimately traces back to something a skill or a fetched
document "said" (a title, a resource path, a why-flagged reason). In a
real deployment (the MCP proxy, fronting a real server) that's
attacker-reachable text. A report generator that interpolates it into HTML
without escaping is an XSS vector in its own security tool's output —
exactly the kind of thing worth a permanent, explicit regression test
rather than trusting that real lab fixtures happen not to contain angle
brackets.
"""

from __future__ import annotations

from html.parser import HTMLParser

from skillfence.reporting.security_report import SecurityReport

_INJECTION = '<script>alert(1)</script>'


def _malicious_report() -> SecurityReport:
    return SecurityReport(
        lab="test-lab",
        skill=_INJECTION,
        risk="critical",
        cds=0.95,
        cds_band="BLOCK",
        ast=["AST01", _INJECTION],
        findings=[
            {
                "title": _INJECTION,
                "severity": "critical",
                "ast": ["AST01", _INJECTION],
                "action": _INJECTION,
                "resource": _INJECTION,
                "status": "blocked",
                "human_decision": "reject",
                "why_flagged": [_INJECTION, "sensitive credential read (+40)"],
                "attack_chain": [_INJECTION, "Sensitive Tool Request"],
            }
        ],
        attack_chains=[[_INJECTION]],
        decision="BLOCKED",
        human_decisions=["reject"],
        evidence_event_count=3,
    )


def test_html_report_is_well_formed():
    html_doc = _malicious_report().to_html()

    class _Strict(HTMLParser):
        def error(self, message):  # pragma: no cover - only hit on a real bug
            raise AssertionError(message)

    _Strict().feed(html_doc)  # raises on malformed markup


def test_html_report_never_contains_raw_script_tag():
    html_doc = _malicious_report().to_html()
    assert "<script>alert(1)</script>" not in html_doc
    assert "&lt;script&gt;" in html_doc  # escaped form is present instead


def test_html_report_contains_expected_summary_fields():
    html_doc = _malicious_report().to_html()
    assert "CRITICAL" in html_doc
    assert "0.95" in html_doc
    assert "BLOCK" in html_doc
    assert "BLOCKED" in html_doc


def test_html_report_handles_no_findings():
    report = SecurityReport(
        lab="clean-lab",
        skill="benign-skill",
        risk="low",
        cds=0.0,
        cds_band="ALLOW",
        ast=[],
        findings=[],
        attack_chains=[],
        decision="ALLOWED (no findings)",
        human_decisions=[],
        evidence_event_count=1,
    )
    html_doc = report.to_html()
    assert "No findings" in html_doc

    class _Strict(HTMLParser):
        def error(self, message):
            raise AssertionError(message)

    _Strict().feed(html_doc)
