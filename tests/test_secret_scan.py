"""Unit tests for content-based secret detection. Pure logic, no fixtures
needed — this is exactly the kind of deterministic, offline-testable
detector the whole project is built around.
"""

from __future__ import annotations

from skillfence.policy.secret_scan import scan_for_secrets


def test_clean_content_returns_empty():
    assert scan_for_secrets("Q3 revenue was up 12% year over year.") == []


def test_empty_content_returns_empty():
    assert scan_for_secrets("") == []


def test_aws_access_key_detected():
    found = scan_for_secrets("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    assert "AWS Access Key ID" in found


def test_github_pat_detected():
    found = scan_for_secrets("token = ghp_" + "a" * 36)
    assert "GitHub Personal Access Token" in found


def test_github_fine_grained_pat_detected():
    found = scan_for_secrets("github_pat_" + "b" * 30)
    assert "GitHub Fine-Grained PAT" in found


def test_slack_token_detected():
    # repeated-character synthetic value (same technique the other fixtures
    # in this file use) -- a plausible-looking placeholder still trips
    # GitHub's own push-protection secret scanner, which can't tell
    # "obviously fake" from "real" any better than this detector can.
    found = scan_for_secrets("SLACK_BOT_TOKEN=xoxb-" + "a" * 20)
    assert "Slack Token" in found


def test_slack_webhook_url_detected():
    found = scan_for_secrets("post to https://hooks.slack.com/services/T" + "A" * 8 + "/B" + "A" * 8 + "/" + "a" * 24)
    assert "Slack Webhook URL" in found


def test_stripe_key_detected():
    found = scan_for_secrets("STRIPE_KEY=sk_live_" + "c" * 24)
    assert "Stripe Secret Key" in found


def test_google_api_key_detected():
    found = scan_for_secrets("AIza" + "d" * 35)
    assert "Google API Key" in found


def test_private_key_material_detected():
    found = scan_for_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----")
    assert "Private Key Material" in found


def test_jwt_shaped_token_detected():
    found = scan_for_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    assert "JWT-Shaped Token" in found


def test_generic_secret_assignment_detected():
    found = scan_for_secrets('password: "sup3rSecretValue123!"')
    assert "Generic secret-like assignment" in found


def test_result_never_contains_the_matched_secret_value():
    secret_value = "AKIAIOSFODNN7EXAMPLE"
    found = scan_for_secrets(f"AWS_ACCESS_KEY_ID={secret_value}")
    for label in found:
        assert secret_value not in label  # only the label, never the value


def test_multiple_distinct_secrets_all_reported_once_each():
    content = f"AKIAIOSFODNN7EXAMPLE\nghp_{'x' * 36}\nghp_{'y' * 36}"  # AWS + 2x github token
    found = scan_for_secrets(content)
    assert "AWS Access Key ID" in found
    assert found.count("GitHub Personal Access Token") == 1  # deduplicated despite 2 matches
