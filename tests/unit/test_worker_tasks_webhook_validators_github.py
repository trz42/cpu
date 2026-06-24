# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.worker.tasks.webhook_validators.github: GitHubWebhookValidator.

Verifies webhook signatures per
https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

Both the recommended SHA-256 signature (X-Hub-Signature-256) and the
legacy SHA-1 signature (X-Hub-Signature) are supported; SHA-256 is
preferred when both headers are present.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from cpu.worker.tasks.webhook_validators.base import WebhookValidationError
from cpu.worker.tasks.webhook_validators.github import GitHubWebhookValidator

SECRET = "super-secret-token"
RAW_BODY = b'{"action":"opened","number":42}'


def _sha256_signature(secret: str, raw_body: bytes) -> str:
    mac = hmac.new(secret.encode(), raw_body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _sha1_signature(secret: str, raw_body: bytes) -> str:
    mac = hmac.new(secret.encode(), raw_body, hashlib.sha1)
    return f"sha1={mac.hexdigest()}"


class TestGitHubWebhookValidatorMatches:
    """Tests for platform self-identification from request headers."""

    def test_matches_on_event_header(self) -> None:
        assert GitHubWebhookValidator.matches({"X-GitHub-Event": "push"}) is True

    def test_matches_on_sha256_signature_header(self) -> None:
        assert GitHubWebhookValidator.matches({"X-Hub-Signature-256": "sha256=abc"}) is True

    def test_matches_on_sha1_signature_header(self) -> None:
        assert GitHubWebhookValidator.matches({"X-Hub-Signature": "sha1=abc"}) is True

    def test_does_not_match_unrelated_headers(self) -> None:
        assert GitHubWebhookValidator.matches({"X-Gitlab-Event": "Push Hook"}) is False

    def test_platform_attribute(self) -> None:
        assert GitHubWebhookValidator.platform == "github"


class TestGitHubWebhookValidatorValidateSha256:
    """Tests for the preferred SHA-256 signature scheme."""

    def test_valid_sha256_signature_passes(self) -> None:
        headers = {"X-Hub-Signature-256": _sha256_signature(SECRET, RAW_BODY)}
        GitHubWebhookValidator().validate(headers, RAW_BODY, SECRET)  # must not raise

    def test_invalid_sha256_signature_raises(self) -> None:
        headers = {"X-Hub-Signature-256": "sha256=" + "0" * 64}
        with pytest.raises(WebhookValidationError):
            GitHubWebhookValidator().validate(headers, RAW_BODY, SECRET)

    def test_sha256_preferred_over_sha1_when_both_present(self) -> None:
        headers = {
            "X-Hub-Signature-256": _sha256_signature(SECRET, RAW_BODY),
            "X-Hub-Signature": "sha1=" + "0" * 40,  # would fail verification if checked
        }
        GitHubWebhookValidator().validate(headers, RAW_BODY, SECRET)  # must not raise

    def test_malformed_sha256_header_raises(self) -> None:
        headers = {"X-Hub-Signature-256": "not-a-valid-signature"}
        with pytest.raises(WebhookValidationError):
            GitHubWebhookValidator().validate(headers, RAW_BODY, SECRET)


class TestGitHubWebhookValidatorValidateSha1:
    """Tests for the legacy SHA-1 signature scheme (fallback only)."""

    def test_valid_sha1_signature_passes_when_sha256_absent(self) -> None:
        headers = {"X-Hub-Signature": _sha1_signature(SECRET, RAW_BODY)}
        GitHubWebhookValidator().validate(headers, RAW_BODY, SECRET)  # must not raise

    def test_invalid_sha1_signature_raises(self) -> None:
        headers = {"X-Hub-Signature": "sha1=" + "0" * 40}
        with pytest.raises(WebhookValidationError):
            GitHubWebhookValidator().validate(headers, RAW_BODY, SECRET)


class TestGitHubWebhookValidatorValidateMissingOrBadInput:
    """Tests for missing headers and edge cases."""

    def test_missing_signature_headers_raises(self) -> None:
        with pytest.raises(WebhookValidationError):
            GitHubWebhookValidator().validate({"X-GitHub-Event": "push"}, RAW_BODY, SECRET)

    def test_empty_headers_raises(self) -> None:
        with pytest.raises(WebhookValidationError):
            GitHubWebhookValidator().validate({}, RAW_BODY, SECRET)

    def test_wrong_secret_fails_verification(self) -> None:
        headers = {"X-Hub-Signature-256": _sha256_signature("the-right-secret", RAW_BODY)}
        with pytest.raises(WebhookValidationError):
            GitHubWebhookValidator().validate(headers, RAW_BODY, "the-wrong-secret")

    def test_case_insensitive_header_lookup(self) -> None:
        headers = {"x-hub-signature-256": _sha256_signature(SECRET, RAW_BODY)}
        GitHubWebhookValidator().validate(headers, RAW_BODY, SECRET)  # must not raise
