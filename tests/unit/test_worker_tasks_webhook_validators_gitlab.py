# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.worker.tasks.webhook_validators.gitlab: GitLabWebhookValidator.

Verifies webhook signatures using GitLab's signing-token scheme
(Webhook-Signature header, HMAC-SHA256, "v1,<base64>"), introduced in
GitLab 19.0 (generally available in 19.1). The legacy plain secret-token
scheme (X-Gitlab-Token header, used by GitLab < 19) is intentionally
NOT supported: a request carrying only that header is recognised as a
GitLab request but rejected with a clear error.

See https://docs.gitlab.com/user/project/integrations/webhooks/
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from cpu.worker.tasks.webhook_validators.base import WebhookValidationError
from cpu.worker.tasks.webhook_validators.gitlab import GitLabWebhookValidator

# base64-encoded signing token (decodes to a 32-byte raw key)
SECRET_B64 = base64.standard_b64encode(b"gitlab-signing-key-32-bytes!!!!").decode()
RAW_BODY = b'{"object_kind":"push","event_type":"push"}'
WEBHOOK_ID = "3c5c0404-c866-44bc-a5f6-452bb1bfc76e"
TIMESTAMP = "1718000000"


def _v1_signature(secret_b64: str, webhook_id: str, timestamp: str, raw_body: bytes) -> str:
    key = base64.standard_b64decode(secret_b64)
    components = (webhook_id.encode(), timestamp.encode(), raw_body)
    mac = hmac.new(key, msg=b".".join(components), digestmod=hashlib.sha256)
    return "v1," + base64.standard_b64encode(mac.digest()).decode()


def _headers(
    signature: str | None = "unset",
    webhook_id: str | None = WEBHOOK_ID,
    timestamp: str | None = TIMESTAMP,
) -> dict[str, str]:
    """Build GitLab request headers; pass signature=None to omit it entirely."""
    headers: dict[str, str] = {"X-Gitlab-Event": "Push Hook"}
    if signature == "unset":
        signature = _v1_signature(SECRET_B64, WEBHOOK_ID, TIMESTAMP, RAW_BODY)
    if signature is not None:
        headers["Webhook-Signature"] = signature
    if webhook_id is not None:
        headers["Webhook-Id"] = webhook_id
    if timestamp is not None:
        headers["Webhook-Timestamp"] = timestamp
    return headers


class TestGitLabWebhookValidatorMatches:
    """Tests for platform self-identification from request headers."""

    def test_matches_on_event_header(self) -> None:
        assert GitLabWebhookValidator.matches({"X-Gitlab-Event": "Push Hook"}) is True

    def test_matches_on_webhook_signature_header(self) -> None:
        assert GitLabWebhookValidator.matches({"Webhook-Signature": "v1,abc"}) is True

    def test_matches_on_legacy_token_header(self) -> None:
        # Still recognised as GitLab, so validate() can reject it with a
        # clear "unsupported scheme" error instead of "unknown platform".
        assert GitLabWebhookValidator.matches({"X-Gitlab-Token": "secret"}) is True

    def test_does_not_match_unrelated_headers(self) -> None:
        assert GitLabWebhookValidator.matches({"X-GitHub-Event": "push"}) is False

    def test_platform_attribute(self) -> None:
        assert GitLabWebhookValidator.platform == "gitlab"


class TestGitLabWebhookValidatorValidateSuccess:
    """Tests for successful signature verification."""

    def test_valid_signature_passes(self) -> None:
        GitLabWebhookValidator().validate(_headers(), RAW_BODY, SECRET_B64)  # must not raise

    def test_one_of_multiple_space_separated_signatures_matches(self) -> None:
        valid = _v1_signature(SECRET_B64, WEBHOOK_ID, TIMESTAMP, RAW_BODY)
        signature_header = f"v1,bogus== {valid}"
        GitLabWebhookValidator().validate(_headers(signature_header), RAW_BODY, SECRET_B64)

    def test_case_insensitive_header_lookup(self) -> None:
        signature = _v1_signature(SECRET_B64, WEBHOOK_ID, TIMESTAMP, RAW_BODY)
        headers = {
            "x-gitlab-event": "Push Hook",
            "webhook-signature": signature,
            "webhook-id": WEBHOOK_ID,
            "webhook-timestamp": TIMESTAMP,
        }
        GitLabWebhookValidator().validate(headers, RAW_BODY, SECRET_B64)


class TestGitLabWebhookValidatorValidateFailure:
    """Tests for rejected requests."""

    def test_invalid_signature_raises(self) -> None:
        bogus = "v1," + base64.standard_b64encode(b"0" * 32).decode()
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate(_headers(bogus), RAW_BODY, SECRET_B64)

    def test_wrong_secret_fails_verification(self) -> None:
        valid_for_other_secret = _v1_signature(
            base64.standard_b64encode(b"a-different-key-32-bytes!!!!!!!").decode(),
            WEBHOOK_ID,
            TIMESTAMP,
            RAW_BODY,
        )
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate(_headers(valid_for_other_secret), RAW_BODY, SECRET_B64)

    def test_missing_webhook_signature_header_raises(self) -> None:
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate(_headers(signature=None), RAW_BODY, SECRET_B64)

    # TODO how about a test with a header that has both the legacy token and the new signing token?
    def test_legacy_token_only_request_is_explicitly_rejected(self) -> None:
        headers = {"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "plain-secret"}
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate(headers, RAW_BODY, SECRET_B64)

    def test_signature_without_v1_prefix_raises(self) -> None:
        headers = _headers(signature="v2,deadbeef")
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate(headers, RAW_BODY, SECRET_B64)

    def test_missing_webhook_id_raises(self) -> None:
        signature = _v1_signature(SECRET_B64, WEBHOOK_ID, TIMESTAMP, RAW_BODY)
        headers = _headers(signature=signature, webhook_id=None)
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate(headers, RAW_BODY, SECRET_B64)

    def test_missing_timestamp_raises(self) -> None:
        signature = _v1_signature(SECRET_B64, WEBHOOK_ID, TIMESTAMP, RAW_BODY)
        headers = _headers(signature=signature, timestamp=None)
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate(headers, RAW_BODY, SECRET_B64)

    def test_non_base64_secret_raises(self) -> None:
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate(_headers(), RAW_BODY, "abc")

    def test_empty_headers_raises(self) -> None:
        with pytest.raises(WebhookValidationError):
            GitLabWebhookValidator().validate({}, RAW_BODY, SECRET_B64)
