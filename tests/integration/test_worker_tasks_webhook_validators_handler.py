# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.worker.tasks.webhook_validators.handler: WebhookValidationHandler,
the TaskHandler registered for TaskType.VALIDATE_WEBHOOK in a WorkerPoolComponent.

Given a task context of {"headers": ..., "body": ...}, the handler detects
the originating platform from the headers, fetches the matching webhook
secret from the default (catch-all) secret configuration for that
platform, and verifies the signature. Any failure (unsupported platform,
bad signature, missing secret configuration) is raised rather than
swallowed, so WorkerPoolComponent turns it into an error TASK_COMPLETE
result.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock

import pytest

from cpu.config.secrets import (
    GitHubAppSecrets,
    GitLabSecrets,
    SecretManager,
    SecretNotFoundError,
)
from cpu.config.secrets_context import SecretContext
from cpu.worker.tasks.types import TaskHandler
from cpu.worker.tasks.webhook_validators.base import (
    UnsupportedPlatformError,
    WebhookValidationError,
)
from cpu.worker.tasks.webhook_validators.handler import WebhookValidationHandler

GITHUB_SECRET = "github-webhook-secret"
GITLAB_SECRET_B64 = base64.standard_b64encode(b"gitlab-signing-key-32-bytes!!!!").decode()


def _github_secrets_manager(webhook_secret: str = GITHUB_SECRET) -> MagicMock:
    manager = MagicMock(spec=SecretManager)
    manager.get_github_secrets.return_value = GitHubAppSecrets(
        app_id="123456", private_key=b"pem-bytes", webhook_secret=webhook_secret
    )
    return manager


def _gitlab_secrets_manager(webhook_secret: str = GITLAB_SECRET_B64) -> MagicMock:
    manager = MagicMock(spec=SecretManager)
    manager.get_gitlab_secrets.return_value = GitLabSecrets(token="gitlab-token", webhook_secret=webhook_secret)
    return manager


def _github_request(body: dict[str, Any], secret: str = GITHUB_SECRET) -> dict[str, Any]:
    raw_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    signature = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return {
        "headers": {"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": signature},
        "body": body,
    }


def _gitlab_request(body: dict[str, Any], secret_b64: str = GITLAB_SECRET_B64) -> dict[str, Any]:
    raw_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    webhook_id = "abc-123"
    timestamp = "1718000000"
    key = base64.standard_b64decode(secret_b64)
    mac = hmac.new(key, msg=b".".join([webhook_id.encode(), timestamp.encode(), raw_body]), digestmod=hashlib.sha256)
    signature = "v1," + base64.standard_b64encode(mac.digest()).decode()
    return {
        "headers": {
            "X-Gitlab-Event": "Push Hook",
            "Webhook-Signature": signature,
            "Webhook-Id": webhook_id,
            "Webhook-Timestamp": timestamp,
        },
        "body": body,
    }


class TestWebhookValidationHandlerIsTaskHandler:
    def test_is_a_task_handler(self) -> None:
        validator = WebhookValidationHandler(secrets_manager=MagicMock(spec=SecretManager))
        assert isinstance(validator, TaskHandler)


class TestWebhookValidationHandlerGitHub:
    """Tests for dispatching GitHub webhooks."""

    def test_valid_github_webhook_succeeds(self) -> None:
        manager = _github_secrets_manager()
        validator = WebhookValidationHandler(secrets_manager=manager)
        context = _github_request({"action": "opened", "number": 42})

        result = validator.handle(context)

        assert result == {"platform": "github", "valid": True}

    def test_looks_up_github_secrets_with_platform_context(self) -> None:
        manager = _github_secrets_manager()
        validator = WebhookValidationHandler(secrets_manager=manager)
        validator.handle(_github_request({"action": "opened"}))

        manager.get_github_secrets.assert_called_once()
        used_context = manager.get_github_secrets.call_args.args[0]
        assert isinstance(used_context, SecretContext)
        assert used_context.platform == "github"
        manager.get_gitlab_secrets.assert_not_called()

    # TODO is this correctly implemented? should we not first validate then handle?
    def test_invalid_github_signature_raises(self) -> None:
        manager = _github_secrets_manager(webhook_secret="wrong-secret")
        validator = WebhookValidationHandler(secrets_manager=manager)
        context = _github_request({"action": "opened"})

        with pytest.raises(WebhookValidationError):
            validator.handle(context)


class TestWebhookValidationHandlerGitLab:
    """Tests for dispatching GitLab webhooks."""

    def test_valid_gitlab_webhook_succeeds(self) -> None:
        manager = _gitlab_secrets_manager()
        validator = WebhookValidationHandler(secrets_manager=manager)
        context = _gitlab_request({"object_kind": "push"})

        result = validator.handle(context)

        assert result == {"platform": "gitlab", "valid": True}

    def test_looks_up_gitlab_secrets_with_platform_context(self) -> None:
        manager = _gitlab_secrets_manager()
        validator = WebhookValidationHandler(secrets_manager=manager)
        validator.handle(_gitlab_request({"object_kind": "push"}))

        manager.get_gitlab_secrets.assert_called_once()
        used_context = manager.get_gitlab_secrets.call_args.args[0]
        assert isinstance(used_context, SecretContext)
        assert used_context.platform == "gitlab"
        manager.get_github_secrets.assert_not_called()

    def test_invalid_gitlab_signature_raises(self) -> None:
        other_secret = base64.standard_b64encode(b"a-different-key-32-bytes!!!!!!!").decode()
        manager = _gitlab_secrets_manager(webhook_secret=other_secret)
        validator = WebhookValidationHandler(secrets_manager=manager)
        context = _gitlab_request({"object_kind": "push"})

        with pytest.raises(WebhookValidationError):
            validator.handle(context)


class TestWebhookValidationHandlerErrors:
    """Tests for malformed input and missing secret configuration."""

    def test_platform_without_secret_lookup_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cpu.worker.tasks.webhook_validators.base import PlatformWebhookValidator, get_header

        class _StubValidator(PlatformWebhookValidator):
            platform = "stub_platform"

            @classmethod
            def matches(cls, headers: Mapping[str, str]) -> bool:
                return get_header(headers, "X-Stub-Platform") is not None

            def validate(self, headers: Mapping[str, str], raw_body: bytes, secret: str) -> None:
                pass  # signature always passes; we're testing the secret lookup branch

        monkeypatch.setattr(
            "cpu.worker.tasks.webhook_validators.base.WEBHOOK_VALIDATORS",
            [_StubValidator],
        )
        manager = MagicMock(spec=SecretManager)
        validator = WebhookValidationHandler(secrets_manager=manager)

        with pytest.raises(WebhookValidationError):
            validator.handle({"headers": {"X-Stub-Platform": "1"}, "body": {}})

    def test_unrecognized_platform_raises_unsupported(self) -> None:
        manager = MagicMock(spec=SecretManager)
        validator = WebhookValidationHandler(secrets_manager=manager)
        context = {"headers": {"X-Something-Else": "1"}, "body": {}}

        with pytest.raises(UnsupportedPlatformError):
            validator.handle(context)

    def test_missing_headers_key_raises(self) -> None:
        manager = MagicMock(spec=SecretManager)
        validator = WebhookValidationHandler(secrets_manager=manager)

        with pytest.raises(WebhookValidationError):
            validator.handle({"body": {}})

    def test_missing_body_key_raises(self) -> None:
        manager = MagicMock(spec=SecretManager)
        validator = WebhookValidationHandler(secrets_manager=manager)

        with pytest.raises(WebhookValidationError):
            validator.handle({"headers": {"X-GitHub-Event": "push"}})

    def test_no_matching_github_secret_config_propagates(self) -> None:
        manager = MagicMock(spec=SecretManager)
        manager.get_github_secrets.side_effect = SecretNotFoundError("no github config")
        validator = WebhookValidationHandler(secrets_manager=manager)
        context = _github_request({"action": "opened"})

        with pytest.raises(SecretNotFoundError):
            validator.handle(context)

    def test_no_matching_gitlab_secret_config_propagates(self) -> None:
        manager = MagicMock(spec=SecretManager)
        manager.get_gitlab_secrets.side_effect = SecretNotFoundError("no gitlab config")
        validator = WebhookValidationHandler(secrets_manager=manager)
        context = _gitlab_request({"object_kind": "push"})

        with pytest.raises(SecretNotFoundError):
            validator.handle(context)
