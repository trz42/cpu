# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.worker.tasks.webhook_validators.base: the
PlatformWebhookValidator interface, the case-insensitive header lookup
helper, and the platform-detection registry used to dispatch webhook
validation to the right platform-specific validator.

The registry is what lets new hosting platforms be supported later by
adding one new validator module and registering it, without touching
detect_platform() or anything that calls it.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from cpu.worker.tasks.webhook_validators.base import (
    WEBHOOK_VALIDATORS,
    PlatformWebhookValidator,
    UnsupportedPlatformError,
    WebhookValidationError,
    detect_platform,
    get_header,
)


class TestGetHeader:
    """Tests for the case-insensitive header lookup helper."""

    # TODO how does it work that we support both exact case AND case insensitive match with the same function
    def test_exact_case_match(self) -> None:
        headers = {"X-Hub-Signature-256": "sha256=abc"}
        assert get_header(headers, "X-Hub-Signature-256") == "sha256=abc"

    def test_case_insensitive_match(self) -> None:
        headers = {"x-hub-signature-256": "sha256=abc"}
        assert get_header(headers, "X-Hub-Signature-256") == "sha256=abc"

    def test_mixed_case_match(self) -> None:
        headers = {"X-hub-SIGNATURE-256": "sha256=abc"}
        assert get_header(headers, "x-hub-signature-256") == "sha256=abc"

    def test_missing_header_returns_none(self) -> None:
        headers: Mapping[str, str] = {}
        assert get_header(headers, "X-Hub-Signature-256") is None

    def test_does_not_partial_match(self) -> None:
        headers = {"X-Hub-Signature": "sha1=abc"}
        # "X-Hub-Signature-256" must not match on the "X-Hub-Signature" prefix.
        assert get_header(headers, "X-Hub-Signature-256") is None


class TestPlatformWebhookValidatorInterface:
    """Tests for the abstract PlatformWebhookValidator base class."""

    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            PlatformWebhookValidator()  # type: ignore[abstract]


class TestWebhookValidationErrors:
    """Tests for the exception hierarchy."""

    def test_unsupported_platform_error_is_webhook_validation_error(self) -> None:
        assert issubclass(UnsupportedPlatformError, WebhookValidationError)

    def test_webhook_validation_error_is_exception(self) -> None:
        assert issubclass(WebhookValidationError, Exception)


class _StubValidatorA(PlatformWebhookValidator):
    """Minimal concrete validator used to test registry/detection in isolation."""

    platform = "stub_a"

    @classmethod
    def matches(cls, headers: Mapping[str, str]) -> bool:
        return get_header(headers, "X-Stub-A") is not None

    def validate(self, headers: Mapping[str, str], raw_body: bytes, secret: str) -> None:
        del headers, raw_body, secret


class _StubValidatorB(PlatformWebhookValidator):
    """Second minimal concrete validator used to test registry/detection."""

    platform = "stub_b"

    @classmethod
    def matches(cls, headers: Mapping[str, str]) -> bool:
        return get_header(headers, "X-Stub-B") is not None

    def validate(self, headers: Mapping[str, str], raw_body: bytes, secret: str) -> None:
        del headers, raw_body, secret


class TestWebhookValidatorsRegistry:
    """Tests for the built-in registry contents."""

    def test_registry_contains_github_validator(self) -> None:
        from cpu.worker.tasks.webhook_validators.github import GitHubWebhookValidator

        assert GitHubWebhookValidator in WEBHOOK_VALIDATORS

    def test_registry_contains_gitlab_validator(self) -> None:
        from cpu.worker.tasks.webhook_validators.gitlab import GitLabWebhookValidator

        assert GitLabWebhookValidator in WEBHOOK_VALIDATORS


class TestDetectPlatform:
    """
    Tests for detect_platform().

    Uses stub validators (via monkeypatching the module-level registry) to
    isolate dispatch behaviour from real platform logic, plus a couple of
    tests against the real, built-in registry.
    """

    def test_detects_matching_validator(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "cpu.worker.tasks.webhook_validators.base.WEBHOOK_VALIDATORS",
            [_StubValidatorA, _StubValidatorB],
        )
        result = detect_platform({"X-Stub-B": "1"})
        assert result is _StubValidatorB

    def test_first_registered_match_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "cpu.worker.tasks.webhook_validators.base.WEBHOOK_VALIDATORS",
            [_StubValidatorA, _StubValidatorB],
        )
        result = detect_platform({"X-Stub-A": "1", "X-Stub-B": "1"})
        assert result is _StubValidatorA

    def test_raises_when_no_validator_matches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "cpu.worker.tasks.webhook_validators.base.WEBHOOK_VALIDATORS",
            [_StubValidatorA, _StubValidatorB],
        )
        with pytest.raises(UnsupportedPlatformError):
            detect_platform({"X-Something-Else": "1"})

    def test_real_registry_detects_github(self) -> None:
        from cpu.worker.tasks.webhook_validators.github import GitHubWebhookValidator

        result = detect_platform({"X-GitHub-Event": "push"})
        assert result is GitHubWebhookValidator

    def test_real_registry_detects_gitlab(self) -> None:
        from cpu.worker.tasks.webhook_validators.gitlab import GitLabWebhookValidator

        result = detect_platform({"X-Gitlab-Event": "Push Hook"})
        assert result is GitLabWebhookValidator

    def test_real_registry_raises_for_unknown_platform(self) -> None:
        with pytest.raises(UnsupportedPlatformError):
            detect_platform({"X-Bitbucket-Event": "repo:push"})
