# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

GitHub webhook signature validator.

Validates webhook signatures per
https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

GitHub signs requests with HMAC using the webhook secret as the key and the
raw request body as the message. Two headers may be present:

- "X-Hub-Signature-256" — HMAC-SHA256 in "sha256=<hexdigest>" format
  (recommended, preferred when present).
- "X-Hub-Signature" — HMAC-SHA1 in "sha1=<hexdigest>" format
  (legacy, accepted as fallback when the SHA-256 header is absent).

At least one of these headers must be present; if both are present the
SHA-256 header takes precedence and SHA-1 is ignored.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from collections.abc import Mapping
from typing import Any

from cpu.worker.tasks.webhook_validators.base import (
    WEBHOOK_VALIDATORS,
    PlatformWebhookValidator,
    WebhookValidationError,
    get_header,
)

logger = logging.getLogger(__name__)

_HEADER_EVENT = "X-GitHub-Event"
_HEADER_SIGNATURE_256 = "X-Hub-Signature-256"
_HEADER_SIGNATURE_1 = "X-Hub-Signature"

_GITHUB_IDENTIFYING_HEADERS = (
    _HEADER_EVENT,
    _HEADER_SIGNATURE_256,
    _HEADER_SIGNATURE_1,
)


class GitHubWebhookValidator(PlatformWebhookValidator):
    """Validates webhook signatures from GitHub."""

    platform = "github"

    @classmethod
    def matches(cls, headers: Mapping[str, str]) -> bool:
        return any(get_header(headers, header) is not None for header in _GITHUB_IDENTIFYING_HEADERS)

    def validate(self, headers: Mapping[str, str], raw_body: bytes, secret: str) -> None:
        """
        Verify the GitHub webhook signature.

        Prefers the SHA-256 signature ("X-Hub-Signature-256"); falls back
        to the SHA-1 signature ("X-Hub-Signature") when the SHA-256 header
        is absent. Raises if neither header is present.

        Args:
            headers: Incoming request headers.
            raw_body: Raw request body bytes.
            secret: Webhook secret string (UTF-8, as configured in GitHub).

        Raises:
            WebhookValidationError: If the signature is missing, malformed,
                or does not match.
        """
        sig256 = get_header(headers, _HEADER_SIGNATURE_256)
        if sig256 is not None:
            self._verify(sig256, hashlib.sha256, "sha256", secret, raw_body)
            return

        sig1 = get_header(headers, _HEADER_SIGNATURE_1)
        if sig1 is not None:
            self._verify(sig1, hashlib.sha1, "sha1", secret, raw_body)
            return

        raise WebhookValidationError(
            f"Missing GitHub signature headers: expected {_HEADER_SIGNATURE_256} "
            f"(preferred) or {_HEADER_SIGNATURE_1} (legacy)"
        )

    @staticmethod
    def _verify(
        header_value: str,
        digestmod: Any,
        algo: str,
        secret: str,
        raw_body: bytes,
    ) -> None:
        """Compute the expected HMAC and compare it to the header value."""
        expected = f"{algo}=" + hmac.new(secret.encode(), raw_body, digestmod).hexdigest()
        if not hmac.compare_digest(expected, header_value):
            raise WebhookValidationError(f"GitHub {algo.upper()} signature verification failed")


# Self-register in the global validator registry.
# This side-effect runs when the module is first imported, which is triggered
# by cpu.worker.tasks.webhook_validators.__init__ importing this module.
WEBHOOK_VALIDATORS.append(GitHubWebhookValidator)
