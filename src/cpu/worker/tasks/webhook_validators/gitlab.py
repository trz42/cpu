# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

GitLab webhook signature validator (GitLab 19+ signing-token scheme only).

GitLab 19.0 introduced a signing-token scheme where webhooks are signed with
HMAC-SHA256 and the signature is sent in the "Webhook-Signature" header:

    Webhook-Signature: v1,<base64(HMAC-SHA256(key, webhook_id.timestamp.body))>

The key is the base64-decoded signing token (configured per webhook in
GitLab, stored in CPU as a base64-encoded string). Multiple space-separated
signatures may be present (key rotation); validation succeeds if any one of
them matches.

This validator explicitly does NOT support the legacy "X-Gitlab-Token"
plain-secret scheme used by GitLab < 19. Requests that carry only that header
are recognised as GitLab but rejected with a clear error message.

See https://docs.gitlab.com/user/project/integrations/webhooks/#signing-tokens
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
from collections.abc import Mapping

from cpu.worker.tasks.webhook_validators.base import (
    WEBHOOK_VALIDATORS,
    PlatformWebhookValidator,
    WebhookValidationError,
    get_header,
)

logger = logging.getLogger(__name__)

_HEADER_EVENT = "X-Gitlab-Event"
_HEADER_SIGNATURE = "Webhook-Signature"
_HEADER_TOKEN_LEGACY = "X-Gitlab-Token"
_HEADER_WEBHOOK_ID = "Webhook-Id"
_HEADER_TIMESTAMP = "Webhook-Timestamp"

_GITLAB_IDENTIFYING_HEADERS = (
    _HEADER_EVENT,
    _HEADER_SIGNATURE,
    _HEADER_TOKEN_LEGACY,
)

_V1_PREFIX = "v1,"


class GitLabWebhookValidator(PlatformWebhookValidator):
    """Validates webhook signatures from GitLab 19+ (signing-token scheme)."""

    platform = "gitlab"

    @classmethod
    def matches(cls, headers: Mapping[str, str]) -> bool:
        # X-Gitlab-Token (legacy) is also recognised so that validate() can
        # return a clear "unsupported scheme" error instead of "unknown platform".
        return any(get_header(headers, header) is not None for header in _GITLAB_IDENTIFYING_HEADERS)

    def validate(self, headers: Mapping[str, str], raw_body: bytes, secret: str) -> None:
        """
        Verify the GitLab webhook signature (signing-token scheme, GitLab 19+).

        Args:
            headers: Incoming request headers.
            raw_body: Raw request body bytes.
            secret: Base64-encoded signing token as configured in GitLab and
                stored in CPU's secret manager.

        Raises:
            WebhookValidationError: If the Webhook-Signature header is
                absent (including when only the legacy X-Gitlab-Token is
                present), if no "v1," signature is found, if required
                "Webhook-Id" or "Webhook-Timestamp" headers are missing,
                if the secret is not valid base64, or if no signature matches.
        """
        signature_header = get_header(headers, _HEADER_SIGNATURE)

        if signature_header is None:
            if get_header(headers, _HEADER_TOKEN_LEGACY) is not None:
                raise WebhookValidationError(
                    f"Webhook signed with the legacy {_HEADER_TOKEN_LEGACY} header is not supported. "
                    "Configure a signing token in GitLab (requires GitLab 19+) to use the "
                    f"{_HEADER_SIGNATURE} scheme."
                )
            raise WebhookValidationError(f"Missing {_HEADER_SIGNATURE} header")

        # GitLab may send a space-separated list of signatures for key rotation.
        signatures = signature_header.split(" ")
        v1_signatures = [sig for sig in signatures if sig.startswith(_V1_PREFIX)]
        if not v1_signatures:
            raise WebhookValidationError(
                f"No supported signature scheme found in {_HEADER_SIGNATURE} header "
                f"(expected '{_V1_PREFIX}' prefix, got: {signature_header!r})"
            )

        webhook_id = get_header(headers, _HEADER_WEBHOOK_ID)
        if webhook_id is None:
            raise WebhookValidationError(f"Missing {_HEADER_WEBHOOK_ID} header")

        timestamp = get_header(headers, _HEADER_TIMESTAMP)
        if timestamp is None:
            raise WebhookValidationError(f"Missing {_HEADER_TIMESTAMP} header")

        try:
            key = base64.standard_b64decode(secret)
        except Exception as err:
            raise WebhookValidationError(
                f"GitLab webhook secret is not valid base64: {err}"
            ) from err

        components = (webhook_id.encode(), timestamp.encode(), raw_body)
        mac = hmac.new(key, msg=b".".join(components), digestmod=hashlib.sha256)
        expected = _V1_PREFIX + base64.standard_b64encode(mac.digest()).decode()

        if not any(hmac.compare_digest(expected, sig) for sig in v1_signatures):
            raise WebhookValidationError("GitLab webhook signature verification failed")


# Self-register in the global validator registry.
# This side-effect runs when the module is first imported, which is triggered
# by cpu.worker.tasks.webhook_validators.__init__ importing this module.
WEBHOOK_VALIDATORS.append(GitLabWebhookValidator)
