# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

TaskHandler for webhook signature validation (TaskType.VALIDATE_WEBHOOK).

WebhookValidationHandler is registered for TaskType.VALIDATE_WEBHOOK in a
WorkerPoolComponent. Given a task context produced by SmeeClientComponent
(or a direct webhook receiver), it:

1. Detects the originating platform from the request headers.
2. Fetches the webhook secret from the default (catch-all) secret
   configuration for that platform via SecretManager.
3. Re-serialises the body dict to bytes and runs the platform-specific
   signature validator.
4. Returns {"platform": "<name>", "valid": True} on success.

Any failure (unsupported platform, missing secret configuration, signature
mismatch) is raised rather than swallowed, so WorkerPoolComponent converts
it to an error TASK_COMPLETE result.

Note on Smee and raw-body fidelity
-----------------------------------
GitHub and GitLab sign the *exact raw bytes* of the original request body.
When webhooks arrive via Smee (a EESSI operated proxy), Smee parses and
re-serialises the JSON before forwarding it over SSE, and the CPU bot then
JSON-decodes it again. The bytes produced by re-serialising the parsed dict
here (json.dumps(body, separators=(",", ":"))) may not byte-match the
original signed payload (e.g. different whitespace or key ordering), which
can cause signature verification to fail for otherwise valid webhooks. This
is a known limitation of Smee and is expected with the used proxy (however,
in 3+ years of operations we never hit this issue)
"""

from __future__ import annotations

import json
import logging
from typing import Any

from cpu.config.secrets import SecretManager
from cpu.config.secrets_context import SecretContext
from cpu.worker.tasks.types import TaskHandler
from cpu.worker.tasks.webhook_validators.base import (
    PlatformWebhookValidator,
    WebhookValidationError,
    detect_platform,
)

logger = logging.getLogger(__name__)


class WebhookValidationHandler(TaskHandler):
    """
    Verifies the signature of an incoming webhook request.

    Registered for TaskType.VALIDATE_WEBHOOK in a WorkerPoolComponent.

    Args:
        secrets_manager: Used to fetch the webhook secret for the detected
            platform. A default (catch-all) SecretContext is used per
            platform; per-organisation or per-repository secret lookup is
            not yet implemented.
    """

    def __init__(self, secrets_manager: SecretManager) -> None:
        self.secrets_manager = secrets_manager

    def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Verify the webhook signature in the task context.

        Args:
            context: Task context dict, expected to contain:
                - "headers": dict of incoming request headers.
                - "body": parsed JSON body dict.

        Returns:
            {"platform": "<name>", "valid": True} on success.

        Raises:
            WebhookValidationError: If the context is malformed (missing
                "headers" or "body" key), or if the signature is
                absent or invalid.
            UnsupportedPlatformError: Propagated from detect_platform()
                if no registered validator matches the headers.
            SecretNotFoundError: Propagated from SecretManager if no
                secret configuration is found for the detected platform.
        """
        if "headers" not in context:
            raise WebhookValidationError("Task context is missing required key 'headers'")
        if "body" not in context:
            raise WebhookValidationError("Task context is missing required key 'body'")

        headers: dict[str, str] = context["headers"]
        body: Any = context["body"]

        validator_cls = detect_platform(headers)
        logger.debug(f"Detected platform: {validator_cls.platform}")

        secret = self._get_webhook_secret(validator_cls)

        # Re-serialise body to bytes for HMAC computation.
        # See module docstring for the Smee caveat on raw-body fidelity.
        raw_body = json.dumps(body, separators=(",", ":")).encode("utf-8")

        validator_cls().validate(headers, raw_body, secret)
        logger.debug(f"Webhook signature verified for platform: {validator_cls.platform}")

        return {"platform": validator_cls.platform, "valid": True}

    def _get_webhook_secret(self, validator_cls: type[PlatformWebhookValidator]) -> str:
        """
        Fetch the webhook secret for the given platform.

        Uses a default (catch-all) SecretContext for now. Per-organisation
        or per-repository lookup can be added here later once the full
        webhook context (org, repo) is propagated through the task context.
        """
        platform = validator_cls.platform
        if platform == "github":
            context = SecretContext(platform="github")
            return self.secrets_manager.get_github_secrets(context).webhook_secret
        if platform == "gitlab":
            context = SecretContext(platform="gitlab")
            return self.secrets_manager.get_gitlab_secrets(context).webhook_secret
        raise WebhookValidationError(
            f"No secret lookup implemented for platform {platform!r}. "
            f"Add a branch in WebhookValidationHandler._get_webhook_secret()."
        )
