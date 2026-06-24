# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Webhook validation base types: abstract validator interface, exception
hierarchy, case-insensitive header lookup helper, and the platform-detection
registry used to dispatch validation to the right platform-specific validator.

Adding a new hosting platform requires:
1. A new module (e.g. bitbucket.py) with a class that inherits
   PlatformWebhookValidator and calls
   WEBHOOK_VALIDATORS.append(MyValidator) at module level.
2. Importing that module in __init__.py to ensure the self-registration
   side-effect runs when the package is imported.

No changes to this module, to detect_platform(), or to any caller are
needed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import ClassVar


class WebhookValidationError(Exception):
    """
    Raised when a webhook request cannot be validated.

    Covers missing or malformed signature headers, HMAC mismatches,
    unsupported signature schemes, and malformed secret material.
    """


class UnsupportedPlatformError(WebhookValidationError):
    """
    Raised when no registered validator recognises the incoming request headers.

    The calling code should treat this as an indication that the webhook
    originated from a platform that is not yet supported, rather than as a
    security failure.
    """


def get_header(headers: Mapping[str, str], name: str) -> str | None:
    """
    Case-insensitive lookup of a single header value.

    Args:
        headers: Mapping of header names to values.
        name: Header name to look up (case-insensitive).

    Returns:
        The header value, or None if the header is absent.
    """
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return None


class PlatformWebhookValidator(ABC):
    """
    Abstract base class for platform-specific webhook signature validators.

    Each concrete implementation is responsible for:
    - Recognising whether an incoming request originated from its platform
      (matches()).
    - Verifying the request's signature (validate()).

    Concrete classes self-register in WEBHOOK_VALIDATORS at import time,
    which is the only change needed to add support for a new platform.
    """

    # TODO Why is it a class variable?
    platform: ClassVar[str]
    """Short lowercase platform identifier, e.g. "github" or "gitlab"."""

    @classmethod
    @abstractmethod
    def matches(cls, headers: Mapping[str, str]) -> bool:
        """
        Return True if the request headers indicate this platform.

        This is a lightweight check on header presence/names only; it does
        not verify the signature. Used by detect_platform() to route
        requests to the right validator.

        Args:
            headers: Incoming request headers.
        """

    @abstractmethod
    def validate(self, headers: Mapping[str, str], raw_body: bytes, secret: str) -> None:
        """
        Verify the webhook signature.

        Args:
            headers: Incoming request headers.
            raw_body: Raw request body bytes used to compute the expected HMAC.
            secret: Platform-specific webhook secret (encoding depends on
                the platform; see concrete implementations for details).

        Raises:
            WebhookValidationError: If the signature is missing, malformed,
                or does not match the expected value.
        """


#: Ordered list of registered platform validators.
#:
#: Platform modules append their validator class here at import time.
#: detect_platform() iterates this list in order; the first match wins,
#: so registration order matters when headers could match multiple validators.
WEBHOOK_VALIDATORS: list[type[PlatformWebhookValidator]] = []


# TODO Should one implement a function that determines all matches? I.e., to determine ambiguous headers?
def detect_platform(headers: Mapping[str, str]) -> type[PlatformWebhookValidator]:
    """
    Identify the originating platform from the request headers.

    Iterates WEBHOOK_VALIDATORS in registration order and returns the
    first class whose matches() method returns True.

    Args:
        headers: Incoming request headers.

    Returns:
        The matching PlatformWebhookValidator subclass (not an instance).

    Raises:
        UnsupportedPlatformError: If no registered validator matches.
    """
    for validator_cls in WEBHOOK_VALIDATORS:
        if validator_cls.matches(headers):
            return validator_cls
    header_names = list(headers.keys())
    raise UnsupportedPlatformError(
        f"No registered validator matches the incoming request headers: {header_names}"
    )
