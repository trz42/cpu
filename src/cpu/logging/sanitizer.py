# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Log message sanitization to remove sensitive data.
"""

from __future__ import annotations

import re


class LogSanitizer:
    """Removes sensitive data from log messages."""

    PATTERNS: list[tuple[str, str]] = [
        # Bearer tokens
        (r'Bearer\s+[a-zA-Z0-9_\-\.]+', r'Bearer ***'),
        # Passwords
        (r'password["\s:=]+\S+', r'password=***'),
        # GitHub Personal Access Tokens (ghp_)
        (r'ghp_[a-zA-Z0-9]{36}', r'***'),
        # GitHub OAuth tokens (ghs_)
        (r'ghs_[a-zA-Z0-9]{36}', r'***'),
        # API keys
        (r'api[_-]?key["\s:=]+\S+', r'api_key=***'),
        # Generic tokens
        (r'token["\s:=]+([a-zA-Z0-9_-]+)', r'token=***'),
    ]

    def sanitize(self, message: str) -> str:
        """
        Remove sensitive data from message.

        Args:
            message: Log message to sanitize

        Returns:
            Sanitized message with secrets replaced
        """
        result = message
        for pattern, replacement in self.PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        return result
