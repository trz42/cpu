# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for log sanitization.
"""

from __future__ import annotations

from cpu.logging.sanitizer import LogSanitizer


class TestLogSanitizer:
    """Test log message sanitization."""

    def test_sanitize_removes_bearer_tokens(self) -> None:
        """Test Bearer token sanitization."""
        sanitizer = LogSanitizer()

        message = "Authorization: Bearer abc123def456"
        result = sanitizer.sanitize(message)

        assert "abc123def456" not in result
        assert "Bearer ***" in result

    def test_sanitize_removes_passwords(self) -> None:
        """Test password sanitization."""
        sanitizer = LogSanitizer()

        message = 'password="secret123"'
        result = sanitizer.sanitize(message)

        assert "secret123" not in result
        assert "password=***" in result

    def test_sanitize_removes_github_pat_tokens(self) -> None:
        """Test GitHub Personal Access Token sanitization."""
        sanitizer = LogSanitizer()

        message = "token: ghp_1234567890123456789012345678901234"
        result = sanitizer.sanitize(message)

        assert "ghp_" not in result
        assert "***" in result

    def test_sanitize_removes_github_oauth_tokens(self) -> None:
        """Test GitHub OAuth token sanitization."""
        sanitizer = LogSanitizer()

        message = "token: ghs_1234567890123456789012345678901234"
        result = sanitizer.sanitize(message)

        assert "ghs_" not in result
        assert "***" in result

    def test_sanitize_removes_api_keys(self) -> None:
        """Test API key sanitization."""
        sanitizer = LogSanitizer()

        message = "api_key=sk-1234567890abcdef"
        result = sanitizer.sanitize(message)

        assert "sk-1234567890abcdef" not in result
        assert "api_key=***" in result

    def test_sanitize_preserves_normal_text(self) -> None:
        """Test normal text is not affected."""
        sanitizer = LogSanitizer()

        message = "Processing job job_123 for user admin"
        result = sanitizer.sanitize(message)

        assert result == message

    def test_sanitize_handles_multiple_secrets(self) -> None:
        """Test multiple secrets in one message."""
        sanitizer = LogSanitizer()

        message = "Bearer token123 and password=secret456"
        result = sanitizer.sanitize(message)

        assert "token123" not in result
        assert "secret456" not in result
        assert "Bearer ***" in result
        assert "password=***" in result
