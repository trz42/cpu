# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.config.secrets_audit module.

Tests the dedicated audit logger for tracking secret access.
"""

from __future__ import annotations

from pathlib import Path

from cpu.config.secrets_audit import SecretsAuditLogger


class TestSecretsAuditLogger:
    """Test SecretsAuditLogger implementation."""

    def test_initialization(self, tmp_path: Path) -> None:
        """Test that audit logger initializes correctly."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        assert logger.audit_file == audit_file
        assert audit_file.parent.exists()

    def test_log_secret_access_success(self, tmp_path: Path) -> None:
        """Test logging successful secret access."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_secret_access(
            secret_ref="github_default_private_key",
            source="file:/etc/cpu/secrets/github_default_private_key",
            context={"organization": "EESSI", "repository": "software-layer"},
            success=True,
        )

        # Verify log was written
        assert audit_file.exists()
        content = audit_file.read_text()
        assert "SUCCESS" in content
        assert "github_default_private_key" in content
        assert "organization=EESSI" in content
        assert "repository=software-layer" in content

    def test_log_secret_access_failure(self, tmp_path: Path) -> None:
        """Test logging failed secret access."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_secret_access(
            secret_ref="missing_secret",
            source="none",
            success=False,
        )

        content = audit_file.read_text()
        assert "FAILED" in content
        assert "missing_secret" in content

    def test_log_secret_access_no_context(self, tmp_path: Path) -> None:
        """Test logging secret access without context."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_secret_access(
            secret_ref="simple_secret",
            source="env:plain",
            context=None,
            success=True,
        )

        content = audit_file.read_text()
        assert "simple_secret" in content
        assert "context=none" in content

    def test_log_encryption_init_enabled(self, tmp_path: Path) -> None:
        """Test logging encryption initialization when enabled."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_encryption_init(
            encryption_enabled=True,
            passphrase_source="interactive",
        )

        content = audit_file.read_text()
        assert "ENCRYPTION ENABLED" in content
        assert "passphrase_source=interactive" in content

    def test_log_encryption_init_disabled(self, tmp_path: Path) -> None:
        """Test logging encryption initialization when disabled."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_encryption_init(
            encryption_enabled=False,
            passphrase_source="none",
        )

        content = audit_file.read_text()
        assert "ENCRYPTION DISABLED" in content

    def test_log_decryption_error(self, tmp_path: Path) -> None:
        """Test logging decryption errors."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_decryption_error(
            secret_ref="corrupted_secret",
            error="Invalid token",
        )

        content = audit_file.read_text()
        assert "DECRYPTION_FAILED" in content
        assert "corrupted_secret" in content
        assert "Invalid token" in content

    def test_log_permission_check_granted(self, tmp_path: Path) -> None:
        """Test logging granted permission."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_permission_check(
            user="maintainer1",
            action="trigger_build",
            allowed=True,
        )

        content = audit_file.read_text()
        assert "PERMISSION GRANTED" in content
        assert "user=maintainer1" in content
        assert "action=trigger_build" in content

    def test_log_permission_check_denied(self, tmp_path: Path) -> None:
        """Test logging denied permission."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_permission_check(
            user="unauthorized_user",
            action="trigger_deploy",
            allowed=False,
        )

        content = audit_file.read_text()
        assert "PERMISSION DENIED" in content
        assert "user=unauthorized_user" in content

    def test_multiple_log_entries(self, tmp_path: Path) -> None:
        """Test that multiple log entries are written correctly."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_secret_access("secret1", "env", success=True)
        logger.log_secret_access("secret2", "file", success=True)
        logger.log_encryption_init(True, "env")

        content = audit_file.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 3
        assert "secret1" in lines[0]
        assert "secret2" in lines[1]
        assert "ENCRYPTION" in lines[2]

    def test_format_context_with_values(self, tmp_path: Path) -> None:
        """Test context formatting with multiple values."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_secret_access(
            "test_secret",
            "file",
            context={
                "organization": "EESSI",
                "repository": "software-layer",
                "cvmfs_repo": "software.eessi.io",
            },
        )

        content = audit_file.read_text()
        assert "organization=EESSI" in content
        assert "repository=software-layer" in content
        assert "cvmfs_repo=software.eessi.io" in content

    def test_format_context_filters_none_values(self, tmp_path: Path) -> None:
        """Test that None values are filtered from context."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file)

        logger.log_secret_access(
            "test_secret",
            "file",
            context={
                "organization": "EESSI",
                "repository": None,
                "cvmfs_repo": "software.eessi.io",
            },
        )

        content = audit_file.read_text()
        assert "organization=EESSI" in content
        assert "repository=" not in content  # None values excluded
        assert "cvmfs_repo=software.eessi.io" in content

    def test_console_logging_disabled_by_default(self, tmp_path: Path) -> None:
        """Test that console logging is disabled by default."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file, enable_console=False)

        # Check that logger has only file handler, not console
        handlers = logger._logger.handlers
        handler_types = [type(h).__name__ for h in handlers]
        assert "FileHandler" in handler_types
        assert "StreamHandler" not in handler_types

    def test_console_logging_can_be_enabled(self, tmp_path: Path) -> None:
        """Test that console logging can be enabled."""
        audit_file = tmp_path / "secrets_audit.log"
        logger = SecretsAuditLogger(audit_file=audit_file, enable_console=True)

        handlers = logger._logger.handlers
        handler_types = [type(h).__name__ for h in handlers]
        assert "FileHandler" in handler_types
        assert "StreamHandler" in handler_types
