# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
Audit logging for secret access.

Logs all secret access to a dedicated audit file:
- What secret was accessed
- When it was accessed
- What context it was used for
- Source it came from

Never logs actual secret values.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any


class SecretsAuditLogger:
    """
    Dedicated logger for secret access auditing.

    Logs to separate file for security auditing purposes.
    Format: timestamp | level | event details
    """

    def __init__(
        self,
        audit_file: Path = Path("/var/log/cpu/secrets_audit.log"),
        enable_console: bool = False,
    ) -> None:
        """
        Initialize audit logger.

        Args:
            audit_file: Path to audit log file
            enable_console: Also log to console (for debugging)
        """
        self.audit_file = audit_file
        self._logger = self._setup_logger(enable_console)

    def _setup_logger(self, enable_console: bool) -> logging.Logger:
        """Set up dedicated logger for secrets audit."""
        logger = logging.getLogger("cpu.secrets.audit")
        logger.setLevel(logging.INFO)
        logger.propagate = False  # Don't propagate to root logger

        # Ensure audit directory exists
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)

        # File handler
        file_handler = logging.FileHandler(self.audit_file)
        file_handler.setLevel(logging.INFO)

        # Simple format: timestamp | level | message
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Optional console handler
        if enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        return logger

    def log_secret_access(
        self,
        secret_ref: str,
        source: str,
        context: dict[str, Any] | None = None,
        success: bool = True,
    ) -> None:
        """
        Log secret access attempt.

        Args:
            secret_ref: Reference/ID of secret accessed
            source: Where secret came from (env, file, vault)
            context: Context information (repo, org, etc.)
            success: Whether access was successful
        """
        context_str = self._format_context(context) if context else "none"
        status = "SUCCESS" if success else "FAILED"

        self._logger.info(
            f"{status} | secret_ref={secret_ref} | "
            f"source={source} | context={context_str}"
        )

    def log_encryption_init(
        self,
        encryption_enabled: bool,
        passphrase_source: str,
    ) -> None:
        """
        Log encryption initialization.

        Args:
            encryption_enabled: Whether encryption is enabled
            passphrase_source: Where passphrase came from (env, interactive, none)
        """
        status = "ENABLED" if encryption_enabled else "DISABLED"
        self._logger.info(
            f"ENCRYPTION {status} | passphrase_source={passphrase_source}"
        )

    def log_decryption_error(
        self,
        secret_ref: str,
        error: str,
    ) -> None:
        """
        Log decryption failure.

        Args:
            secret_ref: Secret that failed to decrypt
            error: Error message (sanitized, no sensitive data)
        """
        self._logger.error(
            f"DECRYPTION_FAILED | secret_ref={secret_ref} | error={error}"
        )

    def log_permission_check(
        self,
        user: str,
        action: str,
        allowed: bool,
    ) -> None:
        """
        Log permission check.

        Args:
            user: User attempting action
            action: Action requested
            allowed: Whether permission was granted
        """
        status = "GRANTED" if allowed else "DENIED"
        self._logger.info(f"PERMISSION {status} | user={user} | action={action}")

    @staticmethod
    def _format_context(context: dict[str, Any]) -> str:
        """Format context dict for logging."""
        parts = [f"{k}={v}" for k, v in context.items() if v is not None]
        return ",".join(parts) if parts else "none"
