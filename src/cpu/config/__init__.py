# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

This package provides configuration loading from YAML files with
environment variable overrides, validation, and secrets management.
"""

from __future__ import annotations

from cpu.config.config import Config, ConfigError, ConfigValidationError
from cpu.config.secrets import (
    GitHubAppSecrets,
    GitLabSecrets,
    S3Secrets,
    SecretConfigurationError,
    SecretManager,
    SecretNotFoundError,
    SmeeSecrets,
)
from cpu.config.secrets_audit import SecretsAuditLogger
from cpu.config.secrets_context import SecretContext
from cpu.config.secrets_encryption import (
    DecryptionError,
    EncryptionConfig,
    EncryptionProvider,
    MasterPassphraseEncryption,
    NoEncryption,
)
from cpu.config.secrets_sources import (
    EnvVarSecretSource,
    FileSecretSource,
    SecretSource,
    SecretValue,
)

__all__ = [
    # Configuration
    "Config",
    "ConfigError",
    "ConfigValidationError",
    # Secret Manager
    "SecretManager",
    "SecretNotFoundError",
    "SecretConfigurationError",
    # Secret Dataclasses
    "GitHubAppSecrets",
    "GitLabSecrets",
    "S3Secrets",
    "SmeeSecrets",
    # Secret Context
    "SecretContext",
    # Secret Sources
    "SecretSource",
    "SecretValue",
    "EnvVarSecretSource",
    "FileSecretSource",
    # Encryption
    "EncryptionProvider",
    "EncryptionConfig",
    "NoEncryption",
    "MasterPassphraseEncryption",
    "DecryptionError",
    # Audit
    "SecretsAuditLogger",
]
