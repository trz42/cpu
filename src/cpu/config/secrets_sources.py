# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Secret sources - backends for loading secrets.

Supports multiple sources with fallback chain:
1. Environment variables (for development/containers)
2. Encrypted files (for production)
3. Plain files (for simple deployments)
4. Vault systems (future)
"""

from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod
from pathlib import Path

from cpu.config.secrets_audit import SecretsAuditLogger
from cpu.config.secrets_encryption import DecryptionError, EncryptionProvider


class SecretValue:
    """
    Container for a secret value (in-memory only).

    Supports different representations:
    - String (tokens, passwords)
    - Bytes (encrypted data, binary keys)
    - In-memory "file" (SSH keys)
    """

    def __init__(
        self,
        value: str | bytes,
        source: str,
        secret_ref: str,
        is_encrypted: bool = False,
    ) -> None:
        """
        Initialize secret value.

        Args:
            value: The secret data
            source: Where it came from (e.g., "env:plain", "file:encrypted")
            secret_ref: Reference/ID of the secret
            is_encrypted: Whether this was encrypted at rest
        """
        self.value = value
        self.source = source
        self.secret_ref = secret_ref
        self.is_encrypted = is_encrypted

    def as_string(self) -> str:
        """Get secret as string."""
        if isinstance(self.value, bytes):
            return self.value.decode("utf-8")
        return self.value

    def as_bytes(self) -> bytes:
        """Get secret as bytes."""
        if isinstance(self.value, str):
            return self.value.encode("utf-8")
        return self.value

    def as_ssh_key_memory(self) -> bytes:
        """
        Get secret as SSH key (in memory).

        Returns raw bytes suitable for in-memory SSH key operations.
        No temp file is created.
        """
        return self.as_bytes()


class SecretSource(ABC):
    """Abstract base for secret sources."""

    def __init__(
        self,
        audit_logger: SecretsAuditLogger,
        encryption: EncryptionProvider,
    ) -> None:
        """
        Initialize secret source.

        Args:
            audit_logger: Logger for audit trail
            encryption: Encryption provider for decryption
        """
        self.audit = audit_logger
        self.encryption = encryption

    @abstractmethod
    def get_secret(self, secret_ref: str) -> SecretValue:
        """Retrieve a secret by reference."""
        pass

    def _decrypt_if_needed(
        self,
        data: bytes,
        secret_ref: str,
    ) -> bytes:
        """Decrypt data if it's encrypted. Knows about EncryptionProvider via self.encryption."""
        try:
            return self.encryption.decrypt(data)
        except DecryptionError as err:
            self.audit.log_decryption_error(secret_ref, str(err))
            raise


class EnvVarSecretSource(SecretSource):
    """
    Load secrets from environment variables.

    Naming conventions:
    - CPU_SECRETS__<REF>=<value>                    # Plain value
    - CPU_SECRETS__<REF>__FILE=/path/to/file        # Path to file
    - CPU_SECRETS__<REF>__BASE64=<base64>           # Base64-encoded
    - CPU_SECRETS__<REF>__ENCRYPTED=<base64>        # Encrypted + base64

    Examples:
        CPU_SECRETS__GITHUB__DEFAULT__WEBHOOK_SECRET=mysecret123
        CPU_SECRETS__GITHUB__DEFAULT__PRIVATE_KEY__FILE=/keys/github.pem
        CPU_SECRETS__S3__ACCESS_KEY_ID__ENCRYPTED=<encrypted-base64>
    """

    def get_secret(self, secret_ref: str) -> SecretValue:
        """Load secret from environment."""
        # Replace dots to with double underscores for path separators, keep underscores in field names
        env_key = f"CPU_SECRETS__{secret_ref.replace('.', '__').upper()}"

        # Try plain value
        if env_key in os.environ:
            value = os.environ[env_key]
            self.audit.log_secret_access(secret_ref, "env:plain")
            return SecretValue(value, "env:plain", secret_ref)

        # Try file path
        file_key = f"{env_key}__FILE"
        if file_key in os.environ:
            # TODO: what if file_path is empty or does not exist?
            file_path = Path(os.environ[file_key])
            data = file_path.read_bytes()
            # _decrypt_if_needed relies on the EncryptionProvider that was specified when this instance was created
            data = self._decrypt_if_needed(data, secret_ref)
            self.audit.log_secret_access(secret_ref, "env:file")
            return SecretValue(data, "env:file", secret_ref)

        # Try base64
        base64_key = f"{env_key}__BASE64"
        if base64_key in os.environ:
            data = base64.b64decode(os.environ[base64_key])
            self.audit.log_secret_access(secret_ref, "env:base64")
            return SecretValue(data, "env:base64", secret_ref)

        # Try encrypted
        enc_key = f"{env_key}__ENCRYPTED"
        if enc_key in os.environ:
            encrypted = base64.b64decode(os.environ[enc_key])
            data = self._decrypt_if_needed(encrypted, secret_ref)
            self.audit.log_secret_access(secret_ref, "env:encrypted")
            return SecretValue(data, "env:encrypted", secret_ref, is_encrypted=True)

        raise KeyError(f"Secret not found in environment: {secret_ref} {enc_key}")


class FileSecretSource(SecretSource):
    """
    Load secrets from filesystem.

    Directory structure:
    /etc/cpu/secrets/
    ├── github_default_private_key           # Plain
    ├── github_default_webhook_secret        # Plain
    ├── s3_production_access_key.enc         # Encrypted
    └── s3_production_secret_key.enc         # Encrypted

    Files with .enc extension are assumed encrypted and have precedence over plain files.
    """

    def __init__(
        self,
        audit_logger: SecretsAuditLogger,
        encryption: EncryptionProvider,
        secrets_dir: Path = Path("/etc/cpu/secrets"),
    ) -> None:
        """
        Initialize file secret source.

        Args:
            audit_logger: Logger for audit trail
            encryption: Encryption provider
            secrets_dir: Directory containing secret files
        """
        super().__init__(audit_logger, encryption)
        self.secrets_dir = secrets_dir

    def get_secret(self, secret_ref: str) -> SecretValue:
        """Load secret from file."""
        # Try encrypted file first
        enc_file = self.secrets_dir / f"{secret_ref}.enc"
        if enc_file.exists():
            encrypted = enc_file.read_bytes()
            data = self._decrypt_if_needed(encrypted, secret_ref)
            self.audit.log_secret_access(secret_ref, "file:encrypted")
            return SecretValue(data, "file:encrypted", secret_ref, is_encrypted=True)

        # Try plain file
        plain_file = self.secrets_dir / secret_ref
        if plain_file.exists():
            data = plain_file.read_bytes()
            self.audit.log_secret_access(secret_ref, "file:plain")
            return SecretValue(data, "file:plain", secret_ref)

        raise FileNotFoundError(
            f"Secret file not found: {secret_ref} "
            f"(tried {enc_file} and {plain_file})"
        )
