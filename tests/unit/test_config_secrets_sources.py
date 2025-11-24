# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Unit tests for secret sources.

Tests different backends for loading secrets:
- SecretValue container
- EnvVarSecretSource
- FileSecretSource
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from cpu.config.secrets_audit import SecretsAuditLogger
from cpu.config.secrets_encryption import NoEncryption
from cpu.config.secrets_sources import (
    EnvVarSecretSource,
    FileSecretSource,
    SecretValue,
)


class TestSecretValue:
    """Test SecretValue container."""

    def test_initialization_with_string(self) -> None:
        """Test initialization with string value."""
        secret = SecretValue(
            value="my-secret-value",
            source="env:plain",
            secret_ref="test_secret",
        )

        assert secret.value == "my-secret-value"
        assert secret.source == "env:plain"
        assert secret.secret_ref == "test_secret"
        assert secret.is_encrypted is False

    def test_initialization_with_bytes(self) -> None:
        """Test initialization with bytes value."""
        secret = SecretValue(
            value=b"binary-secret",
            source="file:plain",
            secret_ref="test_secret",
        )

        assert secret.value == b"binary-secret"
        assert isinstance(secret.value, bytes)

    def test_as_string_from_string(self) -> None:
        """Test as_string with string value."""
        secret = SecretValue("test", "env", "ref")

        assert secret.as_string() == "test"

    def test_as_string_from_bytes(self) -> None:
        """Test as_string converts bytes to string."""
        secret = SecretValue(b"test-bytes", "env", "ref")

        assert secret.as_string() == "test-bytes"

    def test_as_bytes_from_bytes(self) -> None:
        """Test as_bytes with bytes value."""
        secret = SecretValue(b"test", "env", "ref")

        assert secret.as_bytes() == b"test"

    def test_as_bytes_from_string(self) -> None:
        """Test as_bytes converts string to bytes."""
        secret = SecretValue("test-string", "env", "ref")

        assert secret.as_bytes() == b"test-string"

    def test_as_ssh_key_memory_returns_bytes(self) -> None:
        """Test as_ssh_key_memory returns bytes."""
        secret = SecretValue("ssh-key-content", "file", "ssh_key")

        key_bytes = secret.as_ssh_key_memory()

        assert isinstance(key_bytes, bytes)
        assert key_bytes == b"ssh-key-content"

    def test_is_encrypted_flag(self) -> None:
        """Test is_encrypted flag."""
        plain_secret = SecretValue("plain", "env", "ref", is_encrypted=False)
        encrypted_secret = SecretValue(b"encrypted", "file", "ref", is_encrypted=True)

        assert plain_secret.is_encrypted is False
        assert encrypted_secret.is_encrypted is True


class TestEnvVarSecretSource:
    """Test EnvVarSecretSource."""

    def test_get_secret_plain_value(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading plain value from environment."""
        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = EnvVarSecretSource(audit_logger, encryption)

        monkeypatch.setenv("CPU_SECRETS__TEST_SECRET", "my-value")

        secret = source.get_secret("test_secret")

        assert secret.value == "my-value"
        assert secret.source == "env:plain"
        assert secret.secret_ref == "test_secret"

        monkeypatch.delenv("CPU_SECRETS__TEST_SECRET")

    def test_get_secret_from_file_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading secret from file path in environment."""
        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = EnvVarSecretSource(audit_logger, encryption)

        # Create a secret file
        secret_file = tmp_path / "secret.txt"
        secret_file.write_bytes(b"file-content")

        monkeypatch.setenv("CPU_SECRETS__TEST_SECRET__FILE", str(secret_file))

        secret = source.get_secret("test_secret")

        assert secret.value == b"file-content"
        assert secret.source == "env:file"

        monkeypatch.delenv("CPU_SECRETS__TEST_SECRET__FILE")

    def test_get_secret_from_base64(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading secret from base64-encoded environment variable."""
        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = EnvVarSecretSource(audit_logger, encryption)

        # Base64 encode a value
        encoded = base64.b64encode(b"base64-secret").decode("utf-8")
        monkeypatch.setenv("CPU_SECRETS__TEST_SECRET__BASE64", encoded)

        secret = source.get_secret("test_secret")

        assert secret.value == b"base64-secret"
        assert secret.source == "env:base64"

        monkeypatch.delenv("CPU_SECRETS__TEST_SECRET__BASE64")

    def test_get_secret_encrypted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading encrypted secret from environment."""
        from cpu.config.secrets_encryption import MasterPassphraseEncryption

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = MasterPassphraseEncryption(passphrase="test-pass")
        source = EnvVarSecretSource(audit_logger, encryption)

        # Encrypt a value
        plaintext = b"encrypted-secret"
        encrypted = encryption.encrypt(plaintext)
        encoded = base64.b64encode(encrypted).decode("utf-8")

        monkeypatch.setenv("CPU_SECRETS__TEST_SECRET__ENCRYPTED", encoded)

        secret = source.get_secret("test_secret")

        assert secret.value == plaintext
        assert secret.source == "env:encrypted"
        assert secret.is_encrypted is True

        monkeypatch.delenv("CPU_SECRETS__TEST_SECRET__ENCRYPTED")

    def test_get_secret_not_found(self, tmp_path: Path) -> None:
        """Test that KeyError is raised when secret not found."""
        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = EnvVarSecretSource(audit_logger, encryption)

        with pytest.raises(KeyError, match="Secret not found"):
            source.get_secret("nonexistent_secret")

    def test_env_var_naming_convention(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that environment variable names are constructed correctly."""
        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = EnvVarSecretSource(audit_logger, encryption)

        # Lowercase secret_ref should be converted to uppercase
        monkeypatch.setenv("CPU_SECRETS__GITHUB__DEFAULT__PRIVATE_KEY", "key-content")

        secret = source.get_secret("github.default.private_key")

        assert secret.value == "key-content"

        monkeypatch.delenv("CPU_SECRETS__GITHUB__DEFAULT__PRIVATE_KEY")

    def test_audit_logging_on_access(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that secret access is logged to audit."""
        audit_file = tmp_path / "audit.log"
        audit_logger = SecretsAuditLogger(audit_file=audit_file)
        encryption = NoEncryption()
        source = EnvVarSecretSource(audit_logger, encryption)

        monkeypatch.setenv("CPU_SECRETS__TEST", "value")

        source.get_secret("test")

        # Verify audit log was written
        assert audit_file.exists()
        content = audit_file.read_text()
        assert "test" in content
        assert "env:plain" in content

        monkeypatch.delenv("CPU_SECRETS__TEST")


class TestFileSecretSource:
    """Test FileSecretSource."""

    def test_get_secret_from_plain_file(self, tmp_path: Path) -> None:
        """Test loading secret from plain file."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = FileSecretSource(audit_logger, encryption, secrets_dir=secrets_dir)

        # Create plain secret file
        (secrets_dir / "test_secret").write_bytes(b"plain-content")

        secret = source.get_secret("test_secret")

        assert secret.value == b"plain-content"
        assert secret.source == "file:plain"

    def test_get_secret_from_encrypted_file(self, tmp_path: Path) -> None:
        """Test loading secret from encrypted file."""
        from cpu.config.secrets_encryption import MasterPassphraseEncryption

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = MasterPassphraseEncryption(passphrase="test-pass")
        source = FileSecretSource(audit_logger, encryption, secrets_dir=secrets_dir)

        # Create encrypted secret file
        plaintext = b"encrypted-content"
        encrypted = encryption.encrypt(plaintext)
        (secrets_dir / "test_secret.enc").write_bytes(encrypted)

        secret = source.get_secret("test_secret")

        assert secret.value == plaintext
        assert secret.source == "file:encrypted"
        assert secret.is_encrypted is True

    def test_encrypted_file_takes_priority(self, tmp_path: Path) -> None:
        """Test that .enc file is preferred over plain file."""
        from cpu.config.secrets_encryption import MasterPassphraseEncryption

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = MasterPassphraseEncryption(passphrase="test-pass")
        source = FileSecretSource(audit_logger, encryption, secrets_dir=secrets_dir)

        # Create both plain and encrypted files
        (secrets_dir / "test_secret").write_bytes(b"plain")
        encrypted = encryption.encrypt(b"encrypted")
        (secrets_dir / "test_secret.enc").write_bytes(encrypted)

        secret = source.get_secret("test_secret")

        # Should get encrypted version
        assert secret.value == b"encrypted"
        assert secret.source == "file:encrypted"

    def test_get_secret_not_found(self, tmp_path: Path) -> None:
        """Test that FileNotFoundError is raised when secret file doesn't exist."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = FileSecretSource(audit_logger, encryption, secrets_dir=secrets_dir)

        with pytest.raises(FileNotFoundError, match="Secret file not found"):
            source.get_secret("nonexistent")

    def test_default_secrets_directory(self, tmp_path: Path) -> None:
        """Test default secrets directory location."""
        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = FileSecretSource(audit_logger, encryption)

        assert source.secrets_dir == Path("/etc/cpu/secrets")

    def test_custom_secrets_directory(self, tmp_path: Path) -> None:
        """Test using custom secrets directory."""
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = FileSecretSource(audit_logger, encryption, secrets_dir=custom_dir)

        assert source.secrets_dir == custom_dir

    def test_audit_logging_on_file_access(self, tmp_path: Path) -> None:
        """Test that file access is logged to audit."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        audit_file = tmp_path / "audit.log"

        audit_logger = SecretsAuditLogger(audit_file=audit_file)
        encryption = NoEncryption()
        source = FileSecretSource(audit_logger, encryption, secrets_dir=secrets_dir)

        (secrets_dir / "test").write_bytes(b"content")

        source.get_secret("test")

        # Verify audit log
        assert audit_file.exists()
        content = audit_file.read_text()
        assert "test" in content
        assert "file:plain" in content
