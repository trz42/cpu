# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.config.secrets_encryption module.

Tests encryption providers for optional secret encryption at rest.
"""

from __future__ import annotations

import logging

import pytest

from cpu.config.secrets_encryption import (
    DecryptionError,
    EncryptionConfig,
    MasterPassphraseEncryption,
    NoEncryption,
)


class TestNoEncryption:
    """Test NoEncryption provider (plaintext)."""

    def test_decrypt_returns_data_unchanged(self) -> None:
        """Test that NoEncryption returns data as-is."""
        provider = NoEncryption()
        data = b"my secret data"

        result = provider.decrypt(data)

        assert result == data

    def test_decrypt_works_with_empty_data(self) -> None:
        """Test decryption with empty data."""
        provider = NoEncryption()
        data = b""

        result = provider.decrypt(data)

        assert result == b"" == data


class TestMasterPassphraseEncryption:
    """Test MasterPassphraseEncryption provider."""

    def test_encrypt_and_decrypt_roundtrip(self) -> None:
        """Test encrypting and decrypting data."""
        passphrase = "test-passphrase-123"
        provider = MasterPassphraseEncryption(passphrase=passphrase)

        # Encrypt some data (would be done by separate tool)
        plaintext = b"my secret data"
        encrypted = provider.encrypt(plaintext)

        assert plaintext != encrypted

        # Decrypt it
        decrypted = provider.decrypt(encrypted)

        assert decrypted == plaintext

    def test_decrypt_with_correct_passphrase(self) -> None:
        """Test decryption succeeds with correct passphrase."""
        passphrase = "correct-passphrase"
        provider = MasterPassphraseEncryption(passphrase=passphrase)

        plaintext = b"sensitive information"
        encrypted = provider.encrypt(plaintext)

        assert plaintext != encrypted

        # Create new provider with same passphrase
        provider2 = MasterPassphraseEncryption(passphrase=passphrase)
        decrypted = provider2.decrypt(encrypted)

        assert decrypted == plaintext

    def test_decrypt_with_wrong_passphrase_fails(self) -> None:
        """Test decryption fails with wrong passphrase."""
        provider1 = MasterPassphraseEncryption(passphrase="correct")
        plaintext = b"secret"
        encrypted = provider1.encrypt(plaintext)

        assert plaintext != encrypted

        # Try to decrypt with wrong passphrase
        provider2 = MasterPassphraseEncryption(passphrase="wrong")

        with pytest.raises(DecryptionError):
            provider2.decrypt(encrypted)

    def test_decrypt_with_corrupted_data_fails(self) -> None:
        """Test decryption fails with corrupted data."""
        provider = MasterPassphraseEncryption(passphrase="test")

        corrupted_data = b"not valid encrypted data"

        with pytest.raises(DecryptionError):
            provider.decrypt(corrupted_data)

    def test_decrypt_with_too_short_data_fails(self) -> None:
        """Test decryption fails if data is too short (no salt)."""
        provider = MasterPassphraseEncryption(passphrase="test")

        short_data = b"short"  # Less than 16 bytes (salt size)

        with pytest.raises(DecryptionError, match="too short"):
            provider.decrypt(short_data)

    def test_different_salts_produce_different_ciphertexts(self) -> None:
        """Test that same plaintext produces different ciphertexts."""
        provider = MasterPassphraseEncryption(passphrase="test")
        plaintext = b"same data"

        encrypted1 = provider.encrypt(plaintext)
        encrypted2 = provider.encrypt(plaintext)

        assert encrypted1 != plaintext
        assert encrypted2 != plaintext

        # Different salts should produce different ciphertexts
        assert encrypted1 != encrypted2

        # But both should decrypt to same plaintext
        assert provider.decrypt(encrypted1) == plaintext
        assert provider.decrypt(encrypted2) == plaintext

    def test_fernet_caching_for_same_salt(self) -> None:
        """Test that Fernet instances are cached per salt."""
        provider = MasterPassphraseEncryption(passphrase="test")

        plaintext = b"data"
        encrypted = provider.encrypt(plaintext)

        assert encrypted != plaintext

        # Decrypt twice - second should use cached Fernet
        provider.decrypt(encrypted)
        initial_cache_size = len(provider._fernet_cache)

        decrypted = provider.decrypt(encrypted)
        assert len(provider._fernet_cache) == initial_cache_size
        assert decrypted == plaintext

    def test_empty_plaintext(self) -> None:
        """Test encryption/decryption of empty data."""
        provider = MasterPassphraseEncryption(passphrase="test")

        plaintext = b""
        encrypted = provider.encrypt(plaintext)
        decrypted = provider.decrypt(encrypted)

        assert encrypted != plaintext
        assert decrypted == plaintext

    def test_large_plaintext(self) -> None:
        """Test encryption/decryption of large data."""
        provider = MasterPassphraseEncryption(passphrase="test")

        # 1MB of data
        plaintext = b"x" * 1024 * 1024
        encrypted = provider.encrypt(plaintext)
        decrypted = provider.decrypt(encrypted)

        assert encrypted != plaintext
        assert decrypted == plaintext

    def test_decrypt_raises_on_unexpected_exception(self) -> None:
        """Test decrypt wraps unexpected exceptions in DecryptionError."""
        from unittest.mock import patch

        from cryptography.fernet import Fernet

        provider = MasterPassphraseEncryption(passphrase="test")
        encrypted = provider.encrypt(b"plaintext")

        with (
            patch.object(Fernet, "decrypt", side_effect=ValueError("unexpected")),
            pytest.raises(DecryptionError, match="Decryption failed")
        ):
            provider.decrypt(encrypted)


class TestEncryptionConfig:
    """Test EncryptionConfig."""

    def test_create_provider_when_disabled(self) -> None:
        """Test that NoEncryption is created when encryption disabled."""
        config = EncryptionConfig(enabled=False)

        provider = config.create_provider()

        assert isinstance(provider, NoEncryption)

    def test_create_provider_when_enabled_with_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that MasterPassphraseEncryption is created from env var."""
        monkeypatch.setenv("CPU_MASTER_PASSPHRASE", "env-passphrase")
        config = EncryptionConfig(
            enabled=True,
            passphrase_env_var="CPU_MASTER_PASSPHRASE",
        )

        provider = config.create_provider()

        assert isinstance(provider, MasterPassphraseEncryption)

    def test_create_provider_when_enabled_without_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test provider creation prompts for passphrase if not in env."""
        # Ensure env var is not set
        monkeypatch.delenv("CPU_MASTER_PASSPHRASE", raising=False)

        config = EncryptionConfig(enabled=True)

        # Mock getpass to avoid interactive prompt in tests
        monkeypatch.setattr(
            "cpu.config.secrets_encryption.getpass.getpass",
            lambda _: "interactive-passphrase"
        )

        provider = config.create_provider()
        assert isinstance(provider, MasterPassphraseEncryption)

    def test_custom_passphrase_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test using custom environment variable name."""
        monkeypatch.setenv("CUSTOM_PASSPHRASE", "custom-value")
        config = EncryptionConfig(
            enabled=True,
            passphrase_env_var="CUSTOM_PASSPHRASE",
        )

        provider = config.create_provider()

        assert isinstance(provider, MasterPassphraseEncryption)


class TestSecretsEncryptionLogging:
    """Test logging functionality in secrets encryption."""

    def test_encryption_init_logs_at_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test encryption initialization logs at INFO level."""
        caplog.set_level(logging.INFO)

        MasterPassphraseEncryption(passphrase="test_passphrase")

        assert "Initialized MasterPassphraseEncryption" in caplog.text

    def test_no_encryption_init_logs_at_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test NoEncryption initialization logs at INFO level."""
        caplog.set_level(logging.INFO)

        NoEncryption()

        assert "Initialized NoEncryption" in caplog.text

    def test_encrypt_logs_at_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test encryption operation logs at DEBUG level."""
        caplog.set_level(logging.DEBUG)

        encryption = MasterPassphraseEncryption(passphrase="test_passphrase")

        caplog.clear()
        encrypted = encryption.encrypt(b"test data")

        assert "Encrypting data" in caplog.text
        assert "size=" in caplog.text or "bytes" in caplog.text  # should log size
        assert "test data" not in caplog.text  # should not log actual data
        # verify that encrypted data is not logged either
        assert encrypted.hex() not in caplog.text

    def test_decrypt_logs_at_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test decryption operation logs at DEBUG level."""
        caplog.set_level(logging.DEBUG)

        encryption = MasterPassphraseEncryption(passphrase="test_passphrase")
        encrypted = encryption.encrypt(b"test data")

        caplog.clear()
        decrypted = encryption.decrypt(encrypted)

        assert "Decrypting data" in caplog.text
        assert "size=" in caplog.text or "bytes" in caplog.text  # should log size
        assert "test data" not in caplog.text  # should not log actual data
        assert decrypted.hex() not in caplog.text  # should not log decrypted bytes

    def test_decryption_failure_logs_at_error(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test decryption failure logs at ERROR level."""
        caplog.set_level(logging.ERROR)

        encryption = MasterPassphraseEncryption(passphrase="test_passphrase")

        with pytest.raises(DecryptionError):
            encryption.decrypt(b"invalid_encrypted_data")

        assert "Decryption failed" in caplog.text

    def test_encryption_config_create_provider_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test EncryptionConfig.create_provider logs provider creation."""
        caplog.set_level(logging.INFO)

        config = EncryptionConfig(enabled=False)
        provider = config.create_provider()

        assert isinstance(provider, NoEncryption)
        assert "Creating encryption provider" in caplog.text or "NoEncryption" in caplog.text
