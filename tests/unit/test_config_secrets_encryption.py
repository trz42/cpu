# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.config.secrets_encryption module.

Tests encryption providers for optional secret encryption at rest.
"""

from __future__ import annotations

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
