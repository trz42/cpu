# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Secret encryption/decryption with master passphrase.

Supports optional encryption for secrets at rest. When enabled:
1. Bot operator enters master passphrase at startup
2. Encrypted secrets are decrypted on-demand and kept in memory
3. SSH keys remain in memory only

Uses Fernet (symmetric encryption from cryptography library).
"""

from __future__ import annotations

import base64
import getpass
import os
import secrets
from typing import Protocol

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class DecryptionError(Exception):
    """Raised when decryption fails."""

    pass


class EncryptionProvider(Protocol):
    """Protocol for encryption/decryption."""

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data."""
        ...


class NoEncryption:
    """No-op encryption provider (secrets stored in plaintext)."""

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Return data as-is."""
        return encrypted_data


class MasterPassphraseEncryption:
    """
    Encryption using master passphrase.

    Secrets are encrypted at rest with Fernet (AES-128).
    Master passphrase is:
    - Entered at startup (interactive or env var)
    - Used to derive encryption key via PBKDF2
    - Never stored, only kept in memory during bot lifetime

    Encrypted data format: salt (16 bytes) + fernet_ciphertext
    """

    def __init__(self, passphrase: str | None = None) -> None:
        """
        Initialize encryption provider.

        Args:
            passphrase: Master passphrase. If None, prompt interactively.
        """
        self._passphrase = passphrase or self._prompt_passphrase()
        self._fernet_cache: dict[bytes, Fernet] = {}  # Cache Fernet per salt

    def _prompt_passphrase(self) -> str:
        """Prompt for master passphrase interactively."""
        return getpass.getpass("Enter master passphrase for secrets: ")

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data with random salt.

        Args:
            plaintext: Data to encrypt

        Returns:
            salt (16 bytes) + fernet_ciphertext
        """
        # Generate random salt
        salt = secrets.token_bytes(16)

        # Derive key and create Fernet
        key = self._derive_key(salt)
        fernet = Fernet(key)

        # Encrypt
        ciphertext = fernet.encrypt(plaintext)

        return salt + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt secret data.

        Format: salt (16 bytes) + encrypted_data

        Args:
            encrypted_data: Encrypted data with salt prefix

        Returns:
            Decrypted plaintext bytes

        Raises:
            DecryptionError: If decryption fails (wrong passphrase, corrupt data)
        """
        if len(encrypted_data) < 16:
            raise DecryptionError("Invalid encrypted data (too short)")

        # Extract salt and ciphertext
        salt = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Get or create Fernet for this salt
        if salt not in self._fernet_cache:
            key = self._derive_key(salt)
            self._fernet_cache[salt] = Fernet(key)

        fernet = self._fernet_cache[salt]

        try:
            return fernet.decrypt(ciphertext)
        except InvalidToken as err:
            raise DecryptionError(f"Decryption failed: {err}") from err
        except Exception as err:
            raise DecryptionError(f"Decryption failed: {err}") from err

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive encryption key from passphrase using PBKDF2.

        Args:
            salt: Random salt (16 bytes)

        Returns:
            32-byte key for Fernet (base64-encoded)
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Recommended minimum
        )
        key_bytes = kdf.derive(self._passphrase.encode("utf-8"))
        return base64.urlsafe_b64encode(key_bytes)


class EncryptionConfig:
    """Configuration for encryption."""

    def __init__(
        self,
        enabled: bool = False,
        passphrase_env_var: str = "CPU_MASTER_PASSPHRASE",
    ) -> None:
        """
        Initialize encryption configuration.

        Args:
            enabled: Whether encryption is enabled
            passphrase_env_var: Env var to read passphrase from (optional)
        """
        self.enabled = enabled
        self.passphrase_env_var = passphrase_env_var

    def create_provider(self) -> EncryptionProvider:
        """
        Create encryption provider based on configuration.

        Returns:
            NoEncryption if disabled, MasterPassphraseEncryption if enabled
        """
        if not self.enabled:
            return NoEncryption()

        # Try to get passphrase from env var first
        passphrase = os.environ.get(self.passphrase_env_var)

        return MasterPassphraseEncryption(passphrase=passphrase)
