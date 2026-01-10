# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Unit tests for SecretManager and secret type dataclasses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cpu.config.config import Config
from cpu.config.secrets import (
    GitHubAppSecrets,
    GitHubSecretConfig,
    GitLabSecrets,
    S3Secrets,
    SecretConfig,
    SecretManager,
    SecretNotFoundError,
    SecretRefs,
    SecretsConfiguration,
    SmeeSecrets,
)
from cpu.config.secrets_audit import SecretsAuditLogger
from cpu.config.secrets_context import SecretContext
from cpu.config.secrets_sources import EnvVarSecretSource


class TestSecretDataclasses:
    """Test secret type dataclasses."""

    def test_github_app_secrets_creation(self) -> None:
        """Test GitHubAppSecrets creation."""
        secrets = GitHubAppSecrets(
            app_id="123456",
            private_key=b"-----BEGIN RSA PRIVATE KEY-----\ntest\n",
            webhook_secret="secret123",
        )

        assert secrets.app_id == "123456"
        assert isinstance(secrets.private_key, bytes)
        assert secrets.webhook_secret == "secret123"
        assert secrets.installation_id is None

    def test_github_app_secrets_with_installation_id(self) -> None:
        """Test GitHubAppSecrets with optional installation_id."""
        secrets = GitHubAppSecrets(
            app_id="123456",
            private_key=b"key",
            webhook_secret="secret",
            installation_id="789",
        )

        assert secrets.installation_id == "789"

    def test_gitlab_secrets_creation(self) -> None:
        """Test GitLabSecrets creation."""
        secrets = GitLabSecrets(
            token="glpat-abc123",
            webhook_secret="webhook-secret",
        )

        assert secrets.token == "glpat-abc123"
        assert secrets.webhook_secret == "webhook-secret"

    def test_s3_secrets_creation(self) -> None:
        """Test S3Secrets creation."""
        secrets = S3Secrets(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )

        assert secrets.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert secrets.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert secrets.endpoint_url is None
        assert secrets.region is None

    def test_s3_secrets_with_optional_fields(self) -> None:
        """Test S3Secrets with optional fields."""
        secrets = S3Secrets(
            access_key_id="key",
            secret_access_key="secret",
            endpoint_url="https://s3.example.com",
            region="eu-west-1",
        )

        assert secrets.endpoint_url == "https://s3.example.com"
        assert secrets.region == "eu-west-1"

    def test_smee_secrets_creation(self) -> None:
        """Test SmeeSecrets creation."""
        secrets = SmeeSecrets(channel_url="https://smee.io/abc123")

        assert secrets.channel_url == "https://smee.io/abc123"


class TestSecretRefs:
    """Test SecretRefs container."""

    def test_secret_refs_getitem(self) -> None:
        """Test SecretRefs __getitem__."""
        refs = SecretRefs(refs={"app_id": "github.app_id", "private_key": "github.key"})

        assert refs["app_id"] == "github.app_id"
        assert refs["private_key"] == "github.key"

    def test_secret_refs_contains(self) -> None:
        """Test SecretRefs __contains__."""
        refs = SecretRefs(refs={"app_id": "github.app_id"})

        assert "app_id" in refs
        assert "private_key" not in refs

    def test_secret_refs_get_with_default(self) -> None:
        """Test SecretRefs.get() with default."""
        refs = SecretRefs(refs={"app_id": "github.app_id"})

        assert refs.get("app_id") == "github.app_id"
        assert refs.get("missing") is None
        assert refs.get("missing", "default") == "default"


class TestSecretConfig:
    """Test SecretConfig classes."""

    def test_secret_config_matches(self) -> None:
        """Test SecretConfig.matches()."""
        config = GitHubSecretConfig(
            name="test",
            context={"platform": "github", "organization": "EESSI"},
            refs=SecretRefs(refs={}),
        )

        context1 = SecretContext(platform="github", organization="EESSI")
        context2 = SecretContext(platform="github", organization="other")

        assert config.matches(context1) is True
        assert config.matches(context2) is False

    def test_empty_context_matches_all(self) -> None:
        """Test empty context matches any context."""
        config = SecretConfig(
            name="default",
            context={},
            refs=SecretRefs(refs={}),
        )

        context1 = SecretContext(platform="github", organization="EESSI")
        context2 = SecretContext(platform="gitlab")

        assert config.matches(context1) is True
        assert config.matches(context2) is True


class TestSecretsConfiguration:
    """Test SecretsConfiguration loading from Config."""

    def test_from_config_loads_basic_structure(self, tmp_path: Path) -> None:
        """Test loading basic secrets configuration."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  encryption:
    enabled: true
    passphrase_env_var: MY_PASSPHRASE

  sources:
    - type: env
    - type: file
      secrets_dir: /custom/secrets

  github:
    - name: default
      context: {}
      refs:
        app_id: github.default.app_id
        private_key: github.default.private_key
        webhook_secret: github.default.webhook_secret
""")

        config = Config(config_file)
        config.load()

        secrets_config = SecretsConfiguration.from_config(config)

        assert secrets_config.encryption_enabled is True
        assert secrets_config.passphrase_env_var == "MY_PASSPHRASE"
        assert len(secrets_config.sources) == 2
        assert secrets_config.sources[0]["type"] == "env"
        assert len(secrets_config.github_configs) == 1

    def test_from_config_loads_multiple_github_configs(self, tmp_path: Path) -> None:
        """Test loading multiple GitHub configurations."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  github:
    - name: default
      context: {}
      refs:
        app_id: github.default.app_id

    - name: eessi
      context:
        organization: EESSI
      refs:
        app_id: github.eessi.app_id
""")

        config = Config(config_file)
        config.load()

        secrets_config = SecretsConfiguration.from_config(config)

        assert len(secrets_config.github_configs) == 2
        assert secrets_config.github_configs[0].name == "default"
        assert secrets_config.github_configs[1].name == "eessi"
        assert secrets_config.github_configs[1].context == {"organization": "EESSI"}

    def test_from_config_empty_secrets_section(self, tmp_path: Path) -> None:
        """Test handling of missing or empty secrets section."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4")

        config = Config(config_file)
        config.load()

        secrets_config = SecretsConfiguration.from_config(config)

        assert secrets_config.encryption_enabled is False
        assert len(secrets_config.github_configs) == 0


class TestSecretManager:
    """Test SecretManager."""

    def test_initialization(self, tmp_path: Path) -> None:
        """Test SecretManager initialization."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("secrets: {}")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        assert manager.config is config
        assert manager.encryption is not None
        assert manager.audit is not None
        assert len(manager.sources) > 0

    def test_creates_default_sources(self, tmp_path: Path) -> None:
        """Test SecretManager creates default sources if not provided."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("secrets: {}")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        # Should have at least env source
        assert any(isinstance(source, EnvVarSecretSource) for source in manager.sources)

    def test_find_matching_config_most_specific(self, tmp_path: Path) -> None:
        """Test _find_matching_config selects most specific."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  github:
    - name: default
      context: {}
      refs:
        app_id: default_app_id

    - name: eessi_generic
      context:
        organization: EESSI
      refs:
        app_id: eessi.app_id

    - name: software_layer
      context:
        organization: EESSI
        repository: software-layer
      refs:
        app_id: software_layer.app_id
""")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        # Most specific: org + repo
        context1 = SecretContext(
            platform="github",
            organization="EESSI",
            repository="software-layer",
        )
        matched = manager._find_matching_config(
            manager.secrets_config.github_configs,
            context1,
        )
        assert matched is not None
        assert matched.name == "software_layer"

        # Medium: org only
        context2 = SecretContext(
            platform="github",
            organization="EESSI",
            repository="other-repo",
        )
        matched = manager._find_matching_config(
            manager.secrets_config.github_configs,
            context2,
        )
        assert matched is not None
        assert matched.name == "eessi_generic"

        # Least specific: default
        context3 = SecretContext(platform="github", organization="other-org")
        matched = manager._find_matching_config(
            manager.secrets_config.github_configs,
            context3,
        )
        assert matched is not None
        assert matched.name == "default"

    def test_get_github_secrets_from_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test loading GitHub secrets from environment."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  sources:
    - type: env
  github:
    - name: default
      context: {}
      refs:
        app_id: github.default.app_id
        private_key: github.default.private_key
        webhook_secret: github.default.webhook_secret
""")

        monkeypatch.setenv("CPU_SECRETS__GITHUB__DEFAULT__APP_ID", "123456")
        monkeypatch.setenv("CPU_SECRETS__GITHUB__DEFAULT__PRIVATE_KEY", "test-key")
        monkeypatch.setenv("CPU_SECRETS__GITHUB__DEFAULT__WEBHOOK_SECRET", "webhook-secret")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        context = SecretContext(platform="github")
        secrets = manager.get_github_secrets(context)

        assert secrets.app_id == "123456"
        assert secrets.private_key == b"test-key"
        assert secrets.webhook_secret == "webhook-secret"

    def test_get_github_secrets_no_matching_config(self, tmp_path: Path) -> None:
        """Test error when no matching config found."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  github:
    - name: eessi_only
      context:
        organization: EESSI
      refs:
        app_id: eessi.app_id
""")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        context = SecretContext(platform="github", organization="other-org")

        with pytest.raises(SecretNotFoundError, match="No GitHub secret configuration"):
            manager.get_github_secrets(context)

    def test_get_github_secrets_missing_secret(
        self, tmp_path: Path
    ) -> None:
        """Test error when secret not found in sources."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  sources:
    - type: env
  github:
    - name: default
      context: {}
      refs:
        app_id: github.app_id
        private_key: github.key
        webhook_secret: github.webhook
""")

        # Don't set any env vars

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        context = SecretContext(platform="github")

        with pytest.raises(SecretNotFoundError):
            manager.get_github_secrets(context)

    def test_secrets_cached_after_first_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that secrets are cached."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  sources:
    - type: env
  github:
    - name: default
      context: {}
      refs:
        app_id: github.app_id
        private_key: github.key
        webhook_secret: github.webhook
""")

        monkeypatch.setenv("CPU_SECRETS__GITHUB__APP_ID", "123")
        monkeypatch.setenv("CPU_SECRETS__GITHUB__KEY", "key")
        monkeypatch.setenv("CPU_SECRETS__GITHUB__WEBHOOK", "secret")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        context = SecretContext(platform="github")

        secrets1 = manager.get_github_secrets(context)

        # Change env (shouldn't affect cache)
        monkeypatch.setenv("CPU_SECRETS__GITHUB__APP_ID", "456")

        secrets2 = manager.get_github_secrets(context)

        assert secrets1.app_id == "123"
        assert secrets2.app_id == "123"
        assert secrets1 is secrets2  # Same object
