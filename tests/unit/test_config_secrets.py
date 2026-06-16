# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Unit tests for SecretManager and secret type dataclasses.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

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
from cpu.config.secrets_encryption import EncryptionProvider, NoEncryption
from cpu.config.secrets_sources import EnvVarSecretSource, FileSecretSource, SecretSource, SecretValue


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

    def test_parse_gitlab_config(self, tmp_path: Path) -> None:
        """Test parsing GitLab secret configuration."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  gitlab:
    - name: production
      context:
        platform: gitlab
        environment: production
      refs:
        token: gitlab.prod.token
        webhook_secret: gitlab.prod.webhook_secret
""")

        config = Config(config_file=config_file)
        config.load()

        secrets_config = SecretsConfiguration.from_config(config)

        assert len(secrets_config.gitlab_configs) == 1
        assert secrets_config.gitlab_configs[0].name == "production"
        assert secrets_config.gitlab_configs[0].context == {"platform": "gitlab", "environment": "production"}
        assert "token" in secrets_config.gitlab_configs[0].refs
        assert "webhook_secret" in secrets_config.gitlab_configs[0].refs

    def test_parse_s3_config(self, tmp_path: Path) -> None:
        """Test parsing S3 secret configuration."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  s3:
    - name: software-eessi
      context:
        cvmfs_repo: software.eessi.io
        environment: production
      refs:
        access_key_id: s3.eessi.access_key
        secret_access_key: s3.eessi.secret_key
        endpoint_url: s3.eessi.endpoint
        region: s3.eessi.region
""")

        config = Config(config_file=config_file)
        config.load()

        secrets_config = SecretsConfiguration.from_config(config)

        assert len(secrets_config.s3_configs) == 1
        assert secrets_config.s3_configs[0].name == "software-eessi"
        assert secrets_config.s3_configs[0].context == {"cvmfs_repo": "software.eessi.io", "environment": "production"}
        assert "access_key_id" in secrets_config.s3_configs[0].refs
        assert "secret_access_key" in secrets_config.s3_configs[0].refs
        assert "endpoint_url" in secrets_config.s3_configs[0].refs
        assert "region" in secrets_config.s3_configs[0].refs

    def test_parse_smee_config(self, tmp_path: Path) -> None:
        """Test parsing Smee secret configuration."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  smee:
    - name: development
      context: {}
      refs:
        channel_url: smee.dev.channel_url
""")

        config = Config(config_file=config_file)
        config.load()

        secrets_config = SecretsConfiguration.from_config(config)

        assert len(secrets_config.smee_configs) == 1
        assert secrets_config.smee_configs[0].name == "development"
        assert secrets_config.smee_configs[0].context == {}
        assert "channel_url" in secrets_config.smee_configs[0].refs

    def test_parse_multiple_platform_configs(self, tmp_path: Path) -> None:
        """Test parsing multiple platform configurations in one file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  github:
    - name: eessi
      context:
        organization: EESSI
      refs:
        app_id: github.eessi.app_id
        private_key: github.eessi.private_key
        webhook_secret: github.eessi.webhook_secret
  gitlab:
    - name: prod
      context:
        environment: production
      refs:
        token: gitlab.prod.token
        webhook_secret: gitlab.prod.webhook_secret
  s3:
    - name: cvmfs
      context:
        cvmfs_repo: software.eessi.io
      refs:
        access_key_id: s3.access_key
        secret_access_key: s3.secret_key
  smee:
    - name: dev
      context: {}
      refs:
        channel_url: smee.channel
""")

        config = Config(config_file=config_file)
        config.load()

        secrets_config = SecretsConfiguration.from_config(config)

        assert len(secrets_config.github_configs) == 1
        assert len(secrets_config.gitlab_configs) == 1
        assert len(secrets_config.s3_configs) == 1
        assert len(secrets_config.smee_configs) == 1


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

    def test_get_github_secrets_with_installation_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test get_github_secrets loads optional installation_id ref."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  github:
    - name: default
      context: {}
      refs:
        app_id: github.default.app_id
        private_key: github.default.private_key
        webhook_secret: github.default.webhook_secret
        installation_id: github.default.installation_id
""")

        config = Config(config_file)
        config.load()

        monkeypatch.setenv("CPU_SECRETS__GITHUB__DEFAULT__APP_ID", "12345")
        monkeypatch.setenv("CPU_SECRETS__GITHUB__DEFAULT__PRIVATE_KEY", "fake-key")
        monkeypatch.setenv("CPU_SECRETS__GITHUB__DEFAULT__WEBHOOK_SECRET", "secret")
        monkeypatch.setenv("CPU_SECRETS__GITHUB__DEFAULT__INSTALLATION_ID", "67890")

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        context = SecretContext(platform="github")
        secrets = manager.get_github_secrets(context)

        assert secrets.app_id == "12345"

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

    def test_get_gitlab_secrets(self, tmp_path: Path) -> None:
        """Test get_gitlab_secrets retrieves and caches secrets."""
        # Setup secrets
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "gitlab_token").write_text("token123")
        (secrets_dir / "gitlab_webhook").write_text("webhook_secret")

        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)
        encryption = NoEncryption()
        source = FileSecretSource(audit, encryption, secrets_dir=secrets_dir)

        # Setup configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {
            "gitlab": [{
                "name": "production",
                "context": {"platform": "gitlab"},
                "refs": {
                    "token": "gitlab_token",
                    "webhook_secret": "gitlab_webhook"
                }
            }]
        }

        manager = SecretManager(config, audit_logger=audit)
        manager.sources = [source]

        context = SecretContext(platform="gitlab", environment="production")
        secrets = manager.get_gitlab_secrets(context)

        assert secrets.token == "token123"
        assert secrets.webhook_secret == "webhook_secret"

        # Test cache hit
        secrets2 = manager.get_gitlab_secrets(context)
        assert secrets2 is secrets

    def test_get_gitlab_secrets_wraps_secret_not_found(self, tmp_path: Path) -> None:
        """Test get_gitlab_secrets wraps SecretNotFoundError from missing refs."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  gitlab:
    - name: default
      context: {}
      refs:
        token: gitlab.token
        webhook_secret: gitlab.webhook
""")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        context = SecretContext(platform="gitlab")

        with pytest.raises(SecretNotFoundError, match="Failed to load GitLab secrets for config 'default'"):
            manager.get_gitlab_secrets(context)

    def test_get_s3_secrets(self, tmp_path: Path) -> None:
        """Test get_s3_secrets retrieves and caches secrets."""
        # Setup secrets
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "s3_access_key").write_text("AKIAIOSFODNN7EXAMPLE")
        (secrets_dir / "s3_secret_key").write_text("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        (secrets_dir / "s3_endpoint").write_text("https://s3.example.com")
        (secrets_dir / "s3_region").write_text("us-east-1")

        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)
        encryption = NoEncryption()
        source = FileSecretSource(audit, encryption, secrets_dir=secrets_dir)

        # Setup configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {
            "s3": [{
                "name": "cvmfs",
                "context": {"cvmfs_repo": "software.eessi.io"},
                "refs": {
                    "access_key_id": "s3_access_key",
                    "secret_access_key": "s3_secret_key",
                    "endpoint_url": "s3_endpoint",
                    "region": "s3_region"
                }
            }]
        }

        manager = SecretManager(config, audit_logger=audit)
        manager.sources = [source]

        context = SecretContext(cvmfs_repo="software.eessi.io", environment="production")
        secrets = manager.get_s3_secrets(context)

        assert secrets.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert secrets.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert secrets.endpoint_url == "https://s3.example.com"
        assert secrets.region == "us-east-1"

        # Test cache hit
        secrets2 = manager.get_s3_secrets(context)
        assert secrets2 is secrets

    def test_get_s3_secrets_wraps_secret_not_found(self, tmp_path: Path) -> None:
        """Test get_s3_secrets wraps SecretNotFoundError from missing refs."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  s3:
    - name: default
      context: {}
      refs:
        access_key_id: s3.access_key
        secret_access_key: s3.secret_key
""")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        context = SecretContext(cvmfs_repo="software.eessi.io")

        with pytest.raises(SecretNotFoundError, match="Failed to load S3 secrets for config 'default'"):
            manager.get_s3_secrets(context)

    def test_get_s3_secrets_optional_fields(self, tmp_path: Path) -> None:
        """Test get_s3_secrets with only required fields."""
        # Setup secrets
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "s3_access_key").write_text("AKIAIOSFODNN7EXAMPLE")
        (secrets_dir / "s3_secret_key").write_text("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)
        encryption = NoEncryption()
        source = FileSecretSource(audit, encryption, secrets_dir=secrets_dir)

        # Setup configuration without optional fields
        config = MagicMock(spec=Config)
        config.get.return_value = {
            "s3": [{
                "name": "cvmfs",
                "context": {},
                "refs": {
                    "access_key_id": "s3_access_key",
                    "secret_access_key": "s3_secret_key"
                }
            }]
        }

        manager = SecretManager(config, audit_logger=audit)
        manager.sources = [source]

        context = SecretContext(cvmfs_repo="software.eessi.io")
        secrets = manager.get_s3_secrets(context)

        assert secrets.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert secrets.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert secrets.endpoint_url is None
        assert secrets.region is None

    def test_get_smee_secrets(self, tmp_path: Path) -> None:
        """Test get_smee_secrets retrieves and caches secrets."""
        # Setup secrets
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "smee_channel").write_text("https://smee.io/abc123")

        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)
        encryption = NoEncryption()
        source = FileSecretSource(audit, encryption, secrets_dir=secrets_dir)

        # Setup configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {
            "smee": [{
                "name": "development",
                "context": {},
                "refs": {
                    "channel_url": "smee_channel"
                }
            }]
        }

        manager = SecretManager(config, audit_logger=audit)
        manager.sources = [source]

        secrets = manager.get_smee_secrets()

        assert secrets.channel_url == "https://smee.io/abc123"

        # Test cache hit
        secrets2 = manager.get_smee_secrets()
        assert secrets2 is secrets

    def test_get_smee_secrets_wraps_secret_not_found(self, tmp_path: Path) -> None:
        """Test get_smee_secrets wraps SecretNotFoundError from missing refs."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  smee:
    - name: default
      refs:
        channel_url: smee.channel_url
""")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        with pytest.raises(SecretNotFoundError, match="Failed to load Smee secrets for config 'default'"):
            manager.get_smee_secrets()

    def test_get_gitlab_secrets_no_matching_config(self, tmp_path: Path) -> None:
        """Test get_gitlab_secrets raises error when no config matches."""
        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        config = MagicMock(spec=Config)
        config.get.return_value = {"gitlab": []}

        manager = SecretManager(config, audit_logger=audit)

        context = SecretContext(platform="gitlab")

        with pytest.raises(SecretNotFoundError, match="No GitLab secret configuration matches"):
            manager.get_gitlab_secrets(context)

    def test_get_s3_secrets_no_matching_config(self, tmp_path: Path) -> None:
        """Test get_s3_secrets raises error when no config matches."""
        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        config = MagicMock(spec=Config)
        config.get.return_value = {"s3": []}

        manager = SecretManager(config, audit_logger=audit)

        context = SecretContext(cvmfs_repo="software.eessi.io")

        with pytest.raises(SecretNotFoundError, match="No S3 secret configuration matches"):
            manager.get_s3_secrets(context)

    def test_get_smee_secrets_no_config(self, tmp_path: Path) -> None:
        """Test get_smee_secrets raises error when no config exists."""
        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        config = MagicMock(spec=Config)
        config.get.return_value = {"smee": []}

        manager = SecretManager(config, audit_logger=audit)

        with pytest.raises(SecretNotFoundError, match="No Smee secret configuration found"):
            manager.get_smee_secrets()

    def test_create_file_source_from_config(self, tmp_path: Path) -> None:
        """Test creating file secret source from configuration."""
        secrets_dir = tmp_path / "custom_secrets"
        secrets_dir.mkdir()

        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        config = MagicMock(spec=Config)
        config.get.return_value = {
            "sources": [
                {"type": "file", "secrets_dir": str(secrets_dir)}
            ]
        }

        manager = SecretManager(config, audit_logger=audit)

        assert len(manager.sources) == 1
        assert isinstance(manager.sources[0], FileSecretSource)
        assert manager.sources[0].secrets_dir == secrets_dir

    def test_create_env_source_from_config(self, tmp_path: Path) -> None:
        """Test creating env secret source from configuration."""
        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        config = MagicMock(spec=Config)
        config.get.return_value = {
            "sources": [
                {"type": "env"}
            ]
        }

        manager = SecretManager(config, audit_logger=audit)

        assert len(manager.sources) == 1
        assert isinstance(manager.sources[0], EnvVarSecretSource)

    def test_create_multiple_sources_from_config(self, tmp_path: Path) -> None:
        """Test creating multiple sources in priority order."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        config = MagicMock(spec=Config)
        config.get.return_value = {
            "sources": [
                {"type": "env"},
                {"type": "file", "secrets_dir": str(secrets_dir)}
            ]
        }

        manager = SecretManager(config, audit_logger=audit)

        assert len(manager.sources) == 2
        assert isinstance(manager.sources[0], EnvVarSecretSource)
        assert isinstance(manager.sources[1], FileSecretSource)

    def test_default_source_when_none_configured(self, tmp_path: Path) -> None:
        """Test default env source is created when no sources configured."""
        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        config = MagicMock(spec=Config)
        config.get.return_value = {}  # No sources in config

        manager = SecretManager(config, audit_logger=audit)

        # Should have default env source
        assert len(manager.sources) == 1
        assert isinstance(manager.sources[0], EnvVarSecretSource)

    def test_custom_encryption_provider(self, tmp_path: Path) -> None:
        """Test passing custom encryption provider."""
        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        custom_encryption = Mock(spec=EncryptionProvider)

        config = MagicMock(spec=Config)
        config.get.return_value = {}

        manager = SecretManager(config, audit_logger=audit, encryption=custom_encryption)

        assert manager.encryption is custom_encryption

    def test_custom_sources(self, tmp_path: Path) -> None:
        """Test passing custom sources."""
        audit_log = tmp_path / "audit.log"
        audit = SecretsAuditLogger(audit_file=audit_log)

        custom_source = Mock(spec=SecretSource)

        config = MagicMock(spec=Config)
        config.get.return_value = {}

        manager = SecretManager(config, sources=[custom_source], audit_logger=audit)

        assert len(manager.sources) == 1
        assert manager.sources[0] is custom_source

    def test_secret_manager_creates_default_audit_logger(self, tmp_path: Path) -> None:
        """Test SecretManager creates a default SecretsAuditLogger when none provided."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 1")

        config = Config(config_file)
        config.load()

        with patch("cpu.config.secrets.SecretsAuditLogger") as mock_audit_cls:
            manager = SecretManager(config)

        mock_audit_cls.assert_called_once_with(audit_file=Path("logs/secrets_audit.log"))
        assert manager.audit is mock_audit_cls.return_value

    def test_secret_manager_audit_logger_path_configurable(self, tmp_path: Path) -> None:
        """Test secrets.audit_log_file overrides the default audit log path."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 1
secrets:
  audit_log_file: custom/audit.log
""")

        config = Config(config_file)
        config.load()

        with patch("cpu.config.secrets.SecretsAuditLogger") as mock_audit_cls:
            SecretManager(config)

        mock_audit_cls.assert_called_once_with(audit_file=Path("custom/audit.log"))

    def test_create_sources_with_file_source(self, tmp_path: Path) -> None:
        """Test _create_sources_from_config creates FileSecretSource for 'file' type."""
        secrets_dir = tmp_path / "secrets"
        config_file = tmp_path / "config.yaml"
        config_file.write_text(f"""
bot:
  num_workers: 1
secrets:
  sources:
    - type: file
      secrets_dir: {secrets_dir}
    - type: vault
""")

        config = Config(config_file)
        config.load()

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        assert any(isinstance(s, FileSecretSource) for s in manager.sources)


class TestSecretsLogging:
    """Test logging functionality in secrets manager."""

    def test_secrets_configuration_from_config_logs_at_info(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test SecretsConfiguration.from_config logs at INFO level."""
        caplog.set_level(logging.INFO)

        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
secrets:
  encryption:
    enabled: true
  github:
    - name: default
      context: {}
      refs:
        app_id: github.app_id
""")

        config = Config(config_file=config_file)
        config.load()

        caplog.clear()
        SecretsConfiguration.from_config(config)

        assert "Loading secrets configuration" in caplog.text
        assert "encryption=True" in caplog.text

    def test_secret_manager_init_logs_at_info(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test SecretManager initialization logs at INFO level."""
        caplog.set_level(logging.INFO)

        # mock config that returns empty secrets configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {}

        # use temp path for audit log
        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        SecretManager(config, audit_logger=audit_logger)

        assert "Initialized SecretManager" in caplog.text

    def test_load_secret_value_logs_at_debug(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test _load_secret_value logs at DEBUG level."""
        caplog.set_level(logging.DEBUG)

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        secret_file = secrets_dir / "test_secret"
        secret_file.write_text("secret_value")

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = FileSecretSource(audit_logger, encryption, secrets_dir=secrets_dir)

        # mock config that returns empty secrets configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {}

        manager = SecretManager(config, audit_logger=audit_logger)
        manager.sources = [source]

        caplog.clear()
        manager._load_secret_value("test_secret")

        assert "Loading secret" in caplog.text
        assert "test_secret" in caplog.text
        assert "secret_value" not in caplog.text  # should not log actual value

    def test_load_secret_fallback_logs_at_debug(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test _load_secret_value fallback attempt logs at DEBUG level."""
        caplog.set_level(logging.DEBUG)

        # Create two sources where first fails, second succeeds
        source1 = Mock(spec=SecretSource)
        source1.get_secret.side_effect = KeyError("Not found")
        source1.__class__.__name__ = "Source1"

        source2 = Mock(spec=SecretSource)
        source2.get_secret.return_value = SecretValue("value", "source2", "test", False)
        source2.__class__.__name__ = "Source2"

        # mock config that returns empty secrets configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {}

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)
        manager.sources = [source1, source2]

        caplog.clear()
        manager._load_secret_value("test_secret")

        assert "trying next source" in caplog.text

    def test_load_secret_not_found_logs_at_error(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test secret not found logs at ERROR level."""
        caplog.set_level(logging.ERROR)

        # mock config that returns empty secrets configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {}

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)
        manager.sources = []

        with pytest.raises(SecretNotFoundError):
            manager._load_secret_value("nonexistent")

        assert "not found in any source" in caplog.text
        assert "nonexistent" in caplog.text

    def test_get_github_secrets_logs_at_info(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test get_github_secrets logs at INFO level."""
        caplog.set_level(logging.INFO)

        # Setup secrets
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "app_id").write_text("12345")
        (secrets_dir / "private_key").write_text("test_key")
        (secrets_dir / "webhook_secret").write_text("test_secret")

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = FileSecretSource(audit_logger, encryption, secrets_dir=secrets_dir)

        # create mock config that returns our secrets configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {
            "github": [{
                "name": "default",
                "context": {},
                "refs": {
                    "app_id": "app_id",
                    "private_key": "private_key",
                    "webhook_secret": "webhook_secret"
                }
            }]
        }

        manager = SecretManager(config, audit_logger=audit_logger)
        manager.sources = [source]

        caplog.clear()
        context = SecretContext(platform="github", organization="EESSI")
        manager.get_github_secrets(context)

        assert "Retrieved GitHub secrets" in caplog.text or "Loading GitHub secrets" in caplog.text
        assert "default" in caplog.text

    def test_get_secrets_cache_hit_logs_at_debug(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test cache hit logs at DEBUG level."""
        caplog.set_level(logging.DEBUG)

        # Setup secrets
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "app_id").write_text("12345")
        (secrets_dir / "private_key").write_text("test_key")
        (secrets_dir / "webhook_secret").write_text("test_secret")

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        encryption = NoEncryption()
        source = FileSecretSource(audit_logger, encryption, secrets_dir=secrets_dir)

        # create mock config that returns our secrets configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {
            "github": [{
                "name": "default",
                "context": {},
                "refs": {
                    "app_id": "app_id",
                    "private_key": "private_key",
                    "webhook_secret": "webhook_secret"
                }
            }]
        }

        manager = SecretManager(config, audit_logger=audit_logger)
        manager.sources = [source]

        context = SecretContext(platform="github", organization="EESSI")

        # First call - miss
        manager.get_github_secrets(context)

        # Second call - hit
        caplog.clear()
        manager.get_github_secrets(context)

        assert "cache hit" in caplog.text.lower() or "Using cached" in caplog.text

    def test_no_matching_config_logs_at_error(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test no matching configuration logs at ERROR level."""
        caplog.set_level(logging.ERROR)

        # create mock config that returns our secrets configuration
        config = MagicMock(spec=Config)
        config.get.return_value = {"github": []}

        audit_logger = SecretsAuditLogger(audit_file=tmp_path / "audit.log")
        manager = SecretManager(config, audit_logger=audit_logger)

        context = SecretContext(platform="github", organization="EESSI")

        with pytest.raises(SecretNotFoundError):
            manager.get_github_secrets(context)

        assert "No matching" in caplog.text or "not found" in caplog.text.lower()
