# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Main secret manager with configuration-based secret mapping.

This module provides:
- Secret dataclasses (GitHubAppSecrets, GitLabSecrets, S3Secrets, SmeeSecrets)
- Configuration parsing (SecretsConfiguration)
- Secret manager with context-based resolution
- Multi-source fallback chain
- Secret caching
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cpu.config.config import Config
from cpu.config.secrets_audit import SecretsAuditLogger
from cpu.config.secrets_context import SecretContext
from cpu.config.secrets_encryption import EncryptionConfig, EncryptionProvider
from cpu.config.secrets_sources import EnvVarSecretSource, FileSecretSource, SecretSource, SecretValue

# Custom exceptions


class SecretNotFoundError(Exception):
    """
    Raised when required secret cannot be found.

    This includes:
    - No matching secret configuration for context
    - Secret reference not found in any source
    - Required fields missing from configuration
    """

    pass


class SecretConfigurationError(Exception):
    """
    Raised when secret configuration is invalid.

    This includes:
    - Malformed configuration
    - Missing required configuration sections
    - Invalid context patterns
    """

    pass


# Secret dataclasses


@dataclass
class GitHubAppSecrets:
    """
    GitHub App credentials.

    Attributes:
        app_id: GitHub App ID (numeric string)
        private_key: GitHub App private key (PEM format, bytes)
        webhook_secret: Secret for validating webhook signatures
        installation_id: Optional GitHub App installation ID
    """

    app_id: str
    private_key: bytes
    webhook_secret: str
    installation_id: str | None = None


@dataclass
class GitLabSecrets:
    """
    GitLab credentials.

    Attributes:
        token: GitLab personal access token or project token
        webhook_secret: Secret for validating webhook signatures
    """

    token: str
    webhook_secret: str


@dataclass
class S3Secrets:
    """
    S3/object storage credentials.

    Attributes:
        access_key_id: S3 access key ID
        secret_access_key: S3 secret access key
        endpoint_url: Optional custom S3 endpoint URL
        region: Optional AWS region
    """

    access_key_id: str
    secret_access_key: str
    endpoint_url: str | None = None
    region: str | None = None


@dataclass
class SmeeSecrets:
    """
    Smee webhook proxy credentials.

    Attributes:
        channel_url: Smee channel URL (e.g., https://smee.io/abc123)
    """

    channel_url: str


# Configuration classes


@dataclass
class SecretRefs:
    """
    Container for secret references.

    Maps field names to secret reference strings.
    Provides dict-like access to references.

    Example:
        refs = SecretRefs(refs={
            "app_id": "github.eessi.app_id",
            "private_key": "github.eessi.private_key",
        })
        refs["app_id"]  # Returns "github.eessi.app_id"
    """

    refs: dict[str, str] = field(default_factory=dict)

    def __getitem__(self, key: str) -> str:
        """Get secret reference by name."""
        return self.refs[key]

    def __contains__(self, key: str) -> bool:
        """Check if reference exists."""
        return key in self.refs

    def get(self, key: str, default: str | None = None) -> str | None:
        """Get reference with optional default."""
        return self.refs.get(key, default)


@dataclass
class SecretConfig:
    """
    Configuration for a set of secrets with context matching.

    Attributes:
        name: Human-readable name for this configuration
        context: Context pattern to match (empty dict matches all)
        refs: Mapping of field names to secret references
    """

    name: str
    context: dict[str, str]
    refs: SecretRefs

    def matches(self, context: SecretContext) -> bool:
        """
        Check if this config matches the given context.

        Uses SecretContext.matches() to compare patterns.

        Args:
            context: Context to check

        Returns:
            True if context matches this configuration's pattern
        """
        return context.matches(self.context)


@dataclass
class GitHubSecretConfig(SecretConfig):
    """GitHub-specific secret configuration."""

    pass


@dataclass
class GitLabSecretConfig(SecretConfig):
    """GitLab-specific secret configuration."""

    pass


@dataclass
class S3SecretConfig(SecretConfig):
    """S3-specific secret configuration."""

    pass


@dataclass
class SecretsConfiguration:
    """
    Complete secrets configuration loaded from YAML.

    Parses the 'secrets' section from config.yaml and provides
    structured access to encryption settings, sources, and
    secret configurations for different platforms.

    Attributes:
        encryption_enabled: Whether encryption is enabled
        passphrase_env_var: Env var for main passphrase
        sources: List of source configurations in priority order
        github_configs: List of GitHub secret configurations
        gitlab_configs: List of GitLab secret configurations
        s3_configs: List of S3 secret configurations
        smee_configs: List of Smee secret configurations
    """

    encryption_enabled: bool = False
    passphrase_env_var: str = "CPU_MAIN_PASSPHRASE"
    sources: list[dict[str, Any]] = field(default_factory=list)
    github_configs: list[GitHubSecretConfig] = field(default_factory=list)
    gitlab_configs: list[GitLabSecretConfig] = field(default_factory=list)
    s3_configs: list[S3SecretConfig] = field(default_factory=list)
    smee_configs: list[SecretConfig] = field(default_factory=list)

    @classmethod
    def from_config(cls, config: Config) -> SecretsConfiguration:
        """
        Load secrets configuration from Config object.

        Parses the 'secrets' section from the YAML configuration
        and creates structured configuration objects.

        Args:
            config: Config object with loaded YAML

        Returns:
            SecretsConfiguration instance
        """
        secrets_data = config.get("secrets", {})

        # Parse encryption settings
        encryption_data = secrets_data.get("encryption", {})
        encryption_enabled = encryption_data.get("enabled", False)
        passphrase_env_var = encryption_data.get("passphrase_env_var", "CPU_MAIN_PASSPHRASE")

        # Parse sources
        sources = secrets_data.get("sources", [])

        # Parse GitHub configs
        github_configs: list[GitHubSecretConfig] = []
        for gh_data in secrets_data.get("github", []):
            github_config = GitHubSecretConfig(
                name=gh_data["name"], context=gh_data.get("context", {}), refs=SecretRefs(refs=gh_data.get("refs", {}))
            )
            github_configs.append(github_config)

        # Parse GitLab configs
        gitlab_configs: list[GitLabSecretConfig] = []
        for gl_data in secrets_data.get("gitlab", []):
            gitlab_config = GitLabSecretConfig(
                name=gl_data["name"], context=gl_data.get("context", {}), refs=SecretRefs(refs=gl_data.get("refs", {}))
            )
            gitlab_configs.append(gitlab_config)

        # Parse S3 configs
        s3_configs: list[S3SecretConfig] = []
        for s3_data in secrets_data.get("s3", []):
            s3_config = S3SecretConfig(
                name=s3_data["name"], context=s3_data.get("context", {}), refs=SecretRefs(refs=s3_data.get("refs", {}))
            )
            s3_configs.append(s3_config)

        # Parse Smee configs
        smee_configs: list[SecretConfig] = []
        for smee_data in secrets_data.get("smee", []):
            smee_config = SecretConfig(
                name=smee_data["name"],
                context=smee_data.get("context", {}),
                refs=SecretRefs(refs=smee_data.get("refs", {})),
            )
            smee_configs.append(smee_config)

        return cls(
            encryption_enabled=encryption_enabled,
            passphrase_env_var=passphrase_env_var,
            sources=sources,
            github_configs=github_configs,
            gitlab_configs=gitlab_configs,
            s3_configs=s3_configs,
            smee_configs=smee_configs,
        )


# Main SecretManager


class SecretManager:
    """
    Main interface for secret management with configuration-based mapping.

    Features:
    - Configuration-based context-to-secret mapping
    - Multi-source fallback chain (env → file → vault)
    - Secret caching (load once at startup)
    - Audit logging
    - Most specific context matching

    Usage:
        config = Config(config_file="config.yaml")
        config.load()

        manager = SecretManager(config)

        # Get GitHub secrets for specific context
        context = SecretContext(platform="github", organization="EESSI")
        github_secrets = manager.get_github_secrets(context)

        # Access credentials
        app_id = github_secrets.app_id
        private_key = github_secrets.private_key
    """

    def __init__(
        self,
        config: Config,
        sources: list[SecretSource] | None = None,
        audit_logger: SecretsAuditLogger | None = None,
        encryption: EncryptionProvider | None = None,
    ) -> None:
        """
        Initialize secret manager.

        Args:
            config: Configuration object
            sources: Optional list of secret sources (created from config if None)
            audit_logger: Optional audit logger (created if None)
            encryption: Optional encryption provider (created from config if None)
        """
        self.config = config

        # Load secrets configuration from config
        self.secrets_config = SecretsConfiguration.from_config(config)

        # Initialize encryption
        if encryption is None:
            encryption = self._create_encryption_provider()
        self.encryption = encryption

        # Initialize audit logger
        if audit_logger is None:
            audit_logger = SecretsAuditLogger()
        self.audit = audit_logger

        # Initialize sources
        if sources is None:
            sources = self._create_sources_from_config()
        self.sources = sources

        # Cache for loaded secrets
        self._github_cache: dict[str, GitHubAppSecrets] = {}
        self._gitlab_cache: dict[str, GitLabSecrets] = {}
        self._s3_cache: dict[str, S3Secrets] = {}
        self._smee_cache: dict[str, SmeeSecrets] = {}

    def _create_encryption_provider(self) -> EncryptionProvider:
        """Create encryption provider from configuration."""
        encryption_config = EncryptionConfig(
            enabled=self.secrets_config.encryption_enabled,
            passphrase_env_var=self.secrets_config.passphrase_env_var,
        )
        return encryption_config.create_provider()

    def _create_sources_from_config(self) -> list[SecretSource]:
        """
        Create secret sources from configuration.

        Sources are created in the order specified in configuration.
        If no sources are configured, creates default EnvVarSecretSource.

        Returns:
            List of SecretSource instances
        """
        sources: list[SecretSource] = []

        for source_config in self.secrets_config.sources:
            source_type = source_config.get("type")

            if source_type == "env":
                sources.append(EnvVarSecretSource(self.audit, self.encryption))

            elif source_type == "file":
                secrets_dir = Path(source_config.get("secrets_dir", "/etc/cpu/secrets"))
                sources.append(FileSecretSource(self.audit, self.encryption, secrets_dir))

            # Future: vault, etc.

        # Always have at least env source
        if not sources:
            sources.append(EnvVarSecretSource(self.audit, self.encryption))

        return sources

    def _find_matching_config(
        self,
        configs: Sequence[SecretConfig],
        context: SecretContext,
    ) -> SecretConfig | None:
        """
        Find the most specific matching configuration.

        Returns the config with the most context fields matching.
        Configs with empty context match anything (lowest priority).

        Args:
            configs: Sequence of secret configurations
            context: Context to match against

        Returns:
            Best matching config, or None if no match
        """
        matches = []

        for config in configs:
            if config.matches(context):
                # Count specificity (more context fields = more specific)
                specificity = len([value for value in config.context.values() if value])
                matches.append((specificity, config))

        if not matches:
            return None

        # Return most specific match (highest specificity score)
        matches.sort(key=lambda x: x[0], reverse=True)
        return matches[0][1]

    def _load_secret_value(self, secret_ref: str) -> SecretValue:
        """
        Load a secret value from sources.

        Tries each source in order until one succeeds.

        Args:
            secret_ref: Secret reference to load

        Returns:
            SecretValue

        Raises:
            SecretNotFoundError: If secret not found in any source
        """
        errors = []

        for source in self.sources:
            try:
                return source.get_secret(secret_ref)
            except (KeyError, FileNotFoundError) as err:
                errors.append(f"{source.__class__.__name__}: {err}")
                continue

        # Not found in any source
        raise SecretNotFoundError(f"Secret '{secret_ref}' not found in any source. " f"Tried: {', '.join(errors)}")

    def get_github_secrets(
        self,
        context: SecretContext,
    ) -> GitHubAppSecrets:
        """
        Get GitHub App secrets for the given context.

        Args:
            context: Context to match (platform, organization, repository, etc.)

        Returns:
            GitHubAppSecrets

        Raises:
            SecretNotFoundError: If no matching configuration found
            SecretNotFoundError: If any required secret is missing
        """
        # Create cache key from context
        cache_key = f"{context.platform}:{context.organization}:{context.repository}"

        # Check cache
        if cache_key in self._github_cache:
            return self._github_cache[cache_key]

        # Find matching configuration
        config = self._find_matching_config(
            self.secrets_config.github_configs,
            context,
        )

        if config is None:
            raise SecretNotFoundError(f"No GitHub secret configuration matches context: {context}")

        # Log access
        self.audit.log_secret_access(
            secret_ref=f"github:{config.name}",
            source="manager",
            context={
                "platform": context.platform,
                "organization": context.organization,
                "repository": context.repository,
            },
        )

        # Load all required secrets
        try:
            app_id_value = self._load_secret_value(config.refs["app_id"])
            private_key_value = self._load_secret_value(config.refs["private_key"])
            webhook_secret_value = self._load_secret_value(config.refs["webhook_secret"])

            # Optional installation_id
            installation_id_value = None
            if "installation_id" in config.refs:
                installation_id_value = self._load_secret_value(config.refs["installation_id"])

            # Create secrets object
            secrets = GitHubAppSecrets(
                app_id=app_id_value.as_string(),
                private_key=private_key_value.as_bytes(),
                webhook_secret=webhook_secret_value.as_string(),
                installation_id=(installation_id_value.as_string() if installation_id_value else None),
            )

            # Cache it
            self._github_cache[cache_key] = secrets

            return secrets

        except SecretNotFoundError as err:
            raise SecretNotFoundError(f"Failed to load GitHub secrets for config '{config.name}': {err}") from err

    def get_gitlab_secrets(
        self,
        context: SecretContext,
    ) -> GitLabSecrets:
        """
        Get GitLab secrets for the given context.

        Args:
            context: Context to match (platform, environment, etc.)

        Returns:
            GitLabSecrets

        Raises:
            SecretNotFoundError: If no matching configuration found
            SecretNotFoundError: If any required secret is missing
        """
        # Create cache key from context
        cache_key = f"{context.platform}:{context.environment}"

        # Check cache
        if cache_key in self._gitlab_cache:
            return self._gitlab_cache[cache_key]

        # Find matching configuration
        config = self._find_matching_config(
            self.secrets_config.gitlab_configs,
            context,
        )

        if config is None:
            raise SecretNotFoundError(f"No GitLab secret configuration matches context: {context}")

        # Log access
        self.audit.log_secret_access(
            secret_ref=f"gitlab:{config.name}",
            source="manager",
            context={
                "platform": context.platform,
                "environment": context.environment,
            },
        )

        # Load all required secrets
        try:
            token_value = self._load_secret_value(config.refs["token"])
            webhook_secret_value = self._load_secret_value(config.refs["webhook_secret"])

            # Create secrets object
            secrets = GitLabSecrets(
                token=token_value.as_string(),
                webhook_secret=webhook_secret_value.as_string(),
            )

            # Cache it
            self._gitlab_cache[cache_key] = secrets

            return secrets

        except SecretNotFoundError as e:
            raise SecretNotFoundError(f"Failed to load GitLab secrets for config '{config.name}': {e}") from e

    def get_s3_secrets(
        self,
        context: SecretContext,
    ) -> S3Secrets:
        """
        Get S3 secrets for the given context.

        Args:
            context: Context to match (cvmfs_repo, environment, etc.)

        Returns:
            S3Secrets

        Raises:
            SecretNotFoundError: If no matching configuration found
            SecretNotFoundError: If any required secret is missing
        """
        # Create cache key from context
        cache_key = f"{context.cvmfs_repo}:{context.environment}"

        # Check cache
        if cache_key in self._s3_cache:
            return self._s3_cache[cache_key]

        # Find matching configuration
        config = self._find_matching_config(
            self.secrets_config.s3_configs,
            context,
        )

        if config is None:
            raise SecretNotFoundError(f"No S3 secret configuration matches context: {context}")

        # Log access
        self.audit.log_secret_access(
            secret_ref=f"s3:{config.name}",
            source="manager",
            context={
                "cvmfs_repo": context.cvmfs_repo,
                "environment": context.environment,
            },
        )

        # Load all required secrets
        try:
            access_key_id_value = self._load_secret_value(config.refs["access_key_id"])
            secret_access_key_value = self._load_secret_value(config.refs["secret_access_key"])

            # Optional fields
            endpoint_url_value = None
            if "endpoint_url" in config.refs:
                endpoint_url_value = self._load_secret_value(config.refs["endpoint_url"])

            region_value = None
            if "region" in config.refs:
                region_value = self._load_secret_value(config.refs["region"])

            # Create secrets object
            secrets = S3Secrets(
                access_key_id=access_key_id_value.as_string(),
                secret_access_key=secret_access_key_value.as_string(),
                endpoint_url=(endpoint_url_value.as_string() if endpoint_url_value else None),
                region=(region_value.as_string() if region_value else None),
            )

            # Cache it
            self._s3_cache[cache_key] = secrets

            return secrets

        except SecretNotFoundError as e:
            raise SecretNotFoundError(f"Failed to load S3 secrets for config '{config.name}': {e}") from e

    def get_smee_secrets(self) -> SmeeSecrets:
        """
        Get Smee webhook proxy secrets.

        Smee is typically used for development only and doesn't require
        context matching (single configuration).

        Returns:
            SmeeSecrets

        Raises:
            SecretNotFoundError: If no Smee configuration found
            SecretNotFoundError: If required secret is missing
        """
        # Check cache
        cache_key = "default"
        if cache_key in self._smee_cache:
            return self._smee_cache[cache_key]

        # Find configuration (usually just one default config)
        if not self.secrets_config.smee_configs:
            raise SecretNotFoundError("No Smee secret configuration found")

        # Use first config (typically only one for Smee)
        config = self.secrets_config.smee_configs[0]

        # Log access
        self.audit.log_secret_access(
            secret_ref=f"smee:{config.name}",
            source="manager",
            context={},
        )

        # Load required secret
        try:
            channel_url_value = self._load_secret_value(config.refs["channel_url"])

            # Create secrets object
            secrets = SmeeSecrets(
                channel_url=channel_url_value.as_string(),
            )

            # Cache it
            self._smee_cache[cache_key] = secrets

            return secrets

        except SecretNotFoundError as e:
            raise SecretNotFoundError(f"Failed to load Smee secrets for config '{config.name}': {e}") from e
