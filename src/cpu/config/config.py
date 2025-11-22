# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

This module provides configuration loading from YAML files with support for:
- Nested configuration structures using dot notation (e.g., 'bot.num_workers')
- Environment variable overrides with customizable prefix
- Type preservation (int, float, bool, str, list, dict)
- Validation of required configuration keys
- Configuration reloading

Example:
    >>> config = Config(config_file='config.yaml', env_prefix='CPU_')
    >>> config.load()
    >>> num_workers = config.get('bot.num_workers', default=4)
    >>> config.validate(required_keys=['bot.num_workers', 'bot.log_level'])
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


class Config:
    """
    Configuration manager for CPU bot.

    Loads configuration from YAML files and allows environment variable overrides.
    Configuration values are accessed using dot notation for nested keys.

    Attributes:
        config_file: Path to the YAML configuration file
        env_prefix: Prefix for environment variables (e.g., 'CPU_')
                    Set to None to disable environment overrides

    Example:
        # config.yaml:
        # bot:
        #   num_workers: 4
        #   messaging:
        #     timeout: 30

        config = Config('config.yaml', env_prefix='CPU_')
        config.load()

        # Get simple value
        workers = config.get('bot.num_workers')  # Returns 4

        # Get nested value
        timeout = config.get('bot.messaging.timeout')  # Returns 30

        # Get with default
        retries = config.get('bot.retries', default=3)  # Returns 3

        # Environment override (CPU_BOT__NUM_WORKERS=8)
        workers = config.get('bot.num_workers')  # Returns 8 (from env)
    """

    def __init__(
        self,
        config_file: str | Path | None = None,
        env_prefix: str | None = "CPU_",
    ) -> None:
        """
        Initialize configuration manager.

        Args:
            config_file: Path to YAML configuration file
                        If None, uses default 'config.yaml' in current directory
            env_prefix: Prefix for environment variable overrides
                       Environment variables should be named as:
                       {prefix}{SECTION}__{KEY} (e.g., CPU_BOT__NUM_WORKERS)
                       Use double underscores (__) for nesting levels.
                       Single underscores (_) are preserved in key names.
                       Set to None to disable environment overrides
        """
        if config_file is None:
            self.config_file = Path("config.yaml")
        else:
            self.config_file = Path(config_file)

        self.env_prefix = env_prefix
        self._data: dict[str, Any] = {}
        self._loaded = False

    def load(self) -> None:
        """
        Load configuration from YAML file and apply environment overrides.

        Can be called multiple times to reload configuration.

        Raises:
            ConfigError: If config file doesn't exist or cannot be parsed
        """
        # Load from YAML file
        if not self.config_file.exists():
            raise ConfigError(
                f"Configuration file not found: {self.config_file}"
            )

        try:
            with open(self.config_file, encoding="utf-8") as file:
                file_content = file.read()
        except OSError as err:
            # covers permission denied, IO errors, etc.
            raise ConfigError(
                f"Failed to open configuration file {self.config_file}: {err}"
            ) from err

        try:
            self._data = yaml.safe_load(file_content) or {}
        except yaml.YAMLError as err:
            raise ConfigError(
                f"Failed to parse configuration file {self.config_file}: {err}"
            ) from err
        except Exception as err:
            # catch any other unexpected erros during parsing
            raise ConfigError(
                f"Unexpected error loading configuration file {self.config_file}: {err}"
            ) from err

        # Mark as loaded before applying overrides (so get() works in _apply_env_overrides)
        self._loaded = True

        # Apply environment variable overrides
        if self.env_prefix is not None:
            self._apply_env_overrides()

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key.

        Supports dot notation for nested keys (e.g., 'bot.messaging.timeout').

        Args:
            key: Configuration key in dot notation
            default: Default value if key doesn't exist

        Returns:
            Configuration value or default if key doesn't exist

        Raises:
            ConfigError: If configuration hasn't been loaded yet
            ValueError: If key is empty

        Example:
            >>> config.get('bot.num_workers')
            4
            >>> config.get('bot.messaging.timeout')
            30
            >>> config.get('nonexistent.key', default=42)
            42
        """
        if not self._loaded:
            raise ConfigError(
                "Configuration not loaded. Call load() first."
            )

        if not key:
            raise ValueError("Key cannot be empty")

        # Navigate nested dictionary using dot notation
        parts = key.split(".")
        value = self._data

        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default

        return value

    def validate(self, required_keys: list[str], raise_on_error: bool = True) -> bool:
        """
        Validate that required configuration keys are present.

        Args:
            required_keys: List of required keys in dot notation
            raise_on_error: If True, raise exception on validation failure
                          If False, return False on validation failure

        Returns:
            True if all required keys are present, False otherwise

        Raises:
            ConfigError: If configuration not loaded and raise_on_error=True
            ConfigValidationError: If any required keys are missing and raise_on_error=True

        Example:
            # Raise exception on failure
            >>> config.validate(['bot.num_workers', 'bot.missing_key'])
            # Raises ConfigValidationError

            # Return bool without exception
            >>> if not config.validate(['bot.num_workers'], raise_on_error=False):
            ...     print("Configuration incomplete")

            # Successful validation
            >>> config.validate(['bot.num_workers', 'bot.log_level'])
            True
        """
        if not self._loaded:
            if raise_on_error:
                raise ConfigError(
                    "Configuration not loaded. Call load() first."
                )
            return False

        missing_keys = []
        for key in required_keys:
            if self.get(key) is None:
                missing_keys.append(key)

        if missing_keys:
            if raise_on_error:
                raise ConfigValidationError(
                    f"Missing required configuration keys: {', '.join(missing_keys)}"
                )
            return False

        return True

    def _apply_env_overrides(self) -> None:
        """
        Apply environment variable overrides to configuration.

        Environment variables are matched against config keys:
        - CPU_BOT__NUM_WORKERS -> bot.num_workers
        - CPU_BOT__MESSAGING__TIMEOUT -> bot.messaging.timeout

        Double underscores (__) separate nesting levels.
        Single underscores (_) are preserved in key names.

        Values are converted to appropriate types based on existing config values.
        """
        if self.env_prefix is None:
            return

        # Get all environment variables with our prefix
        for env_key, env_value in os.environ.items():
            if not env_key.startswith(self.env_prefix):
                continue

            # Remove prefix and convert to config key format
            # CPU_BOT__NUM_WORKERS -> bot.num_workers
            config_key = env_key[len(self.env_prefix):].lower().replace("__", ".")

            # Get current value to determine type
            current_value = self.get(config_key)

            # Convert env string to appropriate type
            converted_value = self._convert_type(env_value, current_value)

            # Set the value in config
            self._set_value(config_key, converted_value)

    def _convert_type(self, value: str, reference_value: Any) -> Any:
        """
        Convert string value to appropriate type based on reference value.

        Args:
            value: String value from environment variable
            reference_value: Existing config value to infer type from

        Returns:
            Converted value with appropriate type
        """
        # If no reference value, return as string
        if reference_value is None:
            return value

        # Convert based on reference type
        if isinstance(reference_value, bool):
            return value.lower() in ("true", "1", "yes", "on")
        elif isinstance(reference_value, int):
            try:
                return int(value)
            except ValueError:
                return value
        elif isinstance(reference_value, float):
            try:
                return float(value)
            except ValueError:
                return value
        else:
            return value

    def _set_value(self, key: str, value: Any) -> None:
        """
        Set a configuration value using dot notation.

        Creates nested dictionaries as needed.

        Args:
            key: Configuration key in dot notation
            value: Value to set
        """
        parts = key.split(".")
        data = self._data

        # Navigate/create nested structure
        for part in parts[:-1]:
            if part not in data:
                data[part] = {}
            elif not isinstance(data[part], dict):
                # Can't navigate further, value is not a dict
                return
            data = data[part]

        # Set the final value
        data[parts[-1]] = value

    def __repr__(self) -> str:
        """Return string representation of Config."""
        status = "loaded" if self._loaded else "not loaded"
        return f"Config(config_file={self.config_file}, {status})"


# Custom exceptions


class ConfigError(Exception):
    """
    Base exception for configuration errors.

    Raised when:
    - Configuration file cannot be found
    - Configuration file cannot be parsed
    - Configuration is accessed before loading
    """

    pass


class ConfigValidationError(ConfigError):
    """
    Exception raised when configuration validation fails.

    Raised when required configuration keys are missing.
    """

    pass
