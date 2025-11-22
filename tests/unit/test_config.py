# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.config.config module.

Tests configuration loading from YAML files with environment variable overrides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from cpu.config.config import Config, ConfigError, ConfigValidationError


class TestConfigInitialization:
    """Tests for Config initialization."""

    def test_config_creation_without_file(self) -> None:
        """Test creating Config without specifying a config file."""
        config = Config()
        assert config is not None
        assert isinstance(config, Config)

    def test_config_creation_with_file(self, tmp_path: Path) -> None:
        """Test creating Config with a specific config file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)
        assert config.config_file == config_file

    def test_config_creation_with_nonexistent_file(self, tmp_path: Path) -> None:
        """Test creating Config with non-existent file doesn't fail until load()."""
        config_file = tmp_path / "nonexistent.yaml"

        # Should not raise during initialization
        config = Config(config_file=config_file)
        assert config.config_file == config_file

    def test_config_with_string_path(self, tmp_path: Path) -> None:
        """Test Config accepts string paths in addition to Path objects."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=str(config_file))
        assert config.config_file == Path(config_file)


class TestConfigLoading:
    """Tests for loading configuration from YAML files."""

    def test_load_simple_config(self, tmp_path: Path) -> None:
        """Test loading a simple YAML configuration."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        config = Config(config_file=config_file)
        config.load()

        assert config.get("bot.num_workers") == 4
        assert config.get("bot.log_level") == "INFO"

    def test_load_nested_config(self, tmp_path: Path) -> None:
        """Test loading configuration with nested structures."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  messaging:
    queue_size: 100
    timeout: 30
  platforms:
    - github
    - gitlab
""")

        config = Config(config_file=config_file)
        config.load()

        assert config.get("bot.messaging.queue_size") == 100
        assert config.get("bot.messaging.timeout") == 30
        assert config.get("bot.platforms") == ["github", "gitlab"]

    def test_load_from_nonexistent_file(self, tmp_path: Path) -> None:
        """Test loading from non-existent file raises ConfigError."""
        config_file = tmp_path / "nonexistent.yaml"

        config = Config(config_file=config_file)

        with pytest.raises(FileNotFoundError, match="Configuration file not found"):
            config.load()

    def test_load_invalid_yaml(self, tmp_path: Path) -> None:
        """Test loading invalid YAML raises ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("invalid: yaml: content:\n  - bad\n  indentation")

        config = Config(config_file=config_file)

        with pytest.raises(ConfigError, match="Failed to parse"):
            config.load()

    def test_load_empty_yaml(self, tmp_path: Path) -> None:
        """Test loading empty YAML file results in empty config."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")

        config = Config(config_file=config_file)
        config.load()

        assert config.get("anything", default="default") == "default"

    def test_load_yaml_with_comments(self, tmp_path: Path) -> None:
        """Test loading YAML with comments works correctly."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
# This is a comment
bot:
  num_workers: 4  # Number of worker threads
  # log_level: DEBUG
  log_level: INFO
""")

        config = Config(config_file=config_file)
        config.load()

        assert config.get("bot.num_workers") == 4
        assert config.get("bot.log_level") == "INFO"

    def test_load_can_be_called_multiple_times(self, tmp_path: Path) -> None:
        """Test that load() can be called multiple times (reloads config)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)
        config.load()
        assert config.get("bot.num_workers") == 4

        # Modify file and reload
        config_file.write_text("bot:\n  num_workers: 8\n")
        config.load()
        assert config.get("bot.num_workers") == 8


class TestConfigGet:
    """Tests for retrieving configuration values."""

    @pytest.fixture
    def loaded_config(self, tmp_path: Path) -> Config:
        """Provide a loaded configuration for testing."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
  messaging:
    timeout: 30
  enabled: true
  ratio: 0.75
""")
        config = Config(config_file=config_file)
        config.load()
        return config

    def test_get_existing_value(self, loaded_config: Config) -> None:
        """Test getting an existing configuration value."""
        assert loaded_config.get("bot.num_workers") == 4

    def test_get_nested_value(self, loaded_config: Config) -> None:
        """Test getting a nested configuration value."""
        assert loaded_config.get("bot.messaging.timeout") == 30

    def test_get_nonexistent_value_returns_none(self, loaded_config: Config) -> None:
        """Test getting non-existent value returns None by default."""
        assert loaded_config.get("nonexistent.key") is None

    def test_get_with_default_value(self, loaded_config: Config) -> None:
        """Test getting non-existent value with default."""
        assert loaded_config.get("nonexistent.key", default=42) == 42

    def test_get_top_level_key(self, loaded_config: Config) -> None:
        """Test getting top-level configuration key returns entire section."""
        bot_config = loaded_config.get("bot")
        assert isinstance(bot_config, dict)
        assert bot_config["num_workers"] == 4
        assert bot_config["log_level"] == "INFO"

    def test_get_boolean_value(self, loaded_config: Config) -> None:
        """Test getting boolean configuration value."""
        assert loaded_config.get("bot.enabled") is True

    def test_get_float_value(self, loaded_config: Config) -> None:
        """Test getting float configuration value."""
        assert loaded_config.get("bot.ratio") == 0.75

    def test_get_before_load_raises_error(self, tmp_path: Path) -> None:
        """Test that get() before load() raises ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)

        with pytest.raises(ConfigError, match="Configuration not loaded"):
            config.get("bot.num_workers")

    def test_get_with_empty_key_raises_error(self, loaded_config: Config) -> None:
        """Test that get() with empty key raises ValueError."""
        with pytest.raises(ValueError, match="Key cannot be empty"):
            loaded_config.get("")

    def test_get_preserves_type(self, loaded_config: Config) -> None:
        """Test that get() preserves the original type from YAML."""
        assert isinstance(loaded_config.get("bot.num_workers"), int)
        assert isinstance(loaded_config.get("bot.log_level"), str)
        assert isinstance(loaded_config.get("bot.enabled"), bool)
        assert isinstance(loaded_config.get("bot.ratio"), float)


class TestEnvironmentVariableOverrides:
    """Tests for environment variable overrides."""

    def test_apply_env_overrides_with_none_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test _apply_env_overrides returns early when env_prefix is None."""
        config = Config(config_file=None, env_prefix=None)
        config._loaded = True

        # set env var that would normally override
        monkeypatch.setenv("CPU_BOT__NUM_WORKERS", "42")

        # call _apply_env_overrides directly
        config._apply_env_overrides()

        assert config.get("bot.num_workers") is None

    def test_env_override_simple_value(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variable overrides simple config value."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        monkeypatch.setenv("CPU_BOT__NUM_WORKERS", "8")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        assert config.get("bot.num_workers") == 8

    def test_env_override_nested_value(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variable overrides nested config value."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  messaging:\n    timeout: 30\n")

        monkeypatch.setenv("CPU_BOT__MESSAGING__TIMEOUT", "60")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        assert config.get("bot.messaging.timeout") == 60

    def test_env_override_converts_types(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variable override converts string to appropriate type."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  enabled: true
  ratio: 0.75
""")

        monkeypatch.setenv("CPU_BOT__NUM_WORKERS", "8")
        monkeypatch.setenv("CPU_BOT__ENABLED", "false")
        monkeypatch.setenv("CPU_BOT__RATIO", "0.5")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        assert config.get("bot.num_workers") == 8
        assert config.get("bot.enabled") is False
        assert config.get("bot.ratio") == 0.5

    def test_env_override_without_yaml_value(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variable can provide value not in YAML."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        monkeypatch.setenv("CPU_BOT__NEW_SETTING", "value")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        assert config.get("bot.new_setting") == "value"

    def test_custom_env_prefix(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test using custom environment variable prefix."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        monkeypatch.setenv("CUSTOM_BOT__NUM_WORKERS", "8")

        config = Config(config_file=config_file, env_prefix="CUSTOM_")
        config.load()

        assert config.get("bot.num_workers") == 8

    def test_no_env_prefix_disables_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that env_prefix=None disables environment overrides."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        monkeypatch.setenv("CPU_BOT__NUM_WORKERS", "8")

        config = Config(config_file=config_file, env_prefix=None)
        config.load()

        # Should use YAML value, not environment
        assert config.get("bot.num_workers") == 4

    def test_wrong_prefix_env_vars_ignored(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that env vars with wrong prefix are ignored."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
    bot:
      num_workers: 4
    """)

        # Set CPU_ prefix vars
        monkeypatch.setenv("CPU_BOT__NUM_WORKERS", "16")

        # But use different prefix
        config = Config(config_file=config_file, env_prefix="CUSTOM_")
        config.load()

        # Should ignore CPU_ vars and use YAML value
        assert config.get("bot.num_workers") == 4

    def test_env_override_preserves_underscores_in_keys(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that single underscores in key names are preserved."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  retry_count: 3\n  max_retry_delay: 10\n")

        monkeypatch.setenv("CPU_BOT__RETRY_COUNT", "5")
        monkeypatch.setenv("CPU_BOT__MAX_RETRY_DELAY", "20")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        assert config.get("bot.retry_count") == 5
        assert config.get("bot.max_retry_delay") == 20

class TestConfigValidation:
    """Tests for configuration validation."""

    def test_validate_required_keys(self, tmp_path: Path) -> None:
        """Test validation of required configuration keys."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)
        config.load()

        # Should not raise when all required keys present
        config.validate(required_keys=["bot.num_workers"])

    def test_validate_required_keys_returns_true(self, tmp_path: Path) -> None:
        """Test validation returns True when all required keys present."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)
        config.load()

        result = config.validate(required_keys=["bot.num_workers"])
        assert result is True

    def test_validate_before_load_raises_error(self, tmp_path: Path) -> None:
        """Test validate raises error when config not loaded."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
    bot:
      num_workers: 4
    """)

        config = Config(config_file=config_file)
        # Don't call load()

        # Should raise ConfigError (line 210-211)
        with pytest.raises(ConfigError, match="not loaded"):
            config.validate(["bot.num_workers"])

    def test_validate_returns_false_without_raising(self, tmp_path: Path) -> None:
        """Test validation returns False when raise_on_error=False."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)
        config.load()

        result = config.validate(required_keys=["bot.missing_key"], raise_on_error=False)
        assert result is False

    def test_validate_bool_return_for_partial_presence(self, tmp_path: Path) -> None:
        """Test validation returns False when some keys present, some missing."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        config = Config(config_file=config_file)
        config.load()

        result = config.validate(
            required_keys=["bot.num_workers", "bot.missing_key"],
            raise_on_error=False
        )
        assert result is False

    def test_validate_missing_required_key(self, tmp_path: Path) -> None:
        """Test validation fails when required key is missing."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)
        config.load()

        with pytest.raises(ConfigValidationError, match="Missing required configuration"):
            config.validate(required_keys=["bot.missing_key"])

    def test_validate_multiple_required_keys(self, tmp_path: Path) -> None:
        """Test validation of multiple required keys."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        config = Config(config_file=config_file)
        config.load()

        config.validate(required_keys=["bot.num_workers", "bot.log_level"])

    def test_validate_reports_all_missing_keys(self, tmp_path: Path) -> None:
        """Test validation error reports all missing keys."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)
        config.load()

        with pytest.raises(ConfigValidationError) as exc_info:
            config.validate(required_keys=["bot.key1", "bot.key2", "bot.key3"])

        error_message = str(exc_info.value)
        assert "bot.key1" in error_message
        assert "bot.key2" in error_message
        assert "bot.key3" in error_message


class TestConfigEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_config_with_special_characters_in_values(self, tmp_path: Path) -> None:
        """Test configuration with special characters in values."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  message: "Hello: World!"
  path: "/usr/local/bin"
  url: "https://example.com?param=value&foo=bar"
""")

        config = Config(config_file=config_file)
        config.load()

        assert config.get("bot.message") == "Hello: World!"
        assert config.get("bot.path") == "/usr/local/bin"
        assert config.get("bot.url") == "https://example.com?param=value&foo=bar"

    def test_config_with_unicode(self, tmp_path: Path) -> None:
        """Test configuration with Unicode characters."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  name: "CPU © 2025"
  location: "Osterøy"
""")

        config = Config(config_file=config_file)
        config.load()

        assert config.get("bot.name") == "CPU © 2025"
        assert config.get("bot.location") == "Osterøy"

    def test_config_with_null_values(self, tmp_path: Path) -> None:
        """Test configuration with explicit null/None values."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  optional_setting: null
  required_setting: value
""")

        config = Config(config_file=config_file)
        config.load()

        assert config.get("bot.optional_setting") is None
        assert config.get("bot.required_setting") == "value"

    def test_config_with_list_values(self, tmp_path: Path) -> None:
        """Test configuration with list values."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  platforms:
    - github
    - gitlab
    - bitbucket
  ports:
    - 8080
    - 8081
""")

        config = Config(config_file=config_file)
        config.load()

        assert config.get("bot.platforms") == ["github", "gitlab", "bitbucket"]
        assert config.get("bot.ports") == [8080, 8081]

    def test_config_preserves_dict_structure(self, tmp_path: Path) -> None:
        """Test that getting intermediate keys returns dict structure."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  messaging:
    queue_size: 100
    timeout: 30
""")

        config = Config(config_file=config_file)
        config.load()

        messaging = config.get("bot.messaging")
        assert isinstance(messaging, dict)
        assert messaging["queue_size"] == 100
        assert messaging["timeout"] == 30


class TestConfigRepr:
    """Tests for Config string representation."""

    def test_repr_shows_config_file(self, tmp_path: Path) -> None:
        """Test that repr shows the configuration file path."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)

        repr_str = repr(config)
        assert "Config" in repr_str
        assert str(config_file) in repr_str

    def test_repr_shows_loaded_status(self, tmp_path: Path) -> None:
        """Test that repr indicates if config is loaded."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 4\n")

        config = Config(config_file=config_file)

        repr_before = repr(config)
        assert "not loaded" in repr_before.lower() or "loaded=False" in repr_before

        config.load()

        repr_after = repr(config)
        assert "loaded" in repr_after.lower()


class TestConfigEdgeCasesForCoverage:
    """Additional tests to improve coverage."""

    def test_env_override_with_invalid_int_conversion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test env override when int conversion fails."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        # Set environment variable with non-numeric value for int field
        monkeypatch.setenv("CPU_BOT__NUM_WORKERS", "not_a_number")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        # Should keep as string when conversion fails (line 275-276)
        result = config.get("bot.num_workers")
        assert result == "not_a_number"

    def test_env_override_with_invalid_float_conversion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test env override when float conversion fails."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  timeout: 30.5
""")

        # Set environment variable with non-numeric value for float field
        monkeypatch.setenv("CPU_BOT__TIMEOUT", "not_a_float")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        # Should keep as string when conversion fails (line 280-283)
        result = config.get("bot.timeout")
        assert result == "not_a_float"

    def test_env_override_with_invalid_string_conversion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test env override when string conversion fails."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  name: "original"
""")

        # Set environment variable with non-numeric value for string field
        monkeypatch.setenv("CPU_BOT__NAME", "not_a_number")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        # Should hit else branch at line 292 (string type)
        assert config.get("bot.name") == "not_a_number"

    def test_set_value_with_non_dict_intermediate(self, tmp_path: Path) -> None:
        """Test _set_value when intermediate path is not a dict."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  workers: 4
""")

        config = Config(config_file=config_file, env_prefix=None)
        config.load()

        # Manually set bot.workers to a non-dict value
        config._data["bot"]["workers"] = "simple_value"

        # Try to set a nested value under workers (which is now a string, not a dict)
        # This should trigger line 301-304 (return early if not a dict)
        config._set_value("bot.workers.nested", "value")

        # Value should not be set because workers is not a dict
        assert config._data["bot"]["workers"] == "simple_value"

    def test_set_value_creates_nested_dict(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test _set_value creates missing nested dicts (line 310)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
    bot:
      workers: 4
    """)

        # Env var for nested key that doesn't exist in YAML
        monkeypatch.setenv("CPU_BOT__NEW__NESTED__VALUE", "test")

        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        # Should create bot.new.nested structure (line 310)
        assert config.get("bot.new.nested.value") == "test"

    def test_validate_with_raise_on_error_false_and_not_loaded(self, tmp_path: Path) -> None:
        """Test validate returns False when config not loaded and raise_on_error=False."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        config = Config(config_file=config_file)
        # Don't call load()

        # Should return False without raising (line 200-204)
        result = config.validate(["bot.num_workers"], raise_on_error=False)
        assert result is False

    def test_load_empty_file_returns_empty_dict(self, tmp_path: Path) -> None:
        """Test loading completely empty YAML file."""
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")

        config = Config(config_file=config_file)
        config.load()

        # Should handle empty file gracefully (line 113-114: or {})
        assert config._data == {}

class TestConfigFileErrorHandling:
    """Test specific file error scenarios."""

    def test_file_permission_denied(self, tmp_path: Path) -> None:
        """Test handling when file exists but cannot be opened (permission denied)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        config = Config(config_file=config_file)

        # Mock open to raise PermissionError
        import builtins
        original_open = builtins.open

        def mock_open(*args: Any, **kwargs: Any) -> Any:
            if str(config_file) in str(args[0]):
                raise PermissionError("Permission denied")
            return original_open(*args, **kwargs)

        with (
            patch("builtins.open", side_effect=mock_open),
            pytest.raises(ConfigError, match="Failed to open"),
        ):
            config.load()

    def test_file_io_error(self, tmp_path: Path) -> None:
        """Test handling when file read fails with IO error."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        config = Config(config_file=config_file)

        # Mock open to raise IOError
        import builtins
        original_open = builtins.open

        def mock_open(*args: Any, **kwargs: Any) -> Any:
            if str(config_file) in str(args[0]):
                raise OSError("Disk read error")
            return original_open(*args, **kwargs)

        with (
            patch("builtins.open", side_effect=mock_open),
            pytest.raises(ConfigError, match="Failed to open"),
        ):
            config.load()

    def test_unexpected_parsing_error(self, tmp_path: Path) -> None:
        """Test handling of unexpected errors during YAML parsing."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        config = Config(config_file=config_file)

        # Mock yaml.safe_load to raise unexpected error
        def mock_safe_load(_: Any) -> Any:
            raise RuntimeError("Unexpected parsing error")

        with (
            patch("yaml.safe_load", side_effect=mock_safe_load),
            pytest.raises(ConfigError, match="Unexpected error loading"),
        ):
            config.load()
