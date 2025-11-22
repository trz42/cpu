# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

End-to-end tests for the main application CLI.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from cpu.__main__ import main


class TestMainCLI:
    """End-to-end tests for the CPU main CLI."""

    def test_main_with_default_config(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with default config file."""
        # Create a minimal config file in the current directory
        config_yaml = "config.yaml"
        config_file = tmp_path / config_yaml
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        # Change to temp directory so default config.yaml is found
        import os
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)

            # Run main
            with patch.object(sys, "argv", ["cpu"]):
                exit_code = main()

            # Should succeed
            assert exit_code == 0

            # Check output
            captured = capsys.readouterr()
            assert "CPU" in captured.out
            assert "EESSI build-and-deploy bot" in captured.out
            assert "version:" in captured.out.lower()
            assert "config file:" in captured.out.lower()
            assert config_yaml in captured.out

        finally:
            os.chdir(original_cwd)

    def test_main_with_custom_config(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with custom config file path."""
        custom_config = "custom_config.yaml"
        config_file = tmp_path / custom_config
        config_file.write_text("""
bot:
  num_workers: 8
  log_level: DEBUG
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        assert exit_code == 0

        captured = capsys.readouterr()
        assert custom_config in captured.out

    def test_main_with_short_config_option(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with -c short option."""
        test_config = "test_config.yaml"
        config_file = tmp_path / test_config
        config_file.write_text("""
bot:
  num_workers: 2
""")

        with patch.object(sys, "argv", ["cpu", "-c", str(config_file)]):
            exit_code = main()

        assert exit_code == 0

        captured = capsys.readouterr()
        assert test_config in captured.out

    def test_main_with_missing_config(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with non-existent config file."""
        nonexistent = tmp_path / "nonexistent.yaml"

        with patch.object(sys, "argv", ["cpu", "--config", str(nonexistent)]):
            exit_code = main()

        # Should fail
        assert exit_code != 0

        captured = capsys.readouterr()
        assert "error" in captured.err.lower() or "error" in captured.out.lower()
        assert "not found" in captured.err.lower() or "not found" in captured.out.lower()

    def test_main_with_invalid_yaml(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with invalid YAML file."""
        config_file = tmp_path / "invalid.yaml"
        config_file.write_text("""
bot:
  num_workers: [invalid yaml structure
    missing: close bracket
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        assert exit_code != 0

        captured = capsys.readouterr()
        assert "error" in captured.err.lower() or "error" in captured.out.lower()

    def test_main_with_missing_required_config(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with config missing required keys."""
        config_file = tmp_path / "incomplete.yaml"
        config_file.write_text("""
bot:
  log_level: INFO
# Missing required: num_workers
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        assert exit_code != 0

        captured = capsys.readouterr()
        assert "error" in captured.err.lower() or "error" in captured.out.lower()
        assert "required" in captured.err.lower() or "required" in captured.out.lower()

    def test_main_with_help_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with --help flag."""
        with patch.object(sys, "argv", ["cpu", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

            # Help should exit with 0
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "usage:" in captured.out.lower()
        assert "--config" in captured.out or "-c" in captured.out
        assert "--version" in captured.out or "-v" in captured.out

    def test_main_with_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with --version flag."""
        with patch.object(sys, "argv", ["cpu", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0

        captured = capsys.readouterr()

        # Should print version
        assert "cpu" in captured.out.lower()

        # Version should be present (either real version or "unknown")
        output = captured.out.lower()
        assert any(word in output for word in ["version", "v0.", "unknown"])

    def test_main_shows_version_info(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that main output includes version information."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            main()

        captured = capsys.readouterr()

        # Should show version in output
        assert "version" in captured.out.lower()

    def test_main_shows_executable_path(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that main output includes executable path."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            main()

        captured = capsys.readouterr()

        # Should show executable or module path
        assert "executable" in captured.out.lower() or "path" in captured.out.lower()

    def test_main_shows_env_vars(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that main output shows environment variable overrides."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file), "--extended-startup-info"]):
            main()

        captured = capsys.readouterr()

        # Should mention environment variables
        assert "environment" in captured.out.lower() or "env" in captured.out.lower()

        # Should mention the prefix
        assert "CPU_" in captured.out

    def test_main_with_env_override(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that environment variables override config file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        # Set environment override
        monkeypatch.setenv("CPU_BOT__NUM_WORKERS", "16")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file), "--extended-startup-info"]):
            main()

        captured = capsys.readouterr()

        # Should show the overridden value
        assert "16" in captured.out

    def test_main_invalid_argument(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test running main with invalid argument."""
        with patch.object(sys, "argv", ["cpu", "--invalid-arg"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

            # Should exit with error
            assert exc_info.value.code != 0

        captured = capsys.readouterr()

        # Should show error message
        assert "error" in captured.err.lower() or "unrecognized" in captured.err.lower()


class TestMainConfigValidation:
    """Test configuration validation in main application."""

    def test_validates_required_keys(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that main validates required configuration keys."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
# Empty or minimal config
other:
  setting: value
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        # Should fail validation
        assert exit_code != 0

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "required" in output.lower() or "missing" in output.lower()

    def test_accepts_valid_config(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that main accepts valid configuration."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        # Should succeed
        assert exit_code == 0

        captured = capsys.readouterr()

        # Should show configuration was loaded
        assert "config" in captured.out.lower()


class TestBannerEffects:
    """Test banner effects functionality."""

    def test_banner_with_effects_enabled_but_library_missing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that banner falls back gracefully when effects enabled but library missing."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  banner_effects: true
  banner_effect_type: NonExistentEffect
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        # Should succeed with fallback to plain banner
        assert exit_code == 0

        captured = capsys.readouterr()

        # Should still show banner content
        assert "CPU" in captured.out

    def test_banner_with_effects_disabled(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test banner with effects explicitly disabled."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  banner_effects: false
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        assert exit_code == 0

        captured = capsys.readouterr()
        assert "CPU" in captured.out


class TestExtendedStartupInfo:
    """Test extended startup info flag."""

    def test_default_minimal_output(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that default output is minimal without --extended-startup-info."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        assert exit_code == 0

        captured = capsys.readouterr()

        # Should show basic info
        assert "Version:" in captured.out
        assert "Startup complete!" in captured.out

        # Should NOT show extended info
        assert "Configuration:" not in captured.out
        assert "Environment Variable Overrides:" not in captured.out

    def test_extended_startup_info_flag(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that --extended-startup-info shows detailed output."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  log_level: INFO
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file), "--extended-startup-info"]):
            exit_code = main()

        assert exit_code == 0

        captured = capsys.readouterr()

        # Should show extended info
        assert "Configuration:" in captured.out
        assert "Workers:" in captured.out
        assert "Environment Variable Overrides:" in captured.out


class TestErrorHandling:
    """Test error handling paths."""

    def test_keyboard_interrupt(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test handling of keyboard interrupt (CTRL-C)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        # Mock Config.load to raise KeyboardInterrupt
        from cpu.config.config import Config
        original_load = Config.load

        def mock_load(self):
            raise KeyboardInterrupt()

        with patch.object(Config, "load", mock_load):
            with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
                exit_code = main()

        # Should exit with 130 (standard for SIGINT)
        assert exit_code == 130

        captured = capsys.readouterr()
        assert "interrupted" in captured.err.lower()

    def test_unexpected_error(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test handling of unexpected errors."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        # Mock Config.load to raise unexpected error
        from cpu.config.config import Config

        def mock_load(self):
            raise RuntimeError("Unexpected error occurred")

        with patch.object(Config, "load", mock_load):
            with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
                exit_code = main()

        # Should exit with non-zero
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "unexpected error" in captured.err.lower()
        assert "RuntimeError" in captured.err or "Traceback" in captured.err

    def test_file_not_found_error_explicit(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test explicit FileNotFoundError handling."""
        config_file = tmp_path / "missing.yaml"
        # Don't create the file

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        assert exit_code == 1

        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()


class TestBannerEffectsExceptions:
    """Test exception paths in banner effects."""

    def test_banner_effects_generic_exception(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test banner effects falls back on generic exception."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  banner_effects: true
  banner_effect_type: Slide
""")

        # Mock importlib to raise a generic exception
        import importlib
        original_import = importlib.import_module

        def mock_import(name):
            if "terminaltexteffects" in name:
                raise RuntimeError("Generic error during import")
            return original_import(name)

        with patch("importlib.import_module", side_effect=mock_import):
            with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
                exit_code = main()

        # Should succeed with fallback
        assert exit_code == 0

        captured = capsys.readouterr()

        # Should show plain banner (fallback)
        assert "CPU" in captured.out
        assert "EESSI build-and-deploy bot" in captured.out


class TestBannerEffectsImportSuccess:
    """Test successful banner effects import and execution."""

    def test_banner_effects_successful_execution(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test banner effects when terminaltexteffects is available and works."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
  banner_effects: true
  banner_effect_type: Slide
""")

        # Mock the terminaltexteffects module
        import sys
        from unittest.mock import MagicMock

        # Create mock effect class and module
        mock_frame = MagicMock()
        mock_frame.__iter__ = lambda self: iter(["frame1", "frame2"])
        
        mock_terminal = MagicMock()
        mock_terminal.__enter__ = lambda self: self
        mock_terminal.__exit__ = lambda self, *args: None
        mock_terminal.print = MagicMock()
        
        mock_effect_instance = MagicMock()
        mock_effect_instance.terminal_output = lambda: mock_terminal
        mock_effect_instance.__iter__ = lambda self: iter(["frame1", "frame2"])
        
        mock_effect_class = MagicMock(return_value=mock_effect_instance)
        
        mock_module = MagicMock()
        mock_module.Slide = mock_effect_class
        
        # Mock importlib.import_module to return our mock
        import importlib
        original_import = importlib.import_module
        
        def mock_import(name):
            if "terminaltexteffects" in name:
                return mock_module
            return original_import(name)
        
        with patch("importlib.import_module", side_effect=mock_import):
            with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
                exit_code = main()
        
        # Should succeed
        assert exit_code == 0
        
        # Verify effect was called
        mock_effect_class.assert_called_once()


class TestConfigErrorHandling:
    """Test Config-specific error handling."""

    def test_config_error_from_yaml_parse(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test ConfigError from YAML parsing issues."""
        config_file = tmp_path / "bad.yaml"
        config_file.write_text("""
bot:
  num_workers: [unclosed bracket
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            exit_code = main()

        # Should exit with error
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "configuration error" in captured.err.lower()


class TestRunFunction:
    """Test the run() entry point function."""

    def test_run_function_exits(self, tmp_path: Path) -> None:
        """Test that run() function calls sys.exit with main's return code."""
        from cpu.__main__ import run
        
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 4
""")

        with patch.object(sys, "argv", ["cpu", "--config", str(config_file)]):
            with pytest.raises(SystemExit) as exc_info:
                run()
            
            # Should exit with 0 for success
            assert exc_info.value.code == 0
