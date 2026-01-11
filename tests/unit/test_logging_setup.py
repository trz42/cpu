# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for logging setup.
"""

from __future__ import annotations

import logging
from pathlib import Path

from cpu.config.config import Config
from cpu.logging.setup import configure_logging


class TestLoggingSetup:
    """Test logging configuration."""

    def test_configure_logging_creates_file_handler(self, tmp_path: Path) -> None:
        """Test file handler is created."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  logging:
    file: logs/cpu.log
    level: INFO
""")

        config = Config(config_file=config_file)
        config.load()

        configure_logging(config)

        root_logger = logging.getLogger()
        # should have file handler
        assert any(isinstance(handler, logging.FileHandler) for handler in root_logger.handlers)

    def test_configure_logging_sets_levels(self, tmp_path: Path) -> None:
        """Test logging level is set."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  logging:
    file: logs/cpu.log
    level: DEBUG
""")

        config = Config(config_file=config_file)
        config.load()

        configure_logging(config)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_configure_logging_hierarchical_loggers(self, tmp_path: Path) -> None:
        """Test hierarchical logger levels."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  logging:
    file: logs/cpu.log
    level: WARNING
    loggers:
      cpu.timer: DEBUG
      cpu.job_manager: INFO
""")

        config = Config(config_file=config_file)
        config.load()

        configure_logging(config)

        timer_logger = logging.getLogger("cpu.timer")
        job_logger = logging.getLogger("cpu.job_manager")

        assert timer_logger.level == logging.DEBUG
        assert job_logger.level == logging.INFO

    def test_configure_logging_uses_format_from_config(self, tmp_path: Path) -> None:
        """Test custom log format is applied."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  logging:
    file: logs/cpu.log
    level: INFO
    format: "%(levelname)s - %(message)s"
""")

        config = Config(config_file=config_file)
        config.load()

        # clear existing handlers (pytest adds its own)
        root_logger = logging.getLogger()
        root_logger.handlers.clear()

        configure_logging(config)

        file_handlers = [handler for handler in root_logger.handlers if isinstance(handler, logging.FileHandler)]
        assert len(file_handlers) > 0

        formatter = file_handlers[0].formatter
        assert formatter is not None
        assert formatter._fmt == "%(levelname)s - %(message)s"
