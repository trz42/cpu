# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for logging setup.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from cpu.config.config import Config
from cpu.logging.setup import TRACE, configure_logging


class TestTraceLevel:
    """Test TRACE log level functionality."""

    def test_trace_level_constant_exists(self) -> None:
        """Verify TRACE level constant is defined."""
        assert TRACE == 5

    def test_trace_level_registered(self) -> None:
        """Verify TRACE level is registered with logging."""
        assert logging.getLevelName(TRACE) == "TRACE"
        assert logging.getLevelName("TRACE") == TRACE

    def test_logger_has_trace_method(self) -> None:
        """Verify Logger has trace() method."""
        logger = logging.getLogger("test_trace")
        assert hasattr(logger, "trace")
        assert callable(logger.trace)

    def test_trace_logs_at_correct_level(self, caplog: pytest.LogCaptureFixture) -> None:
        """Verify trace() logs at level 5."""
        logger = logging.getLogger("test_trace_level")
        logger.setLevel(TRACE)

        with caplog.at_level(TRACE):
            logger.trace("test trace message")  # type: ignore[attr-defined]

        assert len(caplog.records) == 1
        assert caplog.records[0].levelno == TRACE
        assert caplog.records[0].levelname == "TRACE"
        assert caplog.records[0].message == "test trace message"

    def test_trace_filtered_when_level_higher(self, caplog: pytest.LogCaptureFixture) -> None:
        """Verify TRACE messages filtered when level > TRACE."""
        logger = logging.getLogger("test_trace_filter")
        logger.setLevel(logging.DEBUG)

        with caplog.at_level(logging.DEBUG):
            logger.trace("should not appear")  # type: ignore[attr-defined]
            logger.debug("should appear")

        assert len(caplog.records) == 1
        assert caplog.records[0].levelname == "DEBUG"
        assert caplog.records[0].message == "should appear"

    def test_trace_enabled_for_debug_logger(self, caplog: pytest.LogCaptureFixture) -> None:
        """Verify TRACE shows when logger at TRACE level but caplog at DEBUG."""
        logger = logging.getLogger("test_trace_enabled")
        logger.setLevel(TRACE)

        with caplog.at_level(TRACE):
            logger.trace("trace message")  # type: ignore[attr-defined]
            logger.debug("debug message")

        assert len(caplog.records) == 2
        assert caplog.records[0].levelname == "TRACE"
        assert caplog.records[1].levelname == "DEBUG"


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

    def test_configure_logging_with_trace_level(self, tmp_path: Path) -> None:
        """Test TRACE level can be configured."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  logging:
    file: logs/cpu.log
    level: TRACE
""")

        config = Config(config_file=config_file)
        config.load()

        configure_logging(config)

        root_logger = logging.getLogger()
        assert root_logger.level == TRACE
