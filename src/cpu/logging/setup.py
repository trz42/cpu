# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Early logging configuration before components start.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import Any

from cpu.config.config import Config

# define TRACE level (below DEBUG)
TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def _trace(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    """
    Log a message at TRACE level.

    This method is monkey-patched onto the Logger class to provide
    TRACE level logging capability.

    Args:
        message: The log message
        *args: Arguments for message formatting
        **kwargs: Keyword arguments (e.g., exc_info, extra)
    """
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)


# monkey-patch the Logger class to add trace method
logging.Logger.trace = _trace  # type: ignore[attr-defined]


def configure_logging(config: Config) -> None:
    """
    Configure Python logging before components start.

    Args:
        config: Configuration object
    """
    # get logging config
    log_file = config.get("bot.logging.file", "logs/cpu.log")
    log_level = config.get("bot.logging.level", "INFO")
    log_format = config.get(
        "bot.logging.format",
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    max_bytes = config.get("bot.logging.max_bytes", 10 * 1024 * 1024)  # 10MB
    backup_count = config.get("bot.logging.backup_count", 5)

    # create log directory
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # configure root logger
    root_logger = logging.getLogger()
    # handle TRACE as a special case since it's not in standard logging
    if log_level.upper() == "TRACE":
        root_logger.setLevel(TRACE)
    else:
        root_logger.setLevel(getattr(logging, log_level.upper()))

    # create file handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
    )
    file_handler.setLevel(logging.DEBUG)  # handler accepts all, logger filters

    # create formatter
    formatter = logging.Formatter(log_format)
    file_handler.setFormatter(formatter)

    # add handler to root logger
    root_logger.addHandler(file_handler)

    # configure hierarchical loggers
    loggers_config = config.get("bot.logging.loggers", {})
    for logger_name, logger_level in loggers_config.items():
        logger = logging.getLogger(logger_name)
        # handle TRACE as a special case
        if logger_level.upper() == "TRACE":
            logger.setLevel(TRACE)
        else:
            logger.setLevel(getattr(logging, logger_level.upper()))
