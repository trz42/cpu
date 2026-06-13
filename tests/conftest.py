# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Configuration of tests.
"""

import logging
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from cpu.logging.component import LoggingComponent
from cpu.messaging.message import Message
from cpu.messaging.queue_thread import ThreadMessageQueue


@pytest.fixture
def logging_component(
    tmp_path: Path,
) -> tuple[LoggingComponent, ThreadMessageQueue[Message], Path]:
    """Create a LoggingComponent with queue for testing."""
    log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
    log_file = tmp_path / "test.log"
    config: dict[str, Any] = {
        "file": str(log_file),
        "level": "DEBUG",
        "format": "%(levelname)s %(name)s %(message)s",
    }
    component = LoggingComponent(name="logger", log_queue=log_queue, config=config)
    component.initialize()
    return component, log_queue, log_file


@pytest.fixture(autouse=True)
def reset_logging() -> Generator[None, None, None]:
    """Reset logging configuration between tests to ensure isolation."""
    # store original state
    original_level = logging.root.level
    original_handlers = logging.root.handlers[:]

    # clear all existing loggers
    loggers_to_clear = [logging.getLogger(name) for name in logging.root.manager.loggerDict]

    yield

    # reset root logger
    logging.root.setLevel(original_level)
    logging.root.handlers = original_handlers

    # reset all other loggers
    for logger in loggers_to_clear:
        logger.setLevel(logging.NOTSET)
        logger.handlers = []
        logger.propagate = True
