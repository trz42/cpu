# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Configuration of tests.
"""

import logging
from collections.abc import Generator

import pytest


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
