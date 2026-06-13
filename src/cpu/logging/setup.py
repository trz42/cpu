# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Early logging configuration before components start.
"""

from __future__ import annotations

import logging
from typing import Any

from cpu.logging.queue_handler import QueueLoggingHandler
from cpu.messaging.interfaces import MessageQueueInterface
from cpu.messaging.message import Message

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


# type stubs for mypy to recognise the trace method
if False:  # pragma: no cover
    # this is never executed but tells mypy that Logger has a trace method
    from typing import Protocol

    class _LoggerProtocol(Protocol):
        def trace(self, message: str, *args: Any, **kwargs: Any) -> None: ...

    logging.Logger.trace = _LoggerProtocol.trace

def configure_queue_logging(
    log_queue: MessageQueueInterface[Message],
    source_component: str = "cpu",
    level: int = logging.INFO,
) -> None:
    """
    Configure queue-based logging for the cpu package.

    Replaces all handlers on the "cpu" logger with a QueueLoggingHandler,
    so every log call from cpu.* modules is sent to the LoggingComponent
    via the message queue instead of being written directly.

    Args:
        log_queue: Queue to send log messages to
        source_component: Name attached as message source
        level: Minimum log level to send to the queue
    """
    cpu_logger = logging.getLogger("cpu")

    # remove any existing handlers to avoid duplicate log paths
    cpu_logger.handlers.clear()

    # add queue handler
    queue_handler = QueueLoggingHandler(log_queue, source_component)
    queue_handler.setLevel(level)
    cpu_logger.addHandler(queue_handler)

    cpu_logger.setLevel(level)

    # don't propagate to root logger (would bypass the queue)
    cpu_logger.propagate = False
