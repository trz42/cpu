# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Queue-based logging component for async log writes.
"""

from __future__ import annotations

import logging
import signal
from pathlib import Path
from typing import Any

from cpu.components.base import ComponentState, HealthStatus, RunnableComponent
from cpu.logging.queue_handler import suppress_queue_logging
from cpu.logging.sanitizer import LogSanitizer
from cpu.messaging.interfaces import MessageQueueInterface, QueueEmptyError
from cpu.messaging.message import Message, MessageType


class LoggingComponent(RunnableComponent):
    """Queue-based async logging component."""

    def __init__(
        self,
        name: str,
        log_queue: MessageQueueInterface[Message],
        config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(name, config)
        self._queue = log_queue
        self._sanitizer = LogSanitizer()
        self._file_handler: logging.FileHandler | None = None
        self._logger: logging.Logger | None = None

    def initialize(self) -> None:
        """Setup file handler and logger."""
        # setup flush handler for flush
        self.setup_flush_signal()

        log_file = self.config.get("file", "logs/cpu.log")
        log_level = self.config.get("level", "INFO")
        log_format = self.config.get(
            "format",
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        # create log directory
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # create file handler
        self._file_handler = logging.FileHandler(log_file)
        self._file_handler.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter(log_format)
        self._file_handler.setFormatter(formatter)

        # create logger
        self._logger = logging.getLogger("cpu.logging")
        self._logger.addHandler(self._file_handler)
        self._logger.setLevel(getattr(logging, log_level.upper()))

        self.state = ComponentState.INITIALIZED

    def process_iteration(self) -> None:
        """Process one log message from queue."""
        try:
            # suppress queue logging around our own queue operation to
            # prevent a feedback loop (get() logs at TRACE level)
            with suppress_queue_logging():
                msg = self._queue.get(timeout=0.1)

            # verif message type
            if msg.type != MessageType.LOG:
                # skip non-log messages
                return

            # extract log info
            level = msg.payload.get("level", logging.INFO)
            message = msg.payload.get("message", "")
            name = msg.payload.get("name", "cpu")
            func = msg.payload.get("funcName", "")
            lineno = msg.payload.get("lineno", 0)

            # sanitize message
            sanitized = self._sanitizer.sanitize(message)

            # write to log, preserving original metadata
            if self._logger and self._logger.isEnabledFor(level):
                record = logging.LogRecord(
                    name=name,
                    level=level,
                    pathname="",
                    lineno=lineno,
                    msg=sanitized,
                    args=(),
                    exc_info=None,
                    func=func,
                )
                self._logger.handle(record)

        except QueueEmptyError:
            # no messages, continue
            pass

    def health_check(self) -> HealthStatus:
        """Check logging health."""
        if self.state in (ComponentState.INITIALIZED, ComponentState.RUNNING):
            return HealthStatus.HEALTHY
        return HealthStatus.UNHEALTHY

    def stop(self, timeout: float | None = None) -> None:
        """Stop and cleanup."""
        del timeout  # Not used
        self._stop_requested = True
        self.state = ComponentState.STOPPING

        # flush and close handler
        if self._file_handler:
            self._file_handler.flush()
            self._file_handler.close()

    def flush(self) -> None:
        """Flush all buffered logs immediately."""
        if self._file_handler:
            self._file_handler.flush()

    def setup_flush_signal(self) -> None:
        """Setup SIGUSR1 handler for flushing."""
        signal.signal(signal.SIGUSR1, self._flush_handler)

    def _flush_handler(self, signum: int, frame: Any) -> None:
        """Handle flush signal."""
        del frame  # unused
        if signum == signal.SIGUSR1:
            self.flush()
