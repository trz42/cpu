# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Queue-based logging component for async log writes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from cpu.components.base import ComponentState, HealthStatus, RunnableComponent
from cpu.logging.sanitizer import LogSanitizer
from cpu.messaging.interfaces import MessageQueueInterface, QueueEmptyError
from cpu.messaging.message import Message


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
        log_file = self.config.get("bot.logging.file", "logs/cpu.log")
        log_level = self.config.get("bot.logging.level", "INFO")
        log_format = self.config.get(
            "bot.logging.format",
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
            msg = self._queue.get(timeout=0.1)

            # verif message type
            if msg.type != MessageType.LOG:
                # skip non-log messages
                return

            # extract log info
            level = msg.payload.get("level", logging.INFO)
            message = msg.payload.get("message", "")

            # sanitize message
            sanitized = self._sanitizer.sanitize(message)

            # write to log
            if self._logger:
                self._logger.log(level, sanitized)

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
