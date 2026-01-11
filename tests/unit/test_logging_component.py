# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for queue-based logging component.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from cpu.logging.component import LoggingComponent

from cpu.components.base import ComponentState, HealthStatus
from cpu.messaging.message import Message, MessageType
from cpu.messaging.queue_thread import ThreadMessageQueue


class TestLoggingComponent:
    """Test LoggingComponent."""

    def test_logging_component_processes_queue_messages(self, tmp_path: Path) -> None:
        """Test component processes messages from queue."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"bot.logging.file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        # send log message
        msg = Message(
            type=MessageType.LOG,
            payload={"level": logging.INFO, "message": "Test message"},
        )
        queue.put(msg)

        # process one iteration
        component.process_iteration()

        # check log file
        assert log_file.exists()
        content = log_file.read_text()
        assert "Test message" in content

# tests/unit/logging/test_logging_component.py - add to TestLoggingComponent:

    def test_logging_component_skips_non_log_messages(self, tmp_path: Path) -> None:
        """Test component ignores non-LOG message types."""
        log_file = tmp_path / "test.log"
        queue = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"bot.logging.file": str(log_file), "bot.logging.level": "INFO"},
        )
        component.initialize()

        # send non-LOG message
        msg = Message(
            type=MessageType.WEBHOOK,
            payload={"message": "Should be ignored"},
        )
        queue.put(msg)

        component.process_iteration()

        # log file should be empty (no logging happened)
        content = log_file.read_text()
        assert "Should be ignored" not in content

    def test_logging_component_sanitizes_before_write(self, tmp_path: Path) -> None:
        """Test messages are sanitized."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"bot.logging.file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        # Send message with secret
        msg = Message(
            type=MessageType.LOG,
            payload={"level": logging.INFO, "message": "Token: ghp_1234567890123456789012345678901234"},
        )
        queue.put(msg)

        component.process_iteration()

        content = log_file.read_text()
        assert "ghp_" not in content
        assert "***" in content

    def test_logging_component_handles_empty_queue(self, tmp_path: Path) -> None:
        """Test component handles empty queue gracefully."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"bot.logging.file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        # should not raise
        component.process_iteration()

    def test_logging_component_stops_gracefully(self, tmp_path: Path) -> None:
        """Test component stops cleanly."""
        import threading

        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"bot.logging.file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        thread = threading.Thread(target=component.start)
        thread.start()

        time.sleep(0.1)
        component.stop()
        thread.join(timeout=1)

        assert component.get_state() == ComponentState.STOPPED

    def test_logging_component_health_check(self, tmp_path: Path) -> None:
        """Test health check."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"bot.logging.file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        # should be healthy when initialized
        assert component.health_check() == HealthStatus.HEALTHY
