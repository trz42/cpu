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

from cpu.components.base import ComponentState, HealthStatus
from cpu.logging.component import LoggingComponent
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
            config={"file": str(log_file), "level": "INFO"},
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

    def test_logging_component_skips_non_log_messages(self, tmp_path: Path) -> None:
        """Test component ignores non-LOG message types."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"file": str(log_file), "level": "INFO"},
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
            config={"file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        # send message with secret
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
            config={"file": str(log_file), "level": "INFO"},
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
            config={"file": str(log_file), "level": "INFO"},
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
            config={"file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        # should be healthy when initialized
        assert component.health_check() == HealthStatus.HEALTHY

    def test_logging_component_flush_handler(self, tmp_path: Path) -> None:
        """Test flush handler calls flush."""
        import signal
        from unittest.mock import patch

        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        # mock flush to verify it's called
        with patch.object(component, 'flush') as mock_flush:
            # call handler directly
            component._flush_handler(signal.SIGUSR1, None)

            # verify flush was called
            mock_flush.assert_called_once()

    def test_logging_component_health_check_unhealthy_when_not_initialized(self, tmp_path: Path) -> None:
        """Test health check returns unhealthy when not initialized."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"file": str(log_file), "level": "INFO"},
        )
        # don't initialize

        assert component.health_check() == HealthStatus.UNHEALTHY

    def test_logging_component_stop_without_handler(self, tmp_path: Path) -> None:
        """Test stop when handler is None."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"file": str(log_file), "level": "INFO"},
        )
        # don't initialize (no handler)

        # should not raise
        component.stop()

    def test_flush_before_initialize_is_noop(self) -> None:
        """Test flush() does nothing if called before initialize()."""
        log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        component = LoggingComponent(name="logger", log_queue=log_queue)

        # should not raise even though _file_handler is None
        component.flush()

    def test_logging_component_flush_handler_ignores_other_signals(self, tmp_path: Path) -> None:
        """Test flush handler ignores non-SIGUSR1 signals."""
        import signal
        from unittest.mock import patch

        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        with patch.object(component, 'flush') as mock_flush:
            # call with SIGTERM instead
            component._flush_handler(signal.SIGTERM, None)

            # flush should not be called
            mock_flush.assert_not_called()

    def test_metadata_preserved_in_log_output(self, tmp_path: Path) -> None:
        """Test original logger name, function, and line number appear in log."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={
                "file": str(log_file),
                "level": "DEBUG",
                "format": "%(name)s:%(funcName)s:%(lineno)d %(message)s",
            },
        )
        component.initialize()

        msg = Message(
            type=MessageType.LOG,
            payload={
                "level": logging.INFO,
                "message": "With metadata",
                "name": "cpu.event_handler",
                "funcName": "handle_webhook",
                "lineno": 42,
            },
        )
        queue.put(msg)
        component.process_iteration()
        component.flush()

        content = log_file.read_text()
        assert "cpu.event_handler:handle_webhook:42 With metadata" in content

    def test_level_filtering_respected(self, tmp_path: Path) -> None:
        """Test messages below configured level are not written."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        msg = Message(
            type=MessageType.LOG,
            payload={"level": logging.DEBUG, "message": "Too detailed"},
        )
        queue.put(msg)
        component.process_iteration()
        component.flush()

        assert "Too detailed" not in log_file.read_text()

    def test_logger_does_not_propagate(self, tmp_path: Path) -> None:
        """Test internal logger has propagation disabled to prevent feedback loop."""
        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"file": str(log_file), "level": "DEBUG"},
        )
        component.initialize()

        assert logging.getLogger("cpu.logging").propagate is False

    def test_uses_compressing_rotating_file_handler(self, tmp_path: Path) -> None:
        """Test LoggingComponent uses CompressingRotatingFileHandler."""
        from cpu.logging.rotation import CompressingRotatingFileHandler

        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={"file": str(log_file), "level": "INFO"},
        )
        component.initialize()

        assert isinstance(component._file_handler, CompressingRotatingFileHandler)

    def test_rotation_config_applied(self, tmp_path: Path) -> None:
        """Test max_bytes and backup_count are read from config."""
        from cpu.logging.rotation import CompressingRotatingFileHandler

        log_file = tmp_path / "test.log"
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        component = LoggingComponent(
            name="logger",
            log_queue=queue,
            config={
                "file": str(log_file),
                "level": "INFO",
                "max_bytes": 1024,
                "backup_count": 3,
            },
        )
        component.initialize()

        assert isinstance(component._file_handler, CompressingRotatingFileHandler)
        assert component._file_handler.maxBytes == 1024
        assert component._file_handler.backupCount == 3
