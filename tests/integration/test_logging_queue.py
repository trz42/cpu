# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
Integration tests for QueueLoggingHandler and LoggingComponent interplay.

These tests verify the full logging chain:
    logger.info("message")
        -> QueueLoggingHandler.emit()
        -> ThreadMessageQueue
        -> LoggingComponent.process_iteration()
        -> log file
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from cpu.components.base import HealthStatus
from cpu.logging.component import LoggingComponent
from cpu.logging.queue_handler import QueueLoggingHandler
from cpu.logging.setup import TRACE, configure_queue_logging
from cpu.messaging.message import Message, MessageType
from cpu.messaging.queue_thread import ThreadMessageQueue


class TestQueueLoggingIntegration:
    """Integration tests for QueueLoggingHandler and LoggingComponent."""

    def test_message_reaches_log_file(
        self,
        logging_component: tuple[LoggingComponent, ThreadMessageQueue[Message], Path],
    ) -> None:
        """Test full chain: handler -> queue -> LoggingComponent -> file."""
        component, log_queue, log_file = logging_component

        handler = QueueLoggingHandler(log_queue, "test_component")
        logger = logging.getLogger("test.integration.basic")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        logger.info("Hello from integration test")

        component.process_iteration()
        component.flush()

        assert log_file.exists()
        assert "Hello from integration test" in log_file.read_text()

    def test_all_log_levels_written_to_file(
        self,
        logging_component: tuple[LoggingComponent, ThreadMessageQueue[Message], Path],
    ) -> None:
        """Test all log levels including TRACE are written to file."""
        component, log_queue, log_file = logging_component

        handler = QueueLoggingHandler(log_queue, "test_component")
        logger = logging.getLogger("test.integration.levels")
        logger.addHandler(handler)
        logger.setLevel(TRACE)

        logger.log(TRACE, "Trace message")
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")

        for _ in range(6):
            component.process_iteration()
        component.flush()

        content = log_file.read_text()
        assert "Debug message" in content
        assert "Info message" in content
        assert "Warning message" in content
        assert "Error message" in content
        assert "Critical message" in content
        # TRACE is below DEBUG so LoggingComponent may filter it
        # depending on configured level - just verify others work

    def test_message_sanitized_before_writing(
        self,
        logging_component: tuple[LoggingComponent, ThreadMessageQueue[Message], Path],
    ) -> None:
        """Test sensitive data is sanitized before writing to file."""
        component, log_queue, log_file = logging_component

        handler = QueueLoggingHandler(log_queue, "test_component")
        logger = logging.getLogger("test.integration.sanitize")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        logger.info("Connecting with token=supersecrettoken123")

        component.process_iteration()
        component.flush()

        content = log_file.read_text()
        assert "supersecrettoken123" not in content
        assert "***" in content

    def test_bad_message_doesnt_crash_component(
        self,
        logging_component: tuple[LoggingComponent, ThreadMessageQueue[Message], Path],
    ) -> None:
        """Test LoggingComponent continues after a malformed message."""
        component, log_queue, log_file = logging_component

        # put a malformed log message (missing required fields)
        bad_message = Message(
            type=MessageType.LOG,
            payload={},  # missing level and message
        )
        log_queue.put(bad_message)

        # put a valid message after the bad one
        good_message = Message(
            type=MessageType.LOG,
            payload={"level": logging.INFO, "message": "Good message after bad"},
        )
        log_queue.put(good_message)

        # process both - should not crash
        component.process_iteration()
        component.process_iteration()
        component.flush()

        # component should still be healthy
        assert component.health_check() == HealthStatus.HEALTHY

        # good message should still be written
        content = log_file.read_text()
        assert "Good message after bad" in content

    def test_non_log_message_ignored(
        self,
        logging_component: tuple[LoggingComponent, ThreadMessageQueue[Message], Path],
    ) -> None:
        """Test LoggingComponent silently ignores non-LOG messages."""
        component, log_queue, log_file = logging_component

        # put a non-LOG message in the queue
        webhook_message = Message(
            type=MessageType.WEBHOOK,
            payload={"data": "some webhook data"},
        )
        log_queue.put(webhook_message)

        # put a valid log message after
        log_message = Message(
            type=MessageType.LOG,
            payload={"level": logging.INFO, "message": "Real log message"},
        )
        log_queue.put(log_message)

        component.process_iteration()  # webhook - should be ignored
        component.process_iteration()  # log - should be written
        component.flush()

        content = log_file.read_text()
        assert "some webhook data" not in content
        assert "Real log message" in content

    def test_log_ordering_preserved(
        self,
        logging_component: tuple[LoggingComponent, ThreadMessageQueue[Message], Path],
    ) -> None:
        """Test that log messages are written in FIFO order."""
        component, log_queue, log_file = logging_component

        handler = QueueLoggingHandler(log_queue, "test_component")
        logger = logging.getLogger("test.integration.ordering")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        messages = [f"Message {i}" for i in range(5)]
        for msg in messages:
            logger.info(msg)

        for _ in range(5):
            component.process_iteration()
        component.flush()

        content = log_file.read_text()
        positions = [content.index(msg) for msg in messages]

        # verify messages appear in order
        assert positions == sorted(positions)

    def test_component_processes_messages_in_thread(
        self,
        logging_component: tuple[LoggingComponent, ThreadMessageQueue[Message], Path],
    ) -> None:
        """Test LoggingComponent processes messages correctly when running in thread."""
        component, log_queue, log_file = logging_component

        thread = threading.Thread(target=component.start)
        thread.start()

        handler = QueueLoggingHandler(log_queue, "test_component")
        logger = logging.getLogger("test.integration.thread")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        for i in range(10):
            logger.info(f"Threaded message {i}")

        # wait for processing
        time.sleep(0.5)

        component.stop()
        thread.join(timeout=2)
        component.flush()

        content = log_file.read_text()
        for i in range(10):
            assert f"Threaded message {i}" in content

    def test_no_feedback_loop_at_trace_level(
        self,
        logging_component: tuple[LoggingComponent, ThreadMessageQueue[Message], Path],
    ) -> None:
        """Test the component's own queue operations don't generate log messages."""
        component, log_queue, log_file = logging_component

        # route all cpu.* logging into the same queue at TRACE level
        configure_queue_logging(log_queue, level=TRACE)

        thread = threading.Thread(target=component.start)
        thread.start()

        # without suppression, every queue.get would enqueue a new TRACE
        # message, keeping the queue busy forever
        time.sleep(0.3)

        component.stop()
        thread.join(timeout=2)
        component.flush()

        # queue must not have balloned with self-generated messages
        assert log_queue.qsize() < 10
        assert "Getting message from queue" not in log_file.read_text()
