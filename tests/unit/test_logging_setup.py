# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for logging setup.
"""

from __future__ import annotations

import logging

import pytest

from cpu.logging.queue_handler import QueueLoggingHandler
from cpu.logging.setup import TRACE, configure_queue_logging
from cpu.messaging.message import Message, MessageType
from cpu.messaging.queue_thread import ThreadMessageQueue


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


class TestConfigureQueueLogging:
    """Test queue-based logging configuration."""

    def test_cpu_logger_gets_queue_handler(self) -> None:
        """Test the cpu logger is configured with a QueueLoggingHandler."""
        log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        configure_queue_logging(log_queue)

        cpu_logger = logging.getLogger("cpu")
        assert len(cpu_logger.handlers) == 1
        assert isinstance(cpu_logger.handlers[0], QueueLoggingHandler)

    def test_log_message_lands_in_queue(self) -> None:
        """Test a log call on a cpu.* logger ends up in the queue."""
        log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        configure_queue_logging(log_queue)

        logger = logging.getLogger("cpu.some.module")
        logger.info("Hello queue")

        msg = log_queue.get(timeout=1)
        assert msg.type == MessageType.LOG
        assert "Hello queue" in msg.payload["message"]
        assert msg.payload["name"] == "cpu.some.module"

    def test_existing_handlers_replaced(self) -> None:
        """Test previously configured handlers are removed."""
        log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        cpu_logger = logging.getLogger("cpu")
        cpu_logger.addHandler(logging.NullHandler())
        cpu_logger.addHandler(logging.NullHandler())

        configure_queue_logging(log_queue)

        assert len(cpu_logger.handlers) == 1
        assert isinstance(cpu_logger.handlers[0], QueueLoggingHandler)

    def test_no_propagation_to_root(self) -> None:
        """Test cpu logger does not propagate to root logger."""
        log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        configure_queue_logging(log_queue)

        cpu_logger = logging.getLogger("cpu")
        assert cpu_logger.propagate is False

    def test_level_respected(self) -> None:
        """Test messages below the configured level are not queued."""
        log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        configure_queue_logging(log_queue, level=logging.WARNING)

        logger = logging.getLogger("cpu.some.module")
        logger.info("Filtered out")
        logger.warning("Passes through")

        msg = log_queue.get(timeout=1)
        assert "Passes through" in msg.payload["message"]
        assert log_queue.empty()

    def test_trace_level_supported(self) -> None:
        """Test TRACE level messages flow through when configured."""
        log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        configure_queue_logging(log_queue, level=TRACE)

        logger = logging.getLogger("cpu.some.module")
        logger.log(TRACE, "Trace through queue")

        msg = log_queue.get(timeout=1)
        assert msg.payload["level"] == TRACE
        assert "Trace through queue" in msg.payload["message"]

    def test_source_component_set(self) -> None:
        """Test the source component name is attached to messages."""
        log_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        configure_queue_logging(log_queue, source_component="event_handler")

        logger = logging.getLogger("cpu.some.module")
        logger.info("Tagged message")

        msg = log_queue.get(timeout=1)
        assert msg.source == "event_handler"
