# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""Tests for QueueLoggingHandler."""

import logging

from cpu.logging.queue_handler import QueueLoggingHandler
from cpu.messaging.message import Message, MessageType
from cpu.messaging.queue_thread import ThreadMessageQueue


class TestQueueLoggingHandler:
    """Test QueueLoggingHandler functionality."""

    def test_handler_sends_message_to_queue(self) -> None:
        """Test handler creates and sends log message to queue."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = QueueLoggingHandler(queue, "test_component")

        logger = logging.getLogger("test.handler")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        logger.info("Test message")

        # verify message in queue
        msg = queue.get(timeout=1)
        assert msg.type == MessageType.LOG
        assert msg.payload["level"] == logging.INFO
        assert "Test message" in msg.payload["message"]
        assert msg.source == "test_component"

    def test_handler_includes_metadata(self) -> None:
        """Test handler includes logger name, function, and line number."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = QueueLoggingHandler(queue, "test_component")

        logger = logging.getLogger("test.metadata")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        logger.debug("Debug message")

        msg = queue.get(timeout=1)
        assert msg.payload["name"] == "test.metadata"
        assert msg.payload["funcName"] == "test_handler_includes_metadata"
        assert msg.payload["lineno"] > 0

    def test_handler_formats_message(self) -> None:
        """Test handler formats message with formatter."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = QueueLoggingHandler(queue, "test_component")

        # set a custom formatter
        formatter = logging.Formatter("%(levelname)s: %(message)s")
        handler.setFormatter(formatter)

        logger = logging.getLogger("test.format")
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)

        logger.warning("Warning message")

        msg = queue.get(timeout=1)
        assert "WARNING: Warning message" in msg.payload["message"]

    def test_handler_different_log_levels(self) -> None:
        """Test handler handles different log levels including TRACE."""
        from cpu.logging.setup import TRACE

        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = QueueLoggingHandler(queue, "test_component")

        logger = logging.getLogger("test.levels")
        logger.addHandler(handler)
        logger.setLevel(TRACE)

        # log at different levels
        logger.log(TRACE, "Trace")
        logger.debug("Debug")
        logger.info("Info")
        logger.warning("Warning")
        logger.error("Error")
        logger.critical("Critical")

        # verify all levels
        levels = []
        for _ in range(6):
            msg = queue.get(timeout=1)
            levels.append(msg.payload["level"])

        assert TRACE in levels
        assert logging.DEBUG in levels
        assert logging.INFO in levels
        assert logging.WARNING in levels
        assert logging.ERROR in levels
        assert logging.CRITICAL in levels

    def test_handler_non_blocking(self) -> None:
        """Test handler doesn't block when queue is full."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue(maxsize=1)
        handler = QueueLoggingHandler(queue, "test")

        logger = logging.getLogger("test.blocking")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # fill queue
        logger.info("Message 1")

        # this should not block (will drop silently)
        logger.info("Message 2")

        # should complete without hanging
        assert queue.qsize() == 1

    def test_handler_with_exception_doesnt_crash(self) -> None:
        """Test handler gracefully handles exceptions."""
        from unittest.mock import Mock

        # create mock queue that raises exception
        queue = Mock()
        queue.put.side_effect = Exception("Queue error")

        handler = QueueLoggingHandler(queue, "test")

        logger = logging.getLogger("test.exception")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # this should not raise exception (logging must not break app)
        logger.info("This should not crash")

        # verify we're still alive
        assert True

    def test_handler_with_args_formatting(self) -> None:
        """Test handler formats messages with arguments."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = QueueLoggingHandler(queue, "test")

        logger = logging.getLogger("test.args")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        logger.info("Value: %d, Name: %s", 42, "test")

        msg = queue.get(timeout=1)
        assert "Value: 42" in msg.payload["message"]
        assert "Name: test" in msg.payload["message"]

    def test_handler_respects_log_level(self) -> None:
        """Test handler respects logger level."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = QueueLoggingHandler(queue, "test")

        logger = logging.getLogger("test.level")
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)  # only WARNING and above

        logger.debug("Should not appear")
        logger.info("Should not appear")
        logger.warning("Should appear")

        # only one message should be in queue
        msg = queue.get(timeout=1)
        assert "Should appear" in msg.payload["message"]

        # queue should be empty
        assert queue.empty()
