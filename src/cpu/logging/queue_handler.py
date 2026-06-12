# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
Custom logging handler that sends logs through message queue.

This handler integrates Python's logging system with the CPU bot's
message-passing architecture, sending all log records to the
LoggingComponent via a message queue.
"""

from __future__ import annotations

import logging
import threading

from cpu.messaging.interfaces import MessageQueueInterface, QueueFullError
from cpu.messaging.message import Message, MessageType


class QueueLoggingHandler(logging.Handler):
    """
    Logging handler that sends log records to LoggingComponent via queue.

    Converts logging.LogRecord objects to Message objects and sends them
    through the message queue for async processing by LoggingComponent.

    This enables:
    - Async, non-blocking logging
    - Centralized log file writing (LoggingComponent only)
    - Message sanitization
    - Support for distributed/multi-process logging

    Example:
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = QueueLoggingHandler(queue, "my_component")
        logger = logging.getLogger("my_app")
        logger.addHandler(handler)
        logger.info("This goes through the queue!")
    """

    def __init__(
        self,
        queue: MessageQueueInterface[Message],
        source_component: str = "unknown",
    ) -> None:
        """
        Initialize queue logging handler.

        Args:
            queue: Message queue to send log messages to
            source_component: Name of component generating logs
        """
        super().__init__()
        self._queue = queue
        self._source = source_component
        self._emitting = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        """
        Send log record to queue as Message.

        Converts the LogRecord to a Message with type LOG and sends
        it to the queue for processing by LoggingComponent.

        Log calls made by the messaging infrastructure itself while
        emitting (e.g. Message creation logs at DEBUG, queue.put logs
        at TRACE) are dropped to prevent infinite recursion.

        Args:
            record: LogRecord to process
        """
        # re-entry guard: creating/queueing the Message below triggers
        # log calls on cpu.messaging.* loggers, which land in this same
        # handler and would recurse forever
        if getattr(self._emitting, "active", False):
            return
        self._emitting.active = True
        try:
            # format the message using configured formatter
            message_text = self.format(record)

            # create log message
            log_message = Message(
                type=MessageType.LOG,
                payload={
                    "level": record.levelno,
                    "message": message_text,
                    "name": record.name,
                    "funcName": record.funcName,
                    "lineno": record.lineno,
                },
                source=self._source,
            )

            # send to queue (non-blocking to avoid deadlock)
            # if queue is full, message is dropped (logging must not block)
            self._queue.put(log_message, block=False)

        except QueueFullError:
            # queue full - drop message silently
            # logging must never block or crash the application
            pass
        except Exception:
            # CRITICAL: don't raise exceptions from logging
            # this would break the component using the logger
            self.handleError(record)
        finally:
            self._emitting.active = False
