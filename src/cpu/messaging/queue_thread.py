# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Thread-safe message queue implementation using queue.Queue.
"""

from __future__ import annotations

import queue
from typing import Generic, TypeVar

from cpu.messaging.interfaces import MessageQueueInterface, QueueEmptyError, QueueFullError

T = TypeVar("T")


class ThreadMessageQueue(MessageQueueInterface[T], Generic[T]):
    """
    Thread-safe message queue using Python's queue.Queue.

    This implementation provides thread-safe FIFO queue operations suitable
    for inter-thread communication within a single process.

    Type Parameters:
        T: Type of items stored in the queue

    Example:
        >>> from cpu.messaging.message import Message, MessageType
        >>> queue = ThreadMessageQueue[Message]()
        >>> msg = Message(type=MessageType.WEBHOOK, payload={"data": "test"})
        >>> queue.put(msg)
        >>> retrieved = queue.get()
        >>> assert retrieved.id == msg.id
    """

    def __init__(self, maxsize: int = 0) -> None:
        """
        Initialize thread-safe queue.

        Args:
            maxsize: Maximum queue size. 0 (default) means unlimited.
                    If maxsize > 0, put() will block when queue is full.
        """
        self._queue: queue.Queue[T] = queue.Queue(maxsize=maxsize)
        self._closed = False

    def put(
        self,
        message: T,
        block: bool = True,
        timeout: float | None = None,
    ) -> None:
        """
        Put a message onto the queue.

        Args:
            message: Message to enqueue
            block: If True, block if queue is full; if False, raise QueueFullError immediately
            timeout: Maximum time to wait in seconds (None = wait forever)
                    Only used if block=True

        Raises:
            QueueFullError: If queue is full and block=False, or if timeout expires

        Example:
            >>> queue.put(message)  # Block until space available
            >>> queue.put(message, block=False)  # Raise immediately if full
            >>> queue.put(message, timeout=5.0)  # Wait max 5 seconds
        """
        try:
            self._queue.put(message, block=block, timeout=timeout)
        except queue.Full as err:
            raise QueueFullError("Queue is full") from err

    def get(
        self,
        block: bool = True,
        timeout: float | None = None,
    ) -> T:
        """
        Get a message from the queue.

        Args:
            block: If True, block if queue is empty; if False, raise QueueEmptyError immediately
            timeout: Maximum time to wait in seconds (None = wait forever)
                    Only used if block=True

        Returns:
            Message from queue

        Raises:
            QueueEmptyError: If queue is empty and block=False, or if timeout expires

        Example:
            >>> msg = queue.get()  # Block until message available
            >>> msg = queue.get(block=False)  # Raise immediately if empty
            >>> msg = queue.get(timeout=5.0)  # Wait max 5 seconds
        """
        try:
            return self._queue.get(block=block, timeout=timeout)
        except queue.Empty as err:
            raise QueueEmptyError("Queue is empty") from err

    def empty(self) -> bool:
        """
        Check if queue is empty.

        Returns:
            True if queue is empty, False otherwise

        Warning:
            This method is NOT reliable in multi-threaded environments.
            By the time you check the result, another thread may have
            modified the queue. Use only for heuristics and debugging.

            Instead of:
                if not queue.empty():
                    item = queue.get()  # May still raise QueueEmptyError!

            Use:
                try:
                    item = queue.get(block=False)
                except QueueEmptyError:
                    # Handle empty queue
        """
        return self._queue.empty()

    def qsize(self) -> int:
        """
        Get approximate queue size.

        Returns:
            Approximate number of items in queue

        Warning:
            Like empty(), this is an approximation only. The size may change
            immediately after this call returns. Use for monitoring and debugging,
            not for critical logic.
        """
        return self._queue.qsize()

    def close(self) -> None:
        """
        Close the queue and release resources.

        After calling close(), no further put() or get() operations should
        be attempted. This method is idempotent - calling it multiple times
        is safe.

        Note:
            queue.Queue doesn't require explicit cleanup, but this method
            is provided for interface compatibility and future extensibility.
        """
        self._closed = True
        # queue.Queue doesn't need explicit closing, but we mark it as closed
        # for potential future use (e.g., raising errors on operations after close)

    def __repr__(self) -> str:
        """Return string representation of queue."""
        return f"ThreadMessageQueue(size={self.qsize()}, closed={self._closed})"
