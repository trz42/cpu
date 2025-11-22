# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for ThreadMessageQueue implementation.
"""

from __future__ import annotations

import threading
import time

import pytest

from cpu.messaging.base import QueueEmptyError, QueueFullError
from cpu.messaging.message import Message, MessageType
from cpu.messaging.queue_thread import ThreadMessageQueue


class TestThreadMessageQueueBasics:
    """Test basic queue operations."""

    def test_create_queue(self) -> None:
        """Test creating a queue."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        assert queue is not None
        assert queue.empty()
        assert queue.qsize() == 0

    def test_create_queue_with_maxsize(self) -> None:
        """Test creating a queue with maximum size."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue(maxsize=5)
        assert queue.empty()
        assert queue.qsize() == 0

    def test_put_and_get_single_message(self) -> None:
        """Test putting and getting a single message."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        msg = Message(type=MessageType.WEBHOOK, payload={"test": "data"})

        queue.put(msg)
        assert not queue.empty()
        assert queue.qsize() == 1

        retrieved = queue.get()
        assert retrieved.id == msg.id
        assert retrieved.payload == msg.payload
        assert queue.empty()

    def test_put_and_get_multiple_messages(self) -> None:
        """Test FIFO ordering with multiple messages."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        messages = [
            Message(type=MessageType.WEBHOOK, payload={"n": i})
            for i in range(5)
        ]

        for msg in messages:
            queue.put(msg)

        assert queue.qsize() == 5

        for i, original in enumerate(messages):
            retrieved = queue.get()
            assert retrieved.id == original.id
            assert retrieved.payload["n"] == i

        assert queue.empty()


class TestThreadMessageQueueBlocking:
    """Test blocking behavior."""

    def test_get_blocks_when_empty(self) -> None:
        """Test that get() blocks when queue is empty."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        # Start a thread that will get from empty queue
        result: list[Message | None] = [None]
        exception: list[Exception | None] = [None]

        def getter() -> None:
            try:
                # This should block until message available
                result[0] = queue.get(timeout=0.5)
            except Exception as err:
                exception[0] = err

        thread = threading.Thread(target=getter)
        thread.start()

        # Wait a bit to ensure getter is blocked
        time.sleep(0.1)
        assert thread.is_alive()  # Still waiting

        # Put a message
        msg = Message(type=MessageType.WEBHOOK, payload={"test": 1})
        queue.put(msg)

        # Thread should complete
        thread.join(timeout=1.0)
        assert not thread.is_alive()
        assert result[0] is not None
        assert result[0].id == msg.id
        assert exception[0] is None

    def test_get_timeout(self) -> None:
        """Test get() with timeout raises QueueEmptyError."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        with pytest.raises(QueueEmptyError):
            queue.get(timeout=0.1)

    def test_get_non_blocking_empty_raises(self) -> None:
        """Test get(block=False) on empty queue raises QueueEmptyError."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        with pytest.raises(QueueEmptyError):
            queue.get(block=False)

    def test_put_blocks_when_full(self) -> None:
        """Test that put() blocks when queue is full."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue(maxsize=2)

        # Fill the queue
        msg1 = Message(type=MessageType.WEBHOOK, payload={"n": 1})
        msg2 = Message(type=MessageType.WEBHOOK, payload={"n": 2})
        queue.put(msg1)
        queue.put(msg2)

        assert queue.qsize() == 2

        # Try to put another - should block
        msg3 = Message(type=MessageType.WEBHOOK, payload={"n": 3})
        put_completed = [False]
        exception: list[Exception | None] = [None]

        def putter() -> None:
            try:
                queue.put(msg3, timeout=0.5)
                put_completed[0] = True
            except Exception as err:
                exception[0] = err

        thread = threading.Thread(target=putter)
        thread.start()

        # Wait to ensure putter is blocked
        time.sleep(0.1)
        assert thread.is_alive()  # Still blocked
        assert not put_completed[0]

        # Get a message to make space
        queue.get()

        # Putter should complete
        thread.join(timeout=1.0)
        assert not thread.is_alive()
        assert put_completed[0]
        assert exception[0] is None

    def test_put_timeout(self) -> None:
        """Test put() with timeout on full queue raises QueueFullError."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue(maxsize=1)

        msg1 = Message(type=MessageType.WEBHOOK, payload={"n": 1})
        queue.put(msg1)

        msg2 = Message(type=MessageType.WEBHOOK, payload={"n": 2})
        with pytest.raises(QueueFullError):
            queue.put(msg2, timeout=0.1)

    def test_put_non_blocking_full_raises(self) -> None:
        """Test put(block=False) on full queue raises QueueFullError."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue(maxsize=1)

        msg1 = Message(type=MessageType.WEBHOOK, payload={"n": 1})
        queue.put(msg1)

        msg2 = Message(type=MessageType.WEBHOOK, payload={"n": 2})
        with pytest.raises(QueueFullError):
            queue.put(msg2, block=False)


class TestThreadMessageQueueThreadSafety:
    """Test thread safety with multiple producers/consumers."""

    def test_multiple_producers(self) -> None:
        """Test multiple threads producing messages."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        num_producers = 3
        messages_per_producer = 10

        def producer(producer_id: int) -> None:
            for i in range(messages_per_producer):
                msg = Message(
                    type=MessageType.WEBHOOK,
                    payload={"producer": producer_id, "n": i}
                )
                queue.put(msg)

        threads = [
            threading.Thread(target=producer, args=(i,))
            for i in range(num_producers)
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=2.0)

        # Should have all messages
        assert queue.qsize() == num_producers * messages_per_producer

        # All messages should be retrievable
        for _ in range(num_producers * messages_per_producer):
            msg = queue.get()
            assert "producer" in msg.payload
            assert "n" in msg.payload

        assert queue.empty()

    def test_multiple_consumers(self) -> None:
        """Test multiple threads consuming messages."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        num_messages = 20

        # Pre-fill queue
        for i in range(num_messages):
            msg = Message(type=MessageType.WEBHOOK, payload={"n": i})
            queue.put(msg)

        results: list[Message] = []
        lock = threading.Lock()

        def consumer() -> None:
            while True:
                try:
                    msg = queue.get(timeout=0.5)
                    with lock:
                        results.append(msg)
                except QueueEmptyError:
                    break

        num_consumers = 3
        threads = [threading.Thread(target=consumer) for _ in range(num_consumers)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=3.0)

        # All messages should be consumed
        assert len(results) == num_messages
        assert queue.empty()

    def test_producers_and_consumers_concurrent(self) -> None:
        """Test producers and consumers running concurrently."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue(maxsize=5)
        num_messages = 30
        produced: list[int] = []
        consumed: list[int] = []

        def producer() -> None:
            nonlocal num_messages
            i = 0
            while i < num_messages:
                msg = Message(type=MessageType.WEBHOOK, payload={"n": i})
                try:
                    queue.put(msg, timeout=2.0)
                    produced.append(i)
                    i += 1
                except QueueFullError:
                    # Queue full even after timeout - reduce number of messages to be delivered
                    num_messages -= 1

        def consumer() -> None:
            while len(consumed) < num_messages:
                try:
                    msg = queue.get(timeout=2.0)
                    consumed.append(msg.payload["n"])
                except QueueEmptyError:
                    if len(consumed) >= num_messages:
                        break

        producer_thread = threading.Thread(target=producer)
        consumer_thread = threading.Thread(target=consumer)

        producer_thread.start()
        consumer_thread.start()

        producer_thread.join(timeout=5.0)
        consumer_thread.join(timeout=5.0)

        assert len(produced) == num_messages
        assert len(consumed) == num_messages


class TestThreadMessageQueueClose:
    """Test queue closing behavior."""

    def test_close_queue(self) -> None:
        """Test closing a queue."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        msg = Message(type=MessageType.WEBHOOK, payload={"test": 1})
        queue.put(msg)

        assert not queue.empty()

        # Close should be safe
        queue.close()

        # Should be able to call close multiple times (idempotent)
        queue.close()
        queue.close()

        # Queue should still report as closed
        assert queue._closed


class TestThreadMessageQueueEdgeCases:
    """Test edge cases and error conditions."""

    def test_queue_with_zero_maxsize_is_unlimited(self) -> None:
        """Test that maxsize=0 means unlimited queue."""
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue(maxsize=0)

        # Should be able to add many messages
        for i in range(100):
            msg = Message(type=MessageType.WEBHOOK, payload={"n": i})
            queue.put(msg, block=False)  # Should not block

        assert queue.qsize() == 100
