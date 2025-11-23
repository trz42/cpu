# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Unit tests for ThreadMessageBus.

Tests the message bus implementation including:
- Named queue management
- Pub/sub functionality
- Shutdown behavior
"""

from __future__ import annotations

from cpu.messaging.message import Message, MessageType
from cpu.messaging.message_bus import ThreadMessageBus


class TestThreadMessageBus:
    """Unit tests for ThreadMessageBus."""

    def test_get_queue_creates_queue(self) -> None:
        """Test that get_queue creates a new queue."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        queue = bus.get_queue("test_queue")
        assert queue is not None

    def test_get_queue_returns_same_instance(self) -> None:
        """Test that get_queue returns same queue instance for same name."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        queue1 = bus.get_queue("test_queue")
        queue2 = bus.get_queue("test_queue")
        assert queue1 is queue2

    def test_get_queue_different_names(self) -> None:
        """Test that different names create different queues."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        queue1 = bus.get_queue("queue1")
        queue2 = bus.get_queue("queue2")
        assert queue1 is not queue2

    def test_publish_to_subscribers(self) -> None:
        """Test that publish sends message to all subscribers."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()

        sub1 = bus.subscribe("test_topic")
        sub2 = bus.subscribe("test_topic")

        msg = Message(type=MessageType.WEBHOOK, payload={"test": 1})
        bus.publish("test_topic", msg)

        # Both subscribers should receive the message
        received1 = sub1.get(timeout=1)
        received2 = sub2.get(timeout=1)

        assert received1.id == msg.id
        assert received2.id == msg.id

    def test_publish_no_subscribers(self) -> None:
        """Test that publish with no subscribers doesn't raise error."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        msg = Message(type=MessageType.WEBHOOK, payload={})

        # Should not raise
        bus.publish("nonexistent_topic", msg)

    def test_subscribe_creates_unique_queues(self) -> None:
        """Test that each subscribe call creates a new queue."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()

        sub1 = bus.subscribe("test_topic")
        sub2 = bus.subscribe("test_topic")

        # Should be different queue instances
        assert sub1 is not sub2

    def test_publish_only_to_specific_topic(self) -> None:
        """Test that messages only go to subscribers of that topic."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()

        sub_topic1 = bus.subscribe("topic1")
        sub_topic2 = bus.subscribe("topic2")

        msg = Message(type=MessageType.WEBHOOK, payload={"topic": 1})
        bus.publish("topic1", msg)

        # Only topic1 subscriber should receive
        received = sub_topic1.get(timeout=1)
        assert received.id == msg.id

        # topic2 subscriber should have empty queue
        assert sub_topic2.empty()

    def test_shutdown_closes_all_queues(self) -> None:
        """Test that shutdown closes all managed queues."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()

        queue1 = bus.get_queue("queue1")
        queue2 = bus.get_queue("queue2")
        sub1 = bus.subscribe("topic1")

        # Put messages before shutdown
        msg = Message(type=MessageType.WEBHOOK, payload={})
        queue1.put(msg)

        bus.shutdown()

        # After shutdown, queues should be closed
        # We can verify by checking the internal state of ThreadMessageQueue
        # since we know the concrete implementation
        from cpu.messaging.queue_thread import ThreadMessageQueue
        assert isinstance(queue1, ThreadMessageQueue)
        assert queue1._closed
        assert isinstance(queue2, ThreadMessageQueue)
        assert queue2._closed
        assert isinstance(sub1, ThreadMessageQueue)
        assert sub1._closed

    def test_multiple_messages_to_multiple_subscribers(self) -> None:
        """Test publishing multiple messages to multiple subscribers."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()

        sub1 = bus.subscribe("test_topic")
        sub2 = bus.subscribe("test_topic")

        messages = [
            Message(type=MessageType.WEBHOOK, payload={"n": i})
            for i in range(3)
        ]

        for msg in messages:
            bus.publish("test_topic", msg)

        # Each subscriber should receive all messages
        for i in range(3):
            received1 = sub1.get(timeout=1)
            received2 = sub2.get(timeout=1)
            assert received1.payload["n"] == i
            assert received2.payload["n"] == i

    def test_named_queue_independent_of_topics(self) -> None:
        """Test that named queues and topics are independent."""
        bus: ThreadMessageBus[Message] = ThreadMessageBus()

        named_queue = bus.get_queue("my_queue")
        subscriber = bus.subscribe("my_queue")  # Same name but different namespace

        # They should be different queues
        assert named_queue is not subscriber

        # Publishing to topic shouldn't affect named queue
        msg = Message(type=MessageType.WEBHOOK, payload={})
        bus.publish("my_queue", msg)

        assert named_queue.empty()
        assert not subscriber.empty()

    def test_concurrent_subscribe_and_publish(self) -> None:
        """Test thread safety with concurrent subscribe and publish operations."""
        import threading
        import time

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        subscribers = []
        errors = []

        def subscribe_worker() -> None:
            """Worker that subscribes to topics."""
            try:
                for _i in range(10):
                    sub = bus.subscribe("test_topic")
                    subscribers.append(sub)
                    time.sleep(0.001)
            except Exception as err:
                errors.append(err)

        def publish_worker() -> None:
            """Worker that publishes messages."""
            try:
                for i in range(10):
                    msg = Message(type=MessageType.WEBHOOK, payload={"n": i})
                    bus.publish("test_topic", msg)
                    time.sleep(0.001)
            except Exception as err:
                errors.append(err)

        # Start concurrent operations
        threads = [
            threading.Thread(target=subscribe_worker),
            threading.Thread(target=subscribe_worker),
            threading.Thread(target=publish_worker),
            threading.Thread(target=publish_worker),
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=5)

        # Should complete without errors
        assert len(errors) == 0, f"Concurrent operations raised errors: {errors}"
