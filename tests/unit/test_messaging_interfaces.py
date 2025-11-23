# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.messaging.interfaces module.

Tests abstract interfaces by creating concrete test implementations.
This ensures the interfaces are well-defined and implementable.
"""

from __future__ import annotations

import pytest

from cpu.messaging.interfaces import (
    MessageBusInterface,
    MessageDeliveryInterface,
    MessageQueueInterface,
    QueueEmptyError,
    QueueError,
    QueueFullError,
    SerializationError,
    SerializerInterface,
)
from cpu.messaging.message import Message, MessageType

# Concrete test implementations of abstract interfaces


class FakeMessageQueue(MessageQueueInterface[Message]):
    """Simple in-memory queue implementation for testing."""

    def __init__(self, maxsize: int = 0) -> None:
        self.maxsize = maxsize
        self._items: list[Message] = []
        self._closed = False

    def put(
        self, message: Message, block: bool = True, timeout: float | None = None
    ) -> None:
        if self._closed:
            raise QueueError("Queue is closed")

        if self.maxsize > 0 and len(self._items) >= self.maxsize:
            if not block:
                raise QueueFullError("Queue is full")
            # Note: timeout parameter received but not used in this simple test implementation
            # A real blocking queue would wait up to 'timeout' seconds
            _ = timeout  # Acknowledge parameter is received
            raise QueueFullError("Queue is full (test implementation doesn't block)")

        # timeout is only relevant when blocking, which this simple implementation doesn't do
        _ = timeout  # Acknowledge parameter is received
        self._items.append(message)

    def get(
        self, block: bool = True, timeout: float | None = None
    ) -> Message:
        if self._closed:
            raise QueueError("Queue is closed")

        if not self._items:
            if not block:
                raise QueueEmptyError("Queue is empty")
            # Note: timeout parameter received but not used in this simple test implementation
            # A real blocking queue would wait up to 'timeout' seconds
            _ = timeout  # Acknowledge parameter is received
            raise QueueEmptyError("Queue is empty (test implementation doesn't block)")

        # timeout is only relevant when blocking, which this simple implementation doesn't do
        _ = timeout  # Acknowledge parameter is received
        return self._items.pop(0)

    def empty(self) -> bool:
        return len(self._items) == 0

    def qsize(self) -> int:
        return len(self._items)

    def close(self) -> None:
        self._closed = True


class FakeMessageBus(MessageBusInterface[Message]):
    """Simple message bus implementation for testing."""

    def __init__(self) -> None:
        self._queues: dict[str, MessageQueueInterface[Message]] = {}
        self._topics: dict[str, list[MessageQueueInterface[Message]]] = {}

    def get_queue(self, name: str) -> MessageQueueInterface[Message]:
        if name not in self._queues:
            self._queues[name] = FakeMessageQueue()
        return self._queues[name]

    def publish(self, topic: str, message: Message) -> None:
        if topic in self._topics:
            for queue in self._topics[topic]:
                queue.put(message)

    def subscribe(self, topic: str) -> MessageQueueInterface[Message]:
        if topic not in self._topics:
            self._topics[topic] = []
        queue = FakeMessageQueue()
        self._topics[topic].append(queue)
        return queue

    def shutdown(self) -> None:
        for queue in self._queues.values():
            queue.close()


class FakeMessageDelivery(MessageDeliveryInterface[Message]):
    """Simple delivery implementation for testing."""

    def __init__(self) -> None:
        self._acknowledged: set[str] = set()

    def send(
        self,
        queue: MessageQueueInterface[Message],
        message: Message,
        timeout: float | None = None,
    ) -> bool:
        try:
            queue.put(message, block=True, timeout=timeout)
            return True
        except Exception:
            return False

    def receive(
        self, queue: MessageQueueInterface[Message], timeout: float | None = None
    ) -> Message | None:
        try:
            return queue.get(block=True, timeout=timeout)
        except QueueEmptyError:
            return None

    def acknowledge(self, message: Message) -> None:
        self._acknowledged.add(message.id)


class FakeSerializer(SerializerInterface[Message]):
    """Simple JSON-based serializer for testing."""

    def serialize(self, obj: Message) -> bytes:
        import json

        try:
            data = obj.to_dict()
            return json.dumps(data).encode("utf-8")
        except Exception as err:
            raise SerializationError(f"Failed to serialize: {err}") from err

    def deserialize(self, data: bytes) -> Message:
        import json

        try:
            obj = json.loads(data.decode("utf-8"))
            return Message.from_dict(obj)
        except Exception as err:
            raise SerializationError(f"Failed to deserialize: {err}") from err


# Tests for MessageQueueInterface


class TestMessageQueueInterface:
    """Test MessageQueueInterface through concrete implementation."""

    @pytest.fixture
    def queue(self) -> FakeMessageQueue:
        """Provide a test queue instance."""
        return FakeMessageQueue()

    @pytest.fixture
    def sample_message(self) -> Message:
        """Provide a sample message for testing."""
        return Message(
            type=MessageType.WEBHOOK, payload={"test": "data"}, source="test"
        )

    def test_put_and_get(self, queue: FakeMessageQueue, sample_message: Message) -> None:
        """Test basic put and get operations."""
        queue.put(sample_message)
        retrieved = queue.get()

        assert retrieved.id == sample_message.id
        assert retrieved.payload == sample_message.payload

    def test_fifo_order(self, queue: FakeMessageQueue) -> None:
        """Test messages are retrieved in FIFO order."""
        messages = [
            Message(type=MessageType.WEBHOOK, payload={"n": i}) for i in range(5)
        ]

        for msg in messages:
            queue.put(msg)

        for i in range(len(messages)):
            retrieved = queue.get()
            assert retrieved.payload["n"] == i

    def test_empty_queue_raises_error(self, queue: FakeMessageQueue) -> None:
        """Test getting from empty queue raises QueueEmptyError."""
        with pytest.raises(QueueEmptyError):
            queue.get()

    def test_full_queue_raises_error(self) -> None:
        """Test putting to full queue raises QueueFullError."""
        queue = FakeMessageQueue(maxsize=2)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        queue.put(msg)
        queue.put(msg)

        with pytest.raises(QueueFullError):
            queue.put(msg)

    def test_empty_method(self, queue: FakeMessageQueue, sample_message: Message) -> None:
        """Test empty() method returns correct status."""
        assert queue.empty() is True

        queue.put(sample_message)
        assert queue.empty() is False

        queue.get()
        assert queue.empty() is True

    def test_qsize_method(self, queue: FakeMessageQueue) -> None:
        """Test qsize() returns correct count."""
        assert queue.qsize() == 0

        for i in range(5):
            msg = Message(type=MessageType.WEBHOOK, payload={"n": i})
            queue.put(msg)
            assert queue.qsize() == i + 1

        for i in range(5):
            queue.get()
            assert queue.qsize() == 4 - i

    def test_close_method(self, queue: FakeMessageQueue, sample_message: Message) -> None:
        """Test close() method prevents further operations."""
        queue.close()

        with pytest.raises(QueueError):
            queue.put(sample_message)

        with pytest.raises(QueueError):
            queue.get()

    def test_multiple_messages_same_type(self, queue: FakeMessageQueue) -> None:
        """Test queue handles multiple messages of same type."""
        messages = [
            Message(type=MessageType.NEW_JOB, payload={"job_id": f"job_{i}"})
            for i in range(10)
        ]

        for msg in messages:
            queue.put(msg)

        assert queue.qsize() == 10

        for i in range(10):
            retrieved = queue.get()
            assert retrieved.payload["job_id"] == f"job_{i}"

    def test_queue_non_blocking_get(self, queue: FakeMessageQueue) -> None:
        """Test non-blocking get raises immediately when queue is empty."""
        with pytest.raises(QueueEmptyError):
            queue.get(block=False)

    def test_queue_non_blocking_put(self) -> None:
        """Test non-blocking put raises immediately when queue is full."""
        queue = FakeMessageQueue(maxsize=1)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        queue.put(msg)  # Fill the queue

        with pytest.raises(QueueFullError):
            queue.put(msg, block=False)

    def test_queue_blocking_behavior(self, queue: FakeMessageQueue, sample_message: Message) -> None:
        """Test that blocking is the default behavior."""
        # Default should be blocking (but our test implementation doesn't actually block)
        queue.put(sample_message)  # Should not raise
        retrieved = queue.get()  # Should not raise
        assert retrieved.id == sample_message.id


# Tests for MessageBusInterface


class TestMessageBusInterface:
    """Test MessageBusInterface through concrete implementation."""

    @pytest.fixture
    def bus(self) -> FakeMessageBus:
        """Provide a test message bus instance."""
        return FakeMessageBus()

    @pytest.fixture
    def sample_message(self) -> Message:
        """Provide a sample message for testing."""
        return Message(type=MessageType.WEBHOOK, payload={"test": "data"})

    def test_get_queue_creates_queue(self, bus: FakeMessageBus) -> None:
        """Test get_queue creates a new queue if it doesn't exist."""
        queue = bus.get_queue("test_queue")
        assert queue is not None
        assert isinstance(queue, MessageQueueInterface)

    def test_get_queue_returns_same_instance(self, bus: FakeMessageBus) -> None:
        """Test get_queue returns the same queue instance for the same name."""
        queue1 = bus.get_queue("test_queue")
        queue2 = bus.get_queue("test_queue")
        assert queue1 is queue2

    def test_get_queue_different_names(self, bus: FakeMessageBus) -> None:
        """Test get_queue creates different queues for different names."""
        queue1 = bus.get_queue("queue_1")
        queue2 = bus.get_queue("queue_2")
        assert queue1 is not queue2

    def test_publish_to_single_subscriber(
        self, bus: FakeMessageBus, sample_message: Message
    ) -> None:
        """Test publishing message to a topic with one subscriber."""
        subscriber = bus.subscribe("test_topic")

        bus.publish("test_topic", sample_message)

        received = subscriber.get()
        assert received.id == sample_message.id

    def test_publish_to_multiple_subscribers(
        self, bus: FakeMessageBus, sample_message: Message
    ) -> None:
        """Test publishing message to a topic with multiple subscribers."""
        sub1 = bus.subscribe("test_topic")
        sub2 = bus.subscribe("test_topic")
        sub3 = bus.subscribe("test_topic")

        bus.publish("test_topic", sample_message)

        # All subscribers should receive the message
        msg1 = sub1.get()
        msg2 = sub2.get()
        msg3 = sub3.get()

        assert msg1.id == sample_message.id
        assert msg2.id == sample_message.id
        assert msg3.id == sample_message.id

    def test_publish_to_nonexistent_topic(
        self, bus: FakeMessageBus, sample_message: Message
    ) -> None:
        """Test publishing to a topic with no subscribers does not raise error."""
        # Should not raise an exception
        bus.publish("nonexistent_topic", sample_message)

    def test_multiple_topics(self, bus: FakeMessageBus) -> None:
        """Test messages are isolated by topic."""
        sub1 = bus.subscribe("topic_1")
        sub2 = bus.subscribe("topic_2")

        msg1 = Message(type=MessageType.WEBHOOK, payload={"topic": 1})
        msg2 = Message(type=MessageType.NEW_JOB, payload={"topic": 2})

        bus.publish("topic_1", msg1)
        bus.publish("topic_2", msg2)

        received1 = sub1.get()
        received2 = sub2.get()

        assert received1.payload["topic"] == 1
        assert received2.payload["topic"] == 2

    def test_shutdown_closes_all_queues(self, bus: FakeMessageBus) -> None:
        """Test shutdown closes all queues."""
        queue1 = bus.get_queue("queue_1")
        queue2 = bus.get_queue("queue_2")

        bus.shutdown()

        msg = Message(type=MessageType.WEBHOOK, payload={})

        with pytest.raises(QueueError):
            queue1.put(msg)

        with pytest.raises(QueueError):
            queue2.put(msg)


# Tests for MessageDeliveryInterface


class TestMessageDeliveryInterface:
    """Test MessageDeliveryInterface through concrete implementation."""

    @pytest.fixture
    def delivery(self) -> FakeMessageDelivery:
        """Provide a test delivery instance."""
        return FakeMessageDelivery()

    @pytest.fixture
    def queue(self) -> FakeMessageQueue:
        """Provide a test queue instance."""
        return FakeMessageQueue()

    @pytest.fixture
    def sample_message(self) -> Message:
        """Provide a sample message for testing."""
        return Message(type=MessageType.WEBHOOK, payload={"test": "data"})

    def test_send_success(
        self,
        delivery: FakeMessageDelivery,
        queue: FakeMessageQueue,
        sample_message: Message,
    ) -> None:
        """Test successful message send."""
        result = delivery.send(queue, sample_message)

        assert result is True
        assert queue.qsize() == 1

    def test_send_failure(
        self, delivery: FakeMessageDelivery, sample_message: Message
    ) -> None:
        """Test send returns False on failure."""
        full_queue = FakeMessageQueue(maxsize=1)  # Will be full after first send
        full_queue.put(sample_message)

        result = delivery.send(full_queue, sample_message)

        assert result is False

    def test_receive_success(
        self,
        delivery: FakeMessageDelivery,
        queue: FakeMessageQueue,
        sample_message: Message,
    ) -> None:
        """Test successful message receive."""
        queue.put(sample_message)

        received = delivery.receive(queue)

        assert received is not None
        assert received.id == sample_message.id

    def test_receive_from_empty_queue(
        self, delivery: FakeMessageDelivery, queue: FakeMessageQueue
    ) -> None:
        """Test receive returns None from empty queue."""
        received = delivery.receive(queue)
        assert received is None

    def test_acknowledge_message(
        self, delivery: FakeMessageDelivery, sample_message: Message
    ) -> None:
        """Test message acknowledgment."""
        delivery.acknowledge(sample_message)

        # Verify message was acknowledged (implementation-specific)
        assert sample_message.id in delivery._acknowledged

    def test_send_receive_workflow(
        self, delivery: FakeMessageDelivery, queue: FakeMessageQueue
    ) -> None:
        """Test complete send-receive-acknowledge workflow."""
        msg = Message(type=MessageType.NEW_JOB, payload={"job_id": "123"})

        # Send
        send_result = delivery.send(queue, msg)
        assert send_result is True

        # Receive
        received = delivery.receive(queue)
        assert received is not None
        assert received.id == msg.id

        # Acknowledge
        delivery.acknowledge(received)
        assert received.id in delivery._acknowledged


# Tests for SerializerInterface


class TestSerializerInterface:
    """Test SerializerInterface through concrete implementation."""

    @pytest.fixture
    def serializer(self) -> FakeSerializer:
        """Provide a test serializer instance."""
        return FakeSerializer()

    @pytest.fixture
    def sample_message(self) -> Message:
        """Provide a sample message for testing."""
        return Message(
            type=MessageType.WEBHOOK,
            payload={"key": "value", "number": 42},
            source="test_source",
        )

    def test_serialize_message(
        self, serializer: FakeSerializer, sample_message: Message
    ) -> None:
        """Test message serialization."""
        data = serializer.serialize(sample_message)

        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_deserialize_message(
        self, serializer: FakeSerializer, sample_message: Message
    ) -> None:
        """Test message deserialization."""
        data = serializer.serialize(sample_message)
        deserialized = serializer.deserialize(data)

        assert deserialized.id == sample_message.id
        assert deserialized.type == sample_message.type
        assert deserialized.payload == sample_message.payload
        assert deserialized.source == sample_message.source

    def test_roundtrip_serialization(
        self, serializer: FakeSerializer, sample_message: Message
    ) -> None:
        """Test serialization and deserialization preserve message data."""
        data = serializer.serialize(sample_message)
        restored = serializer.deserialize(data)

        assert restored.id == sample_message.id
        assert restored.payload == sample_message.payload
        assert restored.delivery == sample_message.delivery

    def test_serialize_multiple_message_types(self, serializer: FakeSerializer) -> None:
        """Test serialization works for different message types."""
        messages = [
            Message(type=MessageType.WEBHOOK, payload={}),
            Message(type=MessageType.NEW_JOB, payload={"job_id": "123"}),
            Message(type=MessageType.CHECK_STATUS, payload={}),
            Message(type=MessageType.TASK_COMPLETE, payload={"result": "success"}),
        ]

        for msg in messages:
            data = serializer.serialize(msg)
            restored = serializer.deserialize(data)
            assert restored.type == msg.type
            assert restored.payload == msg.payload

    def test_serialize_complex_payload(self, serializer: FakeSerializer) -> None:
        """Test serialization with complex nested payload."""
        msg = Message(
            type=MessageType.NEW_JOB,
            payload={
                "job_id": "job_123",
                "metadata": {"user": "test", "priority": 5},
                "tags": ["urgent", "build"],
            },
        )

        data = serializer.serialize(msg)
        restored = serializer.deserialize(data)

        assert restored.payload == msg.payload
        assert restored.payload["metadata"]["user"] == "test"
        assert "urgent" in restored.payload["tags"]

    def test_deserialize_invalid_data_raises_error(
        self, serializer: FakeSerializer
    ) -> None:
        """Test deserializing invalid data raises SerializationError."""
        invalid_data = b"invalid json data {{"

        with pytest.raises(SerializationError):
            serializer.deserialize(invalid_data)


# Tests for custom exceptions


class TestAbstractInterfaceEnforcement:
    """Test that abstract interfaces cannot be instantiated and enforce implementation."""

    def test_cannot_instantiate_message_queue_interface(self) -> None:
        """Test that MessageQueueInterface cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            MessageQueueInterface()  # type: ignore

    def test_cannot_instantiate_message_bus_interface(self) -> None:
        """Test that MessageBusInterface cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            MessageBusInterface()  # type: ignore

    def test_cannot_instantiate_message_delivery_interface(self) -> None:
        """Test that MessageDeliveryInterface cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            MessageDeliveryInterface()  # type: ignore

    def test_cannot_instantiate_serializer_interface(self) -> None:
        """Test that SerializerInterface cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            SerializerInterface()  # type: ignore

    def test_incomplete_queue_implementation_fails(self) -> None:
        """Test that incomplete MessageQueueInterface implementation cannot be instantiated."""

        class IncompleteQueue(MessageQueueInterface[Message]):
            """Incomplete implementation missing several methods."""

            def put(self, message: Message, block: bool = True, timeout: float | None = None) -> None:
                _ = message
                _ = block
                _ = timeout
                pass

            # Missing: get, empty, qsize, close

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            IncompleteQueue()  # type: ignore

    def test_incomplete_bus_implementation_fails(self) -> None:
        """Test that incomplete MessageBusInterface implementation cannot be instantiated."""

        class IncompleteBus(MessageBusInterface[Message]):
            """Incomplete implementation missing several methods."""

            def get_queue(self, name: str) -> MessageQueueInterface[Message]:
                _ = name
                return FakeMessageQueue()

            # Missing: publish, subscribe, shutdown

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            IncompleteBus()  # type: ignore

    def test_incomplete_delivery_implementation_fails(self) -> None:
        """Test that incomplete MessageDeliveryInterface implementation cannot be instantiated."""

        class IncompleteDelivery(MessageDeliveryInterface[Message]):
            """Incomplete implementation missing several methods."""

            def send(
                self,
                queue: MessageQueueInterface[Message],
                message: Message,
                timeout: float | None = None,
            ) -> bool:
                _ = queue
                _ = message
                _ = timeout
                return True

            # Missing: receive, acknowledge

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            IncompleteDelivery()  # type: ignore[abstract]

    def test_incomplete_serializer_implementation_fails(self) -> None:
        """Test that incomplete SerializerInterface implementation cannot be instantiated."""

        class IncompleteSerializer(SerializerInterface[Message]):
            """Incomplete implementation missing deserialize."""

            def serialize(self, obj: Message) -> bytes:
                _ = obj
                return b""

            # Missing: deserialize

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            IncompleteSerializer()  # type: ignore

    def test_complete_queue_implementation_succeeds(self) -> None:
        """Test that complete MessageQueueInterface implementation can be instantiated."""

        class CompleteQueue(MessageQueueInterface[Message]):
            """Complete implementation with all required methods."""

            def put(self, message: Message, block: bool = True, timeout: float | None = None) -> None:
                _ = message
                _ = block
                _ = timeout
                pass

            def get(self, block: bool = True, timeout: float | None = None) -> Message:
                _ = block
                _ = timeout
                raise QueueEmptyError("Empty")

            def empty(self) -> bool:
                return True

            def qsize(self) -> int:
                return 0

            def close(self) -> None:
                pass

        # Should not raise
        queue = CompleteQueue()
        assert isinstance(queue, MessageQueueInterface)


class TestCustomExceptions:
    """Test custom exception classes."""

    def test_queue_error_inheritance(self) -> None:
        """Test QueueError inherits from Exception."""
        error = QueueError("test error")
        assert isinstance(error, Exception)
        assert str(error) == "test error"

    def test_queue_full_error_inheritance(self) -> None:
        """Test QueueFullError inherits from QueueError."""
        error = QueueFullError("queue is full")
        assert isinstance(error, QueueError)
        assert isinstance(error, Exception)

    def test_queue_empty_error_inheritance(self) -> None:
        """Test QueueEmptyError inherits from QueueError."""
        error = QueueEmptyError("queue is empty")
        assert isinstance(error, QueueError)
        assert isinstance(error, Exception)

    def test_serialization_error_inheritance(self) -> None:
        """Test SerializationError inherits from Exception."""
        error = SerializationError("serialization failed")
        assert isinstance(error, Exception)
        assert str(error) == "serialization failed"

    def test_exception_with_cause(self) -> None:
        """Test exceptions can wrap underlying causes."""
        try:
            raise ValueError("underlying error")
        except ValueError as err:
            try:
                raise SerializationError("wrapping error") from err
            except SerializationError as error:
                assert error.__cause__ is err


# Edge cases and stress tests


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_queue_with_zero_maxsize(self) -> None:
        """Test queue with maxsize=0 (unlimited)."""
        queue = FakeMessageQueue(maxsize=0)

        # Should be able to add many messages
        for i in range(1000):
            msg = Message(type=MessageType.WEBHOOK, payload={"n": i})
            queue.put(msg)

        assert queue.qsize() == 1000

    def test_message_with_empty_payload(self) -> None:
        """Test handling message with empty payload."""
        queue = FakeMessageQueue()
        msg = Message(type=MessageType.WEBHOOK, payload={})

        queue.put(msg)
        retrieved = queue.get()

        assert retrieved.payload == {}

    def test_message_with_none_values(self) -> None:
        """Test handling message with None values in payload."""
        queue = FakeMessageQueue()
        msg = Message(
            type=MessageType.NEW_JOB,
            payload={"job_id": None, "optional": None},
        )

        queue.put(msg)
        retrieved = queue.get()

        assert retrieved.payload["job_id"] is None

    def test_serializer_with_special_characters(self) -> None:
        """Test serialization with special characters."""
        serializer = FakeSerializer()
        msg = Message(
            type=MessageType.WEBHOOK,
            payload={"text": "Special chars: 你好 мир 🚀 \n\t"},
        )

        data = serializer.serialize(msg)
        restored = serializer.deserialize(data)

        assert restored.payload["text"] == msg.payload["text"]
