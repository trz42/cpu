# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Abstract base classes for messaging infrastructure.

This module defines the interfaces for message queues and messaging systems,
allowing different implementations (thread-based, process-based, distributed)
to be swapped without changing component code.

The key abstractions are:
- MessageQueueInterface: Interface for any queue implementation
- MessageBusInterface: Interface for managing multiple queues and pub/sub
- MessageDeliveryInterface: Interface for delivery guarantees
- SerializerInterface: Interface for message serialization

These abstractions enable:
1. Easy testing through mock implementations
2. Migration from threads to processes without code changes
3. Support for different queue backends (Redis, RabbitMQ, etc.)
4. Flexibility in delivery semantics
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

# Type variable for queue contents
T = TypeVar("T")


class MessageQueueInterface(ABC, Generic[T]):
    """
    Abstract interface for message queues.

    This interface abstracts the underlying queue implementation, allowing
    different backends to be used interchangeably:
    - Thread-based: queue.Queue
    - Process-based: multiprocessing.Queue
    - Distributed: Redis queues, RabbitMQ, Kafka, etc.

    Implementations must be thread-safe or process-safe as appropriate.

    Type Parameters:
        T: Type of items stored in the queue
    """

    @abstractmethod
    def put(
        self,
        message: T,
        block: bool = True,
        timeout: float | None = None
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
            QueueError: If queue is closed or in an invalid state

        Note:
            If block=True and timeout=None, this will wait indefinitely for space.
            If block=False, timeout is ignored.
        """
        pass

    @abstractmethod
    def get(
        self,
        block: bool = True,
        timeout: float | None = None
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
            QueueError: If queue is closed or in an invalid state

        Note:
            If block=True and timeout=None, this will wait indefinitely for a message.
            If block=False, timeout is ignored.
        """
        pass

    @abstractmethod
    def empty(self) -> bool:
        """
        Check if queue is empty.

        Returns:
            True if queue is empty, False otherwise

        Warning:
            This method is NOT reliable in multi-threaded or multi-process
            environments. By the time you check the result, another thread/process
            may have modified the queue. Use only for heuristics and debugging,
            never for critical logic.

            Instead of:
                if not queue.empty():
                    item = queue.get()  # May still raise QueueEmptyError!

            Use:
                try:
                    item = queue.get(block=False)
                except QueueEmptyError:
                    # Handle empty queue
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def close(self) -> None:
        """
        Close the queue and release resources.

        After calling close(), no further put() or get() operations should
        be attempted. Implementations should raise QueueError if operations
        are attempted on a closed queue.

        This is particularly important for:
        - Cleaning up file descriptors
        - Releasing memory
        - Closing network connections (for distributed queues)

        Note:
            Implementations should be idempotent - calling close() multiple
            times should be safe.
        """
        pass


class MessageBusInterface(ABC, Generic[T]):
    """
    Abstract interface for message bus (manages multiple queues).

    The message bus provides a higher-level abstraction over individual queues:
    - Named queues: Get queues by name for point-to-point messaging
    - Topics/pub-sub: Publish messages to multiple subscribers

    This pattern is useful for:
    - Organizing queues by purpose (e.g., 'webhook_events', 'job_notifications')
    - Broadcasting messages to multiple consumers
    - Decoupling producers from consumers

    Example:
        bus = ThreadMessageBus()

        # Point-to-point messaging
        events_queue = bus.get_queue('webhook_events')
        events_queue.put(message)

        # Pub/sub messaging
        subscriber1 = bus.subscribe('status_updates')
        subscriber2 = bus.subscribe('status_updates')
        bus.publish('status_updates', message)
        # Both subscribers receive the message
    """

    @abstractmethod
    def get_queue(self, name: str) -> MessageQueueInterface[T]:
        """
        Get or create a named queue.

        If a queue with this name already exists, return it.
        If not, create a new queue and return it.

        Args:
            name: Queue name (e.g., 'webhook_events', 'job_notifications')
                  Names should be descriptive and unique per purpose

        Returns:
            Message queue instance

        Note:
            The same queue instance is returned for the same name.
            This enables multiple components to safely share a queue
            by referencing it by name.
        """
        pass

    @abstractmethod
    def publish(self, topic: str, message: T) -> None:
        """
        Publish a message to a topic (pub/sub pattern).

        All current subscribers to this topic will receive a copy of the message.
        If there are no subscribers, the message is typically dropped (though
        implementations may choose to queue it or raise an error).

        Args:
            topic: Topic name (e.g., 'job_status', 'health_check')
            message: Message to publish

        Note:
            Each subscriber gets its own copy of the message. Modifications
            by one subscriber do not affect other subscribers.

            Implementations should handle the case where subscribers are
            added/removed while publishing is in progress.
        """
        pass

    @abstractmethod
    def subscribe(self, topic: str) -> MessageQueueInterface[T]:
        """
        Subscribe to a topic.

        Creates a new queue that will receive all messages published to this topic
        from this point forward. Messages published before subscribing are not received.

        Args:
            topic: Topic name to subscribe to

        Returns:
            Queue that will receive messages published to this topic

        Note:
            Each call to subscribe() creates a new queue, even for the same topic.
            This allows multiple independent subscribers to the same topic.

            To unsubscribe, simply stop reading from the queue and let it be
            garbage collected. Implementations may provide explicit unsubscribe
            methods for cleanup.
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """
        Shutdown the message bus and all managed queues.

        This should:
        1. Close all named queues created via get_queue()
        2. Close all subscriber queues created via subscribe()
        3. Prevent any further operations
        4. Release all resources

        After shutdown, attempts to use the bus should raise appropriate errors.

        Note:
            Like close(), this should be idempotent.
        """
        pass


class MessageDeliveryInterface(ABC, Generic[T]):
    """
    Abstract interface for message delivery guarantees.

    Different delivery semantics provide different trade-offs:

    At-most-once (fire and forget):
        + Fastest, no overhead
        + No acknowledgment needed
        - May lose messages
        Use when: Speed matters, occasional loss is acceptable

    At-least-once (retry until acknowledged):
        + Reliable delivery
        + Handles transient failures
        - May deliver duplicates if ack is lost
        - Requires idempotent message handlers
        Use when: Messages are important, handlers are idempotent

    Exactly-once (deduplication + acknowledgment):
        + Most reliable
        + No duplicates
        - Slowest, most complex
        - Requires message ID tracking
        Use when: Duplicates are unacceptable, correctness is critical

    Example:
        delivery = AtLeastOnceDelivery(max_retries=3)

        # Sender
        success = delivery.send(queue, message)
        if not success:
            # All retries failed
            handle_failure(message)

        # Receiver
        message = delivery.receive(queue)
        if message:
            process_message(message)
            delivery.acknowledge(message)  # Mark as processed
    """

    @abstractmethod
    def send(
        self,
        queue: MessageQueueInterface[T],
        message: T,
        timeout: float | None = None,
    ) -> bool:
        """
        Send a message with delivery guarantees.

        The behavior depends on the delivery guarantee implementation:
        - At-most-once: Attempts send once, returns True regardless
        - At-least-once: Retries until acknowledged or max retries
        - Exactly-once: Checks for duplicates, retries with tracking

        Args:
            queue: Target queue
            message: Message to send
            timeout: Total timeout for the send operation (including retries)
                     None means no timeout

        Returns:
            True if message was delivered according to guarantee,
            False if delivery failed (e.g., all retries exhausted)

        Note:
            For at-least-once and exactly-once, "success" means the message
            was placed in the queue, not that it was processed. Actual processing
            confirmation requires receive() + acknowledge().
        """
        pass

    @abstractmethod
    def receive(
        self,
        queue: MessageQueueInterface[T],
        timeout: float | None = None
    ) -> T | None:
        """
        Receive a message with delivery guarantees.

        The behavior depends on the delivery guarantee implementation:
        - At-most-once: Simple get, no tracking
        - At-least-once: Marks as pending until acknowledged
        - Exactly-once: Checks for and filters out duplicates

        Args:
            queue: Source queue
            timeout: Receive timeout in seconds (None = wait forever)

        Returns:
            Message if available and not a duplicate (for exactly-once),
            None if timeout expires or queue is empty (with timeout=0)

        Note:
            For at-least-once and exactly-once, you MUST call acknowledge()
            after successfully processing the message. Failure to acknowledge
            may result in:
            - Message being redelivered (at-least-once)
            - Pending message leaks (memory/resource issues)
        """
        pass

    @abstractmethod
    def acknowledge(self, message: T) -> None:
        """
        Acknowledge successful processing of a message.

        This signals that:
        1. The message was received successfully
        2. The message was processed successfully
        3. The message should not be redelivered

        Args:
            message: Message to acknowledge

        Note:
            For at-most-once delivery, this is typically a no-op.

            For at-least-once and exactly-once, this is critical:
            - Removes message from pending set
            - Prevents redelivery
            - Allows cleanup of tracking structures

            Acknowledgment should be idempotent - acknowledging the same
            message multiple times should be safe.

        Warning:
            Only acknowledge messages after they have been successfully
            processed. Premature acknowledgment can lead to data loss.
        """
        pass


class SerializerInterface(ABC, Generic[T]):
    """
    Abstract interface for message serialization.

    Serialization is needed when:
    - Messages must be sent over the network
    - Messages must be persisted to disk
    - Messages must be sent between processes

    Different serializers offer different trade-offs:

    JSON:
        + Human-readable
        + Language-independent
        + Widely supported
        - Larger size
        - Only JSON-compatible types

    Pickle:
        + Supports any Python object
        + Compact
        - Python-only
        - Security risk (never unpickle untrusted data)
        - Version dependent

    Protocol Buffers / MessagePack:
        + Compact
        + Fast
        + Schema support
        - Requires schema definition
        - Less human-readable

    Type Parameters:
        T: Type of objects to serialize
    """

    @abstractmethod
    def serialize(self, obj: T) -> bytes:
        """
        Serialize an object to bytes.

        The serialized form should be self-contained and include all
        information needed to reconstruct the object during deserialization.

        Args:
            obj: Object to serialize

        Returns:
            Serialized bytes

        Raises:
            SerializationError: If object cannot be serialized
                - Object contains non-serializable types
                - Object is too large
                - Serialization format doesn't support object structure

        Note:
            Implementations should handle edge cases:
            - None values
            - Empty collections
            - Special characters (Unicode, etc.)
            - Circular references (if supported)
        """
        pass

    @abstractmethod
    def deserialize(self, data: bytes) -> T:
        """
        Deserialize bytes to an object.

        This is the inverse of serialize(). The resulting object should be
        equivalent to the original, though not necessarily identical (e.g.,
        object identity may differ).

        Args:
            data: Serialized data

        Returns:
            Deserialized object

        Raises:
            SerializationError: If data cannot be deserialized
                - Data is corrupted
                - Data is in wrong format
                - Data was serialized with incompatible version
                - Data contains malicious content (for pickle, etc.)

        Security:
            Be cautious when deserializing data from untrusted sources:
            - Pickle can execute arbitrary code
            - Large payloads can cause DoS
            - Malformed data can crash the process

            Consider validating deserialized objects before use.
        """
        pass


# Custom exceptions


class QueueError(Exception):
    """
    Base exception for queue operations.

    All queue-related exceptions inherit from this, allowing code to
    catch all queue errors with a single except clause.
    """

    pass


class QueueFullError(QueueError):
    """
    Raised when attempting to put to a full queue with block=False.

    This indicates:
    - Queue has reached its maximum size
    - No timeout was specified or timeout expired
    - Caller should back off or drop the message

    Handling strategies:
    1. Retry after a delay
    2. Drop the message (for at-most-once delivery)
    3. Write to overflow queue
    4. Log and alert (queue may be stuck)
    """

    pass


class QueueEmptyError(QueueError):
    """
    Raised when attempting to get from an empty queue with block=False.

    This indicates:
    - Queue has no messages available
    - No timeout was specified or timeout expired
    - Caller should wait or try another queue

    Handling strategies:
    1. Sleep and retry
    2. Check other queues
    3. Return to caller (normal condition)
    """

    pass


class SerializationError(Exception):
    """
    Raised when serialization or deserialization fails.

    This can occur when:
    - Object contains non-serializable types
    - Serialized data is corrupted
    - Format version mismatch
    - Size limits exceeded

    Contains the underlying error as __cause__ for debugging.
    """

    pass
