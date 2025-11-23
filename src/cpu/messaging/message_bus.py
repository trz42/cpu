# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Thread-based message bus implementation.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Generic, TypeVar

from cpu.messaging.base import MessageBusInterface, MessageQueueInterface, QueueError
from cpu.messaging.queue_thread import ThreadMessageQueue

T = TypeVar("T")


class ThreadMessageBus(MessageBusInterface[T], Generic[T]):
    """
    Thread-based message bus managing multiple queues and pub/sub topics.

    Provides:
    - Named queues: Get queues by name for point-to-point messaging
    - Topics/pub-sub: Publish messages to multiple subscribers

    Type Parameters:
        T: Type of items stored in queues

    Example:
        >>> bus = ThreadMessageBus()
        >>> # Point-to-point messaging
        >>> events_queue = bus.get_queue('webhook_events')
        >>> events_queue.put(message)
        >>> # Pub/sub messaging
        >>> subscriber1 = bus.subscribe('status_updates')
        >>> subscriber2 = bus.subscribe('status_updates')
        >>> bus.publish('status_updates', message)
        >>> # Both subscribers receive the message
    """

    def __init__(self) -> None:
        """Initialize the message bus."""
        self._queues: dict[str, MessageQueueInterface[T]] = {}
        self._topics: dict[str, list[MessageQueueInterface[T]]] = {}
        self._lock = threading.RLock()  # Reentrant lock for nested operations

    def get_queue(self, name: str) -> MessageQueueInterface[T]:
        """
        Get or create a named queue.

        If a queue with this name already exists, return it.
        If not, create a new queue and return it.

        Args:
            name: Queue name (e.g., 'webhook_events', 'job_notifications')

        Returns:
            Message queue instance

        Example:
            >>> bus = ThreadMessageBus()
            >>> queue1 = bus.get_queue('events')
            >>> queue2 = bus.get_queue('events')
            >>> assert queue1 is queue2  # Same instance
        """
        with self._lock:
            if name not in self._queues:
                self._queues[name] = ThreadMessageQueue[T]()
            return self._queues[name]

    def publish(self, topic: str, message: T) -> None:
        """
        Publish a message to a topic (pub/sub pattern).

        All current subscribers to this topic will receive a copy of the message.
        If there are no subscribers, the message is dropped.

        Thread-safe: Handles concurrent subscribe/unsubscribe operations safely
        by creating a snapshot of subscribers under lock.

        Args:
            topic: Topic name (e.g., 'job_status', 'health_check')
            message: Message to publish

        Example:
            >>> bus = ThreadMessageBus()
            >>> sub1 = bus.subscribe('status')
            >>> sub2 = bus.subscribe('status')
            >>> bus.publish('status', message)
            >>> # Both sub1 and sub2 receive the message
        """
        # Create snapshot of subscribers under lock to avoid race conditions
        with self._lock:
            if topic not in self._topics:
                return  # No subscribers, drop message
            subscribers = list(self._topics[topic])  # Create copy

        # Publish to subscribers outside lock to avoid deadlock
        # and improve concurrency (put() operations are independent)
        for subscriber_queue in subscribers:
            # Queue might be closed, skip it
            # Alternative: could remove closed queues from topic
            with contextlib.suppress(QueueError):
                subscriber_queue.put(message)

    def subscribe(self, topic: str) -> MessageQueueInterface[T]:
        """
        Subscribe to a topic.

        Creates a new queue that will receive all messages published to this topic
        from this point forward.

        Args:
            topic: Topic name to subscribe to

        Returns:
            Queue that will receive messages published to this topic

        Example:
            >>> bus = ThreadMessageBus()
            >>> subscriber = bus.subscribe('notifications')
            >>> bus.publish('notifications', message)
            >>> received = subscriber.get()
        """
        with self._lock:
            subscriber_queue = ThreadMessageQueue[T]()

            if topic not in self._topics:
                self._topics[topic] = []

            self._topics[topic].append(subscriber_queue)

            return subscriber_queue

    def shutdown(self) -> None:
        """
        Shutdown the message bus and all managed queues.

        This closes all named queues and all subscriber queues.

        Example:
            >>> bus = ThreadMessageBus()
            >>> queue = bus.get_queue('test')
            >>> sub = bus.subscribe('topic')
            >>> bus.shutdown()
            >>> # All queues are now closed
        """
        with self._lock:
            # Close all named queues
            for queue in self._queues.values():
                queue.close()

            # Close all subscriber queues
            for subscribers in self._topics.values():
                for queue in subscribers:
                    queue.close()

            # Clear references
            self._queues.clear()
            self._topics.clear()

    def __repr__(self) -> str:
        """Return string representation of the message bus."""
        with self._lock:
            # All reads happen atomically
            num_queues = len(self._queues)
            num_topics = len(self._topics)
            num_subscribers = sum(len(subs) for subs in self._topics.values())
        return (
            f"ThreadMessageBus(queues={num_queues}, "
            f"topics={num_topics}, subscribers={num_subscribers})"
        )
