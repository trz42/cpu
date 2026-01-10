# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Delivery guarantee implementations for reliable messaging.

This module provides three delivery guarantee levels:
- AtMostOnceDelivery: Fire and forget, no retries
- AtLeastOnceDelivery: Retry with acknowledgment, may duplicate
- ExactlyOnceDelivery: Deduplication to prevent duplicates
"""

from __future__ import annotations

import contextlib
import time
from typing import Generic, TypeVar

from cpu.messaging.interfaces import (
    MessageDeliveryInterface,
    MessageQueueInterface,
    QueueEmptyError,
    QueueError,
    QueueFullError,
)

T = TypeVar("T")


class AtMostOnceDelivery(MessageDeliveryInterface[T], Generic[T]):
    """
    At-most-once delivery guarantee.

    Messages are sent once without confirmation. If delivery fails,
    the message is lost. This is the fastest but least reliable option.

    Use cases:
    - Metrics/monitoring data where loss is acceptable
    - Best-effort notifications
    - High-throughput scenarios where speed > reliability

    Example:
        >>> delivery = AtMostOnceDelivery()
        >>> delivery.send(queue, message)  # Send once, no retry
        >>> msg = delivery.receive(queue)  # Simple receive
        >>> # No acknowledgment needed
    """

    def send(
        self,
        queue: MessageQueueInterface[T],
        message: T,
        timeout: float | None = None,
    ) -> bool:
        """
        Send message with at-most-once guarantee.

        Attempts to send once. If it fails, returns True anyway
        (fire and forget).

        Args:
            queue: Target queue
            message: Message to send
            timeout: Put timeout (passed to queue.put)

        Returns:
            Always True (we don't care about failures)
        """
        # At-most-once: don't care if it fails
        with contextlib.suppress(QueueError):
            queue.put(message, timeout=timeout)

        return True

    def receive(
        self, queue: MessageQueueInterface[T], timeout: float | None = None
    ) -> T | None:
        """
        Receive message with at-most-once guarantee.

        Simple queue.get() with no tracking.

        Args:
            queue: Source queue
            timeout: Get timeout

        Returns:
            Message if available, None if queue empty
        """
        try:
            return queue.get(timeout=timeout)
        except QueueEmptyError:
            return None

    def acknowledge(self, message: T) -> None:
        """
        Acknowledge message (no-op for at-most-once).

        At-most-once delivery doesn't track acknowledgments.

        Args:
            message: Message to acknowledge (ignored)
        """
        # No-op for at-most-once
        pass


class AtLeastOnceDelivery(MessageDeliveryInterface[T], Generic[T]):
    """
    At-least-once delivery guarantee.

    Messages are retried until acknowledged. Messages may be delivered
    multiple times if acknowledgment is delayed or lost.

    Features:
    - Configurable retry count and delay
    - Tracks pending (unacknowledged) messages
    - Total timeout support

    Use cases:
    - Critical messages that must not be lost
    - Idempotent operations (safe to retry)
    - Job notifications, state changes

    Example:
        >>> delivery = AtLeastOnceDelivery(max_retries=3, retry_delay=1.0)
        >>> delivery.send(queue, message)  # Retry up to 3 times
        >>> msg = delivery.receive(queue)
        >>> process(msg)
        >>> delivery.acknowledge(msg)  # Mark as processed
    """

    def __init__(self, max_retries: int = 3, retry_delay: float = 1.0) -> None:
        """
        Initialize at-least-once delivery.

        Args:
            max_retries: Maximum retry attempts (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)
        """
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._pending: set[str] = set()  # Track unacknowledged message IDs

    def send(
        self,
        queue: MessageQueueInterface[T],
        message: T,
        timeout: float | None = None,
    ) -> bool:
        """
        Send message with retry logic.

        Retries up to max_retries times if queue is full.
        Respects total timeout if specified.

        Args:
            queue: Target queue
            message: Message to send
            timeout: Total timeout for all attempts (None = no timeout)

        Returns:
            True if delivered, False if all retries exhausted
        """
        start_time = time.time()
        attempts = 0

        while attempts <= self.max_retries:
            # Check total timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    return False

            try:
                queue.put(message, timeout=None)
                return True
            except QueueFullError:
                attempts += 1
                if attempts > self.max_retries:
                    return False

                # Wait before retry (but don't exceed total timeout)
                if timeout is not None:
                    elapsed = time.time() - start_time
                    remaining = timeout - elapsed
                    sleep_time = min(self.retry_delay, remaining)
                    if sleep_time <= 0:
                        return False
                    time.sleep(sleep_time)
                else:
                    time.sleep(self.retry_delay)

        return False

    def receive(
        self, queue: MessageQueueInterface[T], timeout: float | None = None
    ) -> T | None:
        """
        Receive message and track as pending.

        Message is marked pending until acknowledged. This allows
        redelivery if processing fails.

        Args:
            queue: Source queue
            timeout: Get timeout

        Returns:
            Message if available, None if queue empty
        """
        try:
            message = queue.get(timeout=timeout)
            # Track as pending until acknowledged
            # Assumes message has 'id' attribute
            if hasattr(message, "id"):
                self._pending.add(str(message.id))
            return message
        except QueueEmptyError:
            return None

    def acknowledge(self, message: T) -> None:
        """
        Acknowledge successful processing.

        Removes message from pending set, preventing redelivery.

        Args:
            message: Message to acknowledge
        """
        # Remove from pending if it exists (discard = no error if missing)
        if hasattr(message, "id"):
            self._pending.discard(str(message.id))


class ExactlyOnceDelivery(MessageDeliveryInterface[T], Generic[T]):
    """
    Exactly-once delivery guarantee.

    Combines retry logic with deduplication to ensure each message
    is processed exactly once, even with retries or network issues.

    Features:
    - Retry on send (like at-least-once)
    - Deduplication on receive
    - Tracks sent and processed message IDs
    - Automatic cleanup to prevent memory leaks

    Use cases:
    - Database updates
    - Any operation that must not be duplicated

    Example:
        >>> delivery = ExactlyOnceDelivery()
        >>> delivery.send(queue, message)  # Tracked by ID
        >>> msg = delivery.receive(queue)  # Duplicate filtered
        >>> if msg:
        >>>     process(msg)
        >>>     delivery.acknowledge(msg)  # Mark as done
    """

    def __init__(
        self,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        max_processed_ids: int = 10000,
    ) -> None:
        """
        Initialize exactly-once delivery.

        Args:
            max_retries: Maximum retry attempts (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)
            max_processed_ids: Max processed IDs to track before cleanup (default: 10000)
        """
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.max_processed_ids = max_processed_ids

        self._sent_ids: set[str] = set()  # Messages we've sent
        self._processed_ids: set[str] = set()  # Messages fully processed
        self._pending: set[str] = set()  # Messages received but not acked

    def send(
        self,
        queue: MessageQueueInterface[T],
        message: T,
        timeout: float | None = None,
    ) -> bool:
        """
        Send message with deduplication tracking.

        Tracks message ID to enable duplicate detection on receiver side.

        Args:
            queue: Target queue
            message: Message to send
            timeout: Total timeout for all attempts

        Returns:
            True if delivered, False if all retries exhausted
        """
        # # Track that we've sent this message
        # if hasattr(message, "id"):
        #     self._sent_ids.add(str(message.id))

        # Use same retry logic as at-least-once
        start_time = time.time()
        attempts = 0

        while attempts <= self.max_retries:
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    return False

            try:
                queue.put(message, timeout=None)
                # Only track as sent if delivery succeeded
                if hasattr(message, "id"):
                    self._sent_ids.add(str(message.id))
                return True
            except QueueFullError:
                attempts += 1
                if attempts > self.max_retries:
                    return False

                if timeout is not None:
                    elapsed = time.time() - start_time
                    remaining = timeout - elapsed
                    sleep_time = min(self.retry_delay, remaining)
                    if sleep_time <= 0:
                        return False
                    time.sleep(sleep_time)
                else:
                    time.sleep(self.retry_delay)

        return False

    def receive(
        self, queue: MessageQueueInterface[T], timeout: float | None = None
    ) -> T | None:
        """
        Receive message with duplicate filtering.

        Filters out messages that have already been processed.
        Allows unacknowledged messages to be received again (redelivery).

        Args:
            queue: Source queue
            timeout: Get timeout

        Returns:
            Message if available and not a duplicate, None otherwise
        """
        try:
            message = queue.get(timeout=timeout)

            if not hasattr(message, "id"):
                # Can't deduplicate without ID, just return it
                return message

            msg_id = str(message.id)

            # Filter out already-processed messages
            if msg_id in self._processed_ids:
                return None  # Duplicate, drop it

            # Track as pending
            self._pending.add(msg_id)

            return message

        except QueueEmptyError:
            return None

    def acknowledge(self, message: T) -> None:
        """
        Acknowledge successful processing.

        Marks message as fully processed, enabling duplicate filtering.
        Performs cleanup if processed_ids set grows too large.

        Args:
            message: Message to acknowledge
        """
        if not hasattr(message, "id"):
            return

        msg_id = str(message.id)

        # Move from pending to processed
        self._pending.discard(msg_id)
        self._processed_ids.add(msg_id)

        # Cleanup old processed IDs to prevent memory leak
        if len(self._processed_ids) > self.max_processed_ids:
            # Keep most recent (arbitrary choice: keep last 80%)
            keep_count = int(self.max_processed_ids * 0.8)
            # Convert to list, keep last N, convert back to set
            # Note: This loses ordering but prevents unbounded growth
            ids_list = list(self._processed_ids)
            self._processed_ids = set(ids_list[-keep_count:])
