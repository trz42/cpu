# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.messaging.delivery module.

Tests the three delivery guarantee levels:
- AtMostOnceDelivery: Fire and forget
- AtLeastOnceDelivery: Retry with acknowledgment
- ExactlyOnceDelivery: Deduplication
"""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

from cpu.messaging.delivery import (
    AtLeastOnceDelivery,
    AtMostOnceDelivery,
    ExactlyOnceDelivery,
)
from cpu.messaging.interfaces import MessageQueueInterface, QueueEmptyError, QueueFullError
from cpu.messaging.message import Message, MessageType


class TestAtMostOnceDelivery:
    """Test AtMostOnceDelivery implementation."""

    def test_send_succeeds_immediately(self) -> None:
        """Test that send succeeds on first attempt."""
        queue = Mock(spec=MessageQueueInterface)
        delivery: AtMostOnceDelivery[Message] = AtMostOnceDelivery()
        msg = Message(type=MessageType.WEBHOOK, payload={})

        result = delivery.send(queue, msg)

        assert result is True
        queue.put.assert_called_once_with(msg, timeout=None)

    def test_send_with_timeout(self) -> None:
        """Test that send respects timeout parameter."""
        queue = Mock(spec=MessageQueueInterface)
        delivery: AtMostOnceDelivery[Message] = AtMostOnceDelivery()
        msg = Message(type=MessageType.WEBHOOK, payload={})

        delivery.send(queue, msg, timeout=5.0)

        queue.put.assert_called_once_with(msg, timeout=5.0)

    def test_send_returns_true_even_on_failure(self) -> None:
        """Test that send returns True even if queue.put fails."""
        queue = Mock(spec=MessageQueueInterface)
        queue.put.side_effect = QueueFullError("Queue full")
        delivery: AtMostOnceDelivery[Message] = AtMostOnceDelivery()
        msg = Message(type=MessageType.WEBHOOK, payload={})

        result = delivery.send(queue, msg)

        # At-most-once doesn't care about failures
        assert result is True

    def test_receive_simple_get(self) -> None:
        """Test that receive just calls queue.get."""
        queue = Mock(spec=MessageQueueInterface)
        msg = Message(type=MessageType.WEBHOOK, payload={})
        queue.get.return_value = msg
        delivery: AtMostOnceDelivery[Message] = AtMostOnceDelivery()

        result = delivery.receive(queue, timeout=1.0)

        assert result == msg
        queue.get.assert_called_once_with(timeout=1.0)

    def test_receive_returns_none_on_empty(self) -> None:
        """Test that receive returns None on empty queue."""
        queue = Mock(spec=MessageQueueInterface)
        queue.get.side_effect = QueueEmptyError("Empty")
        delivery: AtMostOnceDelivery[Message] = AtMostOnceDelivery()

        result = delivery.receive(queue, timeout=1.0)

        assert result is None

    def test_acknowledge_is_noop(self) -> None:
        """Test that acknowledge does nothing for at-most-once."""
        delivery: AtMostOnceDelivery[Message] = AtMostOnceDelivery()
        msg = Message(type=MessageType.WEBHOOK, payload={})

        # Should not raise
        delivery.acknowledge(msg)


class TestAtLeastOnceDelivery:
    """Test AtLeastOnceDelivery implementation."""

    def test_send_succeeds_on_first_attempt(self) -> None:
        """Test successful send on first try."""
        queue = Mock(spec=MessageQueueInterface)
        delivery: AtLeastOnceDelivery[Message] = AtLeastOnceDelivery(max_retries=3, retry_delay=0.1)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        result = delivery.send(queue, msg)

        assert result is True
        queue.put.assert_called_once()

    def test_send_retries_on_failure(self) -> None:
        """Test that send retries on QueueFullError."""
        queue = Mock(spec=MessageQueueInterface)
        queue.put.side_effect = [
            QueueFullError("Full"),
            QueueFullError("Full"),
            None,  # Success on third attempt
        ]
        delivery: AtLeastOnceDelivery[Message] = AtLeastOnceDelivery(max_retries=3, retry_delay=0.01)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        result = delivery.send(queue, msg)

        assert result is True
        assert queue.put.call_count == 3  # Initial + 2 retries

    def test_send_fails_after_max_retries(self) -> None:
        """Test that send fails after exhausting retries."""
        queue = Mock(spec=MessageQueueInterface)
        queue.put.side_effect = QueueFullError("Full")
        delivery: AtLeastOnceDelivery[Message] = AtLeastOnceDelivery(max_retries=2, retry_delay=0.01)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        result = delivery.send(queue, msg)

        assert result is False
        assert queue.put.call_count == 3  # Initial + 2 retries

    def test_send_respects_timeout(self) -> None:
        """Test that total timeout is respected across retries."""
        queue = Mock(spec=MessageQueueInterface)
        queue.put.side_effect = QueueFullError("Full")
        delivery: AtLeastOnceDelivery[Message] = AtLeastOnceDelivery(max_retries=100, retry_delay=0.1)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        import time
        start = time.time()
        result = delivery.send(queue, msg, timeout=0.3)
        elapsed = time.time() - start

        assert result is False
        assert elapsed < 0.5  # Should timeout before max_retries

    def test_receive_tracks_pending_messages(self) -> None:
        """Test that receive tracks messages until acknowledged."""
        queue = Mock(spec=MessageQueueInterface)
        msg = Message(type=MessageType.WEBHOOK, payload={})
        queue.get.return_value = msg
        delivery: AtLeastOnceDelivery[Message] = AtLeastOnceDelivery()

        result = delivery.receive(queue)

        assert result == msg
        # Message should be in pending set
        assert msg.id in delivery._pending

    def test_acknowledge_removes_from_pending(self) -> None:
        """Test that acknowledge removes message from pending."""
        queue = Mock(spec=MessageQueueInterface)
        msg = Message(type=MessageType.WEBHOOK, payload={})
        queue.get.return_value = msg
        delivery: AtLeastOnceDelivery[Message] = AtLeastOnceDelivery()

        delivery.receive(queue)
        assert msg.id in delivery._pending

        delivery.acknowledge(msg)
        assert msg.id not in delivery._pending

    def test_acknowledge_idempotent(self) -> None:
        """Test that acknowledging same message multiple times is safe."""
        delivery: AtLeastOnceDelivery[Message] = AtLeastOnceDelivery()
        msg = Message(type=MessageType.WEBHOOK, payload={})
        delivery._pending.add(msg.id)

        delivery.acknowledge(msg)
        delivery.acknowledge(msg)  # Should not raise

    def test_send_timeout_during_sleep(self) -> None:
        """Test that timeout is checked during retry sleep period."""
        queue = Mock(spec=MessageQueueInterface)
        queue.put.side_effect = QueueFullError("Full")
        delivery: AtLeastOnceDelivery[Message] = AtLeastOnceDelivery(max_retries=10, retry_delay=0.5)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        import time
        start = time.time()
        result = delivery.send(queue, msg, timeout=0.2)
        elapsed = time.time() - start

        assert result is False
        assert elapsed < 0.4  # Should timeout quickly, not do all retries

    def test_receive_message_without_id(self) -> None:
        """Test receive handles messages without id attribute."""
        queue = Mock(spec=MessageQueueInterface)
        # Create a simple dict without 'id' attribute
        msg_dict = {"data": "test"}
        queue.get.return_value = msg_dict
        delivery: AtLeastOnceDelivery[dict[str, Any]] = AtLeastOnceDelivery()

        result = delivery.receive(queue)

        assert result == msg_dict
        # Should not crash, _pending should remain empty
        assert len(delivery._pending) == 0

    def test_acknowledge_message_without_id(self) -> None:
        """Test acknowledge handles messages without id attribute."""
        delivery: AtLeastOnceDelivery[dict[str, Any]] = AtLeastOnceDelivery()
        msg_dict = {"data": "test"}

        # Should not raise
        delivery.acknowledge(msg_dict)


class TestExactlyOnceDelivery:
    """Test ExactlyOnceDelivery implementation."""

    def test_send_tracks_message_id(self) -> None:
        """Test that send tracks message IDs."""
        queue = Mock(spec=MessageQueueInterface)
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery()
        msg = Message(type=MessageType.WEBHOOK, payload={})

        result = delivery.send(queue, msg)

        assert result is True
        assert msg.id in delivery._sent_ids

    def test_send_retries_like_at_least_once(self) -> None:
        """Test that send has retry logic."""
        queue = Mock(spec=MessageQueueInterface)
        queue.put.side_effect = [QueueFullError("Full"), None]
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery(max_retries=3, retry_delay=0.01)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        result = delivery.send(queue, msg)

        assert result is True
        assert queue.put.call_count == 2

    def test_receive_filters_duplicates(self) -> None:
        """Test that receive filters out duplicate messages."""
        queue = Mock(spec=MessageQueueInterface)
        msg = Message(type=MessageType.WEBHOOK, payload={})
        queue.get.return_value = msg
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery()

        # First receive - should return message
        result1 = delivery.receive(queue)
        assert result1 == msg

        # Mark as processed
        delivery.acknowledge(msg)

        # Second receive of same message - should filter it out
        result2 = delivery.receive(queue)
        assert result2 is None  # Duplicate filtered

    def test_receive_allows_unacknowledged_duplicate(self) -> None:
        """Test that unacknowledged messages can be received again."""
        queue = Mock(spec=MessageQueueInterface)
        msg = Message(type=MessageType.WEBHOOK, payload={})
        queue.get.return_value = msg
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery()

        # First receive
        result1 = delivery.receive(queue)
        assert result1 == msg

        # Don't acknowledge - simulate processing failure

        # Second receive should return the message again (redelivery)
        result2 = delivery.receive(queue)
        assert result2 == msg

    def test_acknowledge_marks_as_processed(self) -> None:
        """Test that acknowledge marks message as fully processed."""
        queue = Mock(spec=MessageQueueInterface)
        msg = Message(type=MessageType.WEBHOOK, payload={})
        queue.get.return_value = msg
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery()

        delivery.receive(queue)
        delivery.acknowledge(msg)

        # Should be in processed set
        assert msg.id in delivery._processed_ids
        # Should not be in pending
        assert msg.id not in delivery._pending

    def test_cleanup_old_processed_ids(self) -> None:
        """Test that old processed IDs are cleaned up."""
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery(max_processed_ids=3)

        # Add 4 messages
        for i in range(4):
            msg = Message(type=MessageType.WEBHOOK, payload={"n": i})
            delivery._processed_ids.add(msg.id)

        # Trigger cleanup (happens during acknowledge)
        msg5 = Message(type=MessageType.WEBHOOK, payload={"n": 5})
        delivery.acknowledge(msg5)

        # Should keep only max_processed_ids
        assert len(delivery._processed_ids) <= 3

    def test_send_only_tracks_successful_sends(self) -> None:
        """Test that _sent_ids only contains successfully sent message IDs."""
        queue = Mock(spec=MessageQueueInterface)
        queue.put.side_effect = QueueFullError("Full")  # All attempts fail
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery(max_retries=2, retry_delay=0.01)
        msg = Message(type=MessageType.WEBHOOK, payload={"test": 1})

        result = delivery.send(queue, msg)

        # Send failed
        assert result is False
        # Message ID should NOT be in _sent_ids since it wasn't delivered
        assert msg.id not in delivery._sent_ids

    def test_send_tracks_id_on_success(self) -> None:
        """Test that _sent_ids contains ID only after successful send."""
        queue = Mock(spec=MessageQueueInterface)
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery()
        msg = Message(type=MessageType.WEBHOOK, payload={"test": 1})

        result = delivery.send(queue, msg)

        # Send succeeded
        assert result is True
        # Message ID should be in _sent_ids
        assert msg.id in delivery._sent_ids

    def test_send_timeout_during_sleep(self) -> None:
        """Test that timeout is checked during retry sleep period."""
        queue = Mock(spec=MessageQueueInterface)
        queue.put.side_effect = QueueFullError("Full")
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery(max_retries=10, retry_delay=0.5)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        import time
        start = time.time()
        result = delivery.send(queue, msg, timeout=0.2)
        elapsed = time.time() - start

        assert result is False
        assert elapsed < 0.4  # Should timeout quickly
        # Should not track failed send
        assert msg.id not in delivery._sent_ids

    def test_send_timeout_before_first_attempt(self) -> None:
        """Test that immediate timeout is handled."""
        queue = Mock(spec=MessageQueueInterface)
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery(max_retries=3)
        msg = Message(type=MessageType.WEBHOOK, payload={})

        # Timeout of 0 should fail immediately
        result = delivery.send(queue, msg, timeout=0.0)

        assert result is False
        assert queue.put.call_count == 0  # Should not even try

    def test_receive_message_without_id(self) -> None:
        """Test receive handles messages without id attribute."""
        queue = Mock(spec=MessageQueueInterface)
        msg_dict = {"data": "test"}
        queue.get.return_value = msg_dict
        delivery: ExactlyOnceDelivery[dict[str, Any]] = ExactlyOnceDelivery()

        result = delivery.receive(queue)

        # Should return message even without ID (can't deduplicate)
        assert result == msg_dict
        assert len(delivery._pending) == 0

    def test_acknowledge_message_without_id(self) -> None:
        """Test acknowledge handles messages without id attribute."""
        delivery: ExactlyOnceDelivery[dict[str, Any]] = ExactlyOnceDelivery()
        msg_dict = {"data": "test"}

        # Should not raise, just return early
        delivery.acknowledge(msg_dict)

    def test_cleanup_with_few_ids(self) -> None:
        """Test that cleanup doesn't break with fewer IDs than threshold."""
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery(max_processed_ids=100)

        # Add only 5 messages
        for i in range(5):
            msg = Message(type=MessageType.WEBHOOK, payload={"n": i})
            delivery._processed_ids.add(msg.id)

        # Acknowledge one more (shouldn't trigger cleanup)
        msg_new = Message(type=MessageType.WEBHOOK, payload={"n": 99})
        delivery.acknowledge(msg_new)

        # Should still have all 6 IDs
        assert len(delivery._processed_ids) == 6

    def test_failed_send_allows_retry(self) -> None:
        """Test that failed send doesn't prevent retry of same message."""
        queue = Mock(spec=MessageQueueInterface)
        delivery: ExactlyOnceDelivery[Message] = ExactlyOnceDelivery(max_retries=1, retry_delay=0.01)
        msg = Message(type=MessageType.WEBHOOK, payload={"test": 1})

        # First attempt - all retries fail
        queue.put.side_effect = QueueFullError("Full")
        result1 = delivery.send(queue, msg)
        assert result1 is False
        assert msg.id not in delivery._sent_ids

        # Second attempt - succeeds
        queue.put.side_effect = None
        result2 = delivery.send(queue, msg)
        assert result2 is True
        assert msg.id in delivery._sent_ids
