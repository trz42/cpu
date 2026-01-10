# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.messaging.message module.

Tests the Message class and related factory functions.
"""

# enable postponed evaluations of annotations
from __future__ import annotations

import time

import pytest

from cpu.messaging.message import (
    DeliveryGuarantee,
    Message,
    MessageType,
    create_job_notification,
    create_status_check_message,
    create_webhook_message,
)


class TestMessageType:
    """Tests for MessageType enum."""

    def test_message_types_exist(self) -> None:
        """Test all expected message types are defined."""
        assert MessageType.CHECK_STATUS
        assert MessageType.HEALTH_CHECK
        assert MessageType.JOB_FINISHED
        assert MessageType.JOB_RELEASED
        assert MessageType.JOB_RUNNING
        assert MessageType.NEW_JOB
        assert MessageType.PROCESS_FINISHED_JOB
        assert MessageType.SHUTDOWN
        assert MessageType.TASK_COMPLETE
        assert MessageType.WEBHOOK

    def test_message_type_values(self) -> None:
        """Test message type enum values."""
        assert MessageType.CHECK_STATUS.value == "check_status"
        assert MessageType.NEW_JOB.value == "new_job"
        assert MessageType.WEBHOOK.value == "webhook"


class TestDeliveryGuarantee:
    """Tests for DeliveryGuarantee enum."""

    def test_delivery_guarantees_exist(self) -> None:
        """Test all delivery guarantee types are defined."""
        assert DeliveryGuarantee.AT_LEAST_ONCE
        assert DeliveryGuarantee.AT_MOST_ONCE
        assert DeliveryGuarantee.EXACTLY_ONCE

    def test_delivery_guarantee_values(self) -> None:
        """Test delivery guarantee enum values."""
        assert DeliveryGuarantee.AT_LEAST_ONCE.value == "at-least-once"
        assert DeliveryGuarantee.AT_MOST_ONCE.value == "at-most-once"
        assert DeliveryGuarantee.EXACTLY_ONCE.value == "exactly-once"


class TestMessage:
    """Tests for Message class."""

    def test_message_creation_minimal(self) -> None:
        """Test creating message with minimal required arguments."""
        msg = Message(type=MessageType.WEBHOOK, payload={"data": "test"})

        assert msg.type == MessageType.WEBHOOK
        assert msg.payload == {"data": "test"}
        assert msg.id is not None
        assert isinstance(msg.id, str)
        assert msg.timestamp > 0
        assert msg.retries == 0
        assert msg.delivery == DeliveryGuarantee.AT_LEAST_ONCE
        assert msg.source is None
        assert msg.correlation_id is None

    def test_message_creation_full(self) -> None:
        """Test creating message with all arguments."""
        msg = Message(
            type=MessageType.NEW_JOB,
            payload={"job_id": "123"},
            delivery=DeliveryGuarantee.EXACTLY_ONCE,
            id="custom-id",
            timestamp=1234567890.0,
            retries=3,
            source="test_source",
            correlation_id="correlation-123"
        )

        assert msg.type == MessageType.NEW_JOB
        assert msg.payload == {"job_id": "123"}
        assert msg.delivery == DeliveryGuarantee.EXACTLY_ONCE
        assert msg.id == "custom-id"
        assert msg.timestamp == 1234567890.0
        assert msg.retries == 3
        assert msg.source == "test_source"
        assert msg.correlation_id == "correlation-123"

    def test_message_unique_ids(self) -> None:
        """Test that each message gets a unique ID."""
        msg1 = Message(type=MessageType.WEBHOOK, payload={})
        msg2 = Message(type=MessageType.WEBHOOK, payload={})

        assert msg1.id != msg2.id

    def test_message_with_custom_delivery(self) -> None:
        """Test message with custom delivery guarantee."""
        msg = Message(
            type=MessageType.WEBHOOK,
            payload={},
            delivery=DeliveryGuarantee.EXACTLY_ONCE
        )

        assert msg.delivery == DeliveryGuarantee.EXACTLY_ONCE

    def test_message_type_validation(self) -> None:
        """Test message type must be MessageType enum."""
        with pytest.raises(TypeError):
            Message(
                type="webhook",  # type: ignore
                payload={}
            )

    def test_message_with_complex_payload(self) -> None:
        """Test message with complex nested payload."""
        payload = {
            "job_id": "123",
            "metadata": {
                "user": "test_user",
                "priority": 5,
                "tags": ["urgent", "build"]
            },
            "config": {
                "timeout": 3600,
                "retry": True
            }
        }

        msg = Message(type=MessageType.NEW_JOB, payload=payload)

        assert msg.payload == payload
        assert msg.payload["metadata"]["tags"] == ["urgent", "build"]

    def test_message_with_empty_payload(self) -> None:
        """Test message with empty payload."""
        msg = Message(type=MessageType.CHECK_STATUS, payload={})

        assert msg.payload == {}

    def test_message_timestamp_automatic(self) -> None:
        """Test message timestamp is set automatically."""
        before = time.time()
        msg = Message(type=MessageType.WEBHOOK, payload={})
        after = time.time()

        assert before <= msg.timestamp <= after


class TestMessageMethods:
    """Tests for Message methods."""

    def test_increment_retries(self) -> None:
        """Test incrementing retry counter."""
        msg = Message(type=MessageType.WEBHOOK, payload={})

        assert msg.retries == 0
        msg.increment_retries()
        assert msg.retries == 1
        msg.increment_retries()
        assert msg.retries == 2
        msg.increment_retries()
        assert msg.retries == 3

    def test_is_expired_fresh_message(self) -> None:
        """Test fresh message is not expired."""
        msg = Message(type=MessageType.WEBHOOK, payload={})

        assert msg.is_expired(ttl_seconds=3600) is False
        assert msg.is_expired(ttl_seconds=60) is False
        assert msg.is_expired(ttl_seconds=1) is False

    def test_is_expired_old_message(self) -> None:
        """Test old message is expired."""
        msg = Message(type=MessageType.WEBHOOK, payload={})
        msg.timestamp = time.time() - 7200  # 2 hours ago

        assert msg.is_expired(ttl_seconds=3600) is True  # TTL 1 hour
        assert msg.is_expired(ttl_seconds=60) is True    # TTL 1 minute

    def test_is_expired_edge_case(self) -> None:
        """Test expiration at exact boundary."""
        msg = Message(type=MessageType.WEBHOOK, payload={})
        msg.timestamp = time.time() - 100  # 100 seconds ago

        assert msg.is_expired(ttl_seconds=99) is True
        assert msg.is_expired(ttl_seconds=101) is False

    def test_to_dict(self) -> None:
        """Test message serialization to dict."""
        msg = Message(
            type=MessageType.NEW_JOB,
            payload={"job_id": "123"},
            source="test_source",
            correlation_id="corr-123"
        )

        data = msg.to_dict()

        assert data["id"] == msg.id
        assert data["type"] == "new_job"
        assert data["payload"] == {"job_id": "123"}
        assert data["source"] == "test_source"
        assert data["correlation_id"] == "corr-123"
        assert data["delivery"] == "at-least-once"
        assert data["timestamp"] == msg.timestamp
        assert data["retries"] == 0

    def test_to_dict_all_fields(self) -> None:
        """Test to_dict includes all fields."""
        msg = Message(
            type=MessageType.WEBHOOK,
            payload={"test": "data"},
            delivery=DeliveryGuarantee.EXACTLY_ONCE,
            source="source",
            correlation_id="corr"
        )
        msg.increment_retries()

        data = msg.to_dict()

        assert "id" in data
        assert "type" in data
        assert "payload" in data
        assert "delivery" in data
        assert "timestamp" in data
        assert "retries" in data
        assert "source" in data
        assert "correlation_id" in data
        assert data["retries"] == 1

    def test_roundtrip_serialization_basic(self) -> None:
        """Test basic serialization roundtrip preserves all fields."""
        original = Message(
            type=MessageType.NEW_JOB,
            payload={"job_id": "123"},
            source="test",
            correlation_id="corr"
        )

        data = original.to_dict()
        restored = Message.from_dict(data)

        assert restored.id == original.id
        assert restored.type == original.type
        assert restored.payload == original.payload
        assert restored.timestamp == original.timestamp
        assert restored.delivery == original.delivery
        assert restored.source == original.source
        assert restored.correlation_id == original.correlation_id

    def test_roundtrip_serialization_with_retries(self) -> None:
        """Test roundtrip preserves retry count and all fields."""
        msg = Message(
            type=MessageType.JOB_FINISHED,
            payload={"job_id": "456", "status": "success"},
            delivery=DeliveryGuarantee.EXACTLY_ONCE,
            source="JobManager",
            correlation_id="xyz"
        )
        msg.increment_retries()
        msg.increment_retries()

        data = msg.to_dict()
        restored = Message.from_dict(data)

        assert restored.id == msg.id
        assert restored.type == msg.type
        assert restored.payload == msg.payload
        assert restored.delivery == msg.delivery
        assert restored.timestamp == msg.timestamp
        assert restored.retries == 2  # Specifically test retries are preserved
        assert restored.source == msg.source
        assert restored.correlation_id == msg.correlation_id

    def test_from_dict_handles_optional_fields(self) -> None:
        """Test from_dict handles missing optional fields."""
        data = {
            "id": "test-id",
            "type": "webhook",
            "payload": {},
            "delivery": "at-least-once",
            "timestamp": 1234567890.0
        }

        msg = Message.from_dict(data)

        assert msg.id == "test-id"
        assert msg.retries == 0  # Default value
        assert msg.source is None
        assert msg.correlation_id is None


class TestMessageFactoryFunctions:
    """Tests for message factory functions."""

    def test_create_webhook_message_default_platform(self) -> None:
        """Test webhook message creation with default platform."""
        webhook_data = {"action": "opened", "number": 123}

        msg = create_webhook_message(webhook_data)

        assert msg.type == MessageType.WEBHOOK
        assert msg.payload["platform"] == "github"
        assert msg.payload["data"] == webhook_data
        assert msg.source == "SmeeClient"

    def test_create_webhook_message_custom_platform(self) -> None:
        """Test webhook message creation with custom platform."""
        webhook_data = {"action": "merge"}

        msg = create_webhook_message(webhook_data, platform="gitlab")

        assert msg.type == MessageType.WEBHOOK
        assert msg.payload["platform"] == "gitlab"
        assert msg.payload["data"] == webhook_data
        assert msg.source == "SmeeClient"

    def test_create_webhook_message_complex_data(self) -> None:
        """Test webhook message with complex webhook data."""
        webhook_data = {
            "action": "opened",
            "pull_request": {
                "number": 123,
                "title": "Test PR",
                "user": {"login": "testuser"}
            }
        }

        msg = create_webhook_message(webhook_data)

        assert msg.payload["data"]["pull_request"]["number"] == 123

    def test_create_job_notification_minimal(self) -> None:
        """Test job notification with minimal arguments."""
        msg = create_job_notification(job_id="slurm_123")

        assert msg.type == MessageType.NEW_JOB
        assert msg.payload["job_id"] == "slurm_123"
        assert msg.payload["pr_number"] is None
        assert msg.payload["repository"] is None
        assert msg.source == "EventHandler"

    def test_create_job_notification_full(self) -> None:
        """Test job notification with all arguments."""
        msg = create_job_notification(
            job_id="slurm_456",
            pr_number=789,
            repository="EESSI/cpu"
        )

        assert msg.type == MessageType.NEW_JOB
        assert msg.payload["job_id"] == "slurm_456"
        assert msg.payload["pr_number"] == 789
        assert msg.payload["repository"] == "EESSI/cpu"
        assert msg.source == "EventHandler"

    def test_create_status_check_message(self) -> None:
        """Test status check message creation."""
        msg = create_status_check_message()

        assert msg.type == MessageType.CHECK_STATUS
        assert msg.payload == {}
        assert msg.source == "Scheduler"

    def test_factory_functions_create_valid_messages(self) -> None:
        """Test all factory functions create valid Message objects."""
        webhook = create_webhook_message({"test": 1})
        job = create_job_notification("job_1")
        status = create_status_check_message()

        # All should be Message instances
        assert isinstance(webhook, Message)
        assert isinstance(job, Message)
        assert isinstance(status, Message)

        # All should have unique IDs
        assert webhook.id != job.id != status.id

        # All should have timestamps
        assert webhook.timestamp > 0
        assert job.timestamp > 0
        assert status.timestamp > 0


class TestMessageEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_message_with_none_source(self) -> None:
        """Test message with explicitly None source."""
        msg = Message(
            type=MessageType.WEBHOOK,
            payload={},
            source=None
        )

        assert msg.source is None

    def test_message_payload_shares_reference(self) -> None:
        """Test that message payload shares reference with original dict (expected Python behavior)."""
        original_payload = {"key": "value"}
        msg = Message(type=MessageType.WEBHOOK, payload=original_payload)

        # Modify message payload
        msg.payload["new_key"] = "new_value"

        # Original is also modified (they share the same dict reference)
        # This is expected Python behavior for mutable objects
        assert "new_key" in original_payload
        assert original_payload["new_key"] == "new_value"

    def test_message_with_large_payload(self) -> None:
        """Test message with large payload."""
        large_payload = {f"key_{i}": f"value_{i}" for i in range(1000)}

        msg = Message(type=MessageType.WEBHOOK, payload=large_payload)

        assert len(msg.payload) == 1000
        assert msg.payload["key_500"] == "value_500"

    def test_message_serialization_with_special_characters(self) -> None:
        """Test serialization with special characters commonly found in technical contexts."""
        msg = Message(
            type=MessageType.WEBHOOK,
            payload={
                "escape_sequences": "Newline:\nTab:\tCarriage return:\rBackslash:\\Quote:\"Apostrophe:'",
                "accented_chars": "Café, naïve, Zürich, São Paulo",
                "common_symbols": "Copyright © Registered ® Trademark ™ Euro € Pound £ Yen ¥",
                "math_symbols": "Pi π approximately ≈ 3.14, square root √2 not equal ≠ 1.41",
                "arrows": "Right → Left ← Up ↑ Down ↓",
                "unix_path": "/usr/local/bin:/home/user/.local/bin",
                "windows_path": "C:\\Users\\test\\Documents\\file.txt",
                "url": "https://example.com/api?param=value&foo=bar#section",
            }
        )

        data = msg.to_dict()
        restored = Message.from_dict(data)

        # Verify all special characters are preserved
        assert restored.payload["escape_sequences"] == msg.payload["escape_sequences"]
        assert restored.payload["accented_chars"] == msg.payload["accented_chars"]
        assert restored.payload["common_symbols"] == msg.payload["common_symbols"]
        assert restored.payload["math_symbols"] == msg.payload["math_symbols"]
        assert restored.payload["arrows"] == msg.payload["arrows"]
        assert restored.payload["unix_path"] == msg.payload["unix_path"]
        assert restored.payload["windows_path"] == msg.payload["windows_path"]
        assert restored.payload["url"] == msg.payload["url"]

    def test_multiple_messages_same_type_independent(self) -> None:
        """Test multiple messages of same type are independent."""
        msg1 = Message(type=MessageType.NEW_JOB, payload={"job_id": "1"})
        msg2 = Message(type=MessageType.NEW_JOB, payload={"job_id": "2"})

        msg1.increment_retries()
        msg1.increment_retries()

        assert msg1.retries == 2
        assert msg2.retries == 0  # Should not be affected
        assert msg1.id != msg2.id
        assert msg1.payload != msg2.payload
