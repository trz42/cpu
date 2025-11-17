# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU bot Contributors
"""
Message types and protocols for inter-thread communication.

This module defines the message format and types used throughout the bot.
All components communicate by passing Message objects through queues.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DeliveryGuarantee(Enum):
    """Message delivery guarantee levels."""

    AT_MOST_ONCE = "at-most-once"  # Fire and forget, no acknowledgment
    AT_LEAST_ONCE = "at-least-once"  # Require acknowledgment, may duplicate
    EXACTLY_ONCE = "exactly-once"  # Deduplicate using message ID


class MessageType(Enum):
    """Types of messages that can be passed between components."""

    # Webhook-related
    WEBHOOK = "webhook"

    # Job-related
    NEW_JOB = "new_job"
    CHECK_STATUS = "check_status"
    JOB_RELEASED = "job_released"
    JOB_RUNNING = "job_running"
    JOB_FINISHED = "job_finished"

    # Worker-related
    PROCESS_FINISHED_JOB = "process_finished_job"
    TASK_COMPLETE = "task_complete"

    # Control messages
    SHUTDOWN = "shutdown"
    HEALTH_CHECK = "health_check"


@dataclass
class Message:
    """
    Base message class for inter-thread communication.

    Attributes:
        type: Type of message
        payload: Message data (structure depends on type)
        delivery: Delivery guarantee level
        id: Unique message identifier
        timestamp: Unix timestamp when message was created
        retries: Number of delivery attempts
        source: Component that sent the message
        correlation_id: Optional ID to correlate request/response
    """

    type: MessageType
    payload: dict[str, Any]
    delivery: DeliveryGuarantee = DeliveryGuarantee.AT_LEAST_ONCE
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    retries: int = 0
    source: str | None
    correlation_id: str | None

    def __post_init__(self) -> None:
        """Validate message after initialization."""
        if not isinstance(self.type, MessageType):
            raise TypeError(
                f"Message type must be MessageType enum, got {type(self.type)}"
            )

    def increment_retries(self) -> None:
        """Increment the retry counter."""
        self.retries += 1

    def is_expired(self, ttl_seconds: int = 3600) -> bool:
        """
        Check if message has exceeded its time-to-live.

        Args:
            ttl_seconds: Maximum age in seconds before message expires

        Returns:
            True if message is expired, False otherwise
        """
        age = time.time() - self.timestamp
        return age > ttl_seconds

    def to_dict(self) -> dict[str, Any]:
        """
        Convert message to dictionary for serialization.

        Returns:
            Dictionary representation of message
        """
        return {
            "id": self.id,
            "type": self.type.value,
            "payload": self.payload,
            "delivery": self.delivery.value,
            "timestamp": self.timestamp,
            "retries": self.retries,
            "source": self.source,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Message:
        """
        Create message from dictionary.

        Args:
            data: Dictionary containing message data

        Returns:
            Message instance
        """
        return cls(
            id=data["id"],
            type=MessageType(data["type"]),
            payload=data["payload"],
            delivery=DeliveryGuarantee(data["delivery"]),
            timestamp=data["timestamp"],
            retries=data.get("retries", 0),
            source=data.get("source"),
            correlation_id=data.get("correlation_id"),
        )


# Type aliases for common message payloads
WebhookPayload = dict[str, Any]
JobPayload = dict[str, Any]
TaskPayload = dict[str, Any]


def create_webhook_message(
    webhook_data: WebhookPayload, platform: str = "github"
) -> Message:
    """
    Create a webhook message.

    Args:
        webhook_data: Raw webhook data from platform
        platform: Platform name (github, gitlab, etc.)

    Returns:
        Message containing webhook data
    """
    return Message(
        type=MessageType.WEBHOOK,
        payload={"platform": platform, "data": webhook_data},
        source="SmeeClient",
    )


def create_job_notification(
    job_id: str, pr_number: int | None, repository: str | None
) -> Message:
    """
    Create a new job notification message.

    Args:
        job_id: Slurm job ID
        pr_number: Pull request number (if applicable)
        repository: Repository name

    Returns:
        Message notifying about new job
    """
    return Message(
        type=MessageType.NEW_JOB,
        payload={"job_id": job_id, "pr_number": pr_number, "repository": repository},
        source="EventHandler",
    )


def create_status_check_message() -> Message:
    """
    Create a periodic status check trigger message.

    Returns:
        Message triggering job status check
    """
    return Message(type=MessageType.CHECK_STATUS, payload={}, source="Scheduler")
