# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Task definitions for the worker pool.

A WorkerPoolComponent is generic: it knows nothing about what kind of
work it performs. The actual work is delegated to one or more injected
TaskHandlers, registered per TaskType. A single WorkerPoolComponent
instance may serve one TaskType (a dedicated pool) or several (a
shared pool for low-volume/low-effort task types) — which TaskTypes
share a pool, and how many worker threads each pool has, is a wiring
decision made when components are constructed, not something
WorkerPoolComponent or TaskHandler need to know about.

Task and result messages carry a free-form ``context`` dict through
unmodified, so any consumer (event handler, future notifier, etc.) can
correlate a result with the repository/PR/job it relates to, without
WorkerPoolComponent or TaskHandler needing to know about consumers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Literal

from cpu.messaging.message import Message, MessageType


class TaskType(Enum):
    """
    Types of work a worker pool can perform.

    Each TaskType is served by a registered TaskHandler within one or
    more WorkerPoolComponent instances (a pool may serve a single
    TaskType or several).
    """

    # Webhook intake
    VALIDATE_WEBHOOK = "validate_webhook"
    PROCESS_COMMENT = "process_comment"

    # Build/deploy actions
    BUILD_REQUEST = "build_request"
    DEPLOY_ARTEFACTS = "deploy_artefacts"
    CANCEL_JOBS = "cancel_jobs"
    CHECK_BUILD_STATUS = "check_build_status"
    SIGN_TARBALL = "sign_tarball"
    UPLOAD_TARBALL = "upload_tarball"

    # Informational comment responses
    SHOW_HELP = "show_help"
    SHOW_BUILDS_STATUS = "show_builds_status"
    SHOW_CONFIG = "show_config"

    # PR lifecycle
    PROCESS_CLOSED_PR = "process_closed_pr"


class TaskHandler(ABC):
    """
    Performs the actual work for one TaskType.

    Implementations are injected into a WorkerPoolComponent, keeping
    the pool itself generic and the task-specific logic (e.g. signing
    with a private key, uploading to a remote store, scanning job
    directories) independently testable.
    """

    @abstractmethod
    def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Execute the task described by context.

        Args:
            context: Free-form task context (e.g. repository, pr_number,
                comment_id, job_id, event_info, ...)

        Returns:
            Result data on success.

        Raises:
            Exception: Any exception indicates task failure. The worker
                pool catches it and publishes an error result; it is not
                propagated to the caller.
        """
        pass


def create_task_request(
    task_type: TaskType, context: dict[str, Any], source: str | None = None
) -> Message:
    """
    Create a task request message for a worker pool's task queue.

    Args:
        task_type: The kind of work requested. Required so that pools
            serving multiple TaskTypes can dispatch to the right handler.
        context: Free-form task context, passed through unmodified to
            the TaskHandler and echoed back in the result message.
        source: Optional name of the producing component.

    Returns:
        Message of type TASK_REQUEST
    """
    return Message(
        type=MessageType.TASK_REQUEST,
        payload={"task_type": task_type, "context": context},
        source=source,
    )


def create_task_result(
    task: Message,
    status: Literal["success", "error"],
    result: dict[str, Any] | None = None,
    error: str | None = None,
    source: str | None = None,
) -> Message:
    """
    Create a task result message, linked back to the originating task.

    Args:
        task: The original TASK_REQUEST message this result responds to
        status: "success" or "error"
        result: Result data (only included when status="success")
        error: Error description (only included when status="error")
        source: Optional name of the producing component (typically the
            worker pool's name)

    Returns:
        Message of type TASK_COMPLETE, with correlation_id set to the
        originating task's id, and the task's task_type/context carried
        through.

    Raises:
        ValueError: If status is not "success" or "error"
    """
    if status not in ("success", "error"):
        raise ValueError(f"status must be 'success' or 'error', got {status!r}")

    payload: dict[str, Any] = {
        "status": status,
        "task_type": task.payload.get("task_type"),
        "context": task.payload.get("context", {}),
    }
    if status == "success":
        payload["result"] = result if result is not None else {}
    else:
        payload["error"] = error if error is not None else "unknown error"

    return Message(
        type=MessageType.TASK_COMPLETE,
        payload=payload,
        correlation_id=task.id,
        source=source,
    )
