# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.worker.tasks module: TaskType enum, TaskHandler interface,
and task/result message factory helpers used by WorkerPoolComponent.
"""

from __future__ import annotations

from typing import Any

import pytest

from cpu.messaging.message import MessageType
from cpu.worker.tasks.types import (
    TaskHandler,
    TaskType,
    create_task_request,
    create_task_result,
)


class TestTaskType:
    """Tests for the TaskType enum."""

    @pytest.mark.parametrize(
        ("member", "value"),
        [
            (TaskType.VALIDATE_WEBHOOK, "validate_webhook"),
            (TaskType.PROCESS_COMMENT, "process_comment"),
            (TaskType.BUILD_REQUEST, "build_request"),
            (TaskType.DEPLOY_ARTEFACTS, "deploy_artefacts"),
            (TaskType.CANCEL_JOBS, "cancel_jobs"),
            (TaskType.CHECK_BUILD_STATUS, "check_build_status"),
            (TaskType.SIGN_TARBALL, "sign_tarball"),
            (TaskType.UPLOAD_TARBALL, "upload_tarball"),
            (TaskType.SHOW_HELP, "show_help"),
            (TaskType.SHOW_BUILDS_STATUS, "show_builds_status"),
            (TaskType.SHOW_CONFIG, "show_config"),
            (TaskType.PROCESS_CLOSED_PR, "process_closed_pr"),
        ],
    )
    def test_task_type_value(self, member: TaskType, value: str) -> None:
        assert member.value == value


class RecordingHandler(TaskHandler):
    """Minimal concrete TaskHandler for interface tests."""

    def __init__(self, result: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.result = result if result is not None else {}
        self.error = error
        self.received: dict[str, Any] | None = None

    def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        self.received = context
        if self.error is not None:
            raise self.error
        return self.result


class TestTaskHandlerInterface:
    """Tests for the TaskHandler abstract interface."""

    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            TaskHandler()  # type: ignore[abstract]

    def test_concrete_handler_returns_result(self) -> None:
        handler = RecordingHandler(result={"status": "ok"})
        result = handler.handle({"job_id": "123"})
        assert result == {"status": "ok"}
        assert handler.received == {"job_id": "123"}

    def test_concrete_handler_can_raise(self) -> None:
        handler = RecordingHandler(error=RuntimeError("boom"))
        with pytest.raises(RuntimeError, match="boom"):
            handler.handle({"job_id": "123"})


class TestCreateTaskRequest:
    """Tests for create_task_request."""

    def test_creates_task_request_message(self) -> None:
        context = {"job_id": "123", "repository": "EESSI/cpu"}
        msg = create_task_request(TaskType.CHECK_BUILD_STATUS, context)

        assert msg.type == MessageType.TASK_REQUEST
        assert msg.payload["task_type"] == TaskType.CHECK_BUILD_STATUS
        assert msg.payload["context"] == context

    def test_default_source(self) -> None:
        msg = create_task_request(TaskType.CHECK_BUILD_STATUS, {"job_id": "123"})
        assert msg.source is None

    def test_custom_source(self) -> None:
        msg = create_task_request(
            TaskType.CHECK_BUILD_STATUS, {"job_id": "123"}, source="job_manager"
        )
        assert msg.source == "job_manager"

    def test_context_is_passed_through_unmodified(self) -> None:
        context = {
            "repository": "EESSI/cpu",
            "pr_number": 42,
            "comment_id": 9999,
            "job_id": "job_1",
            "event_info": {"action": "opened"},
        }
        msg = create_task_request(TaskType.BUILD_REQUEST, context)
        assert msg.payload["context"] == context

    def test_different_task_types_are_distinguishable(self) -> None:
        sign_msg = create_task_request(TaskType.SIGN_TARBALL, {"job_id": "1"})
        upload_msg = create_task_request(TaskType.UPLOAD_TARBALL, {"job_id": "1"})
        assert sign_msg.payload["task_type"] != upload_msg.payload["task_type"]


class TestCreateTaskResult:
    """Tests for create_task_result."""

    def test_success_result(self) -> None:
        context = {"job_id": "123"}
        task = create_task_request(TaskType.SIGN_TARBALL, context)

        result_msg = create_task_result(
            task, status="success", result={"artefact": "foo.tar.gz"}
        )

        assert result_msg.type == MessageType.TASK_COMPLETE
        assert result_msg.payload["status"] == "success"
        assert result_msg.payload["task_type"] == TaskType.SIGN_TARBALL
        assert result_msg.payload["context"] == context
        assert result_msg.payload["result"] == {"artefact": "foo.tar.gz"}
        assert "error" not in result_msg.payload

    def test_error_result(self) -> None:
        context = {"job_id": "123"}
        task = create_task_request(TaskType.UPLOAD_TARBALL, context)

        result_msg = create_task_result(task, status="error", error="boom")

        assert result_msg.type == MessageType.TASK_COMPLETE
        assert result_msg.payload["status"] == "error"
        assert result_msg.payload["task_type"] == TaskType.UPLOAD_TARBALL
        assert result_msg.payload["context"] == context
        assert result_msg.payload["error"] == "boom"
        assert "result" not in result_msg.payload

    def test_result_correlation_id_links_to_task(self) -> None:
        task = create_task_request(TaskType.CHECK_BUILD_STATUS, {"job_id": "123"})
        result_msg = create_task_result(task, status="success", result={})
        assert result_msg.correlation_id == task.id

    def test_custom_source(self) -> None:
        task = create_task_request(TaskType.SIGN_TARBALL, {"job_id": "123"})
        result_msg = create_task_result(
            task, status="success", result={}, source="worker_pool_sign"
        )
        assert result_msg.source == "worker_pool_sign"

    def test_invalid_status_raises(self) -> None:
        task = create_task_request(TaskType.CHECK_BUILD_STATUS, {"job_id": "123"})
        with pytest.raises(ValueError):
            create_task_result(task, status="bogus")  # type: ignore[arg-type]
