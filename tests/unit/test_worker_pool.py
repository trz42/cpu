# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.worker.pool module which provides WorkerPoolComponent.

WorkerPoolComponent is generic: it runs a fixed number of worker
threads pulling TASK_REQUEST messages from a task queue, dispatches
each to a registered TaskHandler keyed by TaskType, and publishes a
TASK_COMPLETE result (success or error) to a result queue.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from cpu.components.base import ComponentState, HealthStatus
from cpu.messaging.message import Message, MessageType
from cpu.messaging.queue_thread import ThreadMessageQueue
from cpu.worker.pool import WorkerPoolComponent
from cpu.worker.tasks.types import TaskHandler, TaskType, create_task_request


class RecordingHandler(TaskHandler):
    """TaskHandler that records calls and returns/raises a fixed outcome."""

    def __init__(self, result: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.result = result if result is not None else {}
        self.error = error
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.calls.append(context)
        if self.error is not None:
            raise self.error
        return self.result


class SlowHandler(TaskHandler):
    """TaskHandler that blocks until released, to test concurrency."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        self.started.set()
        self.release.wait(timeout=2)
        return {"context": context}


class TestWorkerPoolComponentInitialization:
    """Tests for initialization and validation."""

    def test_initialization_sets_state(self) -> None:
        task_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        result_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=task_queue,
            result_queue=result_queue,
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
        )
        pool.initialize()
        assert pool.get_state() == ComponentState.INITIALIZED

    def test_rejects_empty_handlers(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={},
        )
        with pytest.raises(ValueError):
            pool.initialize()

    def test_rejects_non_positive_num_workers(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
            num_workers=0,
        )
        with pytest.raises(ValueError):
            pool.initialize()

    def test_default_num_workers_is_one(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
        )
        assert pool.num_workers == 1


class TestWorkerPoolComponentDispatch:
    """Tests for task dispatch and result publishing."""

    # TODO name is misleading? there's only one handler so how do we perform a match at all?
    def test_dispatches_to_matching_handler(self) -> None:
        task_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        result_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = RecordingHandler(result={"artefact": "foo.tar.gz"})

        pool = WorkerPoolComponent(
            name="pool",
            task_queue=task_queue,
            result_queue=result_queue,
            handlers={TaskType.CHECK_BUILD_STATUS: handler},
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_dispatches_to_matching_handler"
        )
        thread.start()

        task = create_task_request(TaskType.CHECK_BUILD_STATUS, {"job_id": "1"})
        task_queue.put(task)

        result = result_queue.get(timeout=2)
        pool.stop(timeout=2)
        thread.join(timeout=2)

        assert handler.calls == [{"job_id": "1"}]
        assert result.payload["status"] == "success"
        assert result.payload["task_type"] == TaskType.CHECK_BUILD_STATUS
        assert result.payload["result"] == {"artefact": "foo.tar.gz"}
        assert result.correlation_id == task.id

    def test_handler_exception_produces_error_result(self) -> None:
        task_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        result_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        handler = RecordingHandler(error=RuntimeError("signing failed"))

        pool = WorkerPoolComponent(
            name="pool",
            task_queue=task_queue,
            result_queue=result_queue,
            handlers={TaskType.SIGN_TARBALL: handler},
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_handler_exception_produces_error_result"
        )
        thread.start()

        task_queue.put(create_task_request(TaskType.SIGN_TARBALL, {"job_id": "1"}))

        result = result_queue.get(timeout=2)
        pool.stop(timeout=2)
        thread.join(timeout=2)

        assert result.payload["status"] == "error"
        assert "signing failed" in result.payload["error"]

    def test_unregistered_task_type_produces_error_result(self) -> None:
        task_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        result_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        pool = WorkerPoolComponent(
            name="pool",
            task_queue=task_queue,
            result_queue=result_queue,
            handlers={TaskType.SIGN_TARBALL: RecordingHandler()},
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_unregistered_task_type_produces_error_result"
        )
        thread.start()

        # UPLOAD_TARBALL has no registered handler in this pool.
        task_queue.put(create_task_request(TaskType.UPLOAD_TARBALL, {"job_id": "1"}))

        result = result_queue.get(timeout=2)
        pool.stop(timeout=2)
        thread.join(timeout=2)

        assert result.payload["status"] == "error"
        assert "upload_tarball" in result.payload["error"].lower()

    def test_missing_task_type_produces_error_result(self) -> None:
        task_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        result_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()

        pool = WorkerPoolComponent(
            name="pool",
            task_queue=task_queue,
            result_queue=result_queue,
            handlers={TaskType.SIGN_TARBALL: RecordingHandler()},
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_missing_task_type_produces_error_result"
        )
        thread.start()

        # A malformed task message with no usable task_type at all.
        task_queue.put(Message(type=MessageType.TASK_REQUEST, payload={"context": {}}))

        result = result_queue.get(timeout=2)
        pool.stop(timeout=2)
        thread.join(timeout=2)

        assert result.payload["status"] == "error"
        assert "no handler registered" in result.payload["error"].lower()

    def test_pool_serving_multiple_task_types(self) -> None:
        task_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        result_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        help_handler = RecordingHandler(result={"text": "help"})
        status_handler = RecordingHandler(result={"text": "status"})

        pool = WorkerPoolComponent(
            name="pool",
            task_queue=task_queue,
            result_queue=result_queue,
            handlers={
                TaskType.SHOW_HELP: help_handler,
                TaskType.SHOW_BUILDS_STATUS: status_handler,
            },
            num_workers=2,
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_pool_serving_multiple_task_types"
        )
        thread.start()

        task_queue.put(create_task_request(TaskType.SHOW_HELP, {"pr": 1}))
        task_queue.put(create_task_request(TaskType.SHOW_BUILDS_STATUS, {"pr": 2}))

        results = {result_queue.get(timeout=2).payload["task_type"] for _ in range(2)}

        pool.stop(timeout=2)
        thread.join(timeout=2)

        assert results == {TaskType.SHOW_HELP, TaskType.SHOW_BUILDS_STATUS}
        assert help_handler.calls == [{"pr": 1}]
        assert status_handler.calls == [{"pr": 2}]

    def test_multiple_workers_process_concurrently(self) -> None:
        task_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        result_queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        slow_a = SlowHandler()
        slow_b = SlowHandler()

        # Two distinct task types sharing one pool with 2 workers, so
        # both slow handlers can be in-flight at the same time.
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=task_queue,
            result_queue=result_queue,
            handlers={TaskType.SIGN_TARBALL: slow_a, TaskType.UPLOAD_TARBALL: slow_b},
            num_workers=2,
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_multiple_workers_process_concurrently"
        )
        thread.start()

        task_queue.put(create_task_request(TaskType.SIGN_TARBALL, {"job_id": "a"}))
        task_queue.put(create_task_request(TaskType.UPLOAD_TARBALL, {"job_id": "b"}))

        assert slow_a.started.wait(timeout=2)
        assert slow_b.started.wait(timeout=2)

        slow_a.release.set()
        slow_b.release.set()

        result_queue.get(timeout=2)
        result_queue.get(timeout=2)

        pool.stop(timeout=2)
        thread.join(timeout=2)


class TestWorkerPoolComponentLifecycle:
    """Tests for start/stop lifecycle and health checks."""

    def test_start_before_initialize_raises(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
        )
        with pytest.raises(RuntimeError):
            pool.start()

    def test_process_iteration_exception_sets_failed_state(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
        )
        pool.initialize()
        pool.process_iteration = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match="boom"):
            pool.start()

        assert pool.get_state() == ComponentState.FAILED

    def test_stop_terminates_cleanly(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
            num_workers=3,
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_stop_terminates_cleanly"
        )
        thread.start()
        time.sleep(0.2)

        pool.stop(timeout=2)
        thread.join(timeout=2)

        assert pool.get_state() == ComponentState.STOPPED
        assert not thread.is_alive()

    def test_health_check_unhealthy_before_start(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
        )
        pool.initialize()
        assert pool.health_check() == HealthStatus.UNHEALTHY

    def test_health_check_healthy_while_running(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
            num_workers=2,
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_health_check_healthy_while_running"
        )
        thread.start()
        time.sleep(0.2)

        assert pool.health_check() == HealthStatus.HEALTHY

        pool.stop(timeout=2)
        thread.join(timeout=2)

    def test_health_check_unhealthy_when_a_worker_thread_dies(self) -> None:
        pool = WorkerPoolComponent(
            name="pool",
            task_queue=ThreadMessageQueue(),
            result_queue=ThreadMessageQueue(),
            handlers={TaskType.CHECK_BUILD_STATUS: RecordingHandler()},
            num_workers=2,
        )
        pool.initialize()

        thread = threading.Thread(
            target=pool.start, name="test_health_check_unhealthy_when_a_worker_thread_dies"
        )
        thread.start()
        time.sleep(0.2)

        dead_thread = threading.Thread(target=lambda: None, name="dead_thread_stub")
        dead_thread.start()
        dead_thread.join()
        pool._worker_threads[0] = dead_thread

        assert pool.health_check() == HealthStatus.UNHEALTHY

        pool.stop(timeout=2)
        thread.join(timeout=2)
