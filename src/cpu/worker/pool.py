# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Generic worker pool component.

WorkerPoolComponent knows nothing about what kind of work it performs.
It runs a fixed number of worker threads pulling TASK_REQUEST messages
from a task queue, dispatches each to a TaskHandler registered for the
task's TaskType, and publishes a TASK_COMPLETE result (success or
error) to a result queue. A single instance may serve one TaskType (a
dedicated pool) or several (a shared pool), depending on how it is
wired up.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from cpu.components.base import ComponentState, HealthStatus, RunnableComponent
from cpu.messaging.interfaces import MessageQueueInterface, QueueEmptyError
from cpu.messaging.message import Message
from cpu.worker.tasks.types import TaskHandler, TaskType, create_task_result

logger = logging.getLogger(__name__)


class WorkerPoolComponent(RunnableComponent):
    """
    Runs a fixed-size pool of worker threads processing TASK_REQUEST messages.

    Each worker thread loops: pull a task from task_queue, look up the
    TaskHandler registered for the task's task_type, call handle(context),
    and publish a TASK_COMPLETE result to result_queue. Handler exceptions
    and unregistered task types both produce an error result rather than
    crashing the worker thread.
    """

    def __init__(
        self,
        name: str,
        task_queue: MessageQueueInterface[Message],
        result_queue: MessageQueueInterface[Message],
        handlers: dict[TaskType, TaskHandler],
        num_workers: int = 1,
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Create the worker pool component.

        Args:
            name: Component name
            task_queue: Queue to pull TASK_REQUEST messages from
            result_queue: Queue to publish TASK_COMPLETE results to
            handlers: TaskHandler registered per TaskType this pool serves
            num_workers: Number of worker threads
            config: Optional configuration dictionary
        """
        super().__init__(name, config)
        self.task_queue = task_queue
        self.result_queue = result_queue
        self.handlers = handlers
        self.num_workers = num_workers

        self._worker_threads: list[threading.Thread] = []
        self._worker_stop = threading.Event()

    def initialize(self) -> None:
        """
        Validate configuration and prepare internal state.

        Raises:
            ValueError: If handlers is empty or num_workers is not positive
        """
        if not self.handlers:
            raise ValueError(f"{self.name}: at least one TaskHandler must be registered")
        if self.num_workers < 1:
            raise ValueError(f"{self.name}: num_workers must be >= 1, got {self.num_workers}")

        self.state = ComponentState.INITIALIZED
        logger.info(
            f"Initialized {self.name} with {self.num_workers} worker(s) "
            f"for task types: {[t.value for t in self.handlers]}"
        )

    def start(self) -> None:
        """Transition to RUNNING, then start worker threads, then run the main loop."""
        if self.state != ComponentState.INITIALIZED:
            raise RuntimeError(f"Component {self.name} not initialized (state={self.state})")

        self.state = ComponentState.RUNNING
        self._stop_requested = False

        self._worker_stop.clear()
        self._worker_threads = [
            threading.Thread(
                target=self._worker_loop,
                name=f"{self.name}-worker-{worker_index}",
                daemon=True,
            )
            for worker_index in range(self.num_workers)
        ]
        for worker_thread in self._worker_threads:
            worker_thread.start()

        logger.info(f"Starting component: {self.name}")

        try:
            while not self._stop_requested:
                self.process_iteration()
        except Exception as err:
            self.state = ComponentState.FAILED
            raise err
        else:
            self.state = ComponentState.STOPPED

    def stop(self, timeout: float | None = None) -> None:
        """
        Stop the component and all worker threads.

        Args:
            timeout: Maximum time to wait for each worker thread to stop
        """
        super().stop(timeout)

        self._worker_stop.set()
        for worker_thread in self._worker_threads:
            worker_thread.join(timeout=timeout)

    def process_iteration(self) -> None:
        """Main loop has no work of its own; the worker threads do the work."""
        self._worker_stop.wait(timeout=0.1)

    def health_check(self) -> HealthStatus:
        """
        Check component health.

        Returns:
            HEALTHY if running and all worker threads are alive,
            UNHEALTHY otherwise.
        """
        if not self.is_running():
            return HealthStatus.UNHEALTHY
        if not self._worker_threads or any(not thread.is_alive() for thread in self._worker_threads):
            return HealthStatus.UNHEALTHY
        return HealthStatus.HEALTHY

    def _worker_loop(self) -> None:
        """Pull tasks from task_queue, dispatch to handlers, publish results."""
        while not self._worker_stop.is_set():
            try:
                task = self.task_queue.get(timeout=0.1)
            except QueueEmptyError:
                continue

            result_msg = self._process_task(task)
            self.result_queue.put(result_msg)

    def _process_task(self, task: Message) -> Message:
        """Dispatch a single task to its handler, producing a result message."""
        task_type = task.payload.get("task_type")
        context = task.payload.get("context", {})

        if not isinstance(task_type, TaskType):
            label = repr(task_type)
            logger.warning(f"{self.name}: no handler registered for task_type={label}")
            return create_task_result(
                task,
                status="error",
                error=f"no handler registered for task_type={label}",
                source=self.name,
            )

        handler = self.handlers.get(task_type)
        if handler is None:
            label = task_type.value
            logger.warning(f"{self.name}: no handler registered for task_type={label}")
            return create_task_result(
                task,
                status="error",
                error=f"no handler registered for task_type={label}",
                source=self.name,
            )

        try:
            result = handler.handle(context)
        except Exception as err:  # noqa: BLE001 - any handler failure becomes an error result
            logger.warning(f"{self.name}: handler for {task_type.value} failed: {err}")
            return create_task_result(task, status="error", error=str(err), source=self.name)

        return create_task_result(task, status="success", result=result, source=self.name)
