# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Shared test fixtures and utilities for components.
"""

from __future__ import annotations

import time

from cpu.components.base import (
    ComponentInterface,
    ComponentState,
    HealthStatus,
    RunnableComponent,
)


class MockComponent(ComponentInterface):
    """Mock component for testing."""

    def __init__(self, name: str, config: dict[str, object] | None = None) -> None:
        super().__init__(name, config)
        self._initialized = False

    def initialize(self) -> None:
        """Initialize the component."""
        self._initialized = True
        self.state = ComponentState.INITIALIZED

    def start(self) -> None:
        """Start the component."""
        if not self._initialized:
            raise RuntimeError("Component not initialized")
        self.state = ComponentState.RUNNING

    def stop(self, timeout: float | None = None) -> None:
        """Stop the component."""
        del timeout  # unused in mocked method
        self.state = ComponentState.STOPPED

    def health_check(self) -> HealthStatus:
        """Check component health."""
        if self.state == ComponentState.RUNNING:
            return HealthStatus.HEALTHY
        return HealthStatus.UNHEALTHY


class MockRunnableComponent(RunnableComponent):
    """Mock runnable component for testing."""

    def __init__(self, name: str, config: dict[str, object] | None = None) -> None:
        super().__init__(name, config)
        self.iterations = 0
        self.max_iterations = 10

    def initialize(self) -> None:
        """Initialize the component."""
        self.state = ComponentState.INITIALIZED

    def process_iteration(self) -> None:
        """Process one iteration."""
        self.iterations += 1
        time.sleep(0.1)
        if self.iterations >= self.max_iterations:
            self._stop_requested = True

    def health_check(self) -> HealthStatus:
        """Check component health."""
        return HealthStatus.HEALTHY if self.is_running() else HealthStatus.UNHEALTHY
