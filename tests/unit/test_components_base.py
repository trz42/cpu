# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.components.base module.

Tests abstract interfaces by creating concrete test implementations.
This ensures the interfaces are well-defined and implementable.
"""

from __future__ import annotations

import pytest

import time
from cpu.components.base import ComponentInterface, ComponentState, HealthStatus, RunnableComponent


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
        self.state = ComponentState.STOPPED

    def health_check(self) -> HealthStatus:
        """Check component health."""
        if self.state == ComponentState.RUNNING:
            return HealthStatus.HEALTHY
        return HealthStatus.UNHEALTHY


class TestComponentEnums:
    """Test component enumerations."""

    def test_component_states_are_distinct(self) -> None:
        """Test that component states have distinct values."""
        states = [
            ComponentState.CREATED,
            ComponentState.INITIALIZED,
            ComponentState.RUNNING,
            ComponentState.STOPPING,
            ComponentState.STOPPED,
            ComponentState.FAILED,
        ]
        assert len(states) == len(set(states))

    def test_health_status_values(self) -> None:
        """Test health status enumeration."""
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.DEGRADED.value == "degraded"


class TestComponentInterface:
    """Test ComponentInterface base class."""

    def test_component_creation(self) -> None:
        """Test component can be created with name."""
        component = MockComponent(name="test_component")
        assert component.name == "test_component"
        assert component.get_state() == ComponentState.CREATED

    def test_component_initialization(self) -> None:
        """Test component initialization."""
        component = MockComponent(name="test")
        component.initialize()
        assert component.get_state() == ComponentState.INITIALIZED

    def test_component_lifecycle(self) -> None:
        """Test complete component lifecycle."""
        component = MockComponent(name="test")

        # Created -> Initialized -> Running -> Stopped
        assert component.get_state() == ComponentState.CREATED

        component.initialize()
        assert component.get_state() == ComponentState.INITIALIZED

        component.start()
        assert component.get_state() == ComponentState.RUNNING
        assert component.is_running()

        component.stop()
        assert component.get_state() == ComponentState.STOPPED
        assert not component.is_running()

    def test_component_start_without_initialize_fails(self) -> None:
        """Test that starting without initialization raises error."""
        component = MockComponent(name="test")

        with pytest.raises(RuntimeError, match="not initialized"):
            component.start()

    def test_component_health_check(self) -> None:
        """Test component health checking."""
        component = MockComponent(name="test")
        component.initialize()
        component.start()

        assert component.health_check() == HealthStatus.HEALTHY

        component.stop()
        assert component.health_check() == HealthStatus.UNHEALTHY


class TestRunnableComponent(RunnableComponent):
    """Test implementation of runnable component."""

    def __init__(self, name: str, config: dict[str, object] | None = None) -> None:
        super().__init__(name, config)
        self.iterations = 0
        self.max_iterations = 5

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


class TestRunnableComponentClass:
    """Test RunnableComponent base class."""

    def test_runnable_component_start_without_initialize_fails(self) -> None:
        """Test that starting without initialization raises RuntimeError."""
        component = TestRunnableComponent(name="test")
        # Don't call initialize()

        with pytest.raises(RuntimeError, match="not initialized"):
            component.start()

    def test_runnable_component_runs_in_thread(self) -> None:
        """Test runnable component executes iterations."""
        import threading

        component = TestRunnableComponent(name="test")
        component.initialize()

        # Start in thread
        thread = threading.Thread(target=component.start)
        thread.start()

        # Wait for completion
        thread.join(timeout=2)

        assert component.iterations == 5
        assert component.get_state() == ComponentState.STOPPED

    def test_runnable_component_can_be_stopped(self) -> None:
        """Test runnable component responds to stop signal."""
        import threading

        component = TestRunnableComponent(name="test")
        component.max_iterations = 100  # Would run for 10 seconds
        component.initialize()

        thread = threading.Thread(target=component.start)
        thread.start()

        time.sleep(0.3)  # Let it run a bit
        component.stop(timeout=1)

        thread.join(timeout=2)

        assert component.get_state() == ComponentState.STOPPED
        assert component.iterations < 100  # Stopped early

    def test_runnable_component_exception_sets_failed_state(self) -> None:
        """Test that exceptions in process_iteration set FAILED state."""
        import threading

        class FailingComponent(RunnableComponent):
            def initialize(self) -> None:
                self.state = ComponentState.INITIALIZED

            def process_iteration(self) -> None:
                raise ValueError("Test error")

            def health_check(self) -> HealthStatus:
                return HealthStatus.UNHEALTHY

        component = FailingComponent(name="failing")
        component.initialize()

        thread = threading.Thread(target=component.start)
        thread.start()
        thread.join(timeout=1)

        assert component.get_state() == ComponentState.FAILED
