# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.components.base module.

Tests abstract interfaces by creating concrete test implementations.
This ensures the interfaces are well-defined and implementable.
"""

from __future__ import annotations

import time

import pytest

from cpu.components.base import (
    ComponentState,
    HealthStatus,
    RunnableComponent,
)
from tests.unit.test_components_fixtures import MockComponent, MockRunnableComponent


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


class TestRunnableComponentClass:
    """Test RunnableComponent base class."""

    def test_runnable_component_start_without_initialize_fails(self) -> None:
        """Test that starting without initialization raises RuntimeError."""
        component = MockRunnableComponent(name="test")
        # Don't call initialize()

        with pytest.raises(RuntimeError, match="not initialized"):
            component.start()

    def test_runnable_component_runs_in_thread(self) -> None:
        """Test runnable component executes iterations."""
        import threading

        component = MockRunnableComponent(name="test")
        component.max_iterations = 5  # lower default of 10 to 5
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

        component = MockRunnableComponent(name="test")
        component.max_iterations = 100  # would run for 10 seconds
        component.initialize()

        thread = threading.Thread(target=component.start)
        thread.start()

        time.sleep(0.3)  # let it run a bit
        component.stop(timeout=1)

        thread.join(timeout=2)

        assert component.get_state() == ComponentState.STOPPED
        assert component.iterations < 100  # stopped early

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
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
