# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for component orchestrator.
"""

from __future__ import annotations

import logging
import time

import pytest

from cpu.components.base import (
    ComponentInterface,
    ComponentState,
    HealthStatus,
    RunnableComponent,
)
from cpu.components.orchestrator import Orchestrator
from tests.unit.test_components_fixtures import MockComponent, MockRunnableComponent


class TestOrchestratorRegistry:
    """Test component registration in orchestrator."""

    def test_orchestrator_register_component(self) -> None:
        """Test registering components."""
        orchestrator = Orchestrator()
        component = MockComponent(name="test")

        orchestrator.register(component)

        assert orchestrator.get_component("test") is component

    def test_orchestrator_register_duplicate_name_fails(self) -> None:
        """Test that duplicate component names are rejected."""
        orchestrator = Orchestrator()

        orchestrator.register(MockComponent(name="test"))

        with pytest.raises(ValueError, match="already registered"):
            orchestrator.register(MockComponent(name="test"))

    def test_orchestrator_get_nonexistent_component(self) -> None:
        """Test getting non-existent component returns None."""
        orchestrator = Orchestrator()

        assert orchestrator.get_component("nonexistent") is None


class TestOrchestratorInitialization:
    """Test component initialization in orchestrator."""

    def test_orchestrator_initialize_all(self) -> None:
        """Test initializing all components."""
        orchestrator = Orchestrator()
        orchestrator.register(MockComponent(name="comp1"))
        orchestrator.register(MockComponent(name="comp2"))

        orchestrator.initialize_all()

        comp1 = orchestrator.get_component("comp1")
        comp2 = orchestrator.get_component("comp2")
        assert comp1 is not None
        assert comp2 is not None
        assert comp1.get_state() == ComponentState.INITIALIZED
        assert comp2.get_state() == ComponentState.INITIALIZED

    def test_orchestrator_initialize_failure_stops_initialization(self) -> None:
        """Test that initialization failure is handled."""

        class FailingComponent(ComponentInterface):
            def initialize(self) -> None:
                raise RuntimeError("Initialization failed")

            def start(self) -> None:
                pass

            def stop(self, timeout: float | None = None) -> None:
                del timeout  # unused

            def health_check(self) -> HealthStatus:
                return HealthStatus.UNHEALTHY

        orchestrator = Orchestrator()
        orchestrator.register(FailingComponent(name="failing"))

        with pytest.raises(RuntimeError, match="Failed to initialize component failing"):
            orchestrator.initialize_all()


class TestOrchestratorAllComponentControl:
    """Test all components' initialization, start, and stop."""

    def test_orchestrator_start_all(self) -> None:
        """Test starting all components in threads."""
        orchestrator = Orchestrator()

        comp1 = MockRunnableComponent(name="comp1")
        comp1.max_iterations = 10
        comp2 = MockRunnableComponent(name="comp2")
        comp2.max_iterations = 10

        orchestrator.register(comp1)
        orchestrator.register(comp2)
        orchestrator.initialize_all()

        orchestrator.start_all()

        # Components should be running in threads
        time.sleep(0.2)
        assert comp1.is_running()
        assert comp2.is_running()

        # Stop and verify
        orchestrator.stop_all(timeout=2)

        assert comp1.get_state() == ComponentState.STOPPED
        assert comp2.get_state() == ComponentState.STOPPED

    def test_orchestrator_stop_timeout(self) -> None:
        """Test stop timeout handling."""

        class SlowStopComponent(RunnableComponent):
            def initialize(self) -> None:
                self.state = ComponentState.INITIALIZED

            def process_iteration(self) -> None:
                time.sleep(5)  # Takes long time

            def health_check(self) -> HealthStatus:
                return HealthStatus.HEALTHY

        orchestrator = Orchestrator()
        component = SlowStopComponent(name="slow")

        orchestrator.register(component)
        orchestrator.initialize_all()
        orchestrator.start_all()

        time.sleep(0.1)

        # should timeout and still complete
        orchestrator.stop_all(timeout=0.5)

        # component should be stopped or stopping
        assert component.get_state() in [ComponentState.STOPPED, ComponentState.STOPPING]

    def test_orchestrator_start_all_twice_raises_error(self) -> None:
        """Test that starting already-running components raises error."""
        orchestrator = Orchestrator()

        comp = MockRunnableComponent(name="comp1")
        orchestrator.register(comp)
        orchestrator.initialize_all()

        orchestrator.start_all()
        time.sleep(0.1)

        with pytest.raises(RuntimeError, match="already running"):
            orchestrator.start_all()

        orchestrator.stop_all(timeout=1)

    def test_initialize_all_while_components_running_raises_error(self) -> None:
        """Test that initialize_all with running components raises error."""
        orchestrator = Orchestrator()
        comp = MockRunnableComponent(name="test")
        orchestrator.register(comp)
        orchestrator.initialize_all()
        orchestrator.start_all()

        time.sleep(0.1)

        with pytest.raises(RuntimeError, match="is running"):
            orchestrator.initialize_all()

        orchestrator.stop_all(timeout=1)

    def test_start_all_not_initialized_raises_error(self) -> None:
        """Test start_all with non-initialized components raises error."""
        orchestrator = Orchestrator()
        comp = MockRunnableComponent(name="test")
        orchestrator.register(comp)
        # Don't initialize

        with pytest.raises(RuntimeError, match="not initialized"):
            orchestrator.start_all()

    def test_stop_all_with_non_running_components_is_safe(self) -> None:
        """Test stop_all with non-running components is safe."""
        orchestrator = Orchestrator()
        comp1 = MockComponent(name="comp1")
        comp2 = MockComponent(name="comp2")
        orchestrator.register(comp1)
        orchestrator.register(comp2)
        orchestrator.initialize_all()
        # Don't start

        # Should not raise
        orchestrator.stop_all(timeout=1)


class TestOrchestratorIndividualComponentControl:
    """Test individual component initialization, start, and stop."""

    def test_initialize_component(self) -> None:
        """Test initializing a specific component."""
        orchestrator = Orchestrator()
        comp = MockComponent(name="test")
        orchestrator.register(comp)

        orchestrator.initialize_component("test")

        assert comp.get_state() == ComponentState.INITIALIZED

    def test_initialize_component_not_registered(self) -> None:
        """Test initializing non-existent component raises error."""
        orchestrator = Orchestrator()

        with pytest.raises(ValueError, match="not registered"):
            orchestrator.initialize_component("nonexistent")

    def test_start_component(self) -> None:
        """Test starting a specific component."""
        orchestrator = Orchestrator()
        comp = MockRunnableComponent(name="test")
        orchestrator.register(comp)
        orchestrator.initialize_all()

        orchestrator.start_component("test")
        time.sleep(0.1)

        assert comp.is_running()

        orchestrator.stop_all(timeout=1)

    def test_start_component_not_registered(self) -> None:
        """Test starting non-existent component raises error."""
        orchestrator = Orchestrator()

        with pytest.raises(ValueError, match="not registered"):
            orchestrator.start_component("nonexistent")

    def test_start_component_twice_raises_error(self) -> None:
        """Test starting already-running component raises error."""
        orchestrator = Orchestrator()
        comp = MockRunnableComponent(name="test")
        orchestrator.register(comp)
        orchestrator.initialize_all()

        orchestrator.start_component("test")
        time.sleep(0.1)

        with pytest.raises(RuntimeError, match="already running"):
            orchestrator.start_component("test")

        orchestrator.stop_all(timeout=1)

    def test_stop_component(self) -> None:
        """Test stopping a specific component."""
        orchestrator = Orchestrator()
        comp = MockRunnableComponent(name="test")
        orchestrator.register(comp)
        orchestrator.initialize_all()
        orchestrator.start_component("test")

        time.sleep(0.1)
        orchestrator.stop_component("test", timeout=1)

        assert comp.get_state() == ComponentState.STOPPED

    def test_stop_component_not_registered(self) -> None:
        """Test stopping non-existent component raises error."""
        orchestrator = Orchestrator()

        with pytest.raises(ValueError, match="not registered"):
            orchestrator.stop_component("nonexistent")

# tests/unit/test_orchestrator.py - Add to TestOrchestratorIndividualComponentControl:

    def test_initialize_component_while_running_raises_error(self) -> None:
        """Test that initializing a running component raises error."""
        orchestrator = Orchestrator()
        comp = MockRunnableComponent(name="test")
        orchestrator.register(comp)
        orchestrator.initialize_component("test")
        orchestrator.start_component("test")

        time.sleep(0.1)

        with pytest.raises(RuntimeError, match="is running"):
            orchestrator.initialize_component("test")

        orchestrator.stop_all(timeout=1)

    def test_start_component_not_initialized_raises_error(self) -> None:
        """Test starting non-initialized component raises error."""
        orchestrator = Orchestrator()
        comp = MockRunnableComponent(name="test")
        orchestrator.register(comp)
        # Don't initialize

        with pytest.raises(RuntimeError, match="not initialized"):
            orchestrator.start_component("test")

    def test_stop_component_not_running_is_safe(self) -> None:
        """Test stopping non-running component is safe (no-op)."""
        orchestrator = Orchestrator()
        comp = MockComponent(name="test")
        orchestrator.register(comp)
        orchestrator.initialize_component("test")
        # Don't start

        # Should not raise
        orchestrator.stop_component("test", timeout=1)


class TestOrchestratorSignalHandling:
    """Test signal handling and graceful shutdown."""

    def test_orchestrator_signal_handler_registration(self) -> None:
        """Test that signal handlers can be registered."""
        from unittest.mock import patch

        orchestrator = Orchestrator()

        with patch("signal.signal") as mock_signal:
            orchestrator.setup_signal_handlers()

            # should register SIGTERM and SIGINT
            assert mock_signal.call_count == 2

    def test_orchestrator_handles_sigterm(self) -> None:
        """Test orchestrator handles SIGTERM gracefully."""
        orchestrator = Orchestrator()
        orchestrator.register(MockRunnableComponent(name="test"))
        orchestrator.initialize_all()
        orchestrator.start_all()

        time.sleep(0.1)

        # trigger shutdown via signal handler
        orchestrator._shutdown_requested = True
        orchestrator.stop_all(timeout=1)

        comp = orchestrator.get_component("test")
        assert comp is not None
        assert comp.get_state() == ComponentState.STOPPED


class TestOrchestratorHealthMonitoring:
    """Test health monitoring in orchestrator."""

    def test_orchestrator_health_check_all(self) -> None:
        """Test checking health of all components."""
        orchestrator = Orchestrator()

        comp1 = MockComponent(name="comp1")
        comp2 = MockComponent(name="comp2")

        orchestrator.register(comp1)
        orchestrator.register(comp2)
        orchestrator.initialize_all()
        orchestrator.start_all()

        health = orchestrator.health_check_all()

        assert health["comp1"] == HealthStatus.HEALTHY
        assert health["comp2"] == HealthStatus.HEALTHY

    def test_orchestrator_is_healthy(self) -> None:
        """Test overall health status."""
        orchestrator = Orchestrator()

        comp1 = MockComponent(name="comp1")
        orchestrator.register(comp1)
        orchestrator.initialize_all()
        orchestrator.start_all()

        assert orchestrator.is_healthy()


class TestOrchestratorLogging:
    """Test logging functionality in Orchestrator."""

    def test_orchestrator_creation_logs_at_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test orchestrator creation logs at INFO level."""
        caplog.set_level(logging.INFO)

        Orchestrator()

        assert "Initialized Orchestrator" in caplog.text

    def test_register_component_logs_at_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test component registration logs at INFO level."""
        caplog.set_level(logging.INFO)

        orchestrator = Orchestrator()
        component = MockComponent(name="test_component")

        caplog.clear()
        orchestrator.register(component)

        assert "Registered component: test_component" in caplog.text

    def test_initialize_all_logs_at_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test initialize_all logs at INFO level."""
        caplog.set_level(logging.INFO)

        orchestrator = Orchestrator()
        component = MockComponent(name="test_component")
        orchestrator.register(component)

        caplog.clear()
        orchestrator.initialize_all()

        assert "Initializing all components" in caplog.text

    def test_start_all_logs_at_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test start_all logs at INFO level."""
        caplog.set_level(logging.INFO)

        orchestrator = Orchestrator()
        component = MockRunnableComponent(name="test_component")
        orchestrator.register(component)
        orchestrator.initialize_all()

        caplog.clear()
        orchestrator.start_all()

        time.sleep(0.1)
        orchestrator.stop_all()

        assert "Starting all components" in caplog.text

    def test_stop_all_logs_at_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test stop_all logs at INFO level."""
        caplog.set_level(logging.INFO)

        orchestrator = Orchestrator()
        component = MockRunnableComponent(name="test_component")
        orchestrator.register(component)
        orchestrator.initialize_all()
        orchestrator.start_all()

        time.sleep(0.1)

        caplog.clear()
        orchestrator.stop_all()

        assert "Stopping all components" in caplog.text

    def test_health_check_all_logs_at_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test health_check_all logs at DEBUG level."""
        caplog.set_level(logging.DEBUG)

        orchestrator = Orchestrator()
        component = MockRunnableComponent(name="test_component")
        orchestrator.register(component)
        orchestrator.initialize_all()
        orchestrator.start_all()

        time.sleep(0.1)

        caplog.clear()
        statuses = orchestrator.health_check_all()

        orchestrator.stop_all()

        assert statuses["test_component"] == HealthStatus.HEALTHY
        assert "Health check for component test_component: HEALTHY" in caplog.text

    def test_stop_all_reverse_registration_order(self) -> None:
        """Test components are stopped in reverse registration order."""
        orchestrator = Orchestrator()
        stop_order: list[str] = []

        class OrderTrackingComponent(MockRunnableComponent):
            def stop(self, timeout: float | None = None) -> None:
                stop_order.append(self.name)
                super().stop(timeout=timeout)

        first = OrderTrackingComponent(name="first")
        second = OrderTrackingComponent(name="second")
        third = OrderTrackingComponent(name="third")

        orchestrator.register(first)
        orchestrator.register(second)
        orchestrator.register(third)
        orchestrator.initialize_all()
        orchestrator.start_all()

        orchestrator.stop_all(timeout=2)

        assert stop_order == ["third", "second", "first"]
