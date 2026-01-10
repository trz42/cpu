# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for component orchestrator.
"""

from __future__ import annotations

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


class TestOrchestratorStartStop:
    """Test component start/stop in orchestrator."""

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
