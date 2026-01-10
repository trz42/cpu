# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Base classes and interfaces for CPU bot components.

This module provides the foundational abstractions for all CPU bot components:
- ComponentState: Lifecycle state enumeration
- HealthStatus: Health status enumeration
- ComponentInterface: Abstract base class for all components
- RunnableComponent: Base class for components that run in a loop

All components follow a strict lifecycle:
1. CREATED - Component instantiated
2. INITIALIZED - Component configured and ready
3. RUNNING - Component actively processing
4. STOPPING - Shutdown initiated
5. STOPPED - Component fully stopped
6. FAILED - Component encountered error
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any


class ComponentState(Enum):
    """Component lifecycle states."""

    CREATED = "created"
    INITIALIZED = "initialized"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class HealthStatus(Enum):
    """Component health status."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"


class ComponentInterface(ABC):
    """
    Base interface for all CPU bot components.

    All components follow a strict lifecycle:
    1. CREATED - Component instantiated
    2. INITIALIZED - Component configured and ready
    3. RUNNING - Component actively processing
    4. STOPPING - Shutdown initiated
    5. STOPPED - Component fully stopped
    6. FAILED - Component encountered error
    """

    def __init__(self, name: str, config: dict[str, Any] | None = None) -> None:
        """
        Create component.

        Args:
            name: Component name
            config: Optional configuration dictionary
        """
        self.name = name
        self.config = config or {}
        self.state = ComponentState.CREATED

    @abstractmethod
    def initialize(self) -> None:
        """
        Initialize component (load config, setup resources).

        Must set state to INITIALIZED on success.
        """
        pass

    @abstractmethod
    def start(self) -> None:
        """
        Start component processing.

        Must set state to RUNNING on success.
        Should raise if not initialized.
        """
        pass

    @abstractmethod
    def stop(self, timeout: float | None = None) -> None:
        """
        Stop component gracefully.

        Args:
            timeout: Maximum time to wait for shutdown (seconds)

        Must set state to STOPPED on success.
        """
        del timeout  # parameter not used in interface definition
        pass

    @abstractmethod
    def health_check(self) -> HealthStatus:
        """
        Check component health.

        Returns:
            Current health status
        """
        pass

    def get_state(self) -> ComponentState:
        """Get current component state."""
        return self.state

    def is_running(self) -> bool:
        """Check if component is running."""
        return self.state == ComponentState.RUNNING


class RunnableComponent(ComponentInterface):
    """
    Base class for components that run in a loop.

    Implements start() and stop() defined in ComponentInterface.

    Adds abstract method process_iteration().

    Subclasses must implement:
    - initialize(): Setup
    - process_iteration(): One loop iteration
    - health_check(): Health status
    """

    def __init__(self, name: str, config: dict[str, Any] | None = None) -> None:
        """
        Initialize runnable component.

        Args:
            name: Component name
            config: Optional configuration dictionary
        """
        super().__init__(name, config)
        self._stop_requested = False

    def start(self) -> None:
        """Start the component's main loop."""
        if self.state != ComponentState.INITIALIZED:
            raise RuntimeError(f"Component {self.name} not initialized")

        self.state = ComponentState.RUNNING
        self._stop_requested = False

        try:
            while not self._stop_requested:
                self.process_iteration()
        except Exception as err:
            self.state = ComponentState.FAILED
            raise err
        finally:
            if self.state != ComponentState.FAILED:
                self.state = ComponentState.STOPPED

    @abstractmethod
    def process_iteration(self) -> None:
        """
        Process one iteration of the component's work.

        Should check self._stop_requested and return if True.
        """
        pass

    def stop(self, timeout: float | None = None) -> None:
        """Request component to stop."""
        del timeout  # not used in base implementation
        self._stop_requested = True
        self.state = ComponentState.STOPPING
