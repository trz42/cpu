# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Component orchestrator for lifecycle management and coordination.

This module provides the Orchestrator class which manages:
- Component registration
- Initialization and startup
- Health monitoring
- Graceful shutdown
"""

from __future__ import annotations

import logging
import signal
import threading
from typing import Any

from cpu.components.base import ComponentInterface, ComponentState, HealthStatus

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Manages component lifecycle and coordination.

    Responsibilities:
    - Component registration
    - Initialization and startup
    - Health monitoring
    - Graceful shutdown
    """

    def __init__(self) -> None:
        """Initialize orchestrator."""
        self._components: dict[str, ComponentInterface] = {}
        self._shutdown_requested = False
        self._threads: dict[str, threading.Thread] = {}
        logger.info("Initialized Orchestrator")

    def register(self, component: ComponentInterface) -> None:
        """
        Register a component.

        Args:
            component: Component to register

        Raises:
            ValueError: If component with same name already registered
        """
        if component.name in self._components:
            raise ValueError(f"Component {component.name} already registered")

        self._components[component.name] = component
        logger.info(f"Registered component: {component.name}")

    def get_component(self, name: str) -> ComponentInterface | None:
        """
        Get component by name.

        Args:
            name: Component name

        Returns:
            Component instance or None if not found
        """
        return self._components.get(name)

    def initialize_all(self) -> None:
        """
        Initialize all registered components.

        Raises:
            RuntimeError: If any component initialization fails or is running
        """
        logger.info("Initializing all components")
        for name in self._components:
            self.initialize_component(name)

    def start_all(self) -> None:
        """Start all components in separate threads."""
        logger.info("Starting all components")
        for name in self._components:
            self.start_component(name)

    def stop_all(self, timeout: float | None = None) -> None:
        """
        Stop all components gracefully.

        Components are stopped in reverse registration order, so
        components registered first (e.g. the logging component)
        are stopped last and remain available during shutdown of
        the others.

        Args:
            timeout: Maximum time to wait for all components to stop
        """
        logger.info("Stopping all components")
        for name in reversed(self._components):
            self.stop_component(name, timeout=timeout)

    def initialize_component(self, name: str) -> None:
        """
        Initialize a specific component.

        Args:
            name: Component name

        Raises:
            ValueError: If component not registered
            RuntimeError: If component is running
        """
        component = self._components.get(name)
        if component is None:
            raise ValueError(f"Component {name} not registered")

        # check if component is running
        if name in self._threads and self._threads[name].is_alive():
            raise RuntimeError(f"Cannot initialize component {name}: component is running")

        try:
            component.initialize()
        except Exception as err:
            raise RuntimeError(
                f"Failed to initialize component {name}: {err}"
            ) from err

    def start_component(self, name: str) -> None:
        """
        Start a specific component in a thread.

        Args:
            name: Component name

        Raises:
            ValueError: If component not registered
            RuntimeError: If component is already running or not initialized
        """
        component = self._components.get(name)
        if component is None:
            raise ValueError(f"Component {name} not registered")

        # check if already running
        if name in self._threads and self._threads[name].is_alive():
            raise RuntimeError(f"Component {name} is already running")

        # check if initialized
        if component.get_state() != ComponentState.INITIALIZED:
            raise RuntimeError(f"Component {name} is not initialized")

        thread = threading.Thread(
            target=component.start,
            name=f"cpu-{name}",
            daemon=False,
        )
        self._threads[name] = thread
        thread.start()

    def stop_component(self, name: str, timeout: float | None = None) -> None:
        """
        Stop a specific component.

        Args:
            name: Component name
            timeout: Maximum time to wait for shutdown

        Raises:
            ValueError: If component not registered
        """
        component = self._components.get(name)
        if component is None:
            raise ValueError(f"Component {name} not registered")

        component.stop(timeout=timeout)

        thread = self._threads.get(name)
        if thread and thread.is_alive():
            thread.join(timeout=timeout)

    def setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals."""
        del frame  # unused
        signal_name = signal.Signals(signum).name
        print(f"\nReceived {signal_name}, initiating graceful shutdown...")
        self._shutdown_requested = True
        self.stop_all(timeout=10)

    def health_check_all(self) -> dict[str, HealthStatus]:
        """
        Check health of all components.

        Returns:
            Dict mapping component names to health status
        """
        statuses = {}
        for name, component in self._components.items():
            status = component.health_check()
            statuses[name] = status
            logger.debug(f"Health check for component {name}: {status.value.upper()}")

        return statuses

    def is_healthy(self) -> bool:
        """
        Check if all components are healthy.

        Returns:
            True if all components are healthy
        """
        health = self.health_check_all()
        return all(status == HealthStatus.HEALTHY for status in health.values())
