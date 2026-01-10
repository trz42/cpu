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

import threading

from cpu.components.base import ComponentInterface


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
        self._threads: dict[str, threading.Thread] = {}

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
            RuntimeError: If any component initialization fails
        """
        for name, component in self._components.items():
            try:
                component.initialize()
            except Exception as err:
                raise RuntimeError(
                    f"Failed to initialize component {name}: {err}"
                ) from err

    def start_all(self) -> None:
        """Start all components in separate threads."""
        for name, component in self._components.items():
            thread = threading.Thread(
                target=component.start,
                name=f"cpu-{name}",
                daemon=False,
            )
            self._threads[name] = thread
            thread.start()

    def stop_all(self, timeout: float | None = None) -> None:
        """
        Stop all components gracefully.

        Args:
            timeout: Maximum time to wait for all components to stop
        """
        # request all components to stop
        for component in self._components.values():
            component.stop(timeout=timeout)

        # wait for threads to finish
        per_thread_timeout = timeout / len(self._threads) if timeout and self._threads else None

        for thread in self._threads.values():
            if thread.is_alive():
                thread.join(timeout=per_thread_timeout)
