# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Smee webhook proxy client component.

Connects to a smee.io (or compatible) channel via Server-Sent Events (SSE)
and publishes incoming webhook events to a message bus topic, so any
number of subscribers (typically the event handler) can receive them.
"""

from __future__ import annotations

import contextlib
import json
import logging
import queue
import threading
from typing import Any

import requests

from cpu.components.base import ComponentState, HealthStatus, RunnableComponent
from cpu.config.secrets import SecretManager, SecretNotFoundError
from cpu.messaging.interfaces import MessageBusInterface
from cpu.messaging.message import Message, MessageType

logger = logging.getLogger(__name__)


class SmeeConnectionError(Exception):
    """Raised when the Smee client cannot be configured or connected."""

    pass


class SmeeClientComponent(RunnableComponent):
    """
    Connects to a Smee channel and publishes received webhook events.

    The component runs an SSE (Server-Sent Events) connection to the
    configured Smee channel URL in a background thread. Incoming events
    are parsed (JSON-decoded SSE ``data:`` lines) and placed on an
    internal queue. The main component loop (``process_iteration``)
    drains this queue and publishes each event as-is — as the
    ``payload`` of a ``Message(type=MessageType.WEBHOOK, source=self.name)``
    — to the configured topic on the message bus (pub/sub), so any
    number of subscribers can receive a copy.

    The payload is the raw JSON object received from Smee, typically
    containing a ``body`` (the original webhook payload), ``query``
    (forwarded query parameters), and the original request headers as
    top-level keys (e.g. ``x-github-event``, ``x-github-delivery``).
    This component does not inspect or interpret the payload contents
    or determine the source platform (GitHub, GitLab, ...) — that is
    left to downstream subscribers (e.g. the event handler).

    Delivery is at-most-once: events are not persisted or retried by
    this component if a subscriber fails to process them.

    Reconnects automatically (with a configurable delay) if the SSE
    connection fails or is closed by the server.
    """

    def __init__(
        self,
        name: str,
        message_bus: MessageBusInterface[Message],
        secrets_manager: SecretManager,
        topic: str = "webhook_events",
        reconnect_delay: float = 5.0,
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Create the Smee client component.

        Args:
            name: Component name
            message_bus: Bus to publish received webhook events to
            secrets_manager: Provides the Smee channel URL (treated as a
                secret, since it grants access to the webhook channel)
            topic: Topic to publish webhook messages to (pub/sub)
            reconnect_delay: Seconds to wait before reconnecting after
                a connection error
            config: Optional configuration dictionary
        """
        super().__init__(name, config)
        self.message_bus = message_bus
        self.secrets_manager = secrets_manager
        self.channel_url: str | None = None
        self.topic = topic
        self.reconnect_delay = reconnect_delay

        self._event_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._reader_thread: threading.Thread | None = None
        self._reader_stop = threading.Event()
        self._response: requests.Response | None = None

    def initialize(self) -> None:
        """
        Resolve the Smee channel URL from secrets and prepare internal state.

        Raises:
            SmeeConnectionError: If the channel URL cannot be resolved
        """
        try:
            secrets = self.secrets_manager.get_smee_secrets()
        except SecretNotFoundError as err:
            raise SmeeConnectionError(f"Failed to load Smee secrets: {err}") from err

        if not secrets.channel_url:
            raise SmeeConnectionError("Smee channel_url must be set")

        self.channel_url = secrets.channel_url
        self.state = ComponentState.INITIALIZED
        logger.info(f"Initialized {self.name} for configured Smee channel")

    def start(self) -> None:
        """Start the SSE reader thread, then run the main processing loop."""
        if self.state != ComponentState.INITIALIZED:
            raise RuntimeError(f"Component {self.name} not initialized")

        self._reader_stop.clear()
        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            name=f"{self.name}-reader",
            daemon=True,
        )
        self._reader_thread.start()

        super().start()

    def stop(self, timeout: float | None = None) -> None:
        """
        Stop the component and the SSE reader thread.

        Args:
            timeout: Maximum time to wait for the reader thread to stop
        """
        super().stop(timeout)

        self._reader_stop.set()
        if self._response is not None:
            try:
                self._response.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                logger.debug(f"{self.name}: error closing SSE response", exc_info=True)

        if self._reader_thread is not None:
            self._reader_thread.join(timeout=timeout)

    def process_iteration(self) -> None:
        """Drain the internal event queue and publish webhook messages."""
        try:
            event_data = self._event_queue.get(timeout=0.1)
        except queue.Empty:
            return

        message = Message(
            type=MessageType.WEBHOOK,
            payload=event_data,
            source=self.name,
        )
        self.message_bus.publish(self.topic, message)
        logger.debug(f"{self.name}: published webhook message {message.id[:8]}... to '{self.topic}'")

    def health_check(self) -> HealthStatus:
        """
        Check component health.

        Returns:
            HEALTHY if running and the SSE reader thread is alive,
            UNHEALTHY otherwise.
        """
        if not self.is_running():
            return HealthStatus.UNHEALTHY
        if self._reader_thread is None or not self._reader_thread.is_alive():
            return HealthStatus.UNHEALTHY
        return HealthStatus.HEALTHY

    def _reader_loop(self) -> None:
        """Connect to the Smee channel and feed parsed events into the queue."""
        assert self.channel_url is not None  # set during initialize()
        headers = {"Accept": "text/event-stream"}

        while not self._reader_stop.is_set():
            try:
                logger.info(f"{self.name}: connecting to {self.channel_url}")
                response = requests.get(
                    self.channel_url,
                    headers=headers,
                    stream=True,
                    timeout=(10, None),
                )
                response.raise_for_status()
                self._response = response

                for raw_line in response.iter_lines():
                    if self._reader_stop.is_set():
                        break

                    event_data = self._parse_sse_line(raw_line)
                    if event_data is not None:
                        self._event_queue.put(event_data)

            except Exception as err:  # noqa: BLE001 - any connection error triggers reconnect
                logger.warning(f"{self.name}: connection error: {err}")
            finally:
                if self._response is not None:
                    with contextlib.suppress(Exception):
                        self._response.close()
                    self._response = None

            if not self._reader_stop.is_set():
                self._reader_stop.wait(self.reconnect_delay)

        logger.info(f"{self.name}: reader thread stopped")

    @staticmethod
    def _parse_sse_line(raw_line: bytes | str) -> dict[str, Any] | None:
        """
        Parse a single SSE line, returning event data if it's a usable
        'data:' line containing JSON, or None otherwise.

        Args:
            raw_line: A line yielded by requests' iter_lines()

        Returns:
            Parsed JSON payload as dict, or None if the line should be skipped
        """
        if isinstance(raw_line, bytes):
            line = raw_line.decode("utf-8", errors="replace")
        else:
            line = raw_line

        if not line.startswith("data:"):
            return None

        data = line[len("data:"):].strip()
        if not data:
            return None

        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            logger.debug("Ignoring non-JSON SSE data line")
            return None

        if not isinstance(parsed, dict):
            logger.debug("Ignoring non-object SSE JSON payload")
            return None

        return parsed
