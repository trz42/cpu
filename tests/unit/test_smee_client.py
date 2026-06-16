# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for cpu.smee.client module which provides the SmeeClientComponent.

SmeeClientComponent connects to a smee.io (or compatible) channel via
Server-Sent Events (SSE), and publishes incoming webhook events to a
message bus topic so any number of subscribers (e.g. the event handler)
can receive them.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cpu.components.base import ComponentState, HealthStatus
from cpu.config.secrets import SecretManager, SecretNotFoundError, SmeeSecrets
from cpu.messaging.bus_thread import ThreadMessageBus
from cpu.messaging.message import Message, MessageType
from cpu.smee.client import SmeeClientComponent, SmeeConnectionError


def _make_secrets_manager(channel_url: str | None = "https://smee.io/abc123") -> MagicMock:
    """Build a mocked SecretManager returning the given channel_url (or raising)."""
    manager = MagicMock(spec=SecretManager)
    if channel_url is None:
        manager.get_smee_secrets.side_effect = SecretNotFoundError("no smee config")
    else:
        manager.get_smee_secrets.return_value = SmeeSecrets(channel_url=channel_url)
    return manager


def _sse_lines(*payloads: dict[str, Any]) -> list[bytes]:
    """Build raw SSE 'data:' lines (as iter_lines would yield) for given payloads."""
    lines: list[bytes] = []
    for payload in payloads:
        lines.append(f"data: {json.dumps(payload)}".encode())
        lines.append(b"")  # blank line terminates an SSE event
    return lines


class FakeResponse:
    """Minimal stand-in for requests.Response supporting streaming iteration."""

    def __init__(self, lines: list[bytes], status_code: int = 200) -> None:
        self._lines = lines
        self.status_code = status_code
        self.closed = False

    def iter_lines(self) -> Iterator[bytes]:
        for line in self._lines:
            if self.closed:
                return
            yield line
        # Simulate a long-lived connection that doesn't end on its own
        # unless explicitly closed.
        while not self.closed:
            time.sleep(0.01)

    def close(self) -> None:
        self.closed = True

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class TestSmeeClientComponentInitialization:
    """Tests for initialization and configuration."""

    def test_initialization_sets_state(self) -> None:
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()
        assert client.get_state() == ComponentState.INITIALIZED

    def test_rejects_empty_channel_url(self) -> None:
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(channel_url=""),
        )
        with pytest.raises(SmeeConnectionError):
            client.initialize()

    def test_rejects_missing_secret(self) -> None:
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(channel_url=None),
        )
        with pytest.raises(SmeeConnectionError):
            client.initialize()

    def test_default_topic_is_webhook_events(self) -> None:
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        assert client.topic == "webhook_events"

    def test_custom_topic(self) -> None:
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
            topic="custom_topic",
        )
        assert client.topic == "custom_topic"


class TestSmeeClientComponentEventHandling:
    """Tests for receiving and publishing webhook events."""

    @patch("cpu.smee.client.requests.get")
    def test_publishes_webhook_message_on_event(self, mock_get: MagicMock) -> None:
        payload = {
            "body": {"action": "opened", "number": 42},
            "query": {},
            "x-github-event": "pull_request",
            "x-github-delivery": "abc-123",
        }
        mock_get.return_value = FakeResponse(_sse_lines(payload))

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        subscriber = bus.subscribe("webhook_events")

        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()

        msg = subscriber.get(timeout=2)
        client.stop(timeout=2)
        thread.join(timeout=2)

        assert msg.type == MessageType.WEBHOOK
        assert msg.payload == payload
        assert msg.source == "smee"

    @patch("cpu.smee.client.requests.get")
    def test_ignores_non_data_lines(self, mock_get: MagicMock) -> None:
        payload = {"body": {"ok": True}}
        lines = [b": this is a comment", b"event: ready", b""] + _sse_lines(payload)
        mock_get.return_value = FakeResponse(lines)

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        subscriber = bus.subscribe("webhook_events")

        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()

        msg = subscriber.get(timeout=2)
        client.stop(timeout=2)
        thread.join(timeout=2)

        assert msg.payload == payload

    @patch("cpu.smee.client.requests.get")
    def test_ignores_malformed_json(self, mock_get: MagicMock) -> None:
        good_payload = {"body": {"ok": True}}
        lines = [b"data: not-json", b""] + _sse_lines(good_payload)
        mock_get.return_value = FakeResponse(lines)

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        subscriber = bus.subscribe("webhook_events")

        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()

        msg = subscriber.get(timeout=2)
        client.stop(timeout=2)
        thread.join(timeout=2)

        assert msg.payload == good_payload

    @patch("cpu.smee.client.requests.get")
    def test_no_subscribers_does_not_block(self, mock_get: MagicMock) -> None:
        """Publishing with no subscribers should drop the message, not block."""
        payload = {"body": {"ok": True}}
        mock_get.return_value = FakeResponse(_sse_lines(payload))

        bus: ThreadMessageBus[Message] = ThreadMessageBus()

        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()
        time.sleep(0.2)
        client.stop(timeout=2)
        thread.join(timeout=2)

        assert client.get_state() == ComponentState.STOPPED

    @patch("cpu.smee.client.requests.get")
    def test_stop_during_line_iteration_breaks_loop(self, mock_get: MagicMock) -> None:
        """If _reader_stop is set while iterating SSE lines, the loop should break early."""
        first_payload = {"body": {"first": True}}
        second_payload = {"body": {"second": True}}

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        subscriber = bus.subscribe("webhook_events")

        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        # Custom response whose iter_lines sets _reader_stop after the first
        # event, then yields a second event that should NOT be processed.
        lines = _sse_lines(first_payload) + _sse_lines(second_payload)

        class StoppingResponse(FakeResponse):
            def iter_lines(self) -> Iterator[bytes]:
                for i, line in enumerate(self._lines):
                    if i == 2:  # after first event's data+blank lines
                        client._reader_stop.set()
                    yield line

        mock_get.return_value = StoppingResponse(lines)

        thread = threading.Thread(target=client.start)
        thread.start()

        msg = subscriber.get(timeout=2)
        client.stop(timeout=2)
        thread.join(timeout=2)

        assert msg.payload == first_payload
        # second event must not have been queued/published
        assert subscriber.empty()
        assert not thread.is_alive()


class TestParseSseLine:
    """Direct tests for SmeeClientComponent._parse_sse_line."""

    def test_parses_bytes_data_line(self) -> None:
        line = b'data: {"body": {"ok": true}}'
        assert SmeeClientComponent._parse_sse_line(line) == {"body": {"ok": True}}

    def test_parses_str_data_line(self) -> None:
        line = 'data: {"body": {"ok": true}}'
        assert SmeeClientComponent._parse_sse_line(line) == {"body": {"ok": True}}

    def test_non_data_line_returns_none(self) -> None:
        assert SmeeClientComponent._parse_sse_line(b"event: ready") is None

    def test_empty_data_returns_none(self) -> None:
        assert SmeeClientComponent._parse_sse_line(b"data:") is None
        assert SmeeClientComponent._parse_sse_line(b"data:   ") is None

    def test_non_json_data_returns_none(self) -> None:
        assert SmeeClientComponent._parse_sse_line(b"data: not-json") is None

    def test_non_object_json_returns_none(self) -> None:
        assert SmeeClientComponent._parse_sse_line(b"data: [1, 2, 3]") is None
        assert SmeeClientComponent._parse_sse_line(b"data: 42") is None


class TestSmeeClientComponentLifecycle:
    """Tests for start/stop lifecycle and reconnection."""

    @patch("cpu.smee.client.requests.get")
    def test_stop_terminates_cleanly(self, mock_get: MagicMock) -> None:
        mock_get.return_value = FakeResponse(_sse_lines({"body": {}}))

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()
        time.sleep(0.2)

        client.stop(timeout=2)
        thread.join(timeout=2)

        assert client.get_state() == ComponentState.STOPPED
        assert not thread.is_alive()

    @patch("cpu.smee.client.requests.get")
    def test_health_check_healthy_while_running(self, mock_get: MagicMock) -> None:
        mock_get.return_value = FakeResponse(_sse_lines({"body": {}}))

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()
        time.sleep(0.2)

        assert client.health_check() == HealthStatus.HEALTHY

        client.stop(timeout=2)
        thread.join(timeout=2)

    @patch("cpu.smee.client.requests.get")
    def test_health_check_unhealthy_when_reader_thread_dies(self, mock_get: MagicMock) -> None:
        """If the component is running but the SSE reader thread has died, report UNHEALTHY."""
        mock_get.return_value = FakeResponse(_sse_lines({"body": {}}))

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()
        time.sleep(0.2)

        # Simulate the reader thread having died unexpectedly.
        dead_thread = threading.Thread(target=lambda: None)
        dead_thread.start()
        dead_thread.join()
        client._reader_thread = dead_thread

        assert client.health_check() == HealthStatus.UNHEALTHY

        client.stop(timeout=2)
        thread.join(timeout=2)

    def test_health_check_unhealthy_before_start(self) -> None:
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()
        assert client.health_check() == HealthStatus.UNHEALTHY

    def test_start_before_initialize_raises(self) -> None:
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        with pytest.raises(RuntimeError):
            client.start()

    def test_stop_without_start_is_safe(self) -> None:
        """
        stop() before start() should not raise (no response, no reader
        thread to clean up). State becomes STOPPING, since STOPPED is only
        set by the start() loop when it observes the stop request.
        """
        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()
        client.stop(timeout=1)
        assert client.get_state() == ComponentState.STOPPING

    @patch("cpu.smee.client.requests.get")
    def test_stop_handles_response_close_error(self, mock_get: MagicMock) -> None:
        """stop() should tolerate an exception raised while closing the SSE response."""
        response = FakeResponse(_sse_lines({"body": {}}))
        mock_get.return_value = response

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()
        time.sleep(0.2)

        with patch.object(response, "close", side_effect=RuntimeError("close failed")):
            client.stop(timeout=2)

        thread.join(timeout=2)
        assert client.get_state() == ComponentState.STOPPED

    @patch("cpu.smee.client.requests.get")
    def test_reconnects_after_connection_error(self, mock_get: MagicMock) -> None:
        """If requests.get raises, the reader retries instead of crashing the component."""
        good_payload = {"body": {"ok": True}}
        mock_get.side_effect = [
            ConnectionError("boom"),
            FakeResponse(_sse_lines(good_payload)),
        ]

        bus: ThreadMessageBus[Message] = ThreadMessageBus()
        subscriber = bus.subscribe("webhook_events")

        client = SmeeClientComponent(
            name="smee",
            message_bus=bus,
            secrets_manager=_make_secrets_manager(),
            reconnect_delay=0.01,
        )
        client.initialize()

        thread = threading.Thread(target=client.start)
        thread.start()

        msg = subscriber.get(timeout=2)
        client.stop(timeout=2)
        thread.join(timeout=2)

        assert msg.payload == good_payload
        assert client.get_state() == ComponentState.STOPPED
