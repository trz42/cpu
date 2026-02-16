# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Integration tests for logging across components.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from cpu.components.base import ComponentState, HealthStatus, RunnableComponent
from cpu.components.orchestrator import Orchestrator
from cpu.config.config import Config
from cpu.logging.decorators import trace_calls
from cpu.logging.sanitizer import LogSanitizer
from cpu.logging.setup import TRACE, configure_logging
from cpu.messaging.message import Message, MessageType
from cpu.messaging.queue_thread import ThreadMessageQueue


class TestLoggingIntegration:
    """Test logging behavior across multiple components."""

    def test_end_to_end_logging_flow(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test logging from message creation through queue to delivery."""
        caplog.set_level(TRACE)

        # create message
        msg = Message(type=MessageType.WEBHOOK, payload={"test": "data"})

        # put in queue
        queue: ThreadMessageQueue[Message] = ThreadMessageQueue()
        queue.put(msg)

        # get from queue
        queue.get(timeout=1)

        # verify logging at each stage
        assert "Created message" in caplog.text or "Message" in caplog.text
        assert "queue" in caplog.text.lower()

    def test_log_levels_hierarchy(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that log level settings are respected."""
        # test TRACE filtered when level is DEBUG
        logger = logging.getLogger("test.hierarchy")
        logger.setLevel(logging.DEBUG)

        with caplog.at_level(logging.DEBUG):
            logger.log(TRACE, "Should not appear")
            logger.debug("Should appear")

        messages = [rec.message for rec in caplog.records]
        assert "Should not appear" not in messages
        assert "Should appear" in messages

    def test_per_module_log_levels(self, tmp_path: Path) -> None:
        """Test different log levels for different modules."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
bot:
  num_workers: 2
  logging:
    level: INFO
    loggers:
      cpu.messaging: DEBUG
      cpu.components: WARNING
""")

        config = Config(config_file=config_file)
        config.load()
        configure_logging(config)

        # verify levels are set correctly
        messaging_logger = logging.getLogger("cpu.messaging")
        components_logger = logging.getLogger("cpu.components")

        assert messaging_logger.level == logging.DEBUG or messaging_logger.getEffectiveLevel() == logging.DEBUG
        assert components_logger.level == logging.WARNING or components_logger.getEffectiveLevel() == logging.WARNING

    def test_trace_decorator_overhead(self) -> None:
        """Ensure trace decorator doesn't significantly impact performance."""
        # function without decorator
        def plain_function(number: int) -> int:
            result = 0
            for idx in range(number):
                result += idx * idx
            return result

        # function with decorator
        @trace_calls(level=TRACE)
        def traced_function(number: int) -> int:
            result = 0
            for idx in range(number):
                result += idx * idx
            return result

        # disable TRACE logging (realistic production scenario)
        logger = logging.getLogger("cpu.logging.decorators")
        logger.setLevel(logging.INFO)

        # warm up
        for _ in range(100):
            plain_function(1000)
            traced_function(1000)

        # benchmark plain
        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            plain_function(1000)
        plain_time = time.perf_counter() - start

        # benchmark traced (with TRACE disabled)
        start = time.perf_counter()
        for _ in range(iterations):
            traced_function(1000)
        traced_time = time.perf_counter() - start

        logger = logging.getLogger("cpu.logging.decorators")
        logger.setLevel(logging.INFO)  # TRACE disabled

        # overhead should be minimal when TRACE is disabled
        overhead = (traced_time - plain_time) / plain_time if plain_time > 0 else 0

        # allow up to 20% overhead (decorator still has some cost even when disabled)
        assert overhead < 0.20, (
            f"Overhead too high: {overhead:.1%} (plain: {plain_time:.4f}s, traced: {traced_time:.4f}s)"
        )

    def test_orchestrator_logging_lifecycle(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test orchestrator logs component lifecycle events."""
        logging.getLogger("cpu.components.orchestrator").setLevel(logging.INFO)
        caplog.set_level(logging.INFO)

        # create a simple real component instead of a mock
        class TestComponent(RunnableComponent):
            def initialize(self) -> None:
                self.state = ComponentState.INITIALIZED

            def process_iteration(self) -> None:
                pass  # not needed for this test

            def health_check(self) -> HealthStatus:
                return HealthStatus.HEALTHY

        component = TestComponent(name="test_component")

        caplog.clear()  # clear any previous logs

        orchestrator = Orchestrator()
        orchestrator.register(component)

        # verify registration logged
        assert ("Registered component: test_component" in caplog.text or
                any("test_component" in rec.message for rec in caplog.records))

    def test_no_sensitive_data_in_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that sensitive data is not logged."""
        caplog.set_level(TRACE)

        sanitizer = LogSanitizer()

        # test various sensitive patterns
        sensitive_messages = [
            "Bearer token12345",
            "password=secret123",
            "api_key=abcdef123456",
        ]

        for msg in sensitive_messages:
            sanitized = sanitizer.sanitize(msg)
            # verify secrets are masked
            assert "token12345" not in sanitized
            assert "secret123" not in sanitized
            assert "abcdef123456" not in sanitized
            assert "***" in sanitized
