# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""Integration tests for __main__ logging wiring."""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from cpu.__main__ import create_orchestrator
from cpu.config.config import Config
from cpu.logging.queue_handler import QueueLoggingHandler
from cpu.messaging.interfaces import QueueEmptyError
from cpu.messaging.message import MessageType


class TestMainLoggingWiring:
    """Test that __main__ correctly wires queue-based logging."""

    def test_cpu_logger_uses_queue_handler_after_create_orchestrator(
        self, tmp_path: Path
    ) -> None:
        """Test cpu logger has QueueLoggingHandler after create_orchestrator."""
        config_file = tmp_path / "config.yaml"
        log_file = tmp_path / "cpu.log"
        config_file.write_text(f"""
bot:
  num_workers: 2
  logging:
    level: INFO
    file: {log_file}
    format: "%(levelname)s %(name)s %(message)s"
""")
        config = Config(config_file=config_file)
        config.load()

        create_orchestrator(config)

        cpu_logger = logging.getLogger("cpu")
        assert any(
            isinstance(h, QueueLoggingHandler) for h in cpu_logger.handlers
        )

    def test_logs_after_create_orchestrator_reach_queue(
        self, tmp_path: Path
    ) -> None:
        """Test log calls after create_orchestrator go to the queue."""
        config_file = tmp_path / "config.yaml"
        log_file = tmp_path / "cpu.log"
        config_file.write_text(f"""
bot:
  num_workers: 2
  logging:
    level: INFO
    file: {log_file}
""")
        config = Config(config_file=config_file)
        config.load()

        create_orchestrator(config)

        cpu_logger = logging.getLogger("cpu")
        handler = next(
            h for h in cpu_logger.handlers if isinstance(h, QueueLoggingHandler)
        )

        # Drain any messages queued during create_orchestrator() itself
        # (e.g. component initialization logs).
        with contextlib.suppress(QueueEmptyError):
            while True:
                handler._queue.get(block=False)

        cpu_logger.info("Post-orchestrator log")

        msg = handler._queue.get(timeout=1)
        assert msg.type == MessageType.LOG
        assert "Post-orchestrator log" in msg.payload["message"]

    def test_messages_buffered_before_logging_component_starts(
            self, tmp_path: Path
        ) -> None:
        """Test log messages are buffered in queue before LoggingComponent starts."""
        config_file = tmp_path / "config.yaml"
        log_file = tmp_path / "cpu.log"
        config_file.write_text(f"""
bot:
  num_workers: 2
  logging:
    level: INFO
    file: {log_file}
""")
        config = Config(config_file=config_file)
        config.load()

        # create orchestrator - switches to queue logging but doesn't start yet
        orchestrator = create_orchestrator(config)

        # log something before start_all()
        logger = logging.getLogger("cpu.test")
        logger.info("Buffered message")

        # verify message is in the queue but not yet written to file
        cpu_logger = logging.getLogger("cpu")
        handler = next(
            _handler for _handler in cpu_logger.handlers if isinstance(_handler, QueueLoggingHandler)
        )
        assert not handler._queue.empty()

        # now start and let LoggingComponent process the queue
        orchestrator.initialize_all()
        orchestrator.start_all()

        import time
        time.sleep(0.3)

        orchestrator.stop_all(timeout=2)

        # verify message reached the file
        assert log_file.exists()
        assert "Buffered message" in log_file.read_text()
