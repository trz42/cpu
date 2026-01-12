# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for log rotation with compression.
"""

from __future__ import annotations

import gzip
import logging
from pathlib import Path

from cpu.logging.rotation import CompressingRotatingFileHandler


class TestCompressingRotatingFileHandler:
    """Test log rotation with compression."""

    def test_rotation_triggers_at_max_bytes(self, tmp_path: Path) -> None:
        """Test rotation triggers when max size reached."""
        log_file = tmp_path / "test.log"

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3,
        )

        # write enough to trigger rotation
        for item in range(20):
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=1,
                msg=f"Message {item}" * 10,
                args=(),
                exc_info=None,
            )
            handler.emit(record)

        handler.close()

        # should have rotated
        assert (tmp_path / "test.log.1.gz").exists()

    def test_old_logs_compressed_to_gzip(self, tmp_path: Path) -> None:
        """Test rotated logs are gzip compressed."""
        log_file = tmp_path / "test.log"

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=50,
            backupCount=2,
        )

        # trigger rotation
        for item in range(10):
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=1,
                msg=f"Message {item}" * 10,
                args=(),
                exc_info=None,
            )
            handler.emit(record)

        handler.close()

        gz_file = tmp_path / "test.log.1.gz"
        assert gz_file.exists()

        # verify it's valid gzip
        with gzip.open(gz_file, 'rt') as file:
            content = file.read()
            assert "Message" in content

    def test_backup_count_enforced(self, tmp_path: Path) -> None:
        """Test old backups are removed when limit reached."""
        log_file = tmp_path / "test.log"

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=50,
            backupCount=2,
        )

        # trigger multiple rotations
        for item in range(30):
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=1,
                msg=f"Message {item}" * 10,
                args=(),
                exc_info=None,
            )
            handler.emit(record)

        handler.close()

        # should only keep backupCount files
        assert (tmp_path / "test.log.1.gz").exists()
        assert (tmp_path / "test.log.2.gz").exists()
        assert not (tmp_path / "test.log.3.gz").exists()

    def test_rotation_preserves_current_log(self, tmp_path: Path) -> None:
        """Test current log file remains uncompressed."""
        log_file = tmp_path / "test.log"

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=50,
            backupCount=2,
        )

        for item in range(10):
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=1,
                msg=f"Message {item}" * 10,
                args=(),
                exc_info=None,
            )
            handler.emit(record)

        handler.close()

        # current log exists and is not compressed
        assert log_file.exists()
        assert not str(log_file).endswith('.gz')

    def test_compressed_logs_are_readable(self, tmp_path: Path) -> None:
        """Test compressed logs can be decompressed."""
        log_file = tmp_path / "test.log"

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=50,
            backupCount=2,
        )

        test_message = "UNIQUE_TEST_MESSAGE"
        for item in range(10):
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=1,
                msg=f"{test_message} {item}" * 10,
                args=(),
                exc_info=None,
            )
            handler.emit(record)

        handler.close()

        # decompress and verify
        with gzip.open(tmp_path / "test.log.1.gz", 'rt') as file:
            content = file.read()
            assert test_message in content
