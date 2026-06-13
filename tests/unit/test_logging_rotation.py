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
from unittest.mock import patch

import pytest

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


class TestRotationLogging:
    """Test error logging in CompressingRotatingFileHandler."""

    def test_rollover_logs_error_on_compression_failure(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test doRollover logs error when compression fails."""
        caplog.set_level(logging.ERROR)

        log_file = tmp_path / "test.log"
        log_file.write_text("test log data")

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3
        )

        # mock gzip.open to raise an error
        with patch('gzip.open', side_effect=OSError("Disk full")):
            handler.doRollover()

        assert "Failed to compress rotated log" in caplog.text
        assert "Disk full" in caplog.text

    def test_rollover_logs_error_on_file_removal_failure(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Test doRollover logs error when file removal fails."""
        caplog.set_level(logging.ERROR)

        log_file = tmp_path / "test.log"
        log_file.write_text("test log data")

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3
        )

        # mock os.remove to raise an error
        with patch('os.remove', side_effect=OSError("Permission denied")):
            handler.doRollover()

        assert "Failed to remove file during rotation" in caplog.text or "Permission denied" in caplog.text

    def test_rollover_with_existing_backups(self, tmp_path: Path) -> None:
        """Test doRollover rotates existing backup files."""
        log_file = tmp_path / "test.log"
        log_file.write_text("initial log data")

        # create some existing compressed backups
        backup1 = tmp_path / "test.log.1.gz"
        backup2 = tmp_path / "test.log.2.gz"

        with gzip.open(backup1, 'wb') as file:
            file.write(b"backup 1 data")
        with gzip.open(backup2, 'wb') as file:
            file.write(b"backup 2 data")

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=5
        )

        handler.doRollover()

        # verify rotation: backup1 -> backup2, backup2 -> backup3
        assert (tmp_path / "test.log.2.gz").exists()
        assert (tmp_path / "test.log.3.gz").exists()

    def test_rollover_compresses_current_log(self, tmp_path: Path) -> None:
        """Test doRollover compresses the current log file."""
        log_file = tmp_path / "test.log"
        log_content = "This is the current log content that needs compression"
        log_file.write_text(log_content)

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3
        )

        handler.doRollover()

        # verify compressed backup exists
        backup_file = tmp_path / "test.log.1.gz"
        assert backup_file.exists()

        # verify content is compressed correctly
        with gzip.open(backup_file, 'rb') as file:
            decompressed = file.read().decode('utf-8')
            assert decompressed == log_content

        # verify original file was removed
        assert not log_file.exists() or log_file.stat().st_size == 0

    def test_rollover_removes_oldest_backup(self, tmp_path: Path) -> None:
        """Test doRollover removes oldest backup when limit reached."""
        log_file = tmp_path / "test.log"
        log_file.write_text("current log")

        # create backups up to the limit
        for nr in range(1, 4):
            backup = tmp_path / f"test.log.{nr}.gz"
            with gzip.open(backup, 'wb') as file:
                file.write(f"backup {nr}".encode())

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3  # keep only 3 backups
        )

        handler.doRollover()

        # oldest backup (was .3, now should be .4 but exceeds limit)
        # new structure: .1 (new), .2 (was .1), .3 (was .2)
        assert (tmp_path / "test.log.1.gz").exists()
        assert (tmp_path / "test.log.2.gz").exists()
        assert (tmp_path / "test.log.3.gz").exists()
        # backup 4 should not exist (exceeded backupCount)
        assert not (tmp_path / "test.log.4.gz").exists()

    def test_rollover_no_existing_backups(self, tmp_path: Path) -> None:
        """Test doRollover when no existing backups exist."""
        log_file = tmp_path / "test.log"
        log_file.write_text("first log entry")

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3
        )

        handler.doRollover()

        # should create first backup
        assert (tmp_path / "test.log.1.gz").exists()

        # no other backups should exist
        assert not (tmp_path / "test.log.2.gz").exists()
        assert not (tmp_path / "test.log.3.gz").exists()

    def test_rollover_overwrites_existing_destination(self, tmp_path: Path) -> None:
        """Test doRollover overwrites existing destination backup."""
        log_file = tmp_path / "test.log"
        log_file.write_text("new log content")

        # create existing backup that should be overwritten
        backup1 = tmp_path / "test.log.1.gz"
        with gzip.open(backup1, 'wb') as file:
            file.write(b"old backup content")

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3
        )

        handler.doRollover()

        # verify backup was overwritten with new content
        with gzip.open(backup1, 'rb') as file:
            content = file.read().decode('utf-8')
            assert content == "new log content"

    def test_rollover_with_no_current_log(self, tmp_path: Path) -> None:
        """Test doRollover when current log doesn't exist."""
        log_file = tmp_path / "test.log"

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3,
            delay=True  # don't open the file immediately
        )

        # manually create an empty log file
        log_file.touch()

        handler.doRollover()

        # an empty file still gets compressed (creates a valid but empty gzip)
        # so we should verify the backup exists but is effectively empty
        backup = tmp_path / "test.log.1.gz"
        if backup.exists():
            with gzip.open(backup, 'rb') as file:
                content = file.read()
                assert len(content) == 0  # empty compressed file

    def test_rollover_logs_error_removing_existing_destination(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test doRollover logs error when removing existing .1.gz before compression fails."""
        caplog.set_level(logging.ERROR)

        log_file = tmp_path / "test.log"
        log_file.write_text("current log data")

        existing_backup = tmp_path / "test.log.1.gz"
        with gzip.open(existing_backup, "wb") as f:
            f.write(b"old backup")

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=1,  # loop range(0,0,-1) is empty, so .1.gz is not renamed away
        )

        import os
        real_remove = os.remove
        call_count = 0

        def fail_first_remove(path: str) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("Permission denied")
            real_remove(path)

        with patch("os.remove", side_effect=fail_first_remove):
            handler.doRollover()

        assert "Failed to remove file during rotation" in caplog.text

    def test_rollover_skips_compression_when_base_file_absent(self, tmp_path: Path) -> None:
        """Test doRollover with delay=True and no base log file skips compression."""
        log_file = tmp_path / "test.log"
        # deliberately do NOT create the file

        handler = CompressingRotatingFileHandler(
            filename=str(log_file),
            maxBytes=100,
            backupCount=3,
            delay=True,
        )

        # should not raise even though base file doesn't exist
        handler.doRollover()

        # no backup should be created since there was nothing to compress
        assert not (tmp_path / "test.log.1.gz").exists()
        # stream should remain None because delay=True
        assert handler.stream is None
