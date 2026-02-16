# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Rotating file handler with gzip compression.
"""

from __future__ import annotations

import gzip
import logging
import os
import shutil
from logging.handlers import RotatingFileHandler

logger = logging.getLogger(__name__)


class CompressingRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that compresses old log files."""

    def doRollover(self) -> None:
        """Perform rollover and compress rotated logs."""
        # close current file
        if self.stream:
            self.stream.close()
            self.stream = None  # type: ignore[assignment]

        # rotate and compress old files
        for backup in range(self.backupCount - 1, 0, -1):
            source_filename = f"{self.baseFilename}.{backup}.gz"
            destination_filename = f"{self.baseFilename}.{backup + 1}.gz"
            if os.path.exists(source_filename):
                if os.path.exists(destination_filename):
                    os.remove(destination_filename)
                os.rename(source_filename, destination_filename)

        # compress the current log to .1.gz
        destination_filename = f"{self.baseFilename}.1.gz"
        if os.path.exists(destination_filename):
            try:
                os.remove(destination_filename)
            except OSError as err:
                logger.error(f"Failed to remove file during rotation: {destination_filename}: {err}")

        if os.path.exists(self.baseFilename):
            try:
                with (
                    open(self.baseFilename, 'rb') as file_in,
                    gzip.open(destination_filename, 'wb') as file_out
                ):
                    shutil.copyfileobj(file_in, file_out)
            except OSError as err:
                logger.error(f"Failed to compress rotated log {self.baseFilename}: {err}")
                # continue dspite compression failure

            try:
                os.remove(self.baseFilename)
            except OSError as err:
                logger.error(f"Failed to remove original log file during rotation: {self.baseFilename}: {err}")

        # open new current log
        if not self.delay:
            self.stream = self._open()
