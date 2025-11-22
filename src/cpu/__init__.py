# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

This module provides initialization logic for the package.
"""
try:
    from importlib.metadata import version

    __version__ = version("cpu")
except Exception:  # pragma: no cover
    __version__ = "unknown"
