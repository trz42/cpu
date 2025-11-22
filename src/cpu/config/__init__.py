# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

This package provides configuration loading from YAML files with
environment variable overrides and validation.
"""

from __future__ import annotations

from cpu.config.config import Config, ConfigError, ConfigValidationError

__all__ = [
    "Config",
    "ConfigError",
    "ConfigValidationError",
]
