# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU bot Contributors
"""
CPU bot - A next-generation EESSI build-and-deploy bot.

Tests for package initialization and version.
"""

import cpu


def test_version_exists() -> None:
    """Test that version attribute exists."""
    assert hasattr(cpu, "__version__")


def test_version_format() -> None:
    """Test that version is a non-empty string."""
    assert isinstance(cpu.__version__, str)
    assert len(cpu.__version__) > 0
