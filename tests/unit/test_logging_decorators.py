# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Tests for function tracing decorator.
"""

from __future__ import annotations

import logging

import pytest

from cpu.logging import TRACE
from cpu.logging.decorators import trace_calls


class TestTraceDecorator:
    """Test @trace_calls decorator."""

    def test_trace_decorator_defaults_to_trace_level(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test decorator uses TRACE level by default."""
        caplog.set_level(TRACE)

        @trace_calls()  # no level specified
        def test_func() -> str:
            return "result"

        test_func()

        assert len(caplog.records) > 0
        # check that logs are at TRACE level
        assert any(record.levelno == TRACE for record in caplog.records)
        assert ">>> test_func" in caplog.text

    def test_trace_decorator_filtered_at_debug_level(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test TRACE logs filtered when logger at DEBUG level."""
        caplog.set_level(logging.DEBUG)

        @trace_calls()  # uses TRACE by default
        def test_func() -> str:
            return "result"

        test_func()

        # should not log at TRACE when level is DEBUG
        assert ">>> test_func" not in caplog.text

    def test_trace_decorator_logs_entry(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test function entry is logged."""
        caplog.set_level(logging.DEBUG)

        @trace_calls(level=logging.DEBUG, include_args=False)
        def test_func() -> str:
            return "result"

        test_func()

        assert ">>> test_func()" in caplog.text

    def test_trace_decorator_logs_exit_with_return(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test function exit and return value are logged."""
        caplog.set_level(logging.DEBUG)

        @trace_calls(level=logging.DEBUG)
        def test_func() -> str:
            return "success"

        result = test_func()

        assert result == "success"
        assert "<<< test_func = success" in caplog.text

    def test_trace_decorator_logs_exception(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test exceptions are logged."""
        caplog.set_level(logging.DEBUG)

        @trace_calls(level=logging.DEBUG)
        def test_func() -> None:
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            test_func()

        assert "X test_func raised ValueError: test error" in caplog.text

    def test_trace_decorator_respects_level(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test decorator respects log level."""
        caplog.set_level(logging.INFO)

        @trace_calls(level=logging.DEBUG)
        def test_func() -> str:
            return "result"

        test_func()

        # should not log at DEBUG when level is INFO
        assert ">>> test_func" not in caplog.text

    def test_trace_decorator_includes_args_when_enabled(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test arguments are logged when enabled."""
        caplog.set_level(logging.DEBUG)

        @trace_calls(level=logging.DEBUG, include_args=True)
        def test_func(x: int, y: str) -> str:
            return f"{x}-{y}"

        test_func(42, "hello")

        assert "args=(42, 'hello')" in caplog.text

    def test_trace_decorator_excludes_args_when_disabled(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test arguments are not logged when disabled."""
        caplog.set_level(logging.DEBUG)

        @trace_calls(level=logging.DEBUG, include_args=False)
        def test_func(x: int, y: str) -> str:
            return f"{x}-{y}"

        test_func(42, "hello")

        assert "args=" not in caplog.text
        assert ">>> test_func()" in caplog.text

    def test_trace_decorator_includes_result_when_enabled(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test return value is logged when enabled."""
        caplog.set_level(logging.DEBUG)

        @trace_calls(level=logging.DEBUG, include_result=True)
        def test_func() -> int:
            return 123

        test_func()

        assert "<<< test_func = 123" in caplog.text

    def test_trace_decorator_excludes_result_when_disabled(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test return value is not logged when disabled."""
        caplog.set_level(logging.DEBUG)

        @trace_calls(level=logging.DEBUG, include_result=False)
        def test_func() -> int:
            return 123

        test_func()

        assert "<<< test_func" in caplog.text
        assert "= 123" not in caplog.text
