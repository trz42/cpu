# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Integration tests for main orchestration.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from cpu.__main__ import create_orchestrator, main, run_orchestrator
from cpu.config.config import Config


class TestCreateOrchestrator:
    """Test orchestrator creation."""

    def test_create_orchestrator_returns_instance(self, tmp_path: Path) -> None:
        """Test orchestrator is created."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 2\n")

        config = Config(config_file=config_file)
        config.load()

        orchestrator = create_orchestrator(config)

        assert orchestrator is not None
        # no components registered yet (placeholder implementation)
        assert len(orchestrator._components) == 0


class TestRunOrchestrator:
    """Test orchestrator execution."""

    def test_run_orchestrator_sets_up_signals(self) -> None:
        """Test run_orchestrator sets up signal handlers."""
        orchestrator = MagicMock()
        orchestrator._shutdown_requested = True  # exit immediately

        run_orchestrator(orchestrator)

        orchestrator.setup_signal_handlers.assert_called_once()

    def test_run_orchestrator_starts_all(self) -> None:
        """Test run_orchestrator starts all components."""
        orchestrator = MagicMock()
        orchestrator._shutdown_requested = True  # exit immediately

        run_orchestrator(orchestrator)

        orchestrator.start_all.assert_called_once()

    def test_run_orchestrator_stops_on_shutdown(self) -> None:
        """Test run_orchestrator stops components on shutdown."""
        orchestrator = MagicMock()
        orchestrator._shutdown_requested = True  # exit immediately

        run_orchestrator(orchestrator)

        orchestrator.stop_all.assert_called_once_with(timeout=10)

    def test_run_orchestrator_handles_keyboard_interrupt(self) -> None:
        """Test run_orchestrator handles KeyboardInterrupt."""
        orchestrator = MagicMock()
        orchestrator._shutdown_requested = False

        # simulate KeyboardInterrupt after start_all
        def raise_interrupt(*args, **kwargs) -> None:
            del args, kwargs  # unused
            raise KeyboardInterrupt()

        with patch("time.sleep", side_effect=raise_interrupt):
            run_orchestrator(orchestrator)

        orchestrator.stop_all.assert_called_once_with(timeout=10)


class TestMainIntegration:
    """Test main function integration."""

    @patch("cpu.__main__.run_orchestrator")
    @patch("cpu.__main__.create_orchestrator")
    def test_main_creates_and_runs_orchestrator(
        self, mock_create: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Test main creates and runs orchestrator."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bot:\n  num_workers: 2\n")

        mock_orch = MagicMock()
        mock_create.return_value = mock_orch

        with patch("sys.argv", ["cpu", "--config", str(config_file)]):
            result = main()

        assert result == 0
        mock_create.assert_called_once()
        mock_orch.initialize_all.assert_called_once()
        mock_run.assert_called_once_with(mock_orch)

    def test_main_handles_config_error(self, tmp_path: Path) -> None:
        """Test main handles configuration errors."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("# Missing required keys\n")

        with patch("sys.argv", ["cpu", "--config", str(config_file)]):
            result = main()

        assert result == 1  # error exit code
