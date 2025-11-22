# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Main entry point for the application.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from cpu import __version__
from cpu.config.config import Config, ConfigError, ConfigValidationError


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        prog="cpu",
        description="CPU - The next-generation EESSI build-and-deploy bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  Configuration values can be overridden using environment variables with the
  CPU_ prefix. Use double underscores (__) to separate nested keys:

    CPU_BOT__NUM_WORKERS=8       # Overrides bot.num_workers
    CPU_BOT__LOG_LEVEL=DEBUG     # Overrides bot.log_level

Examples:
  cpu                            # Use default config.yaml
  cpu --config /path/to/config.yaml
  cpu -c custom_config.yaml
  CPU_BOT__NUM_WORKERS=8 cpu    # Override via environment
        """,
    )

    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )

    parser.add_argument(
        "--extended-startup-info",
        action="store_true",
        help="Show extended startup information",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"CPU Bot version {__version__}",
        help="Show version information and exit",
    )

    return parser.parse_args()


def create_header() -> str:
    """
    Create application banner header with ASCII art.

    """
    banner = r"""
    ______ ____   __  __
   / ____// __ \ / / / /
  / /    / /_/ // / / /
 / /___ / ____// /_/ /
 \____//_/     \____/

CPU - The next-generation EESSI build-and-deploy bot

"""

    return banner


def print_banner(banner: str, config: Config | None = None) -> None:
    """
    Print application banner with ASCII art.

    Args:
        banner: The banner to print
        config: Optional configuration object to check for banner effects setting
    """
    # Check if terminal effects are enabled in config
    enable_effects = False
    effect_name = "Slide"
    if config is not None:
        enable_effects = config.get("bot.banner_effects", False)
        effect_name = config.get("bot.banner_effect_type", "Slide")

    # Try to use terminal effects if enabled and available
    if enable_effects:
        try:
            import importlib

            module_name = f"terminaltexteffects.effects.effect_{effect_name.lower()}"
            module = importlib.import_module(module_name)

            # get class from module
            effect_class = getattr(module, effect_name)

            # Create effect
            effect = effect_class(banner)

            # Run the effect
            with effect.terminal_output() as terminal:
                for frame in effect:
                    terminal.print(frame)

            return

        except (ImportError, AttributeError):
            # TerminalTextEffects not installed, fall back to plain banner
            # ... or effect_name does not exist in TerminalTextEffects
            print("IMPORT OR ATTRIBUTE ERROR")
            pass
        except Exception:
            # Any other error, fall back gracefully
            pass

    # Print plain banner
    print(banner)


def create_startup_info(config_file: Path, config: Config, verbose: bool) -> str:
    """
    Create startup information including version, paths, and configuration.

    Args:
        config_file: Path to the configuration file
        config: Loaded configuration object
        verbose: If True, show extended startup information

    Returns:
        Startup info as string
    """
    startup_info = "\n"
    startup_info += f"Version:          {__version__}\n"
    startup_info += f"Started:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    startup_info += f"Executable:       {sys.executable}\n"
    startup_info += f"Python version:   {sys.version.split()[0]}\n"
    startup_info += f"Config file:      {config_file.absolute()}\n"
    startup_info += "\n"

    if verbose:
        # Print configuration summary
        startup_info += "Configuration:\n"
        startup_info += f"  Workers:        {config.get('bot.num_workers', 'not set')}\n"
        startup_info += f"  Log level:      {config.get('bot.log_level', 'not set')}\n"
        startup_info += "\n"

        # Print environment variable information
        startup_info += "Environment Variable Overrides:\n"
        startup_info += "  You can override configuration values using environment variables\n"
        startup_info += "  with the CPU_ prefix and double underscores for nesting:\n"
        startup_info += "\n"
        startup_info += "    CPU_BOT__NUM_WORKERS=8       # Override bot.num_workers\n"
        startup_info += "    CPU_BOT__LOG_LEVEL=DEBUG     # Override bot.log_level\n"
        startup_info += "\n"

        # Check if any environment overrides are active
        import os

        env_overrides = [key for key in os.environ if key.startswith("CPU_")]
        if env_overrides:
            startup_info += "  Active environment overrides:\n"
            for env_key in sorted(env_overrides):
                env_value = os.environ[env_key]

                # Convert to config key format
                config_key = env_key[4:].lower().replace("__", ".")
                startup_info += f"    {env_key}={env_value}\n"
                startup_info += f"      → Overrides: {config_key}\n"
            startup_info += "\n"
        else:
            startup_info += "  No active environment overrides detected.\n"
            startup_info += "\n"

    return startup_info


def validate_configuration(config: Config) -> None:
    """
    Validate that required configuration keys are present.

    Args:
        config: Configuration object to validate

    Raises:
        ConfigValidationError: If required keys are missing
    """
    required_keys = [
        "bot.num_workers",
    ]

    config.validate(required_keys, raise_on_error=True)


def main() -> int:
    """
    Main entry point for the CPU bot application.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    try:
        # Parse command line arguments
        args = parse_arguments()

        # Load configuration first (so we can use banner effects setting)
        config_file = Path(args.config)
        config = Config(config_file=config_file, env_prefix="CPU_")
        config.load()

        # Validate configuration
        validate_configuration(config)

        # create banner header
        banner = create_header()

        banner += f"Loaded configuration from: {config_file}\n"
        banner += "✓ Configuration validated successfully\n"

        # add startup information
        banner += create_startup_info(config_file, config, verbose=args.extended_startup_info)

        # TODO: Start bot components
        banner += "Bot components would start here (not yet implemented)\n"
        banner += "\n"
        banner += "Startup complete!\n"

        # Print banner with effects if configured
        print_banner(banner, config)

        return 0

    except FileNotFoundError as err:
        #print(f"Error: Configuration file not found: {err}", file=sys.stderr)
        print(f"Error: {err}", file=sys.stderr)
        return 1

    except ConfigValidationError as err:
        print(f"Error: Configuration validation failed: {err}", file=sys.stderr)
        print("\nRequired configuration keys:", file=sys.stderr)
        print("  - bot.num_workers: Number of worker threads", file=sys.stderr)
        return 1

    except ConfigError as err:
        print(f"Error: Configuration error: {err}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130

    except Exception as err:
        print(f"Error: Unexpected error: {err}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


def run() -> NoReturn:
    """
    Run the application and exit with appropriate code.

    This is used by the console script entry point.
    """
    sys.exit(main())


if __name__ == "__main__":
    run()
