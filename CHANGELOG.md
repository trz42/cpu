# Changelog

## [0.0.10] - 2026-06-16

### Added

- `SmeeClientComponent`: new component with unit tests (#61)
- Python 3.13 and 3.14 to the test matrix (#60)

### Changed

- `SmeeClientComponent` is now used in `__main__.py`, with integration
  tests added/fixed (#63)
- pinned CI versions updated; GitHub Action warnings about deprecated
  Node versions fixed (#60)
- pytest coverage increased to 100% (#60)
- `terminaltexteffects` bumped to v0.15.0 (#60)

### Fixed

- location of `secrets_audit.log` made configurable, fixing fragile
  `/var/log/cpu` default for non-root deployments (#62, via #63)

### Removed

- unused `create_webhook_message()` and associated tests (#61)

## [0.0.9] - 2026-06-13

### Added

- `QueueLoggingHandler`: custom logging handler that routes all `cpu.*`
  log records through the message queue to `LoggingComponent`, enabling
  async, non-blocking logging
- `suppress_queue_logging()`: thread-local context manager to prevent
  feedback loops when `LoggingComponent` drains its own queue
- `configure_queue_logging()`: configures the `cpu` logger to use
  `QueueLoggingHandler`, replacing direct file writes
- Integration tests for the full logging chain (handler -> queue ->
  `LoggingComponent` -> file)
- `logging_component` pytest fixture in `conftest.py`

### Changed

- `LoggingComponent` is now the sole writer to the log file; all
  `cpu.*` logging flows through the message queue
- `LoggingComponent` uses `CompressingRotatingFileHandler` instead of
  plain `FileHandler`, restoring log rotation with gzip compression
- `LoggingComponent` preserves original log record metadata (logger
  name, function name, line number) in file output
- `__main__.py` uses two-phase logging: console-only during startup,
  queue-based once `LoggingComponent` is registered
- `Orchestrator.stop_all()` stops components in reverse registration
  order, ensuring `LoggingComponent` stops last
- Default banner effect changed from `Slide` to `Beams`
- Console startup logging reduced to `WARNING` level

### Fixed

- `LoggingComponent` config keys aligned with sub-dict passed from
  `__main__.py` (removed erroneous `bot.logging.` prefix)
- Infinite feedback loop at TRACE level when `LoggingComponent`'s own
  queue operations generated log records
- Propagation disabled on `cpu.logging` logger to prevent write ->
  propagate -> queue loop

### Removed

- `configure_logging()` from `setup.py` — replaced by
  `configure_queue_logging()`

## [0.0.8] - 2026-02-16

### Added

- Custom TRACE log level (level 5) for detailed debugging
- Comprehensive logging across all modules
- `@trace_calls` decorator for function entry/exit logging
- Per-module log level configuration
- Log sanitization for sensitive data

### Changed

- Updated all components to use structured logging
- Enhanced error messages with context
- Improved debugging capabilities with TRACE level
- Increased coverage for unit tests

### Fixed

- none

## [0.0.7] - 2026-01-15

### Added

- logging infrastructure including
  - log sanitation
  - log rotation & compression
  - call decorator
  - log flushing at `SIGUSR1`
  - central LoggingComponent that handles log messages
  - new message type `LOG`
  - starting LoggingComponent through orchestrator
- unit and integration tests for logging

### Changed

- none

### Fixed

- none

## [0.0.6] - 2026-01-10

### Added

- ThreadMessageQueue and ThreadMessageBus incl unit tests
- message delivery guarantee levels incl unit tests
- secrets audit logging incl unit tests
- secrets encryption/decryption incl unit tests
- secrets contexts incl unit tests
- obtain secrets from env vars or files
  - supports plain, base64 encoded and encrypted values
  - unit tests for the above
- secrets manager incl unit tests
- component framework with classes for base and orchestrator
  - ability to stop bot gracefully with CTRL-C (catches signal)
  - unit tests for the component framework
  - integration tests for using component framework in main()

### Changed

- make TTE install mandatory
- polished README.md
- improved file name structure
- extended config.yaml.example (complete overhaul)
- extended `__init__.py` in config module (secrets handling)
- updated startup information
- changed tests in main to acknowledge use of orchestrator

### Fixed

- none

## [0.0.5] - 2025-11-22

### Added

- code for basic configuration management
  - including example configuration file
- unit tests for the configuration management code
- simple module for main application and a script to run it
- end-to-end tests for the main application module
- support for TerminalTextEffects (at startup)

### Changed

- polished header
- list objectives in README.md
- improved test coverage

### Fixed

- none

## [0.0.4] - 2025-11-18

### Added

- code for basic Message and Message interfaces
- unit tests for the above code

### Changed

- removed black formatter check (superseded by ruff)

### Fixed

- none

## [0.0.3] - 2025-11-17

### Added

- instructions to manually create a release

### Changed

- none

### Fixed

- combined source and wheel when uploading artifact in CI to build package

## [0.0.2] - 2025-11-16

### Added

- detailed instructions to create a release
- CI running pytest including coverage
- CI running linters
- CI to build package and automatic release when a tag is pushed

### Changed

- none

### Fixed

- syntax issues
- README.md fixes

## [0.0.1] - 2025-11-15

### Added

- Initial package structure
- Basic package installation support
- Version management with setuptools-scm

### Changed

- none

### Fixed

- none
