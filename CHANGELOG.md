# Changelog

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
