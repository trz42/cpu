#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU bot Contributors
"""
CPU bot - A next-generation EESSI build-and-deploy bot.

Extract changelog entry for a specific version from CHANGELOG.md.
Used by CI to generate release notes.
"""

import re
import sys
from pathlib import Path


def extract_version_changelog(changelog_path: Path, version: str) -> str:
    """
    Extract changelog section for a specific version.

    Args:
        changelog_path: Path to CHANGELOG.md file
        version: Version string (e.g., "0.0.2" or "v0.0.2")

    Returns:
        Changelog text for the specified version
    """
    # Remove 'v' prefix if present
    version = version.lstrip("v")

    content = changelog_path.read_text()

    # Pattern to match version headers like "## [0.0.2]" or "## 0.0.2"
    pattern = rf"^##\s+\[?{re.escape(version)}\]?.*$"

    lines = content.split("\n")
    start_idx = None
    end_idx = None

    # Find start of version section
    for i, line in enumerate(lines):
        if re.match(pattern, line):
            start_idx = i
            break

    if start_idx is None:
        return f"No changelog entry found for version {version}"

    # Find end of version section (next ## heading or end of file)
    for i in range(start_idx + 1, len(lines)):
        if lines[i].startswith('## '):
            end_idx = i
            break

    # Extract the section
    if end_idx is None:
        section = lines[start_idx + 1 :]
    else:
        section = lines[start_idx + 1 : end_idx]

    # Clean up and join
    changelog_text = "\n".join(section).strip()

    return changelog_text if changelog_text else f"Empty changelog for version {version}"


def main() -> None:
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: extract_changelog.py <version>", file=sys.stderr)
        sys.exit(1)

    version = sys.argv[1]
    changelog_path = Path("CHANGELOG.md")

    if not changelog_path.exists():
        print(f"Error: {changelog_path} not found", file=sys.stderr)
        sys.exit(1)

    changelog = extract_version_changelog(changelog_path, version)
    print(changelog)


if __name__ == "__main__":
    main()
