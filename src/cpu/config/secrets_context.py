# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Context-based secret resolution.

Defines the context for selecting appropriate secrets based on:
- Platform (GitHub, GitLab)
- Repository (organization, repository name)
- Build target (CVMFS repo, EESSI version)
- Environment (production, staging, development)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecretContext:
    """
    Context for resolving which secrets to use.

    Different contexts require different credentials:
    - Different GitHub apps for different repos
    - Different AWS credentials for different CVMFS repos
    - Different SSH keys for different organizations

    Examples:
        >>> # GitHub context
        >>> context = SecretContext(
        ...     platform="github",
        ...     organization="EESSI",
        ...     repository="software-layer"
        ... )

        >>> # Build target context
        >>> context = SecretContext(
        ...     cvmfs_repo="software.eessi.io",
        ...     eessi_version="2023.06"
        ... )

        >>> # Combined context
        >>> context = SecretContext(
        ...     platform="github",
        ...     organization="EESSI",
        ...     cvmfs_repo="software.eessi.io",
        ...     environment="production"
        ... )
    """

    # Repository context
    platform: str | None = None  # "github", "gitlab"
    organization: str | None = None  # "EESSI", "other-org"
    repository: str | None = None  # "software-layer", "compatibility-layer"

    # Build target context
    cvmfs_repo: str | None = None  # "software.eessi.io", "pilot.eessi.io"
    eessi_version: str | None = None  # "2023.06", "2025.06"
    installation_path: str | None = None  # Full installation path

    # Environment context
    environment: str | None = None  # "production", "staging", "development"

    def matches(self, pattern: dict[str, str]) -> bool:
        """
        Check if this context matches a pattern.

        A pattern is a dictionary of field names to expected values.
        The context matches if all pattern fields match the context's values.

        Args:
            pattern: Dictionary of field names and expected values

        Returns:
            True if all pattern fields match, False otherwise

        Examples:
            >>> context = SecretContext(platform="github", organization="EESSI")
            >>> context.matches({"platform": "github"})
            True
            >>> context.matches({"platform": "gitlab"})
            False
            >>> context.matches({"platform": "github", "organization": "EESSI"})
            True
            >>> context.matches({})  # Empty pattern always matches
            True
        """
        for key, value in pattern.items():
            # Get the corresponding field from context
            context_value = getattr(self, key, None)

            # If pattern value doesn't match context value, no match
            if context_value != value:
                return False

        return True
