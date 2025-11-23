# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Unit tests for cpu.config.secrets_context.

Tests context-based secret selection for different scenarios.
"""

from __future__ import annotations

from cpu.config.secrets_context import SecretContext


class TestSecretContext:
    """Test SecretContext dataclass."""

    def test_initialization_with_defaults(self) -> None:
        """Test that SecretContext initializes with None defaults."""
        context = SecretContext()

        assert context.platform is None
        assert context.organization is None
        assert context.repository is None
        assert context.cvmfs_repo is None
        assert context.eessi_version is None
        assert context.installation_path is None
        assert context.environment is None

    def test_initialization_with_values(self) -> None:
        """Test initialization with specific values."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
            repository="software-layer",
            cvmfs_repo="software.eessi.io",
        )

        assert context.platform == "github"
        assert context.organization == "EESSI"
        assert context.repository == "software-layer"
        assert context.cvmfs_repo == "software.eessi.io"

    def test_matches_empty_pattern(self) -> None:
        """Test that any context matches empty pattern."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
        )

        assert context.matches({})

    def test_matches_single_field(self) -> None:
        """Test matching a single field."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
            repository="software-layer",
        )

        assert context.matches({"platform": "github"})
        assert context.matches({"organization": "EESSI"})
        assert context.matches({"repository": "software-layer"})

    def test_matches_multiple_fields(self) -> None:
        """Test matching multiple fields."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
            repository="software-layer",
        )

        assert context.matches({
            "platform": "github",
            "organization": "EESSI",
        })

        assert context.matches({
            "platform": "github",
            "organization": "EESSI",
            "repository": "software-layer",
        })

    def test_does_not_match_different_value(self) -> None:
        """Test that different values don't match."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
        )

        assert not context.matches({"platform": "gitlab"})
        assert not context.matches({"organization": "other-org"})

    def test_does_not_match_missing_field(self) -> None:
        """Test that pattern with field not in context doesn't match."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
        )

        # Context doesn't have repository set, pattern requires it
        assert not context.matches({"repository": "software-layer"})

    def test_matches_none_value_in_context(self) -> None:
        """Test matching when context has None value."""
        context = SecretContext(
            platform="github",
            organization=None,  # Explicitly None
        )

        # Pattern requires organization, but context has None
        assert not context.matches({"organization": "EESSI"})

    def test_matches_ignores_extra_context_fields(self) -> None:
        """Test that extra fields in context don't prevent match."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
            repository="software-layer",
            cvmfs_repo="software.eessi.io",
        )

        # Pattern only checks platform
        assert context.matches({"platform": "github"})

    def test_matches_cvmfs_repo(self) -> None:
        """Test matching based on CVMFS repository."""
        context = SecretContext(
            cvmfs_repo="software.eessi.io",
        )

        assert context.matches({"cvmfs_repo": "software.eessi.io"})
        assert not context.matches({"cvmfs_repo": "pilot.eessi.io"})

    def test_matches_eessi_version(self) -> None:
        """Test matching based on EESSI version."""
        context = SecretContext(
            eessi_version="2023.06",
        )

        assert context.matches({"eessi_version": "2023.06"})
        assert not context.matches({"eessi_version": "2025.06"})

    def test_matches_environment(self) -> None:
        """Test matching based on environment."""
        context = SecretContext(
            environment="production",
        )

        assert context.matches({"environment": "production"})
        assert not context.matches({"environment": "staging"})

    def test_matches_complex_pattern(self) -> None:
        """Test matching a complex pattern with multiple conditions."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
            repository="software-layer",
            cvmfs_repo="software.eessi.io",
            eessi_version="2023.06",
            environment="production",
        )

        # All conditions must match
        assert context.matches({
            "platform": "github",
            "organization": "EESSI",
            "cvmfs_repo": "software.eessi.io",
        })

        # One condition fails
        assert not context.matches({
            "platform": "github",
            "organization": "EESSI",
            "cvmfs_repo": "pilot.eessi.io",  # Wrong!
        })

    def test_str_representation(self) -> None:
        """Test string representation of context."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
            repository="software-layer",
        )

        str_repr = str(context)
        assert "github" in str_repr
        assert "EESSI" in str_repr
        assert "software-layer" in str_repr

    def test_equality(self) -> None:
        """Test equality comparison of contexts."""
        context1 = SecretContext(
            platform="github",
            organization="EESSI",
        )
        context2 = SecretContext(
            platform="github",
            organization="EESSI",
        )
        context3 = SecretContext(
            platform="gitlab",
            organization="EESSI",
        )

        assert context1 == context2
        assert context1 != context3

    def test_typical_github_context(self) -> None:
        """Test typical GitHub context usage."""
        context = SecretContext(
            platform="github",
            organization="EESSI",
            repository="software-layer",
            environment="production",
        )

        # Should match patterns for EESSI production
        assert context.matches({"platform": "github"})
        assert context.matches({"organization": "EESSI"})
        assert context.matches({
            "organization": "EESSI",
            "environment": "production",
        })

    def test_typical_build_context(self) -> None:
        """Test typical build target context usage."""
        context = SecretContext(
            cvmfs_repo="software.eessi.io",
            eessi_version="2023.06",
            installation_path="/cvmfs/software.eessi.io/versions/2023.06",
        )

        # Should match patterns for production CVMFS repo
        assert context.matches({"cvmfs_repo": "software.eessi.io"})
        assert context.matches({
            "cvmfs_repo": "software.eessi.io",
            "eessi_version": "2023.06",
        })

    def test_pattern_with_invalid_field_name(self) -> None:
        """Test that pattern with non-existent field doesn't match."""
        context = SecretContext(
            platform="github",
        )

        # Pattern has field that doesn't exist in SecretContext
        assert not context.matches({"nonexistent_field": "value"})
