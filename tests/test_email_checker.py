#!/usr/bin/env python3
"""
Tests for the email checker module.

Author: Cameron Hopkin
License: MIT
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from breach_toolkit.core.email_checker import (
    EmailBreachResult,
    EmailChecker,
)


class TestEmailChecker:
    """Tests for EmailChecker class."""

    def test_hash_email(self):
        """Test email hashing produces consistent results."""
        checker = EmailChecker()

        hash1 = checker._hash_email("test@example.com")
        hash2 = checker._hash_email("TEST@EXAMPLE.COM")  # Should normalize
        hash3 = checker._hash_email("  test@example.com  ")  # Should strip

        # All should produce same hash (normalized)
        assert hash1 == hash2
        assert hash2 == hash3

    def test_hash_email_format(self):
        """Test email hash is proper SHA-256."""
        checker = EmailChecker()

        email = "test@example.com"
        result = checker._hash_email(email)

        # SHA-256 produces 64 character hex string
        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)

    @pytest.mark.asyncio
    async def test_check_email_no_api_key(self):
        """Test email check without API key."""
        checker = EmailChecker(hibp_api_key=None)

        result = await checker.check_email_hibp("test@example.com")

        assert isinstance(result, EmailBreachResult)
        assert result.is_breached is False
        assert result.breach_count == 0

    @pytest.mark.asyncio
    async def test_check_email_found(self):
        """Test email check when email is found in breaches."""
        checker = EmailChecker(hibp_api_key="test-key")

        # Mock response
        mock_breaches = [
            {"Name": "Breach1", "Domain": "example.com"},
            {"Name": "Breach2", "Domain": "test.com"},
        ]

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=mock_breaches)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=None)
        ))

        checker._session = mock_session
        checker.rate_limiter = AsyncMock()
        checker.rate_limiter.acquire = AsyncMock()

        result = await checker.check_email_hibp("test@example.com")

        assert result.is_breached is True
        assert result.breach_count == 2
        assert "Breach1" in result.breaches
        assert "Breach2" in result.breaches

    @pytest.mark.asyncio
    async def test_check_email_not_found(self):
        """Test email check when email is not in breaches."""
        checker = EmailChecker(hibp_api_key="test-key")

        mock_response = AsyncMock()
        mock_response.status = 404

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=None)
        ))

        checker._session = mock_session
        checker.rate_limiter = AsyncMock()
        checker.rate_limiter.acquire = AsyncMock()

        result = await checker.check_email_hibp("clean@example.com")

        assert result.is_breached is False
        assert result.breach_count == 0


class TestEmailBreachResult:
    """Tests for EmailBreachResult dataclass."""

    def test_default_values(self):
        """Test default values."""
        result = EmailBreachResult(
            email="test@example.com",
            is_breached=False,
            breach_count=0
        )

        assert result.breaches == []
        assert result.checked_at is not None

    def test_with_breaches(self):
        """Test with breach list."""
        result = EmailBreachResult(
            email="test@example.com",
            is_breached=True,
            breach_count=3,
            breaches=["Breach1", "Breach2", "Breach3"]
        )

        assert len(result.breaches) == 3
        assert result.breach_count == 3
