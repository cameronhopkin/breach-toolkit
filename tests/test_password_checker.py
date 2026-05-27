#!/usr/bin/env python3
"""
Tests for the password checker module.

Author: Cameron Hopkin
License: MIT
"""
import hashlib
from unittest.mock import AsyncMock, MagicMock

import pytest

from breach_toolkit.core.password_checker import (
    BreachResult,
    PasswordChecker,
    check_password_sync,
)


class TestPasswordChecker:
    """Tests for PasswordChecker class."""

    def test_hash_password(self):
        """Test password hashing produces correct format."""
        checker = PasswordChecker()

        # Test known password hash
        password = "password"
        expected_hash = hashlib.sha1(password.encode()).hexdigest().upper()

        prefix, suffix = checker._hash_password(password)

        assert len(prefix) == 5
        assert prefix == expected_hash[:5]
        assert suffix == expected_hash[5:]

    def test_hash_password_consistency(self):
        """Test that hashing is consistent."""
        checker = PasswordChecker()

        prefix1, suffix1 = checker._hash_password("test123")
        prefix2, suffix2 = checker._hash_password("test123")

        assert prefix1 == prefix2
        assert suffix1 == suffix2

    def test_parse_response_found(self):
        """Test parsing HIBP response when password is found."""
        checker = PasswordChecker()

        # SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        prefix = "5BAA6"
        suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

        # Mock response with our suffix
        response_text = f"""
ABC123:100
{suffix}:5000
DEF456:200
""".strip()

        result = checker._parse_response(response_text, prefix, suffix)

        assert result.is_breached is True
        assert result.breach_count == 5000
        assert result.hash_prefix == prefix

    def test_parse_response_not_found(self):
        """Test parsing HIBP response when password is not found."""
        checker = PasswordChecker()

        prefix = "5BAA6"
        suffix = "NOTINTHELIST123456789012345678901234"

        response_text = """
ABC123:100
DEF456:200
GHI789:300
""".strip()

        result = checker._parse_response(response_text, prefix, suffix)

        assert result.is_breached is False
        assert result.breach_count == 0

    @pytest.mark.asyncio
    async def test_check_password_success(self):
        """Test successful password check."""
        checker = PasswordChecker()

        # Mock the aiohttp session
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="ABC123:100\nDEF456:200")

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=None)
        ))

        checker._session = mock_session
        checker.rate_limiter = AsyncMock()
        checker.rate_limiter.acquire = AsyncMock()

        result = await checker.check_password("testpassword")

        assert isinstance(result, BreachResult)
        assert result.is_breached is False  # Not in mock response

    def test_breach_result_dataclass(self):
        """Test BreachResult dataclass."""
        result = BreachResult(
            is_breached=True,
            breach_count=1000,
            hash_prefix="ABCDE"
        )

        assert result.is_breached is True
        assert result.breach_count == 1000
        assert result.hash_prefix == "ABCDE"
        assert result.source == "hibp"  # Default value


class TestBreachResult:
    """Tests for BreachResult dataclass."""

    def test_default_source(self):
        """Test default source value."""
        result = BreachResult(
            is_breached=False,
            breach_count=0,
            hash_prefix="12345"
        )
        assert result.source == "hibp"

    def test_custom_source(self):
        """Test custom source value."""
        result = BreachResult(
            is_breached=True,
            breach_count=100,
            hash_prefix="12345",
            source="custom"
        )
        assert result.source == "custom"


class TestIntegration:
    """Integration tests (require network access)."""

    @pytest.mark.skip(reason="Requires network access")
    def test_check_common_password(self):
        """Test checking a known common password."""
        # "password" should definitely be breached
        result = check_password_sync("password")

        assert result.is_breached is True
        assert result.breach_count > 0

    @pytest.mark.skip(reason="Requires network access")
    def test_check_random_password(self):
        """Test checking a random password."""
        import secrets
        random_password = secrets.token_urlsafe(32)

        result = check_password_sync(random_password)

        # Very unlikely to be breached
        assert result.is_breached is False
