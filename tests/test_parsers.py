#!/usr/bin/env python3
"""
Tests for the parser modules.

Author: Cameron Hopkin
License: MIT
"""
import pytest
import tempfile
from pathlib import Path

from breach_toolkit.parsers.stealer_log_parser import (
    StealerLogParser,
    Credential,
)
from breach_toolkit.parsers.combo_parser import (
    ComboParser,
    ComboEntry,
)


class TestStealerLogParser:
    """Tests for StealerLogParser class."""

    def test_detect_redline_format(self):
        """Test detection of Redline stealer format."""
        parser = StealerLogParser()

        content = """
URL: https://example.com/login
Username: testuser
Password: testpass123
Application: Chrome
"""

        detected = parser._detect_stealer_type(content)
        assert detected == "redline"

    def test_detect_vidar_format(self):
        """Test detection of Vidar stealer format."""
        parser = StealerLogParser()

        content = """
Soft: Chrome
Url: https://example.com
Login: testuser
Password: testpass
"""

        detected = parser._detect_stealer_type(content)
        assert detected == "vidar"

    def test_detect_raccoon_format(self):
        """Test detection of Raccoon stealer format."""
        parser = StealerLogParser()

        content = """
URL: https://example.com | USER: testuser | PASS: testpass
"""

        detected = parser._detect_stealer_type(content)
        assert detected == "raccoon"

    def test_parse_redline_file(self):
        """Test parsing Redline format file."""
        parser = StealerLogParser()

        content = """URL: https://example.com/login
Username: testuser
Password: testpass123
Application: Chrome

URL: https://another.com/auth
Username: user2
Password: pass456
Application: Firefox
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            filepath = f.name

        try:
            credentials = list(parser.parse_file(filepath))

            assert len(credentials) == 2
            assert credentials[0].url == "https://example.com/login"
            assert credentials[0].username == "testuser"
            assert credentials[0].password == "testpass123"
            assert credentials[1].url == "https://another.com/auth"
        finally:
            Path(filepath).unlink()

    def test_credential_domain_property(self):
        """Test Credential domain extraction."""
        cred = Credential(
            url="https://www.example.com/login/page",
            username="user",
            password="pass",
            source_file="test.txt",
            stealer_type="redline"
        )

        assert cred.domain == "www.example.com"

    def test_deduplication(self):
        """Test credential deduplication."""
        parser = StealerLogParser(deduplicate=True)

        content = """URL: https://example.com
Username: same_user
Password: same_pass
Application: Chrome

URL: https://example.com
Username: same_user
Password: same_pass
Application: Firefox
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            filepath = f.name

        try:
            credentials = list(parser.parse_file(filepath))
            # Should deduplicate to 1 entry
            assert len(credentials) == 1
        finally:
            Path(filepath).unlink()


class TestComboParser:
    """Tests for ComboParser class."""

    def test_email_validation(self):
        """Test email validation."""
        parser = ComboParser(validate_emails=True)

        assert parser._is_valid_email("test@example.com") is True
        assert parser._is_valid_email("user.name@domain.co.uk") is True
        assert parser._is_valid_email("not-an-email") is False
        assert parser._is_valid_email("@missing-local.com") is False

    def test_delimiter_detection_colon(self):
        """Test colon delimiter detection."""
        parser = ComboParser()

        sample_lines = [
            "test@example.com:password123",
            "user@domain.com:mypass",
            "another@test.org:secret",
        ]

        detected = parser._detect_delimiter(sample_lines)
        assert detected == ":"

    def test_delimiter_detection_pipe(self):
        """Test pipe delimiter detection."""
        parser = ComboParser()

        sample_lines = [
            "test@example.com|password123",
            "user@domain.com|mypass",
            "another@test.org|secret",
        ]

        detected = parser._detect_delimiter(sample_lines)
        assert detected == "|"

    def test_parse_combo_file(self):
        """Test parsing a combo list file."""
        parser = ComboParser()

        content = """test@example.com:password123
user@domain.com:mypass
another@test.org:secret
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            filepath = f.name

        try:
            entries = list(parser.parse_file(filepath))

            assert len(entries) == 3
            assert entries[0].email == "test@example.com"
            assert entries[0].password == "password123"
            assert entries[0].domain == "example.com"
        finally:
            Path(filepath).unlink()

    def test_combo_entry_properties(self):
        """Test ComboEntry computed properties."""
        entry = ComboEntry(
            email="localpart@example.com",
            password="secret",
            source_file="test.txt",
            line_number=1
        )

        assert entry.domain == "example.com"
        assert entry.username == "localpart"

    def test_minimum_password_length(self):
        """Test minimum password length filtering."""
        parser = ComboParser(min_password_length=8)

        content = """test@example.com:short
user@domain.com:longerpassword
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            filepath = f.name

        try:
            entries = list(parser.parse_file(filepath))

            # Only the longer password should be included
            assert len(entries) == 1
            assert entries[0].password == "longerpassword"
        finally:
            Path(filepath).unlink()

    def test_parser_stats(self):
        """Test parser statistics."""
        parser = ComboParser()

        content = """test@example.com:pass1
user@domain.com:pass2
test@example.com:pass1
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            filepath = f.name

        try:
            _ = list(parser.parse_file(filepath))
            stats = parser.get_stats()

            # Should have 2 unique combos due to deduplication
            assert stats["unique_combos"] == 2
        finally:
            Path(filepath).unlink()
