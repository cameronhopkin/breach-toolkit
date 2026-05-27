#!/usr/bin/env python3
"""
Breach Toolkit - Combo List Parser
Parse email:password combination lists from breach data.

Author: Cameron Hopkin
License: MIT
"""
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from ..utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ComboEntry:
    """Parsed entry from a combo list."""
    email: str
    password: str
    source_file: str
    line_number: int
    parsed_at: datetime = None

    def __post_init__(self):
        if self.parsed_at is None:
            self.parsed_at = datetime.utcnow()

    @property
    def domain(self) -> str:
        """Extract domain from email."""
        if "@" in self.email:
            return self.email.split("@")[1].lower()
        return ""

    @property
    def username(self) -> str:
        """Extract username from email."""
        if "@" in self.email:
            return self.email.split("@")[0]
        return self.email


class ComboParser:
    """
    Parse email:password combination lists.

    Supports various formats commonly found in breach dumps:
    - email:password
    - email;password
    - email|password
    - email\tpassword (tab-separated)
    """

    # Email validation regex
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )

    # Common delimiters in combo lists
    DELIMITERS = [':', ';', '|', '\t']

    def __init__(
        self,
        deduplicate: bool = True,
        validate_emails: bool = True,
        min_password_length: int = 1
    ):
        """
        Initialize the combo parser.

        Args:
            deduplicate: Skip duplicate entries
            validate_emails: Only include valid email addresses
            min_password_length: Minimum password length to include
        """
        self.deduplicate = deduplicate
        self.validate_emails = validate_emails
        self.min_password_length = min_password_length
        self._seen_combos = set()

    def _is_valid_email(self, email: str) -> bool:
        """Check if string is a valid email address."""
        return bool(self.EMAIL_PATTERN.match(email))

    def _detect_delimiter(self, sample_lines: list[str]) -> Optional[str]:
        """
        Auto-detect the delimiter used in the file.

        Args:
            sample_lines: Sample of lines from the file

        Returns:
            Detected delimiter or None
        """
        delimiter_counts = {d: 0 for d in self.DELIMITERS}

        for line in sample_lines:
            for delim in self.DELIMITERS:
                if delim in line:
                    # Check if splitting gives us a valid email
                    parts = line.split(delim, 1)
                    if len(parts) == 2 and self._is_valid_email(parts[0].strip()):
                        delimiter_counts[delim] += 1

        # Return the most common valid delimiter
        best_delim = max(delimiter_counts, key=delimiter_counts.get)
        if delimiter_counts[best_delim] > 0:
            return best_delim
        return None

    def _parse_line(
        self,
        line: str,
        delimiter: str,
        filepath: str,
        line_number: int
    ) -> Optional[ComboEntry]:
        """
        Parse a single line from a combo list.

        Args:
            line: Line to parse
            delimiter: Field delimiter
            filepath: Source file path
            line_number: Line number in file

        Returns:
            ComboEntry or None if invalid
        """
        line = line.strip()
        if not line:
            return None

        parts = line.split(delimiter, 1)
        if len(parts) != 2:
            return None

        email, password = parts[0].strip(), parts[1].strip()

        # Validation
        if self.validate_emails and not self._is_valid_email(email):
            return None

        if len(password) < self.min_password_length:
            return None

        return ComboEntry(
            email=email.lower(),
            password=password,
            source_file=filepath,
            line_number=line_number
        )

    def parse_file(
        self,
        filepath: str,
        delimiter: Optional[str] = None,
        encoding: str = 'utf-8'
    ) -> Iterator[ComboEntry]:
        """
        Parse a combo list file.

        Args:
            filepath: Path to the combo list
            delimiter: Field delimiter (auto-detect if None)
            encoding: File encoding

        Yields:
            ComboEntry objects
        """
        path = Path(filepath)
        if not path.exists():
            logger.error(f"File not found: {filepath}")
            return

        try:
            with open(path, 'r', encoding=encoding, errors='ignore') as f:
                # Read sample for delimiter detection
                sample_lines = []
                for i, line in enumerate(f):
                    sample_lines.append(line)
                    if i >= 100:
                        break

                # Reset file position
                f.seek(0)

                # Auto-detect delimiter if needed
                if delimiter is None:
                    delimiter = self._detect_delimiter(sample_lines)
                    if delimiter is None:
                        logger.error(f"Could not detect delimiter in {filepath}")
                        return
                    logger.info(f"Detected delimiter: {repr(delimiter)}")

                # Parse all lines
                for line_num, line in enumerate(f, 1):
                    entry = self._parse_line(line, delimiter, str(path), line_num)

                    if entry is None:
                        continue

                    # Deduplication
                    if self.deduplicate:
                        combo_key = f"{entry.email}:{entry.password}"
                        if combo_key in self._seen_combos:
                            continue
                        self._seen_combos.add(combo_key)

                    yield entry

        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")

    def parse_directory(
        self,
        directory: str,
        extensions: tuple = ('.txt', '.csv', '.combo'),
        delimiter: Optional[str] = None
    ) -> Iterator[ComboEntry]:
        """
        Parse all combo files in a directory.

        Args:
            directory: Directory path
            extensions: File extensions to process
            delimiter: Field delimiter (auto-detect per file if None)

        Yields:
            ComboEntry objects
        """
        path = Path(directory)
        if not path.is_dir():
            logger.error(f"Not a directory: {directory}")
            return

        for filepath in path.rglob('*'):
            if filepath.suffix.lower() in extensions:
                logger.info(f"Parsing {filepath}")
                yield from self.parse_file(str(filepath), delimiter)

    def get_stats(self) -> dict:
        """
        Get parsing statistics.

        Returns:
            Dict with parsing stats
        """
        return {
            "unique_combos": len(self._seen_combos),
        }

    def reset(self):
        """Reset the parser state (clear deduplication cache)."""
        self._seen_combos.clear()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        parser = ComboParser()
        count = 0

        for entry in parser.parse_file(sys.argv[1]):
            if count < 10:
                print(f"{entry.email} | {'*' * len(entry.password)}")
            count += 1

        print(f"\nTotal entries: {count}")
        print(f"Stats: {parser.get_stats()}")
    else:
        print("Usage: python combo_parser.py <combo_file>")
