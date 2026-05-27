#!/usr/bin/env python3
"""
Breach Toolkit - Stealer Log Parser
Parse common infostealer log formats (Redline, Vidar, Raccoon, etc.)

Author: Cameron Hopkin
License: MIT
"""
import re
import os
from pathlib import Path
from typing import Iterator, Optional
from dataclasses import dataclass
from datetime import datetime
from ..utils.logging_config import get_logger

logger = get_logger(__name__)

@dataclass
class Credential:
    """Parsed credential from stealer logs."""
    url: str
    username: str
    password: str
    source_file: str
    stealer_type: str
    parsed_at: datetime = None

    def __post_init__(self):
        if self.parsed_at is None:
            self.parsed_at = datetime.utcnow()

    @property
    def domain(self) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            return parsed.netloc or self.url
        except Exception:
            return self.url

class StealerLogParser:
    """
    Parse credentials from common infostealer log formats.

    Supported formats:
    - Redline Stealer
    - Vidar Stealer
    - Raccoon Stealer
    - Generic URL:USER:PASS format
    """

    # Common patterns in stealer logs
    PATTERNS = {
        "redline": re.compile(
            r"URL:\s*(.+?)\s*"
            r"Username:\s*(.+?)\s*"
            r"Password:\s*(.+?)(?:\s*Application:|$)",
            re.IGNORECASE | re.DOTALL
        ),
        "vidar": re.compile(
            r"Url:\s*(.+?)\r?\n"
            r"Login:\s*(.+?)\r?\n"
            r"Password:\s*(.+?)(?:\r?\n|$)",
            re.IGNORECASE
        ),
        "raccoon": re.compile(
            r"URL:\s*(.+?)\s*\|\s*"
            r"USER:\s*(.+?)\s*\|\s*"
            r"PASS:\s*(.+?)(?:\s*\||$)",
            re.IGNORECASE
        ),
        "generic_colon": re.compile(
            r"^(https?://[^:]+):([^:]+):(.+)$",
            re.MULTILINE
        ),
        "generic_pipe": re.compile(
            r"^(.+?)\|(.+?)\|(.+?)$",
            re.MULTILINE
        )
    }

    def __init__(self, deduplicate: bool = True):
        self.deduplicate = deduplicate
        self._seen_hashes = set()

    def _get_credential_hash(self, cred: Credential) -> str:
        """Generate hash for deduplication."""
        import hashlib
        data = f"{cred.url}:{cred.username}:{cred.password}"
        # MD5 used for deduplication only, not for security
        return hashlib.md5(data.encode(), usedforsecurity=False).hexdigest()

    def parse_file(
        self,
        filepath: str,
        stealer_type: Optional[str] = None
    ) -> Iterator[Credential]:
        """
        Parse a stealer log file.

        Args:
            filepath: Path to the log file
            stealer_type: Force specific parser (auto-detect if None)

        Yields:
            Credential objects
        """
        path = Path(filepath)
        if not path.exists():
            logger.error(f"File not found: {filepath}")
            return

        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return

        # Auto-detect stealer type if not specified
        if stealer_type is None:
            stealer_type = self._detect_stealer_type(content)

        logger.info(f"Parsing {filepath} as {stealer_type} format")

        pattern = self.PATTERNS.get(stealer_type)
        if not pattern:
            logger.warning(f"Unknown stealer type: {stealer_type}")
            return

        for match in pattern.finditer(content):
            url, username, password = match.groups()

            cred = Credential(
                url=url.strip(),
                username=username.strip(),
                password=password.strip(),
                source_file=str(path),
                stealer_type=stealer_type
            )

            if self.deduplicate:
                cred_hash = self._get_credential_hash(cred)
                if cred_hash in self._seen_hashes:
                    continue
                self._seen_hashes.add(cred_hash)

            yield cred

    def _detect_stealer_type(self, content: str) -> str:
        """Auto-detect stealer type from content patterns."""
        content_lower = content.lower()

        if "application:" in content_lower and "url:" in content_lower:
            return "redline"
        elif "login:" in content_lower and "soft:" in content_lower:
            return "vidar"
        elif "| user:" in content_lower or "|user:" in content_lower:
            return "raccoon"
        elif "://" in content and "|" in content:
            return "generic_pipe"
        else:
            return "generic_colon"

    def parse_directory(
        self,
        directory: str,
        extensions: tuple = ('.txt', '.log')
    ) -> Iterator[Credential]:
        """
        Parse all log files in a directory.

        Args:
            directory: Directory path
            extensions: File extensions to process

        Yields:
            Credential objects
        """
        path = Path(directory)
        if not path.is_dir():
            logger.error(f"Not a directory: {directory}")
            return

        for filepath in path.rglob('*'):
            if filepath.suffix.lower() in extensions:
                yield from self.parse_file(str(filepath))


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        parser = StealerLogParser()
        for cred in parser.parse_file(sys.argv[1]):
            print(f"{cred.domain} | {cred.username} | {'*' * len(cred.password)}")
    else:
        print("Usage: python stealer_log_parser.py <logfile>")
