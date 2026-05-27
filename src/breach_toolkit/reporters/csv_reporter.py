#!/usr/bin/env python3
"""
Breach Toolkit - CSV Reporter
Generate CSV reports from parsed credentials.

Author: Cameron Hopkin
License: MIT
"""
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Union, Optional
from io import StringIO

from ..parsers.stealer_log_parser import Credential
from ..parsers.combo_parser import ComboEntry
from ..core.password_checker import BreachResult
from ..core.email_checker import EmailBreachResult


class CSVReporter:
    """
    Generate CSV reports from breach analysis results.

    Supports multiple input types with configurable columns.
    """

    def __init__(
        self,
        include_header: bool = True,
        mask_passwords: bool = False,
        delimiter: str = ","
    ):
        """
        Initialize the CSV reporter.

        Args:
            include_header: Include column headers
            mask_passwords: Mask passwords in output
            delimiter: Field delimiter
        """
        self.include_header = include_header
        self.mask_passwords = mask_passwords
        self.delimiter = delimiter

    def _mask_password(self, password: str) -> str:
        """Mask password for safe display."""
        if not password:
            return ""
        if len(password) <= 2:
            return "*" * len(password)
        return password[0] + "*" * (len(password) - 2) + password[-1]

    def _format_datetime(self, dt: Optional[datetime]) -> str:
        """Format datetime for CSV."""
        if dt is None:
            return ""
        return dt.isoformat()

    def generate_credentials(self, credentials: List[Credential]) -> str:
        """
        Generate CSV from credentials.

        Args:
            credentials: List of Credential objects

        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output, delimiter=self.delimiter)

        if self.include_header:
            writer.writerow([
                "url",
                "domain",
                "username",
                "password",
                "source_file",
                "stealer_type",
                "parsed_at"
            ])

        for cred in credentials:
            password = self._mask_password(cred.password) if self.mask_passwords else cred.password
            writer.writerow([
                cred.url,
                cred.domain,
                cred.username,
                password,
                cred.source_file,
                cred.stealer_type,
                self._format_datetime(cred.parsed_at)
            ])

        return output.getvalue()

    def generate_combo_entries(self, entries: List[ComboEntry]) -> str:
        """
        Generate CSV from combo entries.

        Args:
            entries: List of ComboEntry objects

        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output, delimiter=self.delimiter)

        if self.include_header:
            writer.writerow([
                "email",
                "domain",
                "username",
                "password",
                "source_file",
                "line_number",
                "parsed_at"
            ])

        for entry in entries:
            password = self._mask_password(entry.password) if self.mask_passwords else entry.password
            writer.writerow([
                entry.email,
                entry.domain,
                entry.username,
                password,
                entry.source_file,
                entry.line_number,
                self._format_datetime(entry.parsed_at)
            ])

        return output.getvalue()

    def generate_breach_results(self, results: List[BreachResult]) -> str:
        """
        Generate CSV from breach results.

        Args:
            results: List of BreachResult objects

        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output, delimiter=self.delimiter)

        if self.include_header:
            writer.writerow([
                "is_breached",
                "breach_count",
                "hash_prefix",
                "source"
            ])

        for result in results:
            writer.writerow([
                result.is_breached,
                result.breach_count,
                result.hash_prefix,
                result.source
            ])

        return output.getvalue()

    def generate_email_results(self, results: List[EmailBreachResult]) -> str:
        """
        Generate CSV from email breach results.

        Args:
            results: List of EmailBreachResult objects

        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output, delimiter=self.delimiter)

        if self.include_header:
            writer.writerow([
                "email",
                "is_breached",
                "breach_count",
                "breaches",
                "checked_at"
            ])

        for result in results:
            writer.writerow([
                result.email,
                result.is_breached,
                result.breach_count,
                "|".join(result.breaches),
                self._format_datetime(result.checked_at)
            ])

        return output.getvalue()

    def generate(
        self,
        data: List[Union[Credential, ComboEntry, BreachResult, EmailBreachResult]]
    ) -> str:
        """
        Generate CSV from mixed data types.

        Determines the data type from the first item.

        Args:
            data: List of items

        Returns:
            CSV string
        """
        if not data:
            return ""

        first_item = data[0]

        if isinstance(first_item, Credential):
            return self.generate_credentials(data)
        elif isinstance(first_item, ComboEntry):
            return self.generate_combo_entries(data)
        elif isinstance(first_item, BreachResult):
            return self.generate_breach_results(data)
        elif isinstance(first_item, EmailBreachResult):
            return self.generate_email_results(data)
        else:
            raise ValueError(f"Unsupported data type: {type(first_item)}")

    def save(
        self,
        data: List[Union[Credential, ComboEntry, BreachResult, EmailBreachResult]],
        filepath: str
    ):
        """
        Save CSV report to file.

        Args:
            data: List of items
            filepath: Output file path
        """
        csv_content = self.generate(data)

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.write(csv_content)
