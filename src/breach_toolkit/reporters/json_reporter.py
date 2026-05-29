#!/usr/bin/env python3
"""
Breach Toolkit - JSON Reporter
Generate JSON reports from parsed credentials.

Author: Cameron Hopkin
License: MIT
"""
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional, Union

from ..core.email_checker import EmailBreachResult
from ..core.password_checker import BreachResult
from ..parsers.combo_parser import ComboEntry
from ..parsers.stealer_log_parser import Credential


class JSONReporter:
    """
    Generate JSON reports from breach analysis results.

    Supports multiple input types and provides configurable
    output formatting.
    """

    def __init__(
        self,
        indent: int = 2,
        include_metadata: bool = True,
        mask_passwords: bool = False
    ):
        """
        Initialize the JSON reporter.

        Args:
            indent: JSON indentation level
            include_metadata: Include report metadata
            mask_passwords: Mask passwords in output
        """
        self.indent = indent
        self.include_metadata = include_metadata
        self.mask_passwords = mask_passwords

    def _serialize_datetime(self, obj):
        """JSON serializer for datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def _mask_password(self, password: str) -> str:
        """Mask password for safe display."""
        if not password:
            return ""
        if len(password) <= 2:
            return "*" * len(password)
        return password[0] + "*" * (len(password) - 2) + password[-1]

    def _credential_to_dict(self, cred: Credential) -> dict:
        """Convert Credential to dictionary."""
        data = {
            "url": cred.url,
            "domain": cred.domain,
            "username": cred.username,
            "password": self._mask_password(cred.password) if self.mask_passwords else cred.password,
            "source_file": cred.source_file,
            "stealer_type": cred.stealer_type,
            "parsed_at": cred.parsed_at.isoformat() if cred.parsed_at else None
        }
        return data

    def _combo_entry_to_dict(self, entry: ComboEntry) -> dict:
        """Convert ComboEntry to dictionary."""
        data = {
            "email": entry.email,
            "domain": entry.domain,
            "username": entry.username,
            "password": self._mask_password(entry.password) if self.mask_passwords else entry.password,
            "source_file": entry.source_file,
            "line_number": entry.line_number,
            "parsed_at": entry.parsed_at.isoformat() if entry.parsed_at else None
        }
        return data

    def _breach_result_to_dict(self, result: BreachResult) -> dict:
        """Convert BreachResult to dictionary."""
        return {
            "is_breached": result.is_breached,
            "breach_count": result.breach_count,
            "hash_prefix": result.hash_prefix,
            "source": result.source
        }

    def _email_breach_to_dict(self, result: EmailBreachResult) -> dict:
        """Convert EmailBreachResult to dictionary."""
        return {
            "email": result.email,
            "is_breached": result.is_breached,
            "breach_count": result.breach_count,
            "breaches": result.breaches,
            "checked_at": result.checked_at.isoformat() if result.checked_at else None
        }

    def generate(
        self,
        data: List[Union[Credential, ComboEntry, BreachResult, EmailBreachResult]],
        title: Optional[str] = None
    ) -> str:
        """
        Generate JSON report string.

        Args:
            data: List of items to include in report
            title: Optional report title

        Returns:
            JSON string
        """
        # Convert items to dictionaries
        items = []
        for item in data:
            if isinstance(item, Credential):
                items.append(self._credential_to_dict(item))
            elif isinstance(item, ComboEntry):
                items.append(self._combo_entry_to_dict(item))
            elif isinstance(item, BreachResult):
                items.append(self._breach_result_to_dict(item))
            elif isinstance(item, EmailBreachResult):
                items.append(self._email_breach_to_dict(item))
            else:
                # Try generic conversion
                try:
                    items.append(asdict(item))
                except Exception:
                    items.append(str(item))

        # Build report structure
        report: Any
        if self.include_metadata:
            report = {
                "metadata": {
                    "title": title or "Breach Toolkit Report",
                    "generated_at": datetime.utcnow().isoformat(),
                    "total_items": len(items),
                    "generator": "Breach Toolkit v1.0.0"
                },
                "data": items
            }
        else:
            report = items

        return json.dumps(report, indent=self.indent, default=self._serialize_datetime)

    def save(
        self,
        data: List[Union[Credential, ComboEntry, BreachResult, EmailBreachResult]],
        filepath: str,
        title: Optional[str] = None
    ):
        """
        Save JSON report to file.

        Args:
            data: List of items to include in report
            filepath: Output file path
            title: Optional report title
        """
        json_content = self.generate(data, title)

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:
            f.write(json_content)

    def generate_summary(
        self,
        credentials: List[Credential],
        breach_results: Optional[List[BreachResult]] = None
    ) -> str:
        """
        Generate a summary report.

        Args:
            credentials: List of parsed credentials
            breach_results: Optional list of breach check results

        Returns:
            JSON summary string
        """
        # Analyze credentials
        domains: dict[str, int] = {}
        stealer_types: dict[str, int] = {}

        for cred in credentials:
            # Count by domain
            domain = cred.domain
            domains[domain] = domains.get(domain, 0) + 1

            # Count by stealer type
            stealer_types[cred.stealer_type] = stealer_types.get(cred.stealer_type, 0) + 1

        summary = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "Breach Toolkit v1.0.0"
            },
            "summary": {
                "total_credentials": len(credentials),
                "unique_domains": len(domains),
                "top_domains": sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10],
                "by_stealer_type": stealer_types
            }
        }

        if breach_results:
            breached = sum(1 for r in breach_results if r.is_breached)
            # mypy sees summary["summary"] as object; the structure is dict by construction above
            summary["summary"]["breach_check"] = {  # type: ignore[index]
                "total_checked": len(breach_results),
                "breached": breached,
                "clean": len(breach_results) - breached,
                "breach_rate": f"{(breached / len(breach_results) * 100):.1f}%"
            }

        return json.dumps(summary, indent=self.indent)
