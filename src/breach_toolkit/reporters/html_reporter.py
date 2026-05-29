#!/usr/bin/env python3
"""
Breach Toolkit - HTML Reporter
Generate HTML reports from parsed credentials.

Author: Cameron Hopkin
License: MIT
"""
from datetime import datetime
from html import escape
from pathlib import Path
from typing import List, Optional, Union

from ..core.password_checker import BreachResult
from ..parsers.combo_parser import ComboEntry
from ..parsers.stealer_log_parser import Credential


class HTMLReporter:
    """
    Generate HTML reports from breach analysis results.

    Produces standalone HTML files with embedded CSS.
    """

    CSS_STYLES = """
    <style>
        :root {
            --bg-color: #1a1a2e;
            --card-bg: #16213e;
            --text-color: #eee;
            --accent: #0f3460;
            --danger: #e94560;
            --success: #00d09c;
            --warning: #f39c12;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: var(--card-bg);
            border-radius: 10px;
        }

        header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
        }

        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--success);
        }

        .stat-card.danger .value {
            color: var(--danger);
        }

        .stat-card.warning .value {
            color: var(--warning);
        }

        .stat-card .label {
            font-size: 0.9rem;
            opacity: 0.8;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 10px;
            overflow: hidden;
        }

        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--accent);
        }

        th {
            background: var(--accent);
            font-weight: 600;
        }

        tr:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
        }

        .badge-danger {
            background: var(--danger);
        }

        .badge-success {
            background: var(--success);
            color: #000;
        }

        .password {
            font-family: monospace;
            background: rgba(0, 0, 0, 0.3);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }

        footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1rem;
            opacity: 0.7;
        }
    </style>
    """

    def __init__(
        self,
        title: str = "Breach Toolkit Report",
        mask_passwords: bool = True
    ):
        """
        Initialize the HTML reporter.

        Args:
            title: Report title
            mask_passwords: Mask passwords in output
        """
        self.title = title
        self.mask_passwords = mask_passwords

    def _mask_password(self, password: str) -> str:
        """Mask password for safe display."""
        if not password:
            return ""
        if len(password) <= 2:
            return "*" * len(password)
        return password[0] + "*" * (len(password) - 2) + password[-1]

    def _escape(self, text: str) -> str:
        """Escape HTML special characters."""
        return escape(str(text))

    def generate_credentials_report(
        self,
        credentials: List[Credential],
        breach_results: Optional[List[BreachResult]] = None
    ) -> str:
        """
        Generate HTML report for credentials.

        Args:
            credentials: List of Credential objects
            breach_results: Optional breach check results

        Returns:
            HTML string
        """
        # Calculate statistics
        total = len(credentials)
        domains = len(set(c.domain for c in credentials))
        stealer_types: dict[str, int] = {}
        for c in credentials:
            stealer_types[c.stealer_type] = stealer_types.get(c.stealer_type, 0) + 1

        breached_count = 0
        if breach_results:
            breached_count = sum(1 for r in breach_results if r.is_breached)

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self._escape(self.title)}</title>
    {self.CSS_STYLES}
</head>
<body>
    <div class="container">
        <header>
            <h1>{self._escape(self.title)}</h1>
            <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="value">{total:,}</div>
                <div class="label">Total Credentials</div>
            </div>
            <div class="stat-card">
                <div class="value">{domains:,}</div>
                <div class="label">Unique Domains</div>
            </div>
"""

        if breach_results:
            breach_pct = (breached_count / len(breach_results) * 100) if breach_results else 0
            html += f"""
            <div class="stat-card danger">
                <div class="value">{breached_count:,}</div>
                <div class="label">Breached ({breach_pct:.1f}%)</div>
            </div>
"""

        html += """
        </div>

        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Type</th>
"""

        if breach_results:
            html += "                    <th>Status</th>\n"

        html += """
                </tr>
            </thead>
            <tbody>
"""

        for i, cred in enumerate(credentials[:1000]):  # Limit to 1000 rows
            password = self._mask_password(cred.password) if self.mask_passwords else cred.password

            html += f"""
                <tr>
                    <td>{self._escape(cred.domain)}</td>
                    <td>{self._escape(cred.username)}</td>
                    <td><span class="password">{self._escape(password)}</span></td>
                    <td>{self._escape(cred.stealer_type)}</td>
"""

            if breach_results and i < len(breach_results):
                result = breach_results[i]
                if result.is_breached:
                    html += f'                    <td><span class="badge badge-danger">Breached ({result.breach_count:,})</span></td>\n'
                else:
                    html += '                    <td><span class="badge badge-success">Clean</span></td>\n'

            html += "                </tr>\n"

        if len(credentials) > 1000:
            html += f"""
                <tr>
                    <td colspan="5" style="text-align: center; opacity: 0.7;">
                        ... and {len(credentials) - 1000:,} more entries (showing first 1000)
                    </td>
                </tr>
"""

        html += """
            </tbody>
        </table>

        <footer>
            <p>Generated by Breach Toolkit v1.0.0</p>
        </footer>
    </div>
</body>
</html>
"""

        return html

    def generate(
        self,
        data: List[Union[Credential, ComboEntry]],
        breach_results: Optional[List[BreachResult]] = None
    ) -> str:
        """
        Generate HTML report from data.

        Args:
            data: List of items
            breach_results: Optional breach check results

        Returns:
            HTML string
        """
        if not data:
            return "<html><body><p>No data to display</p></body></html>"

        if isinstance(data[0], (Credential, ComboEntry)):
            # mypy doesn't narrow list element types from isinstance on data[0];
            # generate_credentials_report accepts both via Union internally.
            return self.generate_credentials_report(data, breach_results)  # type: ignore[arg-type]
        else:
            raise ValueError(f"Unsupported data type: {type(data[0])}")

    def save(
        self,
        data: List[Union[Credential, ComboEntry]],
        filepath: str,
        breach_results: Optional[List[BreachResult]] = None
    ):
        """
        Save HTML report to file.

        Args:
            data: List of items
            filepath: Output file path
            breach_results: Optional breach check results
        """
        html_content = self.generate(data, breach_results)

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
