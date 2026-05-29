#!/usr/bin/env python3
"""
Breach Toolkit - Command Line Interface

Author: Cameron Hopkin
License: MIT
"""
import asyncio
from typing import Union

import click

from .core.email_checker import EmailChecker
from .core.password_checker import PasswordChecker, check_password_sync
from .parsers.stealer_log_parser import StealerLogParser
from .reporters.csv_reporter import CSVReporter
from .reporters.json_reporter import JSONReporter

ReporterT = Union[JSONReporter, CSVReporter]


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Breach Toolkit - Credential breach detection toolkit."""
    pass

@cli.command()
@click.argument('password')
def check_password(password: str):
    """Check if a password has been breached (k-anonymity)."""
    click.echo("Checking password against HIBP...")
    result = check_password_sync(password)

    if result.is_breached:
        click.secho(
            f"⚠️  BREACHED: Found in {result.breach_count:,} data breaches!",
            fg='red',
            bold=True
        )
    else:
        click.secho("✅ Not found in known breaches", fg='green')

@cli.command()
@click.argument('email')
@click.option('--api-key', envvar='HIBP_API_KEY', help='HIBP API key')
def check_email(email: str, api_key: str):
    """Check if an email has been in data breaches."""
    async def _check():
        async with EmailChecker(hibp_api_key=api_key) as checker:
            return await checker.check_email_hibp(email)

    click.echo(f"Checking {email}...")
    result = asyncio.run(_check())

    if result.is_breached:
        click.secho(
            f"⚠️  Found in {result.breach_count} breaches:",
            fg='red'
        )
        for breach in result.breaches[:10]:
            click.echo(f"  - {breach}")
    else:
        click.secho("✅ Not found in known breaches", fg='green')

@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', 'output_format', type=click.Choice(['json', 'csv']), default='json')
def parse_logs(filepath: str, output: str, output_format: str):
    """Parse stealer logs and extract credentials."""
    parser = StealerLogParser()
    credentials = list(parser.parse_file(filepath))

    click.echo(f"Parsed {len(credentials)} credentials")

    if output:
        reporter: ReporterT = JSONReporter() if output_format == 'json' else CSVReporter()
        # save() signatures use invariant List for backward compat; pre-existing.
        reporter.save(credentials, output)  # type: ignore[arg-type]
        click.echo(f"Saved to {output}")
    else:
        for cred in credentials[:10]:
            click.echo(f"{cred.domain} | {cred.username}")
        if len(credentials) > 10:
            click.echo(f"... and {len(credentials) - 10} more")

@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--output', '-o', required=True, help='Output file path')
@click.option('--format', '-f', 'output_format', type=click.Choice(['json', 'csv']), default='json')
@click.option('--recursive/--no-recursive', default=True, help='Search recursively')
def parse_directory(directory: str, output: str, output_format: str, recursive: bool):
    """Parse all stealer logs in a directory."""
    parser = StealerLogParser()
    credentials = list(parser.parse_directory(directory))

    click.echo(f"Parsed {len(credentials)} total credentials from directory")

    reporter: ReporterT = JSONReporter() if output_format == 'json' else CSVReporter()
    # save() signatures use invariant List for backward compat; pre-existing.
    reporter.save(credentials, output)  # type: ignore[arg-type]
    click.echo(f"Saved to {output}")

@cli.command()
@click.argument('passwords_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file path')
@click.option('--concurrency', '-c', default=5, help='Max concurrent requests')
def check_passwords_bulk(passwords_file: str, output: str, concurrency: int):
    """Check multiple passwords from a file (one per line)."""
    with open(passwords_file) as f:
        passwords = [line.strip() for line in f if line.strip()]

    click.echo(f"Checking {len(passwords)} passwords...")

    async def _check_bulk():
        async with PasswordChecker() as checker:
            return await checker.check_passwords_bulk(passwords, concurrency=concurrency)

    results = asyncio.run(_check_bulk())

    breached_count = sum(1 for r in results if r.is_breached)
    click.echo(f"\nResults: {breached_count}/{len(results)} passwords found in breaches")

    if output:
        import json
        output_data = [
            {
                "is_breached": r.is_breached,
                "breach_count": r.breach_count,
                "hash_prefix": r.hash_prefix
            }
            for r in results
        ]
        with open(output, 'w') as f:
            json.dump(output_data, f, indent=2)
        click.echo(f"Saved results to {output}")

if __name__ == "__main__":
    cli()
