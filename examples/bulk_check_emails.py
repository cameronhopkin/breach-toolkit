#!/usr/bin/env python3
"""
Example: Bulk check emails against HIBP breach database.

Requires HIBP API key for email breach lookups.
Set the HIBP_API_KEY environment variable before running.

Author: Cameron Hopkin
License: MIT
"""
import os
import sys
import asyncio

# Add parent directory to path for local development
sys.path.insert(0, str(__file__).rsplit('/', 2)[0] + '/src')

from breach_toolkit.core.email_checker import EmailChecker
from breach_toolkit.reporters.json_reporter import JSONReporter


async def check_emails(emails: list[str], api_key: str):
    """Check multiple emails for breach exposure."""
    print(f"Checking {len(emails)} email addresses...")
    print("-" * 40)

    results = []

    async with EmailChecker(hibp_api_key=api_key) as checker:
        # Check emails with controlled concurrency
        results = await checker.check_emails_bulk(emails, concurrency=3)

    # Display results
    breached_count = 0
    for result in results:
        if result.is_breached:
            breached_count += 1
            print(f"⚠️  {result.email}")
            print(f"   Found in {result.breach_count} breaches:")
            for breach in result.breaches[:5]:
                print(f"     - {breach}")
            if len(result.breaches) > 5:
                print(f"     ... and {len(result.breaches) - 5} more")
        else:
            print(f"✅ {result.email} - Not found in breaches")

    print("-" * 40)
    print(f"Summary: {breached_count}/{len(results)} emails found in breaches")

    return results


def main():
    """Main entry point."""
    # Get API key from environment
    api_key = os.getenv("HIBP_API_KEY")

    if not api_key:
        print("Error: HIBP_API_KEY environment variable not set")
        print("\nTo use the HIBP API for email checks:")
        print("  1. Get an API key from https://haveibeenpwned.com/API/Key")
        print("  2. Set the environment variable:")
        print("     export HIBP_API_KEY='your-key-here'")
        print("  3. Run this script again")
        sys.exit(1)

    # Example emails to check
    test_emails = [
        "test@example.com",
        "admin@example.org",
        # Add more emails here
    ]

    print("=" * 50)
    print("Breach Toolkit - Email Breach Check Example")
    print("=" * 50)

    # Run the check
    results = asyncio.run(check_emails(test_emails, api_key))

    # Optionally save results
    save_results = input("\nSave results to JSON? (y/n): ").lower().strip()
    if save_results == 'y':
        reporter = JSONReporter()
        reporter.save(results, "email_breach_results.json")
        print("Results saved to email_breach_results.json")


if __name__ == "__main__":
    main()
