#!/usr/bin/env python3
"""
Example: Check a single password against HIBP using k-anonymity.

This example demonstrates the privacy-preserving password check
where only the first 5 characters of the SHA-1 hash are sent to HIBP.

Author: Cameron Hopkin
License: MIT
"""
import sys
import asyncio

# Add parent directory to path for local development
sys.path.insert(0, str(__file__).rsplit('/', 2)[0] + '/src')

from breach_toolkit import PasswordChecker, check_password_sync


def check_sync(password: str):
    """Check password using synchronous wrapper."""
    print(f"Checking password (sync): {'*' * len(password)}")

    result = check_password_sync(password)

    if result.is_breached:
        print(f"⚠️  WARNING: Password found in {result.breach_count:,} data breaches!")
        print(f"   Hash prefix: {result.hash_prefix}...")
    else:
        print("✅ Password not found in known breaches")
        print(f"   Hash prefix: {result.hash_prefix}...")

    return result


async def check_async(password: str):
    """Check password using async API."""
    print(f"\nChecking password (async): {'*' * len(password)}")

    async with PasswordChecker() as checker:
        result = await checker.check_password(password)

    if result.is_breached:
        print(f"⚠️  WARNING: Password found in {result.breach_count:,} data breaches!")
    else:
        print("✅ Password not found in known breaches")

    return result


async def check_multiple(passwords: list[str]):
    """Check multiple passwords concurrently."""
    print(f"\nChecking {len(passwords)} passwords concurrently...")

    async with PasswordChecker() as checker:
        results = await checker.check_passwords_bulk(passwords, concurrency=3)

    for password, result in zip(passwords, results):
        status = "⚠️ BREACHED" if result.is_breached else "✅ Clean"
        print(f"  {status}: {'*' * len(password)} (count: {result.breach_count:,})")

    return results


def main():
    """Main entry point."""
    # Example passwords to check
    test_passwords = [
        "password123",      # Common, definitely breached
        "MyS3cur3P@ssw0rd!", # Less common
    ]

    print("=" * 50)
    print("Breach Toolkit - Password Check Example")
    print("=" * 50)

    # Sync check
    for pwd in test_passwords[:1]:
        check_sync(pwd)

    # Async check
    asyncio.run(check_async(test_passwords[1]))

    # Bulk check
    asyncio.run(check_multiple(test_passwords))


if __name__ == "__main__":
    main()
