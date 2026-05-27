#!/usr/bin/env python3
"""
Breach Toolkit - Password Breach Checker
Uses k-anonymity to check passwords against HIBP without exposing the password.

Author: Cameron Hopkin
License: MIT
"""
import hashlib
import asyncio
import aiohttp
from typing import Optional, Tuple
from dataclasses import dataclass
from ..utils.rate_limiter import RateLimiter
from ..utils.logging_config import get_logger

logger = get_logger(__name__)

@dataclass
class BreachResult:
    """Result of a breach check."""
    is_breached: bool
    breach_count: int
    hash_prefix: str
    source: str = "hibp"

class PasswordChecker:
    """
    Check passwords against Have I Been Pwned using k-anonymity.

    K-anonymity ensures we never send the full password hash to HIBP.
    We send only the first 5 characters of the SHA-1 hash, and HIBP
    returns all hashes that match that prefix. We then check locally.

    This means HIBP never knows which password we're checking.
    """

    HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"

    def __init__(
        self,
        rate_limit: float = 1.5,  # requests per second
        timeout: int = 10,
        user_agent: str = "BreachToolkit/1.0"
    ):
        self.rate_limiter = RateLimiter(rate_limit)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.headers = {"User-Agent": user_agent}
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=self.timeout,
            headers=self.headers
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    def _hash_password(self, password: str) -> Tuple[str, str]:
        """
        Hash password with SHA-1 and split into prefix/suffix.

        Returns:
            Tuple of (prefix, suffix) where prefix is first 5 chars
        """
        # SHA-1 required for HIBP API compatibility, not used for security
        sha1_hash = hashlib.sha1(password.encode('utf-8'), usedforsecurity=False).hexdigest().upper()
        return sha1_hash[:5], sha1_hash[5:]

    async def check_password(self, password: str) -> BreachResult:
        """
        Check if a password has been breached using k-anonymity.

        Args:
            password: The plaintext password to check

        Returns:
            BreachResult with breach status and count
        """
        prefix, suffix = self._hash_password(password)

        await self.rate_limiter.acquire()

        try:
            url = self.HIBP_API_URL.format(prefix=prefix)
            async with self._session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    return self._parse_response(text, prefix, suffix)
                elif response.status == 429:
                    logger.warning("Rate limited by HIBP, backing off...")
                    await asyncio.sleep(2)
                    return await self.check_password(password)
                else:
                    logger.error(f"HIBP API error: {response.status}")
                    return BreachResult(
                        is_breached=False,
                        breach_count=0,
                        hash_prefix=prefix,
                        source="error"
                    )
        except aiohttp.ClientError as e:
            logger.error(f"Network error checking password: {e}")
            raise

    def _parse_response(
        self,
        response_text: str,
        prefix: str,
        suffix: str
    ) -> BreachResult:
        """Parse HIBP response and check for our hash suffix."""
        for line in response_text.splitlines():
            parts = line.split(':')
            if len(parts) == 2:
                hash_suffix, count = parts
                if hash_suffix == suffix:
                    return BreachResult(
                        is_breached=True,
                        breach_count=int(count),
                        hash_prefix=prefix
                    )

        return BreachResult(
            is_breached=False,
            breach_count=0,
            hash_prefix=prefix
        )

    async def check_passwords_bulk(
        self,
        passwords: list[str],
        concurrency: int = 5
    ) -> list[BreachResult]:
        """
        Check multiple passwords concurrently.

        Args:
            passwords: List of passwords to check
            concurrency: Max concurrent requests

        Returns:
            List of BreachResults in same order as input
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def check_with_semaphore(password: str) -> BreachResult:
            async with semaphore:
                return await self.check_password(password)

        tasks = [check_with_semaphore(p) for p in passwords]
        return await asyncio.gather(*tasks)


# Synchronous wrapper for simple usage
def check_password_sync(password: str) -> BreachResult:
    """Synchronous wrapper for checking a single password."""
    async def _check():
        async with PasswordChecker() as checker:
            return await checker.check_password(password)

    return asyncio.run(_check())


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) > 1:
        result = check_password_sync(sys.argv[1])
        if result.is_breached:
            print(f"⚠️  Password found in {result.breach_count:,} breaches!")
        else:
            print("✅ Password not found in known breaches")
    else:
        print("Usage: python password_checker.py <password>")
