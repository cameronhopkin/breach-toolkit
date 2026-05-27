#!/usr/bin/env python3
"""
Breach Toolkit - Email Breach Checker
Check if email addresses appear in known breaches.

Author: Cameron Hopkin
License: MIT
"""
import asyncio
import aiohttp
import hashlib
from typing import Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from ..utils.rate_limiter import RateLimiter
from ..utils.logging_config import get_logger

logger = get_logger(__name__)

@dataclass
class EmailBreachResult:
    """Result of an email breach check."""
    email: str
    is_breached: bool
    breach_count: int
    breaches: List[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.utcnow)

class EmailChecker:
    """
    Check email addresses against breach databases.

    Supports multiple backends:
    - Have I Been Pwned (requires API key)
    - Local breach database (privacy-preserving)
    """

    HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

    def __init__(
        self,
        hibp_api_key: Optional[str] = None,
        rate_limit: float = 1.5,
        timeout: int = 10
    ):
        self.hibp_api_key = hibp_api_key
        self.rate_limiter = RateLimiter(rate_limit)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        headers = {"User-Agent": "BreachToolkit/1.0"}
        if self.hibp_api_key:
            headers["hibp-api-key"] = self.hibp_api_key

        self._session = aiohttp.ClientSession(
            timeout=self.timeout,
            headers=headers
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    def _hash_email(self, email: str) -> str:
        """Hash email for privacy-preserving lookups."""
        normalized = email.lower().strip()
        return hashlib.sha256(normalized.encode()).hexdigest()

    async def check_email_hibp(self, email: str) -> EmailBreachResult:
        """
        Check email against Have I Been Pwned.
        Requires API key for full functionality.
        """
        if not self.hibp_api_key:
            logger.warning("HIBP API key not configured, skipping HIBP check")
            return EmailBreachResult(
                email=email,
                is_breached=False,
                breach_count=0
            )

        await self.rate_limiter.acquire()

        try:
            url = self.HIBP_API_URL.format(email=email)
            async with self._session.get(url) as response:
                if response.status == 200:
                    breaches = await response.json()
                    breach_names = [b.get("Name", "Unknown") for b in breaches]
                    return EmailBreachResult(
                        email=email,
                        is_breached=True,
                        breach_count=len(breaches),
                        breaches=breach_names
                    )
                elif response.status == 404:
                    return EmailBreachResult(
                        email=email,
                        is_breached=False,
                        breach_count=0
                    )
                elif response.status == 429:
                    logger.warning("Rate limited, backing off...")
                    await asyncio.sleep(2)
                    return await self.check_email_hibp(email)
                else:
                    logger.error(f"HIBP API error: {response.status}")
                    return EmailBreachResult(
                        email=email,
                        is_breached=False,
                        breach_count=0
                    )
        except aiohttp.ClientError as e:
            logger.error(f"Network error: {e}")
            raise

    async def check_emails_bulk(
        self,
        emails: List[str],
        concurrency: int = 3
    ) -> List[EmailBreachResult]:
        """Check multiple emails with controlled concurrency."""
        semaphore = asyncio.Semaphore(concurrency)

        async def check_with_semaphore(email: str) -> EmailBreachResult:
            async with semaphore:
                return await self.check_email_hibp(email)

        tasks = [check_with_semaphore(e) for e in emails]
        return await asyncio.gather(*tasks)
