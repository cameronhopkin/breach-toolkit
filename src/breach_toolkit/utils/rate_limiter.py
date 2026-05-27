#!/usr/bin/env python3
"""
Breach Toolkit - Rate Limiter
Async-compatible rate limiting for API requests.

Author: Cameron Hopkin
License: MIT
"""
import asyncio
import time
from typing import Optional


class RateLimiter:
    """
    Token bucket rate limiter for API requests.

    Supports both async and sync usage patterns.
    Uses a token bucket algorithm for smooth rate limiting.
    """

    def __init__(
        self,
        rate: float = 1.5,
        burst: Optional[int] = None
    ):
        """
        Initialize the rate limiter.

        Args:
            rate: Maximum requests per second
            burst: Maximum burst size (defaults to rate * 2)
        """
        self.rate = rate
        self.burst = burst or int(rate * 2)
        self._tokens = self.burst
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()

    def _add_tokens(self):
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(
            self.burst,
            self._tokens + elapsed * self.rate
        )
        self._last_update = now

    async def acquire(self):
        """
        Acquire permission to make a request.

        Blocks until a token is available.
        """
        async with self._lock:
            while True:
                self._add_tokens()

                if self._tokens >= 1:
                    self._tokens -= 1
                    return

                # Calculate wait time for next token
                wait_time = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait_time)

    def acquire_sync(self):
        """
        Synchronous version of acquire.

        Blocks until a token is available.
        """
        while True:
            self._add_tokens()

            if self._tokens >= 1:
                self._tokens -= 1
                return

            wait_time = (1 - self._tokens) / self.rate
            time.sleep(wait_time)

    @property
    def available_tokens(self) -> float:
        """Get current number of available tokens."""
        self._add_tokens()
        return self._tokens

    def reset(self):
        """Reset the rate limiter to full capacity."""
        self._tokens = self.burst
        self._last_update = time.monotonic()


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter.

    More accurate than token bucket for strict rate limiting,
    but uses more memory to track request timestamps.
    """

    def __init__(
        self,
        rate: float = 1.5,
        window_seconds: float = 1.0
    ):
        """
        Initialize the sliding window rate limiter.

        Args:
            rate: Maximum requests per window
            window_seconds: Window duration in seconds
        """
        self.rate = rate
        self.window = window_seconds
        self._requests: list[float] = []
        self._lock = asyncio.Lock()

    def _clean_old_requests(self):
        """Remove requests outside the current window."""
        cutoff = time.monotonic() - self.window
        self._requests = [t for t in self._requests if t > cutoff]

    async def acquire(self):
        """
        Acquire permission to make a request.

        Blocks until the request rate is below the limit.
        """
        async with self._lock:
            while True:
                self._clean_old_requests()

                if len(self._requests) < self.rate:
                    self._requests.append(time.monotonic())
                    return

                # Wait until the oldest request expires
                oldest = self._requests[0]
                wait_time = oldest + self.window - time.monotonic()
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                else:
                    # Shouldn't happen, but handle gracefully
                    await asyncio.sleep(0.1)

    def get_wait_time(self) -> float:
        """
        Get estimated wait time before next request is allowed.

        Returns:
            Seconds until next request can be made (0 if immediate)
        """
        self._clean_old_requests()

        if len(self._requests) < self.rate:
            return 0.0

        oldest = self._requests[0]
        wait_time = oldest + self.window - time.monotonic()
        return max(0.0, wait_time)


if __name__ == "__main__":
    # Test the rate limiter
    import asyncio

    async def test():
        limiter = RateLimiter(rate=2.0)  # 2 requests per second

        for i in range(5):
            await limiter.acquire()
            print(f"Request {i+1} at {time.monotonic():.2f}")

    asyncio.run(test())
