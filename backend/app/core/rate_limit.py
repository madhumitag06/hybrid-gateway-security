"""
In-Memory Sliding-Window Rate Limiting Engine
============================================
Provides thread-safe sliding-window rate limiting for sensitive public endpoints
such as authentication (/auth/login, /auth/signup) and prediction APIs.
"""

from collections import defaultdict
import math
import threading
import time
from typing import Dict, List, Optional
from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding-window request rate limiter.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """
        Records an incoming request for `key` and determines whether it exceeds `max_requests`
        in the rolling window of `window_seconds`.

        Returns:
            (is_limited, retry_after_seconds)
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._requests[key]
            # Prune timestamps older than current rolling window
            valid_timestamps = [t for t in timestamps if t > cutoff]

            if len(valid_timestamps) >= max_requests:
                oldest = valid_timestamps[0]
                retry_after = max(1, math.ceil(oldest + window_seconds - now))
                self._requests[key] = valid_timestamps
                return True, retry_after

            valid_timestamps.append(now)
            self._requests[key] = valid_timestamps
            return False, 0

    def clear(self) -> None:
        """Clear all stored rate limit history (primarily for test isolation)."""
        with self._lock:
            self._requests.clear()


# Global in-memory rate limiter instance
_global_rate_limiter = SlidingWindowRateLimiter()


def get_global_rate_limiter() -> SlidingWindowRateLimiter:
    """Access the singleton rate limiter."""
    return _global_rate_limiter


def reset_rate_limits() -> None:
    """Reset rate limiter state across all keys."""
    _global_rate_limiter.clear()


class RateLimiter:
    """
    FastAPI dependency for declaring endpoint-specific rate limits.

    Usage:
        @router.post("/login", dependencies=[Depends(RateLimiter(max_requests=10, window_seconds=60))])
    """

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: int = 60,
        scope: Optional[str] = None,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.scope = scope or "default"

    def __call__(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        # Combine client IP, endpoint path, and explicit scope
        key = f"{self.scope}:{request.url.path}:{client_ip}"

        is_limited, retry_after = _global_rate_limiter.is_rate_limited(
            key=key,
            max_requests=self.max_requests,
            window_seconds=self.window_seconds,
        )

        if is_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {self.max_requests} requests per {self.window_seconds}s. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )
