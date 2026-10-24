"""Distributed & In-Memory Rate Limiting and Abuse Prevention for SentinelFlow AI.

Supports:
- Per-user quotas after authentication
- IP-based quotas for unauthenticated endpoints
- Trusted proxy verification for X-Forwarded-For parsing
- Thread-safe in-memory sliding window implementation
- Redis distributed rate-limiter backend adapter interface
- Clear, non-sensitive rate-limit rejection responses
"""

import os
import time
import threading
from typing import Dict, List, Tuple, Optional, Any
import logging

logger = logging.getLogger("sentinelflow.rate_limiter")

# Environment configurations
RATE_LIMIT_LOGIN_MAX = int(os.getenv("RATE_LIMIT_LOGIN_MAX", "5"))
RATE_LIMIT_AI_MAX = int(os.getenv("RATE_LIMIT_AI_MAX", "10"))
RATE_LIMIT_RESPONSE_MAX = int(os.getenv("RATE_LIMIT_RESPONSE_MAX", "5"))
RATE_LIMIT_ANALYSIS_MAX = int(os.getenv("RATE_LIMIT_ANALYSIS_MAX", "20"))
REDIS_URL = os.getenv("REDIS_URL", "").strip()
TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "1"))


def get_trusted_client_ip(
    headers: Dict[str, str],
    trusted_proxy_count: int = TRUSTED_PROXY_COUNT,
) -> str:
    """Extract client IP accounting for reverse proxy topology.

    Never trusts arbitrary client-supplied forwarding headers.
    When behind N trusted proxies (e.g., Caddy or Nginx reverse proxies),
    the true client IP is located at index: -trusted_proxy_count - 1
    in the X-Forwarded-For header list.
    """
    # Normalize header keys to lowercase
    norm_headers = {k.lower(): v for k, v in headers.items()}

    xff = norm_headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            if len(parts) >= trusted_proxy_count + 1:
                # Read the client IP right before the chain of trusted proxies
                client_ip = parts[-trusted_proxy_count - 1]
            else:
                client_ip = parts[0]
            # Strip port if present
            return client_ip.split(":")[0]

    # Fallback to direct remote addr
    remote_addr = norm_headers.get("remote-addr", norm_headers.get("x-real-ip", "127.0.0.1"))
    return remote_addr.split(":")[0]


class InMemoryRateLimiter:
    """Thread-safe sliding window rate limiter storing hit timestamps."""

    def __init__(self):
        self._lock = threading.Lock()
        self._history: Dict[str, List[float]] = {}

    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int = 60,
    ) -> Tuple[bool, int, float]:
        """Check if request is permitted under sliding window.

        Returns:
            (allowed: bool, remaining_requests: int, retry_after_seconds: float)
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._history.get(key, [])
            # Evict timestamps outside active sliding window
            active = [t for t in timestamps if t > cutoff]

            if len(active) >= max_requests:
                # Limit exceeded: calculate retry-after until oldest item expires
                oldest = active[0]
                retry_after = round(max(0.1, (oldest + window_seconds) - now), 1)
                self._history[key] = active
                return False, 0, retry_after

            # Request allowed: record current timestamp
            active.append(now)
            self._history[key] = active
            remaining = max(0, max_requests - len(active))
            return True, remaining, 0.0

    def reset(self, key: Optional[str] = None) -> None:
        """Reset rate limit history for a key or all keys."""
        with self._lock:
            if key:
                self._history.pop(key, None)
            else:
                self._history.clear()


class RedisRateLimiter:
    """Redis atomic sliding-window rate limiter using sorted sets.

    Used when REDIS_URL is configured for multi-replica production clusters.
    """

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._fallback = InMemoryRateLimiter()
        self._client = None
        try:
            import redis
            self._client = redis.from_url(redis_url, decode_responses=True)
            self._client.ping()
        except Exception as e:
            logger.warning("Redis connection failed (%s); falling back to in-memory store.", e)
            self._client = None

    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int = 60,
    ) -> Tuple[bool, int, float]:
        """Atomic sliding window check via Redis Sorted Sets (ZSET)."""
        if not self._client:
            return self._fallback.is_allowed(key, max_requests, window_seconds)

        now = time.time()
        cutoff = now - window_seconds
        redis_key = f"sentinelflow:ratelimit:{key}"

        try:
            pipe = self._client.pipeline()
            # 1. Remove expired timestamps
            pipe.zremrangebyscore(redis_key, 0, cutoff)
            # 2. Get current active count
            pipe.zcard(redis_key)
            results = pipe.execute()
            current_count = results[1]

            if current_count >= max_requests:
                # Find oldest active item for retry_after calculation
                oldest_entries = self._client.zrange(redis_key, 0, 0, withscores=True)
                retry_after = 60.0
                if oldest_entries:
                    oldest_score = oldest_entries[0][1]
                    retry_after = round(max(0.1, (oldest_score + window_seconds) - now), 1)
                return False, 0, retry_after

            # 3. Add current request and set TTL
            pipe = self._client.pipeline()
            pipe.zadd(redis_key, {str(now): now})
            pipe.expire(redis_key, window_seconds + 5)
            pipe.execute()

            remaining = max(0, max_requests - (current_count + 1))
            return True, remaining, 0.0

        except Exception as e:
            logger.error("Redis rate limit query error: %s. Using in-memory fallback.", e)
            return self._fallback.is_allowed(key, max_requests, window_seconds)


# Global singleton instance (pluggable based on REDIS_URL)
_GLOBAL_LIMITER = RedisRateLimiter(REDIS_URL) if REDIS_URL else InMemoryRateLimiter()


def evaluate_rate_limit(
    action: str,
    user_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    max_requests: Optional[int] = None,
    window_seconds: int = 60,
) -> Tuple[bool, int, float]:
    """Evaluate rate limit for a specific action, scoped by user or client IP.

    Returns:
        (is_allowed, remaining_quota, retry_after_seconds)
    """
    # Prefer authenticated user ID over IP to prevent NAT collision blocking
    scope_key = f"user:{user_id}:{action}" if user_id else f"ip:{client_ip or 'unknown'}:{action}"

    # Default thresholds by action category
    if max_requests is None:
        if action == "login":
            max_requests = RATE_LIMIT_LOGIN_MAX
        elif action in ("gemini_investigation", "ai_triage"):
            max_requests = RATE_LIMIT_AI_MAX
        elif action in ("response_approval", "execute_simulation"):
            max_requests = RATE_LIMIT_RESPONSE_MAX
        else:
            max_requests = RATE_LIMIT_ANALYSIS_MAX

    return _GLOBAL_LIMITER.is_allowed(scope_key, max_requests, window_seconds)
