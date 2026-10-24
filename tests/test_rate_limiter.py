"""Tests for Distributed & In-Memory Rate Limiting and Abuse Prevention.

Verifies:
- Sliding-window enforcement and cooldown timing
- Quota exhaustion and remaining count accuracy
- Reverse proxy IP parsing with trusted proxy count
- User-specific isolation (preventing cross-user blocking)
"""

import time
import pytest
from sentinelflow.rate_limiter import (
    InMemoryRateLimiter,
    get_trusted_client_ip,
    evaluate_rate_limit,
)


def test_in_memory_sliding_window_allows_within_quota():
    """Verify rate limiter permits requests up to max_requests."""
    limiter = InMemoryRateLimiter()
    key = "test_user_quota"

    for i in range(5):
        allowed, remaining, retry_after = limiter.is_allowed(key, max_requests=5, window_seconds=10)
        assert allowed is True
        assert remaining == 5 - (i + 1)
        assert retry_after == 0.0


def test_in_memory_sliding_window_exhaustion_and_cooldown():
    """Verify rate limiter blocks when threshold exceeded and returns accurate retry_after."""
    limiter = InMemoryRateLimiter()
    key = "test_user_exhaust"

    # Fill quota of 3 calls
    for _ in range(3):
        allowed, _, _ = limiter.is_allowed(key, max_requests=3, window_seconds=2)
        assert allowed is True

    # 4th call is rejected
    allowed, remaining, retry_after = limiter.is_allowed(key, max_requests=3, window_seconds=2)
    assert allowed is False
    assert remaining == 0
    assert retry_after > 0.0

    # Wait for sliding window to elapse
    time.sleep(2.1)

    # Now allowed again
    allowed_again, remaining_again, _ = limiter.is_allowed(key, max_requests=3, window_seconds=2)
    assert allowed_again is True
    assert remaining_again == 2


def test_user_specific_isolation_does_not_block_unrelated_users():
    """Verify that user A hitting a limit does not penalize user B."""
    limiter = InMemoryRateLimiter()

    # Exhaust User A
    for _ in range(3):
        limiter.is_allowed("user:usr_alice:ai_triage", max_requests=3, window_seconds=10)

    blocked_a, _, _ = limiter.is_allowed("user:usr_alice:ai_triage", max_requests=3, window_seconds=10)
    assert blocked_a is False

    # User B should still be allowed
    allowed_b, remaining_b, _ = limiter.is_allowed("user:usr_bob:ai_triage", max_requests=3, window_seconds=10)
    assert allowed_b is True
    assert remaining_b == 2


def test_get_trusted_client_ip_handles_reverse_proxies():
    """Verify client IP extraction handles X-Forwarded-For with trusted proxy count."""
    # Direct remote addr fallback
    assert get_trusted_client_ip({"remote-addr": "192.168.1.10"}) == "192.168.1.10"

    # 1 trusted proxy (default topology: Client -> Cloudflare/Nginx -> Streamlit)
    headers_single_proxy = {
        "x-forwarded-for": "203.0.113.195, 10.0.0.1"
    }
    # With trusted_proxy_count = 1, client IP is 203.0.113.195
    assert get_trusted_client_ip(headers_single_proxy, trusted_proxy_count=1) == "203.0.113.195"

    # Multiple proxy hops (Client -> CDN -> LoadBalancer -> Streamlit)
    headers_multi_proxy = {
        "x-forwarded-for": "198.51.100.22, 172.16.0.5, 10.0.0.1"
    }
    assert get_trusted_client_ip(headers_multi_proxy, trusted_proxy_count=2) == "198.51.100.22"


def test_evaluate_rate_limit_global_function():
    """Verify the evaluate_rate_limit helper properly maps action thresholds."""
    allowed, remaining, _ = evaluate_rate_limit("login", user_id="test_admin_user", max_requests=2)
    assert allowed is True
    assert remaining == 1

    allowed_second, remaining_second, _ = evaluate_rate_limit("login", user_id="test_admin_user", max_requests=2)
    assert allowed_second is True
    assert remaining_second == 0

    allowed_third, _, retry = evaluate_rate_limit("login", user_id="test_admin_user", max_requests=2)
    assert allowed_third is False
    assert retry > 0.0
