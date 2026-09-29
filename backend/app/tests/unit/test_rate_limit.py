import pytest

from app.core.rate_limit import RateLimiter, RateLimitExceeded


def test_limit_is_enforced_inside_the_window() -> None:
    limiter = RateLimiter(limit=2, window_seconds=60)
    limiter.check(1)
    limiter.check(1)
    with pytest.raises(RateLimitExceeded):
        limiter.check(1)
    limiter.check(2)
    limiter.check("ada@example.com")
    limiter.check("ada@example.com")
    with pytest.raises(RateLimitExceeded):
        limiter.check("ada@example.com")
