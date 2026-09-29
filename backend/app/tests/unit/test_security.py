import base64
from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import settings
from app.core.security import (
    PasswordTooLongError,
    create_access_token,
    create_csrf_token,
    csrf_token_matches,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_round_trip() -> None:
    hashed = hash_password("correct horse")
    assert hashed != "correct horse"
    assert verify_password("correct horse", hashed)
    assert not verify_password("wrong horse", hashed)


def test_password_over_72_bytes_is_rejected() -> None:
    try:
        hash_password("a" * 73)
    except PasswordTooLongError:
        return
    raise AssertionError("expected PasswordTooLongError")


def test_password_of_72_bytes_is_accepted() -> None:
    hashed = hash_password("a" * 72)
    assert verify_password("a" * 72, hashed)


def test_expired_token_is_rejected() -> None:
    token = jwt.encode(
        {"sub": "1", "exp": datetime.now(UTC) - timedelta(minutes=1)},
        settings.secret_key,
        algorithm="HS256",
    )
    assert decode_access_token(token) is None
    assert decode_access_token(token, verify_exp=False) == 1


def test_csrf_token_is_bound_to_the_user() -> None:
    token = create_csrf_token(4)
    assert csrf_token_matches(token, 4)
    assert not csrf_token_matches(token, 5)
    assert not csrf_token_matches("not-a-real-token.deadbeef", 4)


def test_alg_none_token_is_rejected() -> None:
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"1"}').rstrip(b"=").decode()
    assert decode_access_token(f"{header}.{payload}.") is None


def test_wrong_key_token_is_rejected() -> None:
    token = jwt.encode({"sub": "1"}, "not-the-secret-not-the-secret-key!", algorithm="HS256")
    assert decode_access_token(token) is None


def test_valid_token_round_trip() -> None:
    token = create_access_token(7)
    assert decode_access_token(token) == 7
