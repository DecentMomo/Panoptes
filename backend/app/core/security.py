import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt

from app.core.config import settings

ACCESS_TOKEN_COOKIE = "access_token"
CSRF_TOKEN_COOKIE = "csrf_token"
CSRF_HEADER = "x-csrf-token"

# bcrypt only uses the first 72 bytes and would silently ignore the rest.
BCRYPT_MAX_BYTES = 72
_ALGORITHM = "HS256"

# Checked when the email is unknown, so a missing user takes about as long as a wrong password.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"panoptes-dummy-password", bcrypt.gensalt()).decode()


class PasswordTooLongError(ValueError):
    """Raised when a password is longer than bcrypt can actually hash."""


def hash_password(password: str) -> str:
    encoded = password.encode("utf-8")
    if len(encoded) > BCRYPT_MAX_BYTES:
        raise PasswordTooLongError(
            f"Password is {len(encoded)} bytes; bcrypt only hashes the first {BCRYPT_MAX_BYTES}."
        )
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    encoded = password.encode("utf-8")
    # A too-long password can never match a hash we stored (we refuse to truncate).
    # Still run bcrypt so this branch is not obviously faster than a normal check.
    if len(encoded) > BCRYPT_MAX_BYTES:
        encoded = b"password-too-long"
    return bcrypt.checkpw(encoded, hashed_password.encode("utf-8"))


def dummy_password_hash() -> str:
    return _DUMMY_PASSWORD_HASH


def create_access_token(user_id: int) -> str:
    expires = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": str(user_id), "exp": expires}
    return jwt.encode(payload, settings.secret_key, algorithm=_ALGORITHM)


def decode_access_token(token: str, *, verify_exp: bool = True) -> int | None:
    try:
        # The algorithm allowlist is what rejects `alg: none` and algorithm-confusion tokens.
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[_ALGORITHM],
            options={"verify_exp": verify_exp},
        )
        return int(payload["sub"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        return None


def create_csrf_token(user_id: int) -> str:
    """Signed double-submit value: a nonce plus an HMAC bound to the user id.

    A matching cookie and header is not enough. The MAC has to be ours, for
    this user, so an attacker who can write cookies still cannot forge a token
    for someone else's session.
    """
    nonce = secrets.token_urlsafe(32)
    mac = _csrf_mac(user_id, nonce)
    return f"{nonce}.{mac}"


def csrf_token_matches(token: str, user_id: int) -> bool:
    nonce, separator, mac = token.rpartition(".")
    if not separator or not nonce or not mac:
        return False
    expected = _csrf_mac(user_id, nonce)
    if len(mac) != len(expected):
        return False
    return hmac.compare_digest(mac, expected)


def _csrf_mac(user_id: int, nonce: str) -> str:
    return hmac.new(
        settings.secret_key.encode(),
        f"{user_id}.{nonce}".encode(),
        hashlib.sha256,
    ).hexdigest()
