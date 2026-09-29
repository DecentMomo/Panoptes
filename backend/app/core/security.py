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


def decode_access_token(token: str) -> int | None:
    try:
        # The algorithm allowlist is what rejects `alg: none` and algorithm-confusion tokens.
        payload = jwt.decode(token, settings.secret_key, algorithms=[_ALGORITHM])
        return int(payload["sub"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        return None
