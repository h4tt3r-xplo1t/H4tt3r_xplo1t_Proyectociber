"""Access JWTs and signed double-submit CSRF tokens (ADR 0004, decisions 1-3).

Tokens are HS256 with a `kid` so the key can rotate. Verification pins the
algorithm in code, requires every claim and never skips the signature. Errors
are a single InvalidToken with no detail: PyJWT text can echo token parts.
"""

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt

from gateway.secrets import GatewayKeys
from gateway.settings import get_jwt_audience, get_jwt_issuer

ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(minutes=15)
LEEWAY_SECONDS = 30
REQUIRED_CLAIMS = ("sub", "role", "sid", "jti", "iat", "nbf", "exp", "iss", "aud")

# Binding of the CSRF token issued before login, when there is no `sid` yet.
# It differs from every real `sid`, so it cannot be replayed inside a session.
PRE_SESSION_BINDING = "pre-session"


class InvalidToken(Exception):
    """The access token is not acceptable. Deliberately carries no detail."""


def issue_access_token(
    user_id: uuid.UUID, role: str, keys: GatewayKeys, now: datetime
) -> tuple[str, dict]:
    """Return a signed access token and its claims.

    A fresh `sid` per call: every login starts a new session (ASVS 7.2.4).
    """
    issued_at = int(now.timestamp())
    claims = {
        "sub": str(user_id),
        "role": role,
        "sid": secrets.token_urlsafe(16),
        "jti": secrets.token_urlsafe(16),
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + int(ACCESS_TOKEN_TTL.total_seconds()),
        "iss": get_jwt_issuer(),
        "aud": get_jwt_audience(),
    }
    token = jwt.encode(
        claims, keys.jwt_key, algorithm=ALGORITHM, headers={"kid": keys.jwt_kid}
    )
    return token, claims


def decode_access_token(token: str, keys: GatewayKeys) -> dict:
    """Verify signature, algorithm, kid, iss, aud, times and required claims."""
    claims = None
    try:
        header = jwt.get_unverified_header(token)
        if header.get("kid") == keys.jwt_kid:
            # `options` is built on every call and never reused or shared
            # (GHSA-gvp8-978c-rx2q); the signature is always verified.
            claims = jwt.decode(
                token,
                keys.jwt_key,
                algorithms=[ALGORITHM],
                audience=get_jwt_audience(),
                issuer=get_jwt_issuer(),
                leeway=LEEWAY_SECONDS,
                options={"require": list(REQUIRED_CLAIMS)},
            )
    except Exception:
        claims = None
    if claims is None:
        raise InvalidToken
    return claims


CSRF_FUTURE_LEEWAY_SECONDS = 30


def _mac(random_part: str, stamp: str, binding: str, key: bytes) -> str:
    message = f"{random_part}.{stamp}.{binding}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def make_csrf(binding: str, key: bytes, now: datetime | None = None) -> str:
    """Return `<random>.<issued-at>.<hmac>`; the HMAC covers all three inputs.

    The issued-at (Unix seconds) lets the server expire a token without state.
    Every token has it, but only the pre-session one is aged by the caller
    (check_csrf's max_age): a session-bound token lives as long as the access
    JWT that carries its `sid`, which already expires.
    """
    issued_at = int((now or datetime.now(UTC)).timestamp())
    random_part = secrets.token_urlsafe(32)
    stamp = str(issued_at)
    return f"{random_part}.{stamp}.{_mac(random_part, stamp, binding, key)}"


def check_csrf(
    cookie: str | None,
    header: str | None,
    binding: str,
    key: bytes,
    now: datetime | None = None,
    max_age: int | None = None,
) -> bool:
    """Double submit: both present, equal, signed for this binding, not too old."""
    if not cookie or not header:
        return False
    if not hmac.compare_digest(cookie.encode(), header.encode()):
        return False
    parts = cookie.split(".")
    if len(parts) != 3:
        return False
    random_part, stamp, mac = parts
    if not random_part or not (stamp.isascii() and stamp.isdigit()) or len(stamp) > 12:
        return False
    expected = _mac(random_part, stamp, binding, key)
    if not hmac.compare_digest(mac.encode(), expected.encode()):
        return False
    if max_age is not None:
        age = (now or datetime.now(UTC)).timestamp() - int(stamp)
        if age > max_age or age < -CSRF_FUTURE_LEEWAY_SECONDS:
            return False
    return True


def login_attempt_key(username: str, csrf_key: bytes) -> str:
    """Key of the login_attempts row: a keyed hash, never the typed username.

    A password typed into the username box must not end up in the table or in
    the logs. The HMAC key is a subkey derived from the CSRF key with domain
    separation, so no CSRF MAC can collide with a counter key. Rotating the
    CSRF key therefore resets every login counter (accepted: counters are
    short-lived state, and rotation is rare).
    """
    subkey = hmac.new(csrf_key, b"login-attempts-v1", hashlib.sha256).digest()
    return hmac.new(subkey, username.encode(), hashlib.sha256).hexdigest()
