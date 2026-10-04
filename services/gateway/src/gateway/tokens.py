"""Access JWTs and signed double-submit CSRF tokens (ADR 0004, decisions 1-3).

Tokens are HS256 with a `kid` so the key can rotate. Verification pins the
algorithm in code, requires every claim and never skips the signature. Errors
are a single InvalidToken with no detail: PyJWT text can echo token parts.
"""

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta

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


def _mac(random_part: str, binding: str, key: bytes) -> str:
    message = f"{random_part}.{binding}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def make_csrf(binding: str, key: bytes) -> str:
    """Return `<random>.<hmac>`; the HMAC covers the random part and the binding."""
    random_part = secrets.token_urlsafe(32)
    return f"{random_part}.{_mac(random_part, binding, key)}"


def check_csrf(
    cookie: str | None, header: str | None, binding: str, key: bytes
) -> bool:
    """Double submit: both present, equal, and signed for this binding."""
    if not cookie or not header:
        return False
    cookie_bytes, header_bytes = cookie.encode(), header.encode()
    if not hmac.compare_digest(cookie_bytes, header_bytes):
        return False
    random_part, dot, mac = cookie.rpartition(".")
    if not dot or not random_part:
        return False
    expected = _mac(random_part, binding, key)
    return hmac.compare_digest(mac.encode(), expected.encode())
