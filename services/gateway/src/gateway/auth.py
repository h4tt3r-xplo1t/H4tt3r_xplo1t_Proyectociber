import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from gateway.db import get_session
from gateway.models import LoginAttempt, User
from gateway.passwords import (
    HashingBusy,
    hash_password,
    verify_dummy,
    verify_password,
)
from gateway.secrets import GatewayKeys, get_gateway_keys
from gateway.settings import get_allowed_origin
from gateway.tokens import (
    PRE_SESSION_BINDING,
    InvalidToken,
    check_csrf,
    decode_access_token,
    issue_access_token,
    login_attempt_key,
    make_csrf,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger("gateway.auth")

UNIQUE_VIOLATION = "23505"

ACCESS_COOKIE = "__Host-access"
CSRF_COOKIE = "__Host-csrf"
CSRF_HEADER = "X-CSRF-Token"
ACCESS_COOKIE_MAX_AGE = 15 * 60
PRE_SESSION_CSRF_MAX_AGE = 10 * 60

# ADR 0004 decision 4: the first FREE_FAILURES failures cost nothing; every
# failure after that locks the account, for longer each time and capped at the
# last value: 4th failure 1 min, 5th 5 min, 6th 15 min, 7th and later 30 min.
FREE_FAILURES = 3
LOCKOUT_MINUTES = (1, 5, 15, 30)

# How long a login waits for the counter row's lock before giving up (503).
# Module-level so tests can shorten it; it is a fixed literal, never user input.
LOCK_TIMEOUT = "2s"
LOCK_NOT_AVAILABLE = "55P03"

# Responses that carry or depend on a session must never sit in a cache.
NO_STORE = {"Cache-Control": "no-store"}

# One fixed body for wrong password, unknown user and locked account.
LOGIN_FAILED = "Login failed; Invalid user ID or password"


def lockout_duration(failures: int) -> timedelta | None:
    """Lock time owed after `failures` consecutive failures, if any."""
    if failures <= FREE_FAILURES:
        return None
    step = min(failures - FREE_FAILURES - 1, len(LOCKOUT_MINUTES) - 1)
    return timedelta(minutes=LOCKOUT_MINUTES[step])


def get_now() -> datetime:
    """The clock, as a dependency so tests can move it without sleeping."""
    return datetime.now(UTC)


def get_keys() -> GatewayKeys:
    return get_gateway_keys()


def require_same_origin(request: Request) -> None:
    """Reject state-changing requests that are not from the SPA's own origin.

    `Sec-Fetch-Site` is set by the browser and cannot be forged by a page. When
    it is present it must say same-origin; only when it is absent (older
    browsers) does the `Origin` header have to equal the configured origin.
    With neither header the request is refused (fail closed).
    """
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        allowed = fetch_site == "same-origin"
    else:
        allowed = request.headers.get("origin") == get_allowed_origin()
    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def require_presession_csrf(
    request: Request,
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> None:
    """Double-submit check with the token issued by GET /api/auth/csrf."""
    if not check_csrf(
        request.cookies.get(CSRF_COOKIE),
        request.headers.get(CSRF_HEADER),
        PRE_SESSION_BINDING,
        keys.csrf_key,
        now,
        PRE_SESSION_CSRF_MAX_AGE,
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def _log_event(
    event: str, subject: str, now: datetime, level: int = logging.INFO
) -> None:
    # Only the event, who and the UTC time. Who is the user id, or for an unknown
    # user "unknown:<first 16 hex of the keyed hash of the username>", never the
    # typed name. Never a password, token, CSRF value or password hash.
    logger.log(
        level,
        "security_event event=%s subject=%s at=%s",
        event,
        subject,
        now.astimezone(UTC).isoformat(),
    )


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Annotated[
        str, Field(min_length=3, max_length=32, pattern=r"^[a-z0-9_.-]+$")
    ]
    # ADR 0004 decision 4: at least 15 characters and no composition rules.
    # The upper bound only limits the cost of hashing.
    password: Annotated[str, Field(min_length=15, max_length=128)]


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    role: str


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Same username rules as registration, which also bounds the size of the
    # keys kept in login_attempts. The pattern is ASCII lowercase only, so the
    # validated value already is the normalized one.
    username: Annotated[
        str, Field(min_length=3, max_length=32, pattern=r"^[a-z0-9_.-]+$")
    ]
    # Only the upper bound (cost of hashing); length rules apply at registration.
    password: Annotated[str, Field(min_length=1, max_length=128)]


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_same_origin)],
)
def register(
    body: RegisterRequest, session: Annotated[Session, Depends(get_session)]
) -> UserOut:
    user = User(username=body.username, password_hash=hash_password(body.password))
    session.add(user)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        sqlstate = getattr(exc.orig, "sqlstate", None)
        if sqlstate != UNIQUE_VIOLATION:
            # PostgreSQL's DETAIL repeats the failing row, hash included, so
            # only the SQLSTATE goes into the error that gets logged.
            raise RuntimeError(f"user insert failed (sqlstate {sqlstate})") from None
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username not available"
        ) from None
    return UserOut(id=user.id, username=user.username, role=user.role)


@router.get("/csrf")
def csrf(
    response: Response,
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> dict[str, str]:
    """Issue the short-lived CSRF token the login form must send back."""
    token = make_csrf(PRE_SESSION_BINDING, keys.csrf_key, now)
    # Readable by the SPA on purpose (not HttpOnly): it copies it into the header.
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=PRE_SESSION_CSRF_MAX_AGE,
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )
    response.headers.update(NO_STORE)
    return {"csrf_token": token}


def _lock_attempt(session: Session, attempt_key: str) -> LoginAttempt:
    """Get the counter row for `attempt_key` locked, creating it if needed.

    `attempt_key` is the keyed hash of the username, never the name itself.

    The row lock serializes concurrent attempts on the same name, so parallel
    guesses cannot slip past the counter.
    """
    # The queue on the lock (held while Argon2id runs) must not wait forever.
    # SET LOCAL lasts until this transaction ends.
    session.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
    lock_failed = False
    attempt = None
    try:
        session.execute(
            insert(LoginAttempt)
            .values(attempt_key=attempt_key)
            .on_conflict_do_nothing(index_elements=["attempt_key"])
        )
        attempt = session.execute(
            select(LoginAttempt)
            .where(LoginAttempt.attempt_key == attempt_key)
            .with_for_update()
        ).scalar_one()
    except OperationalError as exc:
        if getattr(exc.orig, "sqlstate", None) != LOCK_NOT_AVAILABLE:
            raise
        lock_failed = True
    if lock_failed:
        # Same answer as a saturated hasher; nothing is counted.
        raise HashingBusy("login attempt row is locked")
    return attempt


def _login_failed() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=LOGIN_FAILED,
        headers=NO_STORE,
    )


@router.post(
    "/login",
    dependencies=[Depends(require_same_origin), Depends(require_presession_csrf)],
)
def login(
    body: LoginRequest,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> UserOut:
    username = body.username
    user = session.scalar(select(User).where(User.username == username))
    attempt_key = login_attempt_key(username, keys.csrf_key)
    attempt = _lock_attempt(session, attempt_key)
    # Never log the typed name of an unknown user (it may be a password): only
    # a short prefix of its keyed hash, enough to correlate repeated attempts.
    subject = str(user.id) if user else f"unknown:{attempt_key[:16]}"

    if attempt.locked_until is not None and attempt.locked_until > now:
        # Locked: do not even look at the password, but spend the same time.
        session.commit()
        verify_dummy(body.password)
        _log_event("login_blocked", subject, now, logging.WARNING)
        raise _login_failed()

    if user is None:
        verified = verify_dummy(body.password)
    else:
        verified = verify_password(user.password_hash, body.password)

    if not verified:
        attempt.failures += 1
        attempt.updated_at = now
        lock = lockout_duration(attempt.failures)
        if lock is not None:
            attempt.locked_until = now + lock
        session.commit()
        _log_event("login_failure", subject, now, logging.WARNING)
        if lock is not None:
            _log_event("account_locked", subject, now, logging.WARNING)
        raise _login_failed()

    # Reset in place instead of deleting: a request queued on this row's lock
    # would otherwise wake up to a missing row.
    attempt.failures = 0
    attempt.locked_until = None
    attempt.updated_at = now
    session.commit()
    token, claims = issue_access_token(user.id, user.role, keys, now)
    response.set_cookie(
        ACCESS_COOKIE,
        token,
        max_age=ACCESS_COOKIE_MAX_AGE,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    # From here on the CSRF token is bound to this session's `sid`.
    response.set_cookie(
        CSRF_COOKIE,
        make_csrf(claims["sid"], keys.csrf_key, now),
        max_age=ACCESS_COOKIE_MAX_AGE,
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )
    response.headers.update(NO_STORE)
    _log_event("login_success", subject, now)
    return UserOut(id=user.id, username=user.username, role=user.role)


@dataclass(frozen=True)
class CurrentUser:
    user: User
    claims: dict


def current_user(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
) -> CurrentUser:
    """Authenticate from the access cookie and reload the user from the database.

    Every failure is the same 401: callers learn nothing about why.
    """
    user = None
    claims = None
    token = request.cookies.get(ACCESS_COOKIE)
    if token:
        try:
            claims = decode_access_token(token, keys)
            user = session.get(User, uuid.UUID(claims["sub"]))
        except InvalidToken, ValueError:
            user = None
    if user is None or claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers=NO_STORE,
        )
    return CurrentUser(user=user, claims=claims)


@router.get("/me")
def me(
    current: Annotated[CurrentUser, Depends(current_user)], response: Response
) -> UserOut:
    response.headers.update(NO_STORE)
    user = current.user
    return UserOut(id=user.id, username=user.username, role=user.role)
