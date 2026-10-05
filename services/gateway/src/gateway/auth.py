import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import exists, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from gateway.db import get_session
from gateway.models import (
    LoginAttempt,
    RefreshFamily,
    RefreshToken,
    RevokedJti,
    User,
)
from gateway.passwords import (
    hash_password,
    normalize_password,
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
    decode_access_token_allow_expired,
    hash_refresh_token,
    issue_access_token,
    login_attempt_key,
    make_csrf,
    new_refresh_token,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger("gateway.auth")

UNIQUE_VIOLATION = "23505"

ACCESS_COOKIE = "__Host-access"
CSRF_COOKIE = "__Host-csrf"
REFRESH_COOKIE = "__Secure-refresh"
REFRESH_PATH = "/api/auth/refresh"
CSRF_HEADER = "X-CSRF-Token"
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
# Lock timeout, deadlock detected, serialization failure: the database gave up
# on a lock, and the client is told to try again.
BUSY_SQLSTATES = (LOCK_NOT_AVAILABLE, "40P01", "40001")


@dataclass(frozen=True)
class SessionLimits:
    """How long a session may sit idle and how long it may live in total."""

    idle: timedelta
    absolute: timedelta


# ADR 0004: readers get long sessions, every privileged role a short one.
READER_LIMITS = SessionLimits(idle=timedelta(hours=24), absolute=timedelta(days=7))
PRIVILEGED_LIMITS = SessionLimits(
    idle=timedelta(minutes=30), absolute=timedelta(hours=8)
)


def session_limits(role: str) -> SessionLimits:
    """Limits for `role`; anything but a reader gets the strict ones."""
    return READER_LIMITS if role == "lector" else PRIVILEGED_LIMITS


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


class ServiceBusy(RuntimeError):
    """A row stayed locked (or the database gave up on a lock); answered with 503.

    `cause` only goes to the security log; every cause gets the same 503 body.
    """

    def __init__(self, message: str, cause: str) -> None:
        super().__init__(message)
        self.cause = cause


def log_service_busy(cause: str) -> None:
    """Record why a 503 happened. The client sees the same body for every cause."""
    logger.warning(
        "security_event event=service_busy cause=%s at=%s",
        cause,
        datetime.now(UTC).isoformat(),
    )


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Annotated[
        str, Field(min_length=3, max_length=32, pattern=r"^[a-z0-9_.-]+$")
    ]
    # ADR 0004 decision 4: at least 15 characters and no composition rules.
    # The upper bound only limits the cost of hashing.
    password: Annotated[str, Field(min_length=15, max_length=128)]

    @field_validator("password")
    @classmethod
    def long_enough_after_normalization(cls, value: str) -> str:
        # The hash is taken over the NFC form, so the minimum applies to it: a
        # decomposed string can be longer raw than the password it stands for.
        # The message is fixed; the value never goes into it.
        if len(normalize_password(value)) < 15:
            raise ValueError("password must have at least 15 characters")
        return value


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
        # Answered like a saturated hasher (same 503); nothing is counted.
        raise ServiceBusy("login attempt row is locked", "attempt_row_locked")
    return attempt


def _login_failed() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=LOGIN_FAILED,
        headers=NO_STORE,
    )


def _set_session_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    sid: str,
    role: str,
    keys: GatewayKeys,
    now: datetime,
) -> None:
    """Set the access, session CSRF and refresh cookies of one session step."""
    absolute = int(session_limits(role).absolute.total_seconds())
    response.set_cookie(
        ACCESS_COOKIE,
        access_token,
        # Longer than the 15-minute JWT on purpose: once the cookie is gone the
        # browser cannot send it and logout could not find the session. The
        # JWT's own `exp` bounds its validity; current_user rejects it after.
        max_age=absolute,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    # The CSRF token is bound to the session's `sid` and, unlike the access
    # cookie, must outlive the JWT: the refresh call that replaces an expired
    # access token has to present it.
    response.set_cookie(
        CSRF_COOKIE,
        make_csrf(sid, keys.csrf_key, now),
        max_age=absolute,
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )
    # `__Secure-` (not `__Host-`) because the cookie is scoped to one path.
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=absolute,
        path=REFRESH_PATH,
        secure=True,
        httponly=True,
        samesite="strict",
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

    # Issue everything first and commit once: the counter is only reset if the
    # session exists. A failure while issuing (signing, database) rolls back
    # the family, the token and the reset together, so the counter still counts.
    family = RefreshFamily(
        id=uuid.uuid4(), user_id=user.id, created_at=now, last_used_at=now
    )
    session.add(family)
    token, claims = issue_access_token(user.id, user.role, str(family.id), keys, now)
    refresh_token = new_refresh_token()
    session.add(
        RefreshToken(
            family_id=family.id,
            token_hash=hash_refresh_token(refresh_token),
            created_at=now,
        )
    )
    # Reset in place instead of deleting: a request queued on this row's lock
    # would otherwise wake up to a missing row.
    attempt.failures = 0
    attempt.locked_until = None
    attempt.updated_at = now
    session.commit()
    _set_session_cookies(
        response, token, refresh_token, claims["sid"], user.role, keys, now
    )
    response.headers.update(NO_STORE)
    _log_event("login_success", subject, now)
    return UserOut(id=user.id, username=user.username, role=user.role)


def _session_denied() -> HTTPException:
    """The one 401 for every way a session credential can be refused."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers=NO_STORE,
    )


def _refresh_failed(reason: str, subject: str, now: datetime) -> None:
    # The clients all see the same 401; the reason is for the security log only.
    # `subject` is a user id or "unknown", never the token.
    logger.warning(
        "security_event event=refresh_failed reason=%s subject=%s at=%s",
        reason,
        subject,
        now.astimezone(UTC).isoformat(),
    )


def _lock_refresh_token(
    session: Session, token_hash: str
) -> tuple[RefreshToken, RefreshFamily] | None:
    """Lock the family, then the token; None when the token is unknown.

    The order is fixed on purpose: find the family without a lock, lock the
    family, then lock the token. Logout locks only the family, so a single order
    (family first) rules out a deadlock whatever plan PostgreSQL picks. Two
    requests carrying the same token queue on the family; the second one then
    sees a used token and is treated as reuse.
    """
    # Same bounded wait as the login counter; SET LOCAL lasts for this transaction.
    session.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
    lock_failed = False
    found = None
    try:
        family_id = session.execute(
            select(RefreshToken.family_id).where(RefreshToken.token_hash == token_hash)
        ).scalar_one_or_none()
        if family_id is not None:
            family = session.execute(
                select(RefreshFamily)
                .where(RefreshFamily.id == family_id)
                .with_for_update()
            ).scalar_one_or_none()
            # Read under the lock: this is the current state of the token.
            token = session.execute(
                select(RefreshToken)
                .where(RefreshToken.token_hash == token_hash)
                .with_for_update()
            ).scalar_one_or_none()
            if family is not None and token is not None:
                found = (token, family)
    except OperationalError as exc:
        if getattr(exc.orig, "sqlstate", None) not in BUSY_SQLSTATES:
            raise
        lock_failed = True
    if lock_failed:
        raise ServiceBusy("refresh token row is locked", "refresh_row_locked")
    return found


@router.post("/refresh", dependencies=[Depends(require_same_origin)])
def refresh(
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> UserOut:
    """Swap the refresh token for a new one plus a new access token.

    Every refusal is the same 401. The session CSRF token is checked against the
    family's `sid` and before anything is changed, so a request without it can
    neither rotate a token nor trigger a revocation.
    """
    presented = request.cookies.get(REFRESH_COOKIE)
    if not presented:
        raise _session_denied()
    found = _lock_refresh_token(session, hash_refresh_token(presented))
    if found is None:
        # The subject is unknown: the token matched nothing, and it is never logged.
        _refresh_failed("unknown", "unknown", now)
        raise _session_denied()
    token, family = found
    if not check_csrf(
        request.cookies.get(CSRF_COOKIE),
        request.headers.get(CSRF_HEADER),
        str(family.id),
        keys.csrf_key,
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if token.used_at is not None:
        # A rotated token came back: someone copied it. No grace period.
        if family.revoked_at is None:
            family.revoked_at = now
        session.commit()
        _log_event("refresh_reuse", str(family.user_id), now, logging.WARNING)
        raise _session_denied()

    # The role comes from the database, not from any token.
    subject = str(family.user_id)
    user = session.get(User, family.user_id)
    if user is None:
        _refresh_failed("user_missing", subject, now)
        raise _session_denied()
    if family.revoked_at is not None:
        _refresh_failed("revoked", subject, now)
        raise _session_denied()
    # A password or role change moves `tokens_valid_since` forward and must end
    # the live sessions too. Truncated to the second, like current_user does.
    if family.created_at < user.tokens_valid_since.replace(microsecond=0):
        _refresh_failed("invalidated", subject, now)
        raise _session_denied()
    limits = session_limits(user.role)
    if now - family.last_used_at > limits.idle:
        _refresh_failed("idle_expired", subject, now)
        raise _session_denied()
    if now - family.created_at > limits.absolute:
        _refresh_failed("absolute_expired", subject, now)
        raise _session_denied()

    token.used_at = now
    new_refresh = new_refresh_token()
    session.add(
        RefreshToken(
            family_id=family.id,
            token_hash=hash_refresh_token(new_refresh),
            created_at=now,
        )
    )
    family.last_used_at = now
    access, claims = issue_access_token(user.id, user.role, str(family.id), keys, now)
    session.commit()
    _set_session_cookies(
        response, access, new_refresh, claims["sid"], user.role, keys, now
    )
    response.headers.update(NO_STORE)
    return UserOut(id=user.id, username=user.username, role=user.role)


def _clear_session_cookies(response: Response) -> None:
    """Delete the three cookies with the attributes they were set with."""
    for name, path, httponly in (
        (ACCESS_COOKIE, "/", True),
        (CSRF_COOKIE, "/", False),
        (REFRESH_COOKIE, REFRESH_PATH, True),
    ):
        response.delete_cookie(
            name, path=path, secure=True, httponly=httponly, samesite="strict"
        )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_same_origin)],
)
def logout(
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> None:
    """End the session of the access token: revoke its family, deny its jti.

    An expired access token is fine (the session may outlive the 15 minutes) but
    its signature, issuer and audience must be valid, and the session CSRF token
    must match its `sid`. The call is idempotent.
    """
    try:
        claims = decode_access_token_allow_expired(
            request.cookies.get(ACCESS_COOKIE) or "", keys
        )
        user_id = uuid.UUID(claims["sub"])
        family_id = uuid.UUID(claims["sid"])
        # The decoder did not check `exp` here, so its type is checked now.
        exp = claims["exp"]
        if isinstance(exp, bool) or not isinstance(exp, int | float):
            raise InvalidToken
        expires_at = datetime.fromtimestamp(exp, UTC)
    except (
        InvalidToken,
        ValueError,
        TypeError,
        AttributeError,
        OverflowError,
        OSError,
    ):
        raise _session_denied() from None
    if not check_csrf(
        request.cookies.get(CSRF_COOKIE),
        request.headers.get(CSRF_HEADER),
        claims["sid"],
        keys.csrf_key,
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    # Same bounded wait as refresh and login; SET LOCAL lasts for this transaction.
    session.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
    busy = False
    try:
        session.execute(
            update(RefreshFamily)
            .where(
                RefreshFamily.id == family_id,
                RefreshFamily.user_id == user_id,
                RefreshFamily.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        if expires_at > now:
            # Idempotent: a repeated logout finds the jti already there.
            session.execute(
                insert(RevokedJti)
                .values(jti=claims["jti"], expires_at=expires_at)
                .on_conflict_do_nothing(index_elements=["jti"])
            )
        session.commit()
    except OperationalError as exc:
        session.rollback()
        if getattr(exc.orig, "sqlstate", None) not in BUSY_SQLSTATES:
            raise
        busy = True
    if busy:
        raise ServiceBusy("logout family row is locked", "logout_row_locked")
    _clear_session_cookies(response)
    response.headers.update(NO_STORE)
    _log_event("logout", str(user_id), now)


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

    One query loads the user only if the token's `jti` is not denied (logout),
    its `sid` names a session (refresh family) that exists and is not revoked,
    and the token was issued no earlier than `tokens_valid_since`. `iat` is whole
    seconds while the column has microseconds, so the column is truncated to the
    second: a token issued in the same second as the cut-off still passes.

    Every failure is the same 401: callers learn nothing about why.
    """
    user = None
    claims = None
    token = request.cookies.get(ACCESS_COOKIE)
    if token:
        try:
            claims = decode_access_token(token, keys)
            user = session.scalar(
                select(User).where(
                    User.id == uuid.UUID(claims["sub"]),
                    ~exists().where(RevokedJti.jti == claims["jti"]),
                    exists().where(
                        RefreshFamily.id == uuid.UUID(claims["sid"]),
                        RefreshFamily.revoked_at.is_(None),
                    ),
                    func.date_trunc("second", User.tokens_valid_since)
                    <= func.to_timestamp(claims["iat"]),
                )
            )
        except InvalidToken, ValueError, TypeError, AttributeError:
            user = None
    if user is None or claims is None:
        raise _session_denied()
    return CurrentUser(user=user, claims=claims)


@router.get("/me")
def me(
    current: Annotated[CurrentUser, Depends(current_user)], response: Response
) -> UserOut:
    response.headers.update(NO_STORE)
    user = current.user
    return UserOut(id=user.id, username=user.username, role=user.role)
