import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import exists, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError, InvalidRequestError, OperationalError
from sqlalchemy.orm import Session

from gateway.db import get_session
from gateway.mfa import (
    TOTP_CODE,
    matching_step,
    new_recovery_codes,
    new_totp_secret,
    normalize_recovery_code,
    provisioning_uri,
)
from gateway.models import (
    PRIVILEGED_ROLES,
    LoginAttempt,
    RecoveryCode,
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
    ENROLL_TOKEN_TTL,
    MFA_PENDING_TTL,
    PRE_SESSION_BINDING,
    SCOPE_ENROLL_MFA,
    SCOPE_MFA_PENDING,
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
from gateway.transit import decrypt_totp_secret, encrypt_totp_secret

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


# ADR 0004 decision 4: at least 15 characters (after NFC) and no composition rules.
PASSWORD_MIN_LENGTH = 15


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Annotated[
        str, Field(min_length=3, max_length=32, pattern=r"^[a-z0-9_.-]+$")
    ]
    # The upper bound only limits the cost of hashing.
    password: Annotated[str, Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)]

    @field_validator("password")
    @classmethod
    def long_enough_after_normalization(cls, value: str) -> str:
        # The hash is taken over the NFC form, so the minimum applies to it: a
        # decomposed string can be longer raw than the password it stands for.
        # The message is fixed; the value never goes into it.
        if len(normalize_password(value)) < PASSWORD_MIN_LENGTH:
            raise ValueError(
                f"password must have at least {PASSWORD_MIN_LENGTH} characters"
            )
        return value


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    role: str


class StatusOut(BaseModel):
    """Login answer when the session is not issued yet: a second step is due."""

    status: Literal["mfa_enrollment_required", "mfa_required"]


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Required from a full session (re-authentication); the enroll-mfa session
    # has just checked the password and sends nothing.
    current_password: Annotated[str, Field(min_length=1, max_length=128)] | None = None


class EnrollOut(BaseModel):
    otpauth_uri: str
    secret: str


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]
    # Always True: every session of the user ends and a normal login, which
    # now asks for the second factor, follows.
    relogin_required: bool


# The second factor is a TOTP (6 digits) or a recovery code (XXXX-XXXX-XXXX, the
# dashes optional), so only the shape of the characters is checked here.
class MfaLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: Annotated[
        str, Field(min_length=6, max_length=32, pattern=r"^[0-9A-Za-z -]+$")
    ]


class ConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: Annotated[str, Field(pattern=r"^[0-9]{6}$")]


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
    body: RegisterRequest,
    session: Annotated[Session, Depends(get_session)],
    now: Annotated[datetime, Depends(get_now)],
) -> UserOut:
    # `tokens_valid_since` is compared with values from the app clock (`iat`,
    # `family.created_at`), so it must be written from that same clock, never
    # from the database's now(). Any future write to this column (password or
    # role change, A3) must use the app clock too.
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        tokens_valid_since=now,
    )
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
        # A purge can delete the row between the insert and the lock; one retry
        # recreates it, and a second miss is answered like a busy service.
        for _ in range(2):
            session.execute(
                insert(LoginAttempt)
                .values(attempt_key=attempt_key)
                .on_conflict_do_nothing(index_elements=["attempt_key"])
            )
            attempt = session.execute(
                select(LoginAttempt)
                .where(LoginAttempt.attempt_key == attempt_key)
                .with_for_update()
            ).scalar_one_or_none()
            if attempt is not None:
                break
    except OperationalError as exc:
        if getattr(exc.orig, "sqlstate", None) != LOCK_NOT_AVAILABLE:
            raise
        lock_failed = True
    if lock_failed:
        # Answered like a saturated hasher (same 503); nothing is counted.
        raise ServiceBusy("login attempt row is locked", "attempt_row_locked")
    if attempt is None:
        session.rollback()
        raise ServiceBusy("login attempt row vanished", "attempt_row_vanished")
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


def _record_failure(
    session: Session,
    attempt: LoginAttempt,
    subject: str,
    now: datetime,
    event: str,
) -> None:
    """Count one failure on the (locked) row, lock the account if owed, commit."""
    attempt.failures += 1
    attempt.updated_at = now
    lock = lockout_duration(attempt.failures)
    if lock is not None:
        attempt.locked_until = now + lock
    session.commit()
    _log_event(event, subject, now, logging.WARNING)
    if lock is not None:
        _log_event("account_locked", subject, now, logging.WARNING)


def _start_session(
    response: Response,
    session: Session,
    user: User,
    attempt: LoginAttempt,
    keys: GatewayKeys,
    now: datetime,
) -> UserOut:
    """Issue the full session (family, access, refresh, CSRF) and reset the counter.

    The one path every successful login ends in: the password alone for a user
    without MFA, the second factor for one with it. The caller may have staged
    other changes (a denied token, a spent recovery code): everything commits
    together.
    """
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
    _log_event("login_success", str(user.id), now)
    return UserOut(id=user.id, username=user.username, role=user.role)


def _start_scoped_session(
    response: Response,
    user: User,
    scope: str,
    ttl: timedelta,
    keys: GatewayKeys,
    now: datetime,
) -> None:
    """Set the cookies of a limited-purpose session: no family, no refresh token.

    The `sid` is a fresh random id that names nothing in the database; the CSRF
    token is bound to it, like a real session's, and both cookies live as long
    as the token does.
    """
    sid = str(uuid.uuid4())
    token, _ = issue_access_token(
        user.id, user.role, sid, keys, now, scope=scope, ttl=ttl
    )
    max_age = int(ttl.total_seconds())
    response.set_cookie(
        ACCESS_COOKIE,
        token,
        max_age=max_age,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    response.set_cookie(
        CSRF_COOKIE,
        make_csrf(sid, keys.csrf_key, now),
        max_age=max_age,
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )
    response.headers.update(NO_STORE)


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
) -> UserOut | StatusOut:
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
        _record_failure(session, attempt, subject, now, "login_failure")
        raise _login_failed()

    if user.mfa_enabled_at is not None:
        # Password ok, second factor due. The counter is not reset: only a
        # complete login does that, so guessing codes cannot restart it.
        session.commit()
        _start_scoped_session(
            response, user, SCOPE_MFA_PENDING, MFA_PENDING_TTL, keys, now
        )
        return StatusOut(status="mfa_required")

    if user.role in PRIVILEGED_ROLES:
        # A privileged role cannot operate without MFA. Within the enrollment
        # window the user may enroll; outside it (or with no window) the answer
        # is the generic one, counted like any failed login.
        if user.mfa_enroll_until is None or user.mfa_enroll_until <= now:
            _record_failure(session, attempt, subject, now, "login_failure")
            raise _login_failed()
        session.commit()
        _start_scoped_session(
            response, user, SCOPE_ENROLL_MFA, ENROLL_TOKEN_TTL, keys, now
        )
        return StatusOut(status="mfa_enrollment_required")

    return _start_session(response, session, user, attempt, keys, now)


def _session_denied() -> HTTPException:
    """The one 401 for every way a session credential can be refused."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers=NO_STORE,
    )


def _lacks_required_mfa(user: User) -> bool:
    """A privileged role without an active second factor has no full session."""
    return user.role in PRIVILEGED_ROLES and user.mfa_enabled_at is None


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
    if _lacks_required_mfa(user):
        # Promoted (or already privileged) without a second factor: the session
        # must not be renewed, and its family ends here for good.
        family.revoked_at = now
        session.commit()
        _refresh_failed("mfa_required", subject, now)
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
    response_model=None,
    dependencies=[Depends(require_same_origin)],
)
def logout(
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> Response | None:
    """End the session of the access token: revoke its family, deny its jti.

    An expired access token is fine (the session may outlive the 15 minutes) but
    its signature, issuer and audience must be valid, and the session CSRF token
    must match its `sid`. The call is idempotent.

    An unidentifiable session (missing or invalid access cookie) answers 401 and
    clears the cookies. A failed origin or CSRF check answers 403 and clears
    nothing: those requests may be forged by another site, and a forgery must
    not be able to wipe the victim's cookies.
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
        # Same 401 as everywhere, but the browser is also told to drop whatever
        # it holds: a missing or broken access cookie must not leave the other
        # two behind. HTTPException cannot carry several Set-Cookie headers, so
        # the response is built here.
        denied = _session_denied()
        unauthenticated = JSONResponse(
            status_code=denied.status_code,
            content={"detail": denied.detail},
            headers=denied.headers,
        )
        _clear_session_cookies(unauthenticated)
        return unauthenticated
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


# `None` stands for a full session (a token without a `scope` claim).
FULL_SESSION = frozenset({None})
ENROLLMENT_SESSIONS = frozenset({None, SCOPE_ENROLL_MFA})
SECOND_FACTOR_SESSIONS = frozenset({SCOPE_MFA_PENDING})


def _authenticate(
    request: Request,
    session: Session,
    keys: GatewayKeys,
    accepted: frozenset[str | None],
) -> CurrentUser:
    """Authenticate from the access cookie and reload the user from the database.

    One query loads the user only if the token's `jti` is not denied (logout),
    and the token was issued no earlier than `tokens_valid_since`. `iat` is whole
    seconds while the column has microseconds, so the column is truncated to the
    second: a token issued in the same second as the cut-off still passes.

    `accepted` lists the scopes the caller takes; a token whose `scope` claim is
    not in it is refused (a token without the claim is the key `None`). A full
    session must also name a refresh family that exists and is not revoked; a
    scoped token has no family.

    Every failure is the same 401: callers learn nothing about why.
    """
    user = None
    claims = None
    token = request.cookies.get(ACCESS_COOKIE)
    if token:
        try:
            claims = decode_access_token(token, keys)
            scope = claims["scope"] if "scope" in claims else None
            # A present-but-null claim is not "no scope": refuse it outright.
            if ("scope" in claims and scope is None) or scope not in accepted:
                raise InvalidToken
            conditions = [
                User.id == uuid.UUID(claims["sub"]),
                ~exists().where(RevokedJti.jti == claims["jti"]),
                func.date_trunc("second", User.tokens_valid_since)
                <= func.to_timestamp(claims["iat"]),
            ]
            if scope is None:
                conditions.append(
                    exists().where(
                        RefreshFamily.id == uuid.UUID(claims["sid"]),
                        RefreshFamily.revoked_at.is_(None),
                    )
                )
            user = session.scalar(select(User).where(*conditions))
        except InvalidToken, ValueError, TypeError, AttributeError:
            user = None
    if user is None or claims is None:
        raise _session_denied()
    return CurrentUser(user=user, claims=claims)


def _require_session_csrf(request: Request, claims: dict, keys: GatewayKeys) -> None:
    """Double-submit check against the `sid` of the token (scoped or full)."""
    if not check_csrf(
        request.cookies.get(CSRF_COOKIE),
        request.headers.get(CSRF_HEADER),
        claims["sid"],
        keys.csrf_key,
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def current_user(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
) -> CurrentUser:
    """The user of a full session. Any token with a `scope` claim is refused.

    A privileged role without MFA is refused too, whatever its token says: the
    role comes from the database, so a promotion or a session opened before MFA
    was required ends on the next request (ADR 0004, decision 4).
    """
    actor = _authenticate(request, session, keys, FULL_SESSION)
    if _lacks_required_mfa(actor.user):
        raise _session_denied()
    return actor


def enrollment_actor(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
) -> CurrentUser:
    """Who may enroll: an `enroll-mfa` token or a full session, with its CSRF."""
    actor = _authenticate(request, session, keys, ENROLLMENT_SESSIONS)
    _require_session_csrf(request, actor.claims, keys)
    return actor


def second_factor_actor(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
) -> CurrentUser:
    """Who may give the second factor: only an `mfa-pending` token, with its CSRF."""
    actor = _authenticate(request, session, keys, SECOND_FACTOR_SESSIONS)
    _require_session_csrf(request, actor.claims, keys)
    return actor


def _deny_jti(session: Session, claims: dict) -> None:
    """Deny the token's `jti` until it would have expired anyway."""
    session.execute(
        insert(RevokedJti)
        .values(
            jti=claims["jti"], expires_at=datetime.fromtimestamp(claims["exp"], UTC)
        )
        .on_conflict_do_nothing(index_elements=["jti"])
    )


def _reload_user(session: Session, user: User) -> None:
    """Re-read the user after taking the counter lock: the actor's copy is older."""
    try:
        session.refresh(user)
    except InvalidRequestError:
        session.rollback()
        raise _session_denied() from None


def _lock_second_factor(
    session: Session, user: User, keys: GatewayKeys, now: datetime
) -> LoginAttempt:
    """Lock the user's login counter; a locked account gets the generic 401.

    Same row and same rules as the password step. A locked account is answered
    before any code is looked at or any transit call is made.
    """
    attempt = _lock_attempt(session, login_attempt_key(user.username, keys.csrf_key))
    _reload_user(session, user)
    if attempt.locked_until is not None and attempt.locked_until > now:
        session.commit()
        _log_event("login_blocked", str(user.id), now, logging.WARNING)
        raise _login_failed()
    return attempt


def _check_can_enroll(actor: CurrentUser, now: datetime) -> None:
    user = actor.user
    if user.mfa_enabled_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled",
            headers=NO_STORE,
        )
    # The enroll token outlives its window by up to 10 minutes: the window
    # (ADR 0004, decision 11) is checked on every call, not only at login.
    if "scope" in actor.claims and (
        user.mfa_enroll_until is None or user.mfa_enroll_until <= now
    ):
        raise _login_failed()
    # A full session may enroll only a reader: every other role must have been
    # through the limited enroll-mfa session (and cannot hold a full one without
    # MFA).
    if "scope" not in actor.claims and user.role != "lector":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden", headers=NO_STORE
        )


@router.post("/mfa/enroll", dependencies=[Depends(require_same_origin)])
def mfa_enroll(
    actor: Annotated[CurrentUser, Depends(enrollment_actor)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
    body: EnrollRequest | None = None,
) -> EnrollOut:
    """Generate a TOTP secret, keep it (encrypted, pending) and show it once.

    It becomes the user's secret only when /mfa/confirm proves a valid code. A
    new call replaces a pending secret that was never confirmed.

    From a full session (a reader) the current password is required again: a
    stolen session must not be able to attach the attacker's authenticator. A
    wrong or missing password is a counted failure in the login lockout.
    """
    _check_can_enroll(actor, now)
    user = actor.user
    if "scope" not in actor.claims:
        attempt = _lock_second_factor(session, user, keys, now)
        password = body.current_password if body is not None else None
        if password is None:
            verified = verify_dummy("")
        else:
            verified = verify_password(user.password_hash, password)
        if not verified:
            _record_failure(session, attempt, str(user.id), now, "mfa_failure")
            raise _login_failed()
    secret = new_totp_secret()
    # A transit failure raises TransitError (fixed 503) before anything is saved.
    user.mfa_pending_ciphertext = encrypt_totp_secret(secret.encode(), user.id)
    session.commit()
    response.headers.update(NO_STORE)
    _log_event("mfa_enrollment_started", str(user.id), now)
    return EnrollOut(otpauth_uri=provisioning_uri(secret, user.username), secret=secret)


@router.post("/mfa/confirm", dependencies=[Depends(require_same_origin)])
def mfa_confirm(
    body: ConfirmRequest,
    actor: Annotated[CurrentUser, Depends(enrollment_actor)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> RecoveryCodesOut:
    """Activate MFA with a valid code and show the recovery codes once.

    A wrong code counts in the same progressive lockout as a wrong password. For
    a privileged user the enroll token is denied afterwards: the session ends and
    a normal login (which now asks for the second factor) follows.

    For every user, a new factor is a change of credentials: all existing
    sessions end (`tokens_valid_since`, every refresh family revoked), the
    presented token is denied and the cookies are cleared.
    """
    _check_can_enroll(actor, now)
    user = actor.user
    if user.mfa_pending_ciphertext is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No enrollment in progress",
            headers=NO_STORE,
        )
    attempt = _lock_second_factor(session, user, keys, now)
    subject = str(user.id)
    pending = user.mfa_pending_ciphertext
    if user.mfa_enabled_at is not None or pending is None:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No enrollment in progress",
            headers=NO_STORE,
        )
    secret = decrypt_totp_secret(pending, user.id).decode()
    step = matching_step(secret, body.code, now)
    if step is None:
        _record_failure(session, attempt, subject, now, "mfa_failure")
        raise _login_failed()

    codes = new_recovery_codes()
    session.add_all(
        RecoveryCode(user_id=user.id, code_hash=hash_password(code), created_at=now)
        for code in codes
    )
    user.mfa_secret_ciphertext = pending
    user.mfa_pending_ciphertext = None
    user.mfa_enabled_at = now
    user.mfa_last_step = step
    user.mfa_enroll_until = None
    # From the app clock, like every write of this column (see register).
    user.tokens_valid_since = now
    session.execute(
        update(RefreshFamily)
        .where(RefreshFamily.user_id == user.id, RefreshFamily.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    _deny_jti(session, actor.claims)
    session.commit()
    _clear_session_cookies(response)
    response.headers.update(NO_STORE)
    _log_event("mfa_enabled", subject, now)
    return RecoveryCodesOut(recovery_codes=codes, relogin_required=True)


def _check_second_factor(
    session: Session, user: User, code: str, now: datetime
) -> Literal["totp", "recovery"] | None:
    """Which kind of valid second factor `code` is, or None. Stages the changes.

    A TOTP must fall in the window and in a step after the last accepted one
    (replay, ASVS 6.5.1). A recovery code is compared against the unused hashes
    and marked used.
    """
    if user.mfa_enabled_at is None or user.mfa_secret_ciphertext is None:
        return None
    if TOTP_CODE.fullmatch(code):
        secret = decrypt_totp_secret(user.mfa_secret_ciphertext, user.id).decode()
        step = matching_step(secret, code, now)
        if step is None:
            return None
        if user.mfa_last_step is not None and step <= user.mfa_last_step:
            return None
        user.mfa_last_step = step
        return "totp"
    recovery = normalize_recovery_code(code)
    if recovery is None:
        return None
    unused = session.scalars(
        select(RecoveryCode)
        .where(RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None))
        .with_for_update()
    ).all()
    for row in unused:
        if verify_password(row.code_hash, recovery):
            row.used_at = now
            return "recovery"
    return None


@router.post("/login/mfa", dependencies=[Depends(require_same_origin)])
def login_mfa(
    body: MfaLoginRequest,
    response: Response,
    actor: Annotated[CurrentUser, Depends(second_factor_actor)],
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> UserOut:
    """Finish a login with a TOTP or a recovery code, then issue the session."""
    user = actor.user
    attempt = _lock_second_factor(session, user, keys, now)
    subject = str(user.id)
    # Single use under concurrency: the authentication above saw the denylist
    # before this request queued on the counter row's lock, so a request that
    # waited may hold a token the winner has just consumed. Re-check it here,
    # inside the lock. The jti is inserted only on success (still under this
    # lock, which serializes every attempt of the user), so a wrong code does
    # not burn the token and can be retried within the lockout limits.
    if session.scalar(select(exists().where(RevokedJti.jti == actor.claims["jti"]))):
        session.commit()
        raise _session_denied()
    kind = _check_second_factor(session, user, body.code, now)
    if kind is None:
        _record_failure(session, attempt, subject, now, "mfa_failure")
        raise _login_failed()
    # The pending token is good for one second factor only.
    _deny_jti(session, actor.claims)
    if kind == "recovery":
        _log_event("recovery_code_used", subject, now, logging.WARNING)
    _log_event("mfa_success", subject, now)
    return _start_session(response, session, user, attempt, keys, now)


@router.get("/me")
def me(
    current: Annotated[CurrentUser, Depends(current_user)], response: Response
) -> UserOut:
    response.headers.update(NO_STORE)
    user = current.user
    return UserOut(id=user.id, username=user.username, role=user.role)
