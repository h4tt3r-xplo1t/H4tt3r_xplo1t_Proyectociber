"""User management for administrators: `/api/admin/...` (ADR 0004, decisions 5 and 11).

Every route needs a full session (so, for the administrator, an active MFA) and
the role `administrador`, read from the database on each request. The routes
that change state also need the same origin and the session CSRF token.

Each change takes the locks it needs first (the role-change lock for roles, then
the target's row), rechecks what it decided from the rows it just locked, and
leaves a security event with the actor and the target, never a secret.
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.orm import Session

from gateway.auth import (
    LOCK_TIMEOUT,
    NO_STORE,
    CurrentUser,
    _lock_attempt,
    _require_session_csrf,
    busy_guard,
    current_user,
    get_keys,
    get_now,
    invalidate_tokens,
    require_same_origin,
)
from gateway.db import get_session
from gateway.mfa import ENROLL_WINDOW
from gateway.models import (
    PRIVILEGED_ROLES,
    LoginAttempt,
    MfaResetRequest,
    PasswordResetCode,
    RecoveryCode,
    RefreshFamily,
    User,
    mark_privileged,
    needs_two_administrators,
)
from gateway.passwords import hash_password
from gateway.recovery import (
    MFA_RESET_KIND,
    MFA_RESET_REQUEST_TTL,
    RESET_CODE_KIND,
    RESET_CODE_TTL,
    new_reset_code,
)
from gateway.secrets import GatewayKeys
from gateway.tokens import login_attempt_key

router = APIRouter(prefix="/api/admin", tags=["admin"])
logger = logging.getLogger("gateway.admin")

# Names the advisory lock that serializes the changes of roles, so the "last
# administrator" check and the change it protects cannot interleave. Any fixed
# number works (the bootstrap uses another one for its own lock).
ROLE_LOCK_KEY = 4_540_000_002
MAX_PAGE = 100
DEFAULT_PAGE = 50


class AdminUserOut(BaseModel):
    """What an administrator sees of a user: no hash, no MFA secret, no codes."""

    id: uuid.UUID
    username: str
    role: str
    pending_role: str | None
    mfa_enabled: bool
    locked: bool


class UserPageOut(BaseModel):
    items: list[AdminUserOut]
    total: int
    limit: int
    offset: int


Role = Literal["lector", "editor", "auditor", "administrador"]


class RoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role


class ResetCodeOut(BaseModel):
    """The code is shown once, here; only its hash is stored."""

    code: str
    expires_at: datetime


class MfaResetOut(BaseModel):
    status: Literal["mfa_reset"]


class MfaResetPendingOut(BaseModel):
    status: Literal["approval_required"]
    expires_at: datetime


def _forbidden() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden", headers=NO_STORE
    )


def _log_admin_event(
    event: str,
    actor: uuid.UUID,
    target: uuid.UUID | None,
    now: datetime,
    level: int = logging.INFO,
    detail: str = "",
) -> None:
    # Who acted, on whom and what. `detail` is a role name or a count, never a
    # password, token, code or hash.
    logger.log(
        level,
        "security_event event=%s actor=%s target=%s%s at=%s",
        event,
        actor,
        target,
        f" {detail}" if detail else "",
        now.astimezone(UTC).isoformat(),
    )


def administrator(
    actor: Annotated[CurrentUser, Depends(current_user)],
    now: Annotated[datetime, Depends(get_now)],
) -> CurrentUser:
    """A full session whose user is an administrator now (the database says so)."""
    if actor.user.role != "administrador":
        _log_admin_event("admin_denied", actor.user.id, None, now, logging.WARNING)
        raise _forbidden()
    return actor


def administrator_writer(
    request: Request,
    actor: Annotated[CurrentUser, Depends(administrator)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
) -> CurrentUser:
    """`administrator` plus the session CSRF check, for routes that change state."""
    _require_session_csrf(request, actor.claims, keys)
    return actor


def _begin_change(session: Session) -> None:
    # Same bounded wait as the login counter; SET LOCAL lasts for the transaction.
    session.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))


def _lock_target(session: Session, target_id: uuid.UUID) -> User:
    with busy_guard("admin_target_locked"):
        target = session.scalar(
            select(User).where(User.id == target_id).with_for_update()
        )
    if target is None:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers=NO_STORE,
        )
    return target


def _locked_usernames(
    session: Session, usernames: list[str], keys: GatewayKeys, now: datetime
) -> set[str]:
    """Which of `usernames` have a lockout in force (looked up by keyed hash)."""
    by_key = {login_attempt_key(name, keys.csrf_key): name for name in usernames}
    if not by_key:
        return set()
    rows = session.execute(
        select(LoginAttempt.attempt_key).where(
            LoginAttempt.attempt_key.in_(by_key),
            LoginAttempt.locked_until > now,
        )
    ).scalars()
    return {by_key[key] for key in rows}


def _out(user: User, locked: bool) -> AdminUserOut:
    return AdminUserOut(
        id=user.id,
        username=user.username,
        role=user.role,
        pending_role=user.pending_role,
        mfa_enabled=user.mfa_enabled_at is not None,
        locked=locked,
    )


def _out_one(
    session: Session, user: User, keys: GatewayKeys, now: datetime
) -> AdminUserOut:
    return _out(
        user, user.username in _locked_usernames(session, [user.username], keys, now)
    )


@router.get("/users")
def list_users(
    actor: Annotated[CurrentUser, Depends(administrator)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
    limit: int = DEFAULT_PAGE,
    offset: int = 0,
) -> UserPageOut:
    if not 1 <= limit <= MAX_PAGE or offset < 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=[{"loc": ["query"], "msg": "invalid pagination", "type": "value"}],
        )
    total = session.scalar(select(func.count()).select_from(User)) or 0
    users = session.scalars(
        select(User).order_by(User.username).limit(limit).offset(offset)
    ).all()
    locked = _locked_usernames(session, [u.username for u in users], keys, now)
    response.headers.update(NO_STORE)
    return UserPageOut(
        items=[_out(u, u.username in locked) for u in users],
        total=total,
        limit=limit,
        offset=offset,
    )


def _administrators_left(session: Session, leaving: uuid.UUID) -> int:
    """Administrators other than `leaving` who can actually act (MFA active)."""
    return (
        session.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.role == "administrador",
                User.id != leaving,
                User.mfa_enabled_at.is_not(None),
            )
        )
        or 0
    )


@router.put("/users/{user_id}/role", dependencies=[Depends(require_same_origin)])
def assign_role(
    user_id: uuid.UUID,
    body: RoleRequest,
    actor: Annotated[CurrentUser, Depends(administrator_writer)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> AdminUserOut:
    """Assign a role to a user (ADR 0004, decisions 5 and 11).

    A privileged role for a user without an active MFA does not take effect: the
    user stays a reader with `pending_role` set and a new 24 h enrollment window,
    and the role applies when they confirm the factor. For a user with MFA it
    applies now. Any change moves `tokens_valid_since`, ending the user's tokens.
    """
    actor_user = actor.user
    _begin_change(session)
    with busy_guard("admin_role_lock"):
        session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": ROLE_LOCK_KEY}
        )
        # The actor was authenticated before the lock; a concurrent change may
        # have taken the role away since.
        session.refresh(actor_user)
    if actor_user.role != "administrador":
        session.rollback()
        raise _forbidden()
    target = _lock_target(session, user_id)

    new_role = body.role
    # Separation of duties (decision 5): the audit log is read by the auditor,
    # so an administrator can neither give it to themselves nor take it up.
    if new_role == "auditor" and (
        target.id == actor_user.id or target.role == "administrador"
    ):
        session.rollback()
        raise _forbidden()

    pending_mfa = new_role in PRIVILEGED_ROLES and target.mfa_enabled_at is None
    effective, pending = ("lector", new_role) if pending_mfa else (new_role, None)
    if (target.role, target.pending_role) == (effective, pending):
        session.rollback()
        return _out_one(session, target, keys, now)
    if (
        target.role == "administrador"
        and effective != "administrador"
        and _administrators_left(session, target.id) == 0
    ):
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The last administrator cannot lose the role",
            headers=NO_STORE,
        )

    # The marker records the first privileged role or pending role, also for an
    # account that got one outside this route, before a demotion hides it.
    if (
        effective in PRIVILEGED_ROLES
        or pending is not None
        or target.role in PRIVILEGED_ROLES
        or target.pending_role is not None
    ):
        mark_privileged(target, now)
    target.role = effective
    target.pending_role = pending
    if pending is not None:
        target.mfa_enroll_until = now + ENROLL_WINDOW
    invalidate_tokens(session, target, now)
    session.commit()
    _log_admin_event(
        "role_assignment_pending" if pending else "role_assigned",
        actor_user.id,
        target.id,
        now,
        detail=f"role={new_role}",
    )
    response.headers.update(NO_STORE)
    return _out_one(session, target, keys, now)


@router.post(
    "/users/{user_id}/enrollment-window", dependencies=[Depends(require_same_origin)]
)
def reissue_enrollment_window(
    user_id: uuid.UUID,
    actor: Annotated[CurrentUser, Depends(administrator_writer)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> AdminUserOut:
    """Open a new 24 h MFA enrollment window once the previous one has lapsed.

    Only for someone who still has to enroll: a privileged role or a pending role
    without an active factor.
    """
    _begin_change(session)
    target = _lock_target(session, user_id)
    owes_enrollment = target.mfa_enabled_at is None and (
        target.role in PRIVILEGED_ROLES or target.pending_role is not None
    )
    window_open = target.mfa_enroll_until is not None and target.mfa_enroll_until > now
    if not owes_enrollment or window_open:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No enrollment window can be reissued for this user",
            headers=NO_STORE,
        )
    target.mfa_enroll_until = now + ENROLL_WINDOW
    session.commit()
    _log_admin_event("enrollment_window_reissued", actor.user.id, target.id, now)
    response.headers.update(NO_STORE)
    return _out_one(session, target, keys, now)


def _conflict(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT, detail=detail, headers=NO_STORE
    )


def _has_mfa(user: User) -> bool:
    return (
        user.mfa_enabled_at is not None
        or user.mfa_secret_ciphertext is not None
        or user.mfa_pending_ciphertext is not None
    )


def _apply_mfa_reset(session: Session, target: User, now: datetime) -> None:
    """Clear the MFA of `target` and end its sessions (caller holds the row lock).

    A privileged account, or a reader with a pending privileged role, must enroll
    again within the usual 24 h window and until then only gets an `enroll-mfa`
    session; any other reader needs no window. Any pending MFA reset request for
    the target is spent with this reset (a reset code request stays).
    """
    target.mfa_secret_ciphertext = None
    target.mfa_pending_ciphertext = None
    target.mfa_enabled_at = None
    target.mfa_last_step = None
    target.mfa_enroll_until = (
        now + ENROLL_WINDOW
        if target.role in PRIVILEGED_ROLES or target.pending_role is not None
        else None
    )
    session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == target.id))
    session.execute(
        delete(MfaResetRequest).where(
            MfaResetRequest.target_user_id == target.id,
            MfaResetRequest.kind == MFA_RESET_KIND,
        )
    )
    with busy_guard("admin_families_locked", session):
        session.execute(
            update(RefreshFamily)
            .where(
                RefreshFamily.user_id == target.id, RefreshFamily.revoked_at.is_(None)
            )
            .values(revoked_at=now)
        )
    invalidate_tokens(session, target, now)


def _lock_request(
    session: Session, target_id: uuid.UUID, kind: str
) -> MfaResetRequest | None:
    with busy_guard("admin_mfa_reset_request_locked", session):
        return session.scalar(
            select(MfaResetRequest)
            .where(
                MfaResetRequest.target_user_id == target_id,
                MfaResetRequest.kind == kind,
            )
            .with_for_update()
        )


def _record_request(
    session: Session,
    target: User,
    actor_user: User,
    kind: str,
    now: datetime,
    *,
    too_few: str,
    already: str,
) -> datetime:
    """Store a request for a second administrator to approve; return its expiry.

    The caller holds the target's row lock. At least two administrators other
    than the target must exist (the requester and an approver), and a live
    request of the same kind blocks a new one; an expired one is replaced.
    """
    if _administrators_left(session, target.id) < 2:
        session.rollback()
        raise _conflict(too_few)
    pending = _lock_request(session, target.id, kind)
    if pending is not None and pending.expires_at > now:
        session.rollback()
        raise _conflict(already)
    if pending is not None:
        session.delete(pending)
        session.flush()
    expires_at = now + MFA_RESET_REQUEST_TTL
    session.add(
        MfaResetRequest(
            target_user_id=target.id,
            requested_by=actor_user.id,
            kind=kind,
            created_at=now,
            expires_at=expires_at,
        )
    )
    session.commit()
    return expires_at


def _refuse_if_demoted(session: Session, actor: User) -> None:
    # The actor was authenticated before the locks; a concurrent change may have
    # taken the role away since.
    session.refresh(actor)
    if actor.role != "administrador":
        session.rollback()
        raise _forbidden()


# Lock order of both MFA-reset routes, kept identical to avoid deadlocks: the
# target's user row, then the target's request row, then (on approval only) the
# requester's user row. `_administrators_left` is a plain count that takes no
# row locks, so it may run before or after the request row is locked.
@router.post("/users/{user_id}/mfa-reset", dependencies=[Depends(require_same_origin)])
def request_mfa_reset(
    user_id: uuid.UUID,
    actor: Annotated[CurrentUser, Depends(administrator_writer)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    now: Annotated[datetime, Depends(get_now)],
) -> MfaResetOut | MfaResetPendingOut:
    """Reset the MFA of a user (ADR 0004, decision 10).

    A reader that never was privileged is reset at once. An account that is or
    was privileged (`needs_two_administrators`) needs a second administrator to
    approve (`/mfa-reset/approve`), and at least two administrators other than
    the account itself must exist: nobody resets their own MFA.
    """
    actor_user = actor.user
    if user_id == actor_user.id:
        _log_admin_event("admin_denied", actor_user.id, user_id, now, logging.WARNING)
        raise _forbidden()
    _begin_change(session)
    target = _lock_target(session, user_id)
    _refuse_if_demoted(session, actor_user)
    response.headers.update(NO_STORE)
    if not _has_mfa(target):
        session.rollback()
        raise _conflict("The user has no MFA to reset")
    if not needs_two_administrators(target):
        _apply_mfa_reset(session, target, now)
        session.commit()
        _log_admin_event("mfa_reset", actor_user.id, target.id, now)
        return MfaResetOut(status="mfa_reset")
    expires_at = _record_request(
        session,
        target,
        actor_user,
        MFA_RESET_KIND,
        now,
        too_few=(
            "Two administrators are required to reset the MFA of a privileged account"
        ),
        already="An MFA reset request is already pending for this user",
    )
    _log_admin_event("mfa_reset_requested", actor_user.id, target.id, now)
    response.status_code = status.HTTP_202_ACCEPTED
    return MfaResetPendingOut(status="approval_required", expires_at=expires_at)


@router.post(
    "/users/{user_id}/mfa-reset/approve", dependencies=[Depends(require_same_origin)]
)
def approve_mfa_reset(
    user_id: uuid.UUID,
    actor: Annotated[CurrentUser, Depends(administrator_writer)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    now: Annotated[datetime, Depends(get_now)],
) -> MfaResetOut:
    """Approve the pending reset of a privileged account's MFA.

    The approver must be neither the affected user nor the administrator who
    asked. What the request relied on is rechecked under the locks: a request
    whose requester lost the role, or whose target lost its MFA, is deleted.
    An expired request counts as missing and is left for the purge.
    """
    actor_user = actor.user
    if user_id == actor_user.id:
        _log_admin_event("admin_denied", actor_user.id, user_id, now, logging.WARNING)
        raise _forbidden()
    _begin_change(session)
    target = _lock_target(session, user_id)
    _refuse_if_demoted(session, actor_user)
    response.headers.update(NO_STORE)
    pending = _lock_request(session, target.id, MFA_RESET_KIND)
    if pending is None or pending.expires_at <= now:
        session.rollback()
        raise _conflict("No pending MFA reset request for this user")
    if pending.requested_by == actor_user.id:
        session.rollback()
        _log_admin_event("admin_denied", actor_user.id, user_id, now, logging.WARNING)
        raise _forbidden()
    requester_id = pending.requested_by
    with busy_guard("admin_requester_locked", session):
        requester = session.scalar(
            select(User).where(User.id == requester_id).with_for_update()
        )
    # `requester is None` cannot happen while the request row is locked
    # (`requested_by` cascades on delete); the check is kept defensively.
    stale = None
    if requester is None or requester.role != "administrador":
        stale = "requester_not_admin"
    elif not _has_mfa(target):
        stale = "target_without_mfa"
    if stale is not None:
        session.delete(pending)
        session.commit()
        _log_admin_event(
            "mfa_reset_request_voided",
            actor_user.id,
            target.id,
            now,
            logging.WARNING,
            f"requested_by={requester_id} reason={stale}",
        )
        raise _conflict("The MFA reset request is no longer valid")
    _apply_mfa_reset(session, target, now)
    session.commit()
    _log_admin_event(
        "mfa_reset_approved",
        actor_user.id,
        target.id,
        now,
        detail=f"requested_by={requester_id}",
    )
    _log_admin_event("mfa_reset", actor_user.id, target.id, now)
    return MfaResetOut(status="mfa_reset")


@router.post("/users/{user_id}/reset-code", dependencies=[Depends(require_same_origin)])
def issue_reset_code(
    user_id: uuid.UUID,
    actor: Annotated[CurrentUser, Depends(administrator_writer)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    now: Annotated[datetime, Depends(get_now)],
) -> ResetCodeOut | MfaResetPendingOut:
    """Issue a one-use password reset code for a user (ADR 0004, decision 10).

    A reader that never was privileged gets it from this administrator alone: the
    code is handed over out of band, expires after 15 minutes and replaces any
    earlier code of that user. For an account that is or was privileged
    (`needs_two_administrators`) no code is made here: a request is recorded and
    a second administrator approves it (`/reset-code/approve`) and receives the
    code. Issuing changes nothing else: the password, the sessions and the
    lockout stay as they are.
    """
    actor_user = actor.user
    if user_id == actor_user.id:
        _log_admin_event("admin_denied", actor_user.id, user_id, now, logging.WARNING)
        raise _forbidden()
    # The slow hash goes before any lock (a saturated hasher answers 503). It is
    # wasted when the target turns out to need a second administrator.
    code = new_reset_code()
    code_hash = hash_password(code)
    _begin_change(session)
    target = _lock_target(session, user_id)
    _refuse_if_demoted(session, actor_user)
    response.headers.update(NO_STORE)
    if needs_two_administrators(target):
        expires_at = _record_request(
            session,
            target,
            actor_user,
            RESET_CODE_KIND,
            now,
            too_few=(
                "Two administrators are required to issue a reset code for this account"
            ),
            already="A reset code request is already pending for this user",
        )
        _log_admin_event("reset_code_requested", actor_user.id, target.id, now)
        response.status_code = status.HTTP_202_ACCEPTED
        return MfaResetPendingOut(status="approval_required", expires_at=expires_at)
    _store_reset_code(session, target, code_hash, actor_user.id, None, now)
    session.commit()
    _log_admin_event("password_reset_code_issued", actor_user.id, target.id, now)
    return ResetCodeOut(code=code, expires_at=now + RESET_CODE_TTL)


def _store_reset_code(
    session: Session,
    target: User,
    code_hash: str,
    issued_by: uuid.UUID,
    approved_by: uuid.UUID | None,
    now: datetime,
) -> None:
    """Replace the target's code with a new one (caller commits)."""
    session.execute(
        delete(PasswordResetCode).where(PasswordResetCode.user_id == target.id)
    )
    session.add(
        PasswordResetCode(
            user_id=target.id,
            code_hash=code_hash,
            issued_by=issued_by,
            approved_by=approved_by,
            created_at=now,
            expires_at=now + RESET_CODE_TTL,
        )
    )


@router.post(
    "/users/{user_id}/reset-code/approve", dependencies=[Depends(require_same_origin)]
)
def approve_reset_code(
    user_id: uuid.UUID,
    actor: Annotated[CurrentUser, Depends(administrator_writer)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    now: Annotated[datetime, Depends(get_now)],
) -> ResetCodeOut:
    """Approve a pending reset code request and receive the code.

    The approver must be neither the affected user nor the administrator who
    asked. The code is made and hashed before the locks (so a refusal discards
    it); under them the request and its requester are checked again. The stored
    code records both administrators and is shown only in this response.
    """
    actor_user = actor.user
    if user_id == actor_user.id:
        _log_admin_event("admin_denied", actor_user.id, user_id, now, logging.WARNING)
        raise _forbidden()
    code = new_reset_code()
    code_hash = hash_password(code)
    _begin_change(session)
    target = _lock_target(session, user_id)
    _refuse_if_demoted(session, actor_user)
    response.headers.update(NO_STORE)
    pending = _lock_request(session, target.id, RESET_CODE_KIND)
    if pending is None or pending.expires_at <= now:
        session.rollback()
        raise _conflict("No pending reset code request for this user")
    if pending.requested_by == actor_user.id:
        session.rollback()
        _log_admin_event("admin_denied", actor_user.id, user_id, now, logging.WARNING)
        raise _forbidden()
    requester_id = pending.requested_by
    with busy_guard("admin_requester_locked", session):
        requester = session.scalar(
            select(User).where(User.id == requester_id).with_for_update()
        )
    # `requester is None` cannot happen while the request row is locked
    # (`requested_by` cascades on delete); the check is kept defensively.
    if requester is None or requester.role != "administrador":
        session.delete(pending)
        session.commit()
        _log_admin_event(
            "reset_code_request_voided",
            actor_user.id,
            target.id,
            now,
            logging.WARNING,
            f"requested_by={requester_id} reason=requester_not_admin",
        )
        raise _conflict("The reset code request is no longer valid")
    session.delete(pending)
    _store_reset_code(session, target, code_hash, requester_id, actor_user.id, now)
    session.commit()
    _log_admin_event(
        "reset_code_approved",
        actor_user.id,
        target.id,
        now,
        detail=f"requested_by={requester_id}",
    )
    _log_admin_event("password_reset_code_issued", actor_user.id, target.id, now)
    return ResetCodeOut(code=code, expires_at=now + RESET_CODE_TTL)


@router.post("/users/{user_id}/unlock", dependencies=[Depends(require_same_origin)])
def unlock_account(
    user_id: uuid.UUID,
    actor: Annotated[CurrentUser, Depends(administrator_writer)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> AdminUserOut:
    """Reset the failed-login counter of a user: the next login is not blocked."""
    target = session.get(User, user_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers=NO_STORE,
        )
    # The counter row is locked the way a login locks it (bounded wait, 503).
    attempt = _lock_attempt(session, login_attempt_key(target.username, keys.csrf_key))
    attempt.failures = 0
    attempt.locked_until = None
    attempt.updated_at = now
    session.commit()
    _log_admin_event("account_unlocked", actor.user.id, target.id, now)
    response.headers.update(NO_STORE)
    return _out(target, False)


@router.post(
    "/users/{user_id}/sessions/end", dependencies=[Depends(require_same_origin)]
)
def end_sessions(
    user_id: uuid.UUID,
    actor: Annotated[CurrentUser, Depends(administrator_writer)],
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    keys: Annotated[GatewayKeys, Depends(get_keys)],
    now: Annotated[datetime, Depends(get_now)],
) -> AdminUserOut:
    """End every session of a user (ASVS 7.4.5): revoke the families and cut off
    the tokens issued so far."""
    _begin_change(session)
    target = _lock_target(session, user_id)
    with busy_guard("admin_families_locked", session):
        revoked = session.execute(
            update(RefreshFamily)
            .where(
                RefreshFamily.user_id == target.id, RefreshFamily.revoked_at.is_(None)
            )
            .values(revoked_at=now)
        ).rowcount
    invalidate_tokens(session, target, now)
    session.commit()
    _log_admin_event(
        "sessions_ended", actor.user.id, target.id, now, detail=f"families={revoked}"
    )
    response.headers.update(NO_STORE)
    return _out_one(session, target, keys, now)


__all__ = ["router"]
