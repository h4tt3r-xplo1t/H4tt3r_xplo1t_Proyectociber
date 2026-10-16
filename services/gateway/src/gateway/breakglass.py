"""Operator recovery: `python -m gateway.breakglass --username <name> --break-glass`.

ADR 0004, decision 11. An account that is or was privileged (an administrator,
editor or auditor, one with a pending privileged role, or one with
`privileged_at`) needs two administrators to recover. When two are not
available (the only administrator is locked out, or the bootstrap administrator
did not enroll within 24 h) this command is the way back, and only the
operator's own access to OpenBao and the database can run it.

The responsible person seeds `{"username": ..., "password": ...}` in OpenBao KV
v2 at `secret/breakglass/account` with their own credentials. This one-shot
command logs in with its own AppRole (read and destroy of that path only) and,
in one transaction under the row lock of the account:

- sets the seeded password, with `must_change_password`;
- clears the MFA (secret, pending secret, activation, last step) and deletes the
  recovery codes, and opens a 24 h enrollment window;
- deletes the pending approval requests (both kinds) and the reset code of the
  account, so nothing issued before the reset survives it;
- revokes every refresh family and invalidates every access token;
- sets `password_reset_notice_at`, so the next full login tells the user that
  the password was reset;
- destroys every version of the secret, then commits.

The next login gets only the `enroll-mfa` session: it must change the password
and enroll the MFA. The password never travels on the command line and is never
printed or logged; the username is not echoed either; every failure prints one
fixed message. The wrong-target guard refuses a secret whose `username` is not
the `--username` given, so a secret seeded for one account cannot reset another.

Order of the steps follows `gateway.bootstrap`: the destroy runs after the
changes are flushed and before the commit. If it fails definitely (exit 4) the
reset rolls back and the secret is intact. If its outcome is unknown (exit 5)
the reset also rolls back but the secret may be gone: check it and reseed before
rerunning. If the commit fails after the destroy (exit 1) nothing changed and no
secret exists: seed a new one. The outcome that cannot happen is an account
reset while its new password still sits in OpenBao.

Limits, by design. The login lockout counter is not reset: its key derives from
the CSRF key, which this command does not hold, so a locked-out account waits at
most 30 minutes or is unlocked by an administrator. The MFA clearing mirrors
`admin._apply_mfa_reset` (which needs FastAPI request state) and is kept here on
purpose; the account always gets the enrollment window, whatever its role,
because it must enroll before holding any privileged session again.
"""

import logging
import re
import sys
from datetime import UTC, datetime

from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from gateway.auth import ServiceBusy, busy_guard, invalidate_tokens
from gateway.db import get_engine
from gateway.mfa import ENROLL_WINDOW
from gateway.models import (
    ApprovalRequest,
    PasswordResetCode,
    RecoveryCode,
    RefreshFamily,
    User,
    mark_privileged,
    needs_two_administrators,
)
from gateway.oneshot import DestroyFailed, DestroyUncertain, destroy_secret
from gateway.passwords import hash_password, meets_password_policy
from gateway.secrets import KV_MOUNT, SecretsError, login_from_env, revoke

logger = logging.getLogger("gateway.breakglass")

KV_PATH = "breakglass/account"
USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]{3,32}$")
LOCK_TIMEOUT = "10s"

EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3
EXIT_DESTROY_FAILED = 4
EXIT_DESTROY_UNCERTAIN = 5

USAGE = "usage: python -m gateway.breakglass --username <name> --break-glass"
REFUSED = (
    "break-glass refused: the account does not exist or never had a privileged role"
)
INPUT_UNAVAILABLE = (
    "break-glass failed: could not read a valid break-glass secret from OpenBao"
)
WRONG_TARGET = (
    "break-glass failed: the seeded secret was not made for the account named "
    "in --username; nothing was changed"
)
RESET_FAILED = (
    "break-glass failed: the account could not be reset (database unavailable "
    "or not configured); check whether the secret still exists"
)
BUSY = (
    "break-glass failed: the account is busy (locked by another request); "
    "nothing was changed, run it again"
)
DESTROY_FAILED = (
    "break-glass failed: the break-glass secret could not be destroyed, so "
    "nothing was changed; check the OpenBao access and run it again"
)
DESTROY_UNCERTAIN = (
    "break-glass failed: the outcome of destroying the break-glass secret is "
    "unknown, so nothing was changed; check whether the secret still exists, "
    "seed a new one if it does not, and run it again"
)
SUCCESS = "break-glass complete: account reset, secret destroyed"


def _now() -> datetime:
    return datetime.now(UTC)


def login_client():
    """An hvac client logged in with the break-glass AppRole."""
    return login_from_env(
        role_file_env="GATEWAY_BREAKGLASS_ROLE_ID_FILE",
        credential_file_env="GATEWAY_BREAKGLASS_SECRET_ID_FILE",
    )


def _parse(argv: list[str]) -> str | None:
    """The username, or None unless the arguments are `--username <name>` and
    `--break-glass`, in either order and nothing else."""
    if len(argv) != 3:
        return None
    if argv[0] == "--username" and argv[2] == "--break-glass":
        username = argv[1]
    elif argv[0] == "--break-glass" and argv[1] == "--username":
        username = argv[2]
    else:
        return None
    return username if USERNAME_PATTERN.fullmatch(username) else None


def _read_secret(client) -> tuple[str, str] | None:
    """The seeded (username, password), or None if missing or not acceptable."""
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=KV_PATH, mount_point=KV_MOUNT, raise_on_deleted_version=True
        )
        data = response["data"]["data"]
        username, password = data.get("username"), data.get("password")
    except Exception:
        return None
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    if not meets_password_policy(password):
        return None
    return username, password


def _apply(session: Session, user: User, password_hash: str, now: datetime) -> None:
    """Reset `user` (the caller holds its row lock) as the module docstring says."""
    user.password_hash = password_hash
    user.must_change_password = True
    mark_privileged(user, now)
    user.mfa_secret_ciphertext = None
    user.mfa_pending_ciphertext = None
    user.mfa_enabled_at = None
    user.mfa_last_step = None
    user.mfa_enroll_until = now + ENROLL_WINDOW
    user.password_reset_notice_at = now
    session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    session.execute(
        delete(ApprovalRequest).where(ApprovalRequest.target_user_id == user.id)
    )
    session.execute(
        delete(PasswordResetCode).where(PasswordResetCode.user_id == user.id)
    )
    session.execute(
        update(RefreshFamily)
        .where(RefreshFamily.user_id == user.id, RefreshFamily.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    invalidate_tokens(session, user, now)


def _reset(client, username: str, password: str) -> int:
    """Reset the account and destroy the secret in one transaction."""
    with Session(get_engine(), expire_on_commit=False) as session:
        peek = session.scalar(select(User).where(User.username == username))
        if peek is None or not needs_two_administrators(peek):
            return EXIT_REFUSED
        user_id = peek.id
        # Hashed before taking the lock: it is slow, and a run that is going to
        # be refused should not hold the account up.
        password_hash = hash_password(password)
        session.rollback()
        session.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
        with busy_guard("breakglass_target_locked", session):
            user = session.scalar(
                select(User).where(User.id == user_id).with_for_update()
            )
            if user is None or not needs_two_administrators(user):
                session.rollback()
                return EXIT_REFUSED
            now = _now()
            _apply(session, user, password_hash, now)
            session.flush()
        try:
            destroy_secret(client, KV_PATH)
        except DestroyUncertain:
            session.rollback()
            return EXIT_DESTROY_UNCERTAIN
        except DestroyFailed:
            session.rollback()
            return EXIT_DESTROY_FAILED
        session.commit()
        logger.info(
            "security_event event=break_glass_reset subject=%s at=%s",
            user.id,
            now.isoformat(),
        )
    return 0


MESSAGES = {
    EXIT_REFUSED: REFUSED,
    EXIT_DESTROY_FAILED: DESTROY_FAILED,
    EXIT_DESTROY_UNCERTAIN: DESTROY_UNCERTAIN,
}


def main(argv: list[str]) -> int:
    username = _parse(argv)
    if username is None:
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    client = None
    try:
        client = login_client()
        secret = _read_secret(client)
        if secret is None:
            print(INPUT_UNAVAILABLE, file=sys.stderr)
            return EXIT_FAILED
        seeded_username, password = secret
        if seeded_username != username:
            print(WRONG_TARGET, file=sys.stderr)
            return EXIT_FAILED
        try:
            code = _reset(client, username, password)
        except ServiceBusy:
            print(BUSY, file=sys.stderr)
            return EXIT_FAILED
        except RuntimeError, SQLAlchemyError:
            # Fixed text on purpose: the exception text can carry the host, the
            # user, the URL or a row with the password hash. A missing
            # GATEWAY_DATABASE_URL and a saturated hasher are RuntimeErrors.
            print(RESET_FAILED, file=sys.stderr)
            return EXIT_FAILED
        if code != 0:
            print(MESSAGES[code], file=sys.stderr)
        else:
            print(SUCCESS)
        return code
    except SecretsError:
        print(INPUT_UNAVAILABLE, file=sys.stderr)
        return EXIT_FAILED
    finally:
        if client is not None:
            revoke(client)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    sys.exit(main(sys.argv[1:]))
