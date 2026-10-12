"""First administrator: `python -m gateway.bootstrap --username <name>`.

ADR 0004, decision 11. The responsible person seeds a random password in
OpenBao KV v2 at `secret/bootstrap/admin`. This one-shot command, which logs in
with its own AppRole (read and destroy of that path only), creates the
administrator with `must_change_password` and a 24 h MFA enrollment window and
destroys every version of the secret. The password never travels on the command
line and is never printed or logged; every failure prints one fixed message.

Order of the steps, and why. The account is created and the secret destroyed as
one step: the user row is flushed under a database lock, the destroy runs, and
only then the transaction commits. If the destroy fails, the creation rolls back
(nothing exists, the secret is intact, a rerun is safe). If the commit fails
after the destroy, no account and no secret exist (the person seeds a new one).
The outcome that cannot happen is an account whose password still sits in
OpenBao. Creating first and destroying afterwards would allow exactly that, and
a rerun would then refuse (an administrator exists), leaving it there.
"""

import logging
import re
import sys
from datetime import UTC, datetime, timedelta

import hvac
from sqlalchemy import exists, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from gateway.db import get_engine
from gateway.models import User
from gateway.passwords import hash_password, meets_password_policy
from gateway.secrets import KV_MOUNT, SecretsError, login_from_env, revoke

logger = logging.getLogger("gateway.bootstrap")

KV_PATH = "bootstrap/admin"
USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]{3,32}$")
# ADR 0004, decision 11: the enrollment window after the bootstrap.
ENROLL_WINDOW = timedelta(hours=24)
# Any fixed number works: it only has to be the same in every run. It names the
# lock that serializes the runs and is held until the transaction ends.
LOCK_KEY = 4_540_000_001
LOCK_TIMEOUT = "10s"

EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3
EXIT_DESTROY_FAILED = 4

USAGE = "usage: python -m gateway.bootstrap --username <name>"
REFUSED = "bootstrap refused: an administrator already exists"
INPUT_UNAVAILABLE = (
    "bootstrap failed: could not read a valid bootstrap password from OpenBao"
)
CREATE_FAILED = (
    "bootstrap failed: the administrator could not be created "
    "(database unavailable, not configured, or username not available)"
)
DESTROY_FAILED = (
    "bootstrap failed: the bootstrap secret could not be destroyed, so nothing "
    "was created; check the OpenBao access and run it again"
)


class DestroyFailed(RuntimeError):
    """The secret could not be destroyed or still answers a read."""


def login_client():
    """An hvac client logged in with the bootstrap AppRole."""
    return login_from_env(
        role_file_env="GATEWAY_BOOTSTRAP_ROLE_ID_FILE",
        credential_file_env="GATEWAY_BOOTSTRAP_SECRET_ID_FILE",
    )


def _parse(argv: list[str]) -> str | None:
    """The username, or None when the arguments are not exactly `--username <name>`."""
    if len(argv) != 2 or argv[0] != "--username":
        return None
    return argv[1] if USERNAME_PATTERN.fullmatch(argv[1]) else None


def _read_password(client) -> str | None:
    """The bootstrap password, or None if it is missing or breaks the policy."""
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=KV_PATH, mount_point=KV_MOUNT, raise_on_deleted_version=True
        )
        password = response["data"]["data"].get("password")
    except Exception:
        return None
    if not isinstance(password, str) or not meets_password_policy(password):
        return None
    return password


def _destroy(client) -> None:
    """Delete the key with all its versions and prove that it no longer reads."""
    try:
        client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=KV_PATH, mount_point=KV_MOUNT
        )
    except Exception:
        raise DestroyFailed from None
    gone = False
    try:
        client.secrets.kv.v2.read_secret_version(
            path=KV_PATH, mount_point=KV_MOUNT, raise_on_deleted_version=True
        )
    except hvac.exceptions.InvalidPath:
        gone = True
    except Exception:
        gone = False
    if not gone:
        raise DestroyFailed


def _administrator_exists(session: Session) -> bool:
    return bool(session.scalar(select(exists().where(User.role == "administrador"))))


def _create(client, username: str, password: str) -> int:
    """Create the administrator and destroy the secret in one transaction."""
    with Session(get_engine(), expire_on_commit=False) as session:
        if _administrator_exists(session):
            return EXIT_REFUSED
        # Hashed before taking the lock: it is slow, and a run that is going to
        # be refused should not hold the others up.
        password_hash = hash_password(password)
        session.rollback()
        # The lock covers the check, the insert and the destroy: a second run
        # waits here and then finds the administrator.
        session.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": LOCK_KEY})
        if _administrator_exists(session):
            return EXIT_REFUSED
        now = datetime.now(UTC)
        user = User(
            username=username,
            password_hash=password_hash,
            role="administrador",
            must_change_password=True,
            mfa_enroll_until=now + ENROLL_WINDOW,
            # The app clock, like every write of this column.
            tokens_valid_since=now,
        )
        session.add(user)
        session.flush()
        try:
            _destroy(client)
        except DestroyFailed:
            session.rollback()
            return EXIT_DESTROY_FAILED
        session.commit()
        logger.info(
            "security_event event=bootstrap_admin_created subject=%s at=%s",
            user.id,
            now.isoformat(),
        )
    return 0


MESSAGES = {
    EXIT_REFUSED: REFUSED,
    EXIT_DESTROY_FAILED: DESTROY_FAILED,
}


def main(argv: list[str]) -> int:
    username = _parse(argv)
    if username is None:
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    client = None
    try:
        client = login_client()
        password = _read_password(client)
        if password is None:
            print(INPUT_UNAVAILABLE, file=sys.stderr)
            return EXIT_FAILED
        try:
            code = _create(client, username, password)
        except RuntimeError, SQLAlchemyError:
            # Fixed text on purpose: the exception text can carry the host, the
            # user, the URL or a row with the password hash. A missing
            # GATEWAY_DATABASE_URL and a saturated hasher are RuntimeErrors.
            print(CREATE_FAILED, file=sys.stderr)
            return EXIT_FAILED
        if code != 0:
            print(MESSAGES[code], file=sys.stderr)
        else:
            print("bootstrap complete: administrator created, secret destroyed")
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
