"""Housekeeping for the session tables: `python -m gateway.maintenance purge`.

Nothing here changes what a valid session can do. Every row it deletes is one
the rest of the gateway already ignores: an old failure counter, a denied token
id that would be rejected as expired anyway, a session that is over its limit
or revoked.
"""

import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from gateway.auth import PRIVILEGED_LIMITS, READER_LIMITS
from gateway.db import get_engine
from gateway.models import LoginAttempt, RefreshFamily, RefreshToken, RevokedJti, User
from gateway.tokens import LEEWAY_SECONDS

# A failure counter that has not moved for this long is stale: lockouts last 30
# minutes at most, so a row that is not locked has nothing left to remember.
ATTEMPT_TTL = timedelta(hours=24)

USAGE = "usage: python -m gateway.maintenance purge"


def _dead_families(now: datetime):
    """Ids of the families nobody can use any more.

    Revoked, or older than the absolute limit of the owner's CURRENT role (the
    same rule refresh applies), so a role change is honored here too.
    """
    expired_reader = and_(
        User.role == "lector",
        RefreshFamily.created_at < now - READER_LIMITS.absolute,
    )
    expired_privileged = and_(
        User.role != "lector",
        RefreshFamily.created_at < now - PRIVILEGED_LIMITS.absolute,
    )
    return (
        select(RefreshFamily.id)
        .join(User, User.id == RefreshFamily.user_id)
        .where(
            or_(
                RefreshFamily.revoked_at.is_not(None),
                expired_reader,
                expired_privileged,
            )
        )
    )


def purge(session: Session, now: datetime) -> dict[str, int]:
    """Delete stale rows in one transaction and return how many went per table."""
    tokens = session.scalar(
        select(func.count())
        .select_from(RefreshToken)
        .where(RefreshToken.family_id.in_(_dead_families(now)))
    )
    attempts = session.execute(
        delete(LoginAttempt).where(
            LoginAttempt.updated_at < now - ATTEMPT_TTL,
            or_(LoginAttempt.locked_until.is_(None), LoginAttempt.locked_until < now),
        )
    )
    # The decoder still accepts a token LEEWAY_SECONDS after its exp, so its
    # denied jti has to outlive that window.
    jtis = session.execute(
        delete(RevokedJti).where(
            RevokedJti.expires_at < now - timedelta(seconds=LEEWAY_SECONDS)
        )
    )
    # Refresh tokens go with their family through ON DELETE CASCADE.
    families = session.execute(
        delete(RefreshFamily).where(RefreshFamily.id.in_(_dead_families(now)))
    )
    session.commit()
    return {
        "login_attempts": attempts.rowcount,
        "revoked_jtis": jtis.rowcount,
        "refresh_families": families.rowcount,
        "refresh_tokens": tokens or 0,
    }


def main(argv: list[str]) -> int:
    if argv != ["purge"]:
        print(USAGE, file=sys.stderr)
        return 2
    with sessionmaker(get_engine(), expire_on_commit=False)() as session:
        counts = purge(session, datetime.now(UTC))
    # Table names and counts only: never a username, key, token or hash.
    for table, count in counts.items():
        print(f"{table}={count}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
