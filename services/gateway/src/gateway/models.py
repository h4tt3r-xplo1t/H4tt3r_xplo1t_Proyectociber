import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

ROLES = ("lector", "editor", "auditor", "administrador")
# Roles that must have MFA (ADR 0004, decision 8).
PRIVILEGED_ROLES = ("editor", "auditor", "administrador")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN (" + ", ".join(f"'{role}'" for role in ROLES) + ")",
            name="users_role_check",
        ),
        CheckConstraint(
            "pending_role IS NULL OR pending_role IN ("
            + ", ".join(f"'{role}'" for role in ROLES)
            + ")",
            name="users_pending_role_check",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    username: Mapped[str] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(
        String(16), default="lector", server_default="lector"
    )
    tokens_valid_since: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Bumped with every move of `tokens_valid_since` (see `invalidate_tokens`).
    # Every access token carries the value it was issued under and is accepted
    # only while it is still the current one: unlike the timestamp, which `iat`
    # (whole seconds) can only compare to the second, this is exact.
    token_generation: Mapped[int] = mapped_column(
        Integer, default=0, server_default=text("0")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # TOTP MFA (ADR 0004 decisions 8 and 11). Secrets exist only as OpenBao
    # transit ciphertext. `mfa_enabled_at` is set when the user proved a code.
    mfa_secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_pending_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mfa_last_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    mfa_enroll_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Administration (ADR 0004 decisions 5 and 11). `must_change_password` is set
    # by the bootstrap; `pending_role` is a privileged role that becomes `role`
    # once the user confirms the MFA.
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    pending_role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # When an administrator-issued code reset the password; shown by the next
    # login that opens a full session, then cleared (ADR 0004 decision 10).
    password_reset_notice_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # The first time the account got a privileged role or pending role. Never
    # cleared: demotion keeps it, so an account that is or was privileged still
    # needs two administrators to recover (ADR 0004, decision 10).
    privileged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


def needs_two_administrators(user: User) -> bool:
    """Whether recovering this account (MFA reset, reset code) needs two administrators.

    True for an account that is privileged, has a pending privileged role, or
    ever had either (`privileged_at`): a demotion does not lower the bar.
    """
    return (
        user.role in PRIVILEGED_ROLES
        or user.pending_role is not None
        or user.privileged_at is not None
    )


def mark_privileged(user: User, now: datetime) -> None:
    """Record the first time the account got a privileged role (idempotent)."""
    if user.privileged_at is None:
        user.privileged_at = now


class RefreshFamily(Base):
    """One login session. Its id is the access token's `sid`.

    Refresh tokens rotate inside the family; revoking the family (logout, or
    reuse of a rotated token) ends the session. `last_used_at` is the idle
    clock, `created_at` the absolute one.
    """

    __tablename__ = "refresh_families"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class LoginAttempt(Base):
    """Failed-login counter per keyed hash of the username (also for unknown ones).

    `attempt_key` holds hex HMAC-SHA256(subkey of the CSRF key, normalized
    username), see tokens.login_attempt_key; never the raw name.
    """

    __tablename__ = "login_attempts"

    attempt_key: Mapped[str] = mapped_column(Text, primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RefreshToken(Base):
    """A refresh token of a family; only its SHA-256 hex is stored.

    `used_at` is set when the token is rotated. Presenting a used token again is
    reuse: the whole family is revoked.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    family_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("refresh_families.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class RevokedJti(Base):
    """Access token id denied until the token would have expired anyway."""

    __tablename__ = "revoked_jtis"

    jti: Mapped[str] = mapped_column(Text, primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class RecoveryCode(Base):
    """A single-use MFA recovery code; only its Argon2id hash is stored."""

    __tablename__ = "recovery_codes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    code_hash: Mapped[str] = mapped_column(Text)
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class MfaEnrollmentAttempt(Base):
    """One enrollment that got past the password check, for the per-user limit.

    Only the user id and the time: the rows say how often, never what.
    """

    __tablename__ = "mfa_enrollment_attempts"
    __table_args__ = (
        Index("ix_mfa_enrollment_attempts_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PasswordResetCode(Base):
    """The live reset code of a user, as an Argon2id hash (ADR 0004, decision 10).

    One row per user: issuing a new code replaces it, using it deletes it.
    """

    __tablename__ = "password_reset_codes"
    __table_args__ = (
        CheckConstraint(
            "expires_at > created_at", name="password_reset_codes_expiry_check"
        ),
        Index("ix_password_reset_codes_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True
    )
    code_hash: Mapped[str] = mapped_column(Text)
    issued_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    # The second administrator of a code for an account that is or was privileged:
    # `issued_by` asked, this one approved and received it. NULL for a code one
    # administrator issued (never-privileged readers only) or if the approver
    # was deleted, which the use-time check treats as not approved.
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MfaResetRequest(Base):
    """A pending request that a second administrator must approve.

    `kind` is `mfa_reset` (reset the MFA of an account that is or was privileged)
    or `reset_code` (issue it a password reset code). One row per target and
    kind. A second administrator approves it (ADR 0004, decision 10); approving
    or replacing it deletes the row. The requester's deletion voids it.
    """

    __tablename__ = "mfa_reset_requests"
    __table_args__ = (
        CheckConstraint(
            "expires_at > created_at", name="mfa_reset_requests_expiry_check"
        ),
        CheckConstraint(
            "kind IN ('mfa_reset', 'reset_code')", name="mfa_reset_requests_kind_check"
        ),
        UniqueConstraint(
            "target_user_id", "kind", name="mfa_reset_requests_target_user_id_kind_key"
        ),
        Index("ix_mfa_reset_requests_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    target_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(
        Text, default="mfa_reset", server_default="mfa_reset"
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
