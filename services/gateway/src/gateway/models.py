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
