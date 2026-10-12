"""TOTP and recovery-code helpers (ADR 0004, decisions 4, 8 and 11).

Pure functions, no I/O: the routes in gateway.auth do the storage, the transit
calls and the lockout accounting. Every random value comes from a CSPRNG
(`secrets`, or pyotp's own `secrets`-based generator).
"""

import hmac
import re
import secrets
from datetime import datetime

import pyotp

ISSUER = "h4tt3r-1nf0rm4t1v0"
# +-1 step of 30 s around the server's time (ADR 0004, decision 4).
TOTP_WINDOW = 1
TOTP_CODE = re.compile(r"[0-9]{6}")

RECOVERY_CODE_COUNT = 10
RECOVERY_GROUPS = 3
RECOVERY_GROUP_LENGTH = 4
BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_RECOVERY_RAW = re.compile(
    rf"[{BASE32_ALPHABET}]{{{RECOVERY_GROUPS * RECOVERY_GROUP_LENGTH}}}"
)


def new_totp_secret() -> str:
    """A random base32 secret (160 bits at pyotp's default length of 32)."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def matching_step(secret: str, code: str, now: datetime) -> int | None:
    """The TOTP step `code` belongs to within the window around `now`, else None.

    The step is needed to refuse a replay (a step at or below the last accepted
    one). Every offset is compared in constant time and none exits early.
    """
    totp = pyotp.TOTP(secret)
    base = totp.timecode(now)
    found = None
    for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        expected = totp.at(now, offset)
        if hmac.compare_digest(expected.encode(), code.encode()):
            found = base + offset
    return found


def new_recovery_codes() -> list[str]:
    """Ten distinct codes of 12 base32 characters, written XXXX-XXXX-XXXX."""
    codes: set[str] = set()
    while len(codes) < RECOVERY_CODE_COUNT:
        raw = "".join(
            secrets.choice(BASE32_ALPHABET)
            for _ in range(RECOVERY_GROUPS * RECOVERY_GROUP_LENGTH)
        )
        codes.add(
            "-".join(
                raw[i : i + RECOVERY_GROUP_LENGTH]
                for i in range(0, len(raw), RECOVERY_GROUP_LENGTH)
            )
        )
    return list(codes)


def normalize_recovery_code(value: str) -> str | None:
    """Canonical XXXX-XXXX-XXXX form of a typed code, or None if it is not one."""
    raw = value.strip().replace("-", "").upper()
    if not _RECOVERY_RAW.fullmatch(raw):
        return None
    return "-".join(
        raw[i : i + RECOVERY_GROUP_LENGTH]
        for i in range(0, len(raw), RECOVERY_GROUP_LENGTH)
    )
