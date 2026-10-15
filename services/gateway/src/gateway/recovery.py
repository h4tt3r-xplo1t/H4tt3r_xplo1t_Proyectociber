"""Password reset code helpers (ADR 0004, decision 10).

Pure functions, no I/O: the routes in gateway.admin (issue) and gateway.auth
(use) do the storage, the hashing and the lockout accounting. The code comes
from a CSPRNG (`secrets`).
"""

import secrets
from datetime import timedelta

# How long an issued code stays usable.
RESET_CODE_TTL = timedelta(minutes=15)

# Crockford base32: 32 symbols without I, L, O or U, so a code read aloud or
# copied by hand cannot be confused.
RESET_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
RESET_GROUPS = 4
RESET_GROUP_LENGTH = 5
# 20 symbols of 5 bits: 100 bits (the ADR asks for at least 16 alphanumerics).


def new_reset_code() -> str:
    """A random code written as XXXXX-XXXXX-XXXXX-XXXXX."""
    return "-".join(
        "".join(secrets.choice(RESET_ALPHABET) for _ in range(RESET_GROUP_LENGTH))
        for _ in range(RESET_GROUPS)
    )


def normalize_reset_code(text: str) -> str:
    """What a person typed, without spaces or dashes and in uppercase."""
    return "".join(text.split()).replace("-", "").upper()


def canonical_reset_code(text: str) -> str | None:
    """The stored form (XXXXX-XXXXX-XXXXX-XXXXX) of what a person typed, if valid.

    The issuing route hashes the grouped form, so the typed one is normalized and
    regrouped before it is verified. None when it cannot be a code we issued
    (wrong length or a symbol outside the alphabet): nothing to verify then.
    """
    plain = normalize_reset_code(text)
    if len(plain) != RESET_GROUPS * RESET_GROUP_LENGTH or not set(plain) <= set(
        RESET_ALPHABET
    ):
        return None
    return "-".join(
        plain[i : i + RESET_GROUP_LENGTH]
        for i in range(0, len(plain), RESET_GROUP_LENGTH)
    )
