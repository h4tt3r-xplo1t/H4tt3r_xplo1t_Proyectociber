from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

# ADR 0004 decision 4: Argon2id with m=19456 KiB, t=2, p=1.
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerificationError, InvalidHashError:
        return False
