import threading

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

# ADR 0004 decision 4: Argon2id with m=19456 KiB, t=2, p=1.
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    type=Type.ID,
)


# Each Argon2id run uses 19 MiB and registration is an unauthenticated route, so
# unbounded parallel hashes could exhaust memory. Cap them per process; the
# request rate itself is limited at the Ingress (E5).
MAX_CONCURRENT_HASHES = 4
_slots = threading.BoundedSemaphore(MAX_CONCURRENT_HASHES)


def hash_password(password: str) -> str:
    with _slots:
        return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    with _slots:
        try:
            return _hasher.verify(password_hash, password)
        except VerificationError, InvalidHashError:
            return False
