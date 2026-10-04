import threading
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager

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


# How long a request waits for a hashing slot before giving up (HTTP 503).
# Module-level so tests can shorten it.
HASH_WAIT_SECONDS = 5


class HashingBusy(RuntimeError):
    """No hashing slot became free in time; the caller answers 503."""


@contextmanager
def _slot() -> Iterator[None]:
    if not _slots.acquire(timeout=HASH_WAIT_SECONDS):
        raise HashingBusy("password hashing is saturated")
    try:
        yield
    finally:
        _slots.release()


def normalize_password(password: str) -> str:
    """NFC, so the same password typed on another keyboard still matches.

    NIST SP 800-63B rev. 4 asks verifiers to apply a stabilized normalization
    (NFC or NFKC) before hashing; NFC does not fold compatibility characters.
    """
    return unicodedata.normalize("NFC", password)


def hash_password(password: str) -> str:
    password = normalize_password(password)
    with _slot():
        return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    password = normalize_password(password)
    with _slot():
        try:
            return _hasher.verify(password_hash, password)
        except VerificationError, InvalidHashError:
            return False


# Verified for unknown users so they cost the same as known ones. Same
# parameters as real hashes; the input is not a secret.
_DUMMY_HASH = _hasher.hash("dummy password for unknown users")


def verify_dummy(password: str) -> bool:
    """Spend the cost of a verification and always answer False."""
    verify_password(_DUMMY_HASH, password)
    return False
