import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from gateway import passwords
from gateway.passwords import (
    HashingBusy,
    hash_password,
    normalize_password,
    verify_dummy,
    verify_password,
)

BOUND = 4
SAMPLE = "a sample passphrase for tests"  # noqa: S105  (fake, not a real secret)


def test_hash_uses_argon2id_with_adr_parameters():
    hashed = hash_password(SAMPLE)

    assert hashed.startswith("$argon2id$")
    assert "m=19456,t=2,p=1" in hashed


def test_verify_accepts_right_and_rejects_wrong_password():
    hashed = hash_password(SAMPLE)

    assert verify_password(hashed, SAMPLE) is True
    assert verify_password(hashed, SAMPLE + "x") is False


def test_concurrent_hashing_is_bounded(monkeypatch):
    lock = threading.Lock()
    state = {"running": 0, "max": 0}

    def slow_hash(password):
        with lock:
            state["running"] += 1
            state["max"] = max(state["max"], state["running"])
        time.sleep(0.05)
        with lock:
            state["running"] -= 1
        return "fake-hash"

    monkeypatch.setattr(passwords, "_hasher", SimpleNamespace(hash=slow_hash))

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(passwords.hash_password, [SAMPLE] * 16))

    assert state["max"] <= BOUND
    assert state["max"] > 1  # the bound limits concurrency, it does not serialize


def test_concurrent_verification_is_bounded(monkeypatch):
    lock = threading.Lock()
    state = {"running": 0, "max": 0}

    def slow_verify(password_hash, password):
        with lock:
            state["running"] += 1
            state["max"] = max(state["max"], state["running"])
        time.sleep(0.05)
        with lock:
            state["running"] -= 1
        return True

    monkeypatch.setattr(passwords, "_hasher", SimpleNamespace(verify=slow_verify))

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda _: passwords.verify_password("h", SAMPLE), range(16)))

    assert state["max"] <= BOUND


def test_normalize_password_uses_nfc():
    decomposed = "cafe\u0301"  # "e" + combining acute accent
    precomposed = "caf\u00e9"

    assert normalize_password(decomposed) == precomposed


def test_decomposed_and_precomposed_passwords_verify_as_the_same():
    decomposed = "contrase\u0301a-larga-1234"
    precomposed = "contrase\u0301a-larga-1234".replace("e\u0301", "\u00e9")

    hashed = hash_password(decomposed)

    assert verify_password(hashed, precomposed) is True


def test_nfc_does_not_fold_compatibility_characters():
    # NFC (not NFKC): a fullwidth letter stays different from the ASCII one.
    assert normalize_password("\uff21") != normalize_password("A")


def hold_all_slots():
    for _ in range(BOUND):
        passwords._slots.acquire()


def release_all_slots():
    for _ in range(BOUND):
        passwords._slots.release()


def test_waiting_for_a_slot_times_out_with_hashing_busy(monkeypatch):
    called = []
    monkeypatch.setattr(passwords, "HASH_WAIT_SECONDS", 0.05)
    monkeypatch.setattr(
        passwords,
        "_hasher",
        SimpleNamespace(
            hash=lambda p: called.append(p), verify=lambda h, p: called.append(p)
        ),
    )
    hold_all_slots()
    try:
        started = time.monotonic()
        with pytest.raises(HashingBusy):
            hash_password(SAMPLE)
        with pytest.raises(HashingBusy):
            verify_password("h", SAMPLE)
        with pytest.raises(HashingBusy):
            verify_dummy(SAMPLE)
        assert time.monotonic() - started < 2
    finally:
        release_all_slots()

    assert called == []  # nothing was hashed while the slots were taken


def test_the_wait_limit_is_five_seconds_by_default():
    assert passwords.HASH_WAIT_SECONDS == 5


def test_verify_dummy_is_false_and_uses_the_same_argon2id_parameters():
    assert verify_dummy(SAMPLE) is False
    assert passwords._DUMMY_HASH.startswith("$argon2id$")
    assert "m=19456,t=2,p=1" in passwords._DUMMY_HASH
