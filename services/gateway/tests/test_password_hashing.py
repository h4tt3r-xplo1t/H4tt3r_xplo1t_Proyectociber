import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from gateway import passwords
from gateway.passwords import hash_password, verify_password

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
