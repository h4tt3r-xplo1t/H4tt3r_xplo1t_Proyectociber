"""python -m gateway.breakglass: recovering a privileged account without peers.

The secret store is a fake that mimics the hvac calls the command makes. The
database is real. The command resets the password of an account that is or was
privileged (ADR 0004, decision 11) from a one-shot secret and destroys that
secret in the same step. Against the real OpenBao the happy path and the
refusals run in test_breakglass_real.py, and the policy in
test_breakglass_openbao.py; here live the cases the real server cannot be
driven into: a destroy that fails or is uncertain, a commit that fails after the
destroy, and the effects on the account.
"""

import logging
import runpy
import sys
import threading
from datetime import timedelta

import hvac
import pytest
import requests
from fastapi.testclient import TestClient
from sqlalchemy import func, insert, select, text

from gateway import auth, bootstrap, breakglass
from gateway.db import get_engine
from gateway.main import create_app
from gateway.models import (
    ApprovalRequest,
    PasswordResetCode,
    RecoveryCode,
    RefreshFamily,
    User,
)
from gateway.passwords import verify_password
from gateway.tokens import decode_access_token
from tests.helpers import FrozenClock
from tests.test_bootstrap import FakeBao as BootstrapBao
from tests.test_login import GOOD, KEYS, login, register

SEEDED = "correct-horse-battery-staple-9"
OLD_HASH = "not-a-real-hash"
TARGET = "locked-out-user"
BYSTANDER = "bystander"
ARGV = ["--username", TARGET, "--break-glass"]
FIXED_MESSAGES = (
    breakglass.USAGE,
    breakglass.REFUSED,
    breakglass.INPUT_UNAVAILABLE,
    breakglass.WRONG_TARGET,
    breakglass.RESET_FAILED,
    breakglass.BUSY,
    breakglass.DESTROY_FAILED,
    breakglass.DESTROY_UNCERTAIN,
)


class FakeBao:
    """Just enough of hvac's KV v2 client for the break-glass command."""

    def __init__(self, store=None, *, destroy_error=None, verify_error=None):
        if store is not None:
            self.store = store
        else:
            self.store = {"username": TARGET, "password": SEEDED}
        self.destroy_error = destroy_error
        self.verify_error = verify_error
        self.deleted = False
        self.logged_out = False
        self.secrets = self
        self.kv = self
        self.v2 = self

    def read_secret_version(self, path, mount_point, raise_on_deleted_version=True):
        assert (path, mount_point) == ("breakglass/account", "secret")
        if self.deleted and self.verify_error is not None:
            raise self.verify_error
        if not self.store:
            raise hvac.exceptions.InvalidPath
        return {"data": {"data": dict(self.store)}}

    def delete_metadata_and_all_versions(self, path, mount_point):
        assert (path, mount_point) == ("breakglass/account", "secret")
        if self.destroy_error is not None:
            raise self.destroy_error
        self.store.clear()
        self.deleted = True

    def logout(self, revoke_token=False):
        assert revoke_token is True
        self.logged_out = True


@pytest.fixture
def clock(monkeypatch):
    frozen = FrozenClock()
    monkeypatch.setattr(breakglass, "_now", frozen)
    return frozen


@pytest.fixture
def bao(monkeypatch, clock):
    fake = FakeBao()
    monkeypatch.setattr(breakglass, "login_client", lambda: fake)
    return fake


@pytest.fixture
def client(db_engine, clock, openbao_env):
    app = create_app()
    app.dependency_overrides[auth.get_keys] = lambda: KEYS
    app.dependency_overrides[auth.get_now] = clock
    yield TestClient(app, base_url="https://testserver")
    get_engine().dispose()


def run(*argv):
    return breakglass.main(list(argv))


def sql(db_engine, statement, **params):
    with db_engine.begin() as conn:
        return conn.execute(text(statement), params)


def make_user(db_engine, username, role="lector", **columns):
    with db_engine.begin() as conn:
        return conn.execute(
            insert(User)
            .values(username=username, password_hash=OLD_HASH, role=role, **columns)
            .returning(User.id)
        ).scalar_one()


def give_state(db_engine, user_id, requester_id):
    """Everything the reset must wipe: sessions, MFA, codes and requests."""
    sql(db_engine, "INSERT INTO refresh_families (user_id) VALUES (:u)", u=user_id)
    sql(
        db_engine,
        "INSERT INTO recovery_codes (user_id, code_hash) VALUES (:u, 'h1'), (:u, 'h2')",
        u=user_id,
    )
    for kind in ("mfa_reset", "reset_code"):
        sql(
            db_engine,
            "INSERT INTO mfa_reset_requests "
            "(target_user_id, kind, requested_by, created_at, expires_at) "
            "VALUES (:t, :k, :r, now(), now() + interval '1 hour')",
            t=user_id,
            k=kind,
            r=requester_id,
        )
    sql(
        db_engine,
        "INSERT INTO password_reset_codes (user_id, code_hash, issued_by, "
        "created_at, expires_at) "
        "VALUES (:u, 'h', :r, now(), now() + interval '15 minutes')",
        u=user_id,
        r=requester_id,
    )


def row(db_engine, username):
    with db_engine.connect() as conn:
        return (
            conn.execute(
                text("SELECT * FROM users WHERE username = :n"), {"n": username}
            )
            .mappings()
            .one()
        )


def count(db_engine, column, user_id):
    with db_engine.connect() as conn:
        return conn.execute(
            select(func.count()).select_from(column.class_).where(column == user_id)
        ).scalar_one()


def counts(db_engine, user_id):
    return {
        "families": count(db_engine, RefreshFamily.user_id, user_id),
        "live_families": sql(
            db_engine,
            "SELECT count(*) FROM refresh_families "
            "WHERE user_id = :u AND revoked_at IS NULL",
            u=user_id,
        ).scalar_one(),
        "recovery": count(db_engine, RecoveryCode.user_id, user_id),
        "requests": count(db_engine, ApprovalRequest.target_user_id, user_id),
        "reset_codes": count(db_engine, PasswordResetCode.user_id, user_id),
    }


@pytest.fixture
def requester(db_engine):
    return make_user(db_engine, "other-admin", "administrador")


PRIVILEGED_CASES = [
    pytest.param({"role": "administrador"}, id="administrator"),
    pytest.param({"role": "editor"}, id="editor"),
    pytest.param({"role": "auditor"}, id="auditor"),
    pytest.param({"role": "lector", "pending_role": "editor"}, id="pending-role"),
    pytest.param(
        {"role": "lector", "privileged_at": "2026-01-01T00:00:00+00:00"},
        id="demoted-reader",
    ),
]


@pytest.mark.parametrize("columns", PRIVILEGED_CASES)
def test_resets_the_account_and_destroys_the_secret(
    db_engine, bao, clock, requester, caplog, columns
):
    caplog.set_level(logging.INFO, logger="gateway.breakglass")
    mfa = {
        "mfa_secret_ciphertext": "vault:v1:secret",
        "mfa_pending_ciphertext": "vault:v1:pending",
        "mfa_enabled_at": clock(),
        "mfa_last_step": 123,
        "mfa_enroll_until": None,
    }
    user_id = make_user(db_engine, TARGET, **mfa, **columns)
    give_state(db_engine, user_id, requester)
    before = row(db_engine, TARGET)

    assert run(*ARGV) == 0

    after = row(db_engine, TARGET)
    assert verify_password(after["password_hash"], SEEDED)
    assert after["must_change_password"] is True
    assert after["mfa_secret_ciphertext"] is None
    assert after["mfa_pending_ciphertext"] is None
    assert after["mfa_enabled_at"] is None
    assert after["mfa_last_step"] is None
    assert after["mfa_enroll_until"] == clock() + timedelta(hours=24)
    assert after["privileged_at"] is not None
    # Role and pending role are not touched: the account keeps what it had.
    assert after["role"] == before["role"]
    assert after["pending_role"] == before["pending_role"]
    assert after["tokens_valid_since"] == clock()
    # The next full login shows that the password was reset out of band.
    assert after["password_reset_notice_at"] == clock()
    assert after["token_generation"] == before["token_generation"] + 1
    assert counts(db_engine, user_id) == {
        "families": 1,
        "live_families": 0,
        "recovery": 0,
        "requests": 0,
        "reset_codes": 0,
    }
    assert bao.store == {}
    assert bao.logged_out is True
    assert f"security_event event=break_glass_reset subject={user_id}" in caplog.text


def test_a_reset_leaves_other_accounts_alone(db_engine, bao, clock, requester):
    user_id = make_user(db_engine, TARGET, "editor")
    other_id = make_user(db_engine, BYSTANDER, "editor")
    give_state(db_engine, user_id, requester)
    give_state(db_engine, other_id, requester)
    before = row(db_engine, BYSTANDER)

    assert run(*ARGV) == 0

    assert row(db_engine, BYSTANDER) == before
    assert counts(db_engine, other_id) == {
        "families": 1,
        "live_families": 1,
        "recovery": 2,
        "requests": 2,
        "reset_codes": 1,
    }


def test_the_login_lockout_counter_is_left_alone(db_engine, bao, clock):
    make_user(db_engine, TARGET, "editor")
    sql(
        db_engine,
        "INSERT INTO login_attempts (attempt_key, failures, locked_until) "
        "VALUES ('k', 4, now() + interval '30 minutes')",
    )

    assert run(*ARGV) == 0

    assert sql(db_engine, "SELECT failures FROM login_attempts").scalar_one() == 4


def test_the_next_login_is_the_scoped_password_change_session(
    client, db_engine, bao, clock
):
    register(client, TARGET)
    assert login(client, TARGET, GOOD).status_code == 200
    sql(
        db_engine,
        "UPDATE users SET role = 'administrador', privileged_at = now(), "
        "mfa_enabled_at = now() WHERE username = :n",
        n=TARGET,
    )
    # A live full session before: it must die with the reset.
    assert client.get("/api/auth/me").status_code == 200

    assert run(*ARGV) == 0

    assert client.get("/api/auth/me").status_code == 401
    fresh = TestClient(client.app, base_url="https://testserver")
    assert login(fresh, TARGET, GOOD).status_code == 401
    response = login(fresh, TARGET, SEEDED)
    assert response.status_code == 200
    assert response.json() == {"status": "password_change_required"}
    assert fresh.get("/api/auth/me").status_code == 401
    claims = decode_access_token(fresh.cookies.get("__Host-access"), KEYS)
    assert claims["scope"] == "enroll-mfa"


def test_an_expired_bootstrap_administrator_window_is_recovered(
    client, db_engine, clock, monkeypatch
):
    # L1 of #45: the bootstrap administrator who did not enroll within 24 h has
    # no peer to reopen the window, so only this command can.
    first = BootstrapBao(SEEDED)
    monkeypatch.setattr(bootstrap, "login_client", lambda: first)
    assert bootstrap.main(["--username", TARGET]) == 0
    sql(
        db_engine,
        "UPDATE users SET mfa_enroll_until = :t WHERE username = :n",
        t=clock() - timedelta(hours=1),
        n=TARGET,
    )
    assert login(client, TARGET, SEEDED).status_code == 401
    fake = FakeBao()
    monkeypatch.setattr(breakglass, "login_client", lambda: fake)

    assert run(*ARGV) == 0

    fresh = TestClient(client.app, base_url="https://testserver")
    response = login(fresh, TARGET, SEEDED)
    assert response.status_code == 200
    assert response.json() == {"status": "password_change_required"}
    assert row(db_engine, TARGET)["mfa_enroll_until"] == clock() + timedelta(hours=24)
    assert fake.store == {}


def test_refuses_an_account_that_never_was_privileged(db_engine, bao, capsys):
    user_id = make_user(db_engine, TARGET, "lector")
    before = row(db_engine, TARGET)

    assert run(*ARGV) == breakglass.EXIT_REFUSED

    assert row(db_engine, TARGET) == before
    assert counts(db_engine, user_id)["families"] == 0
    assert bao.store == {"username": TARGET, "password": SEEDED}
    assert capsys.readouterr().err.strip() == breakglass.REFUSED
    assert bao.logged_out is True


def test_refuses_an_unknown_account(db_engine, bao, capsys):
    assert run(*ARGV) == breakglass.EXIT_REFUSED

    assert bao.store == {"username": TARGET, "password": SEEDED}
    assert capsys.readouterr().err.strip() == breakglass.REFUSED


def test_an_account_that_stops_being_eligible_under_the_lock_is_refused(
    db_engine, bao, monkeypatch
):
    # Eligible at the plain read; gone before the lock is taken.
    make_user(db_engine, TARGET, "editor")
    real_hash = breakglass.hash_password

    def hash_then_delete(password):
        result = real_hash(password)
        sql(db_engine, "DELETE FROM users WHERE username = :n", n=TARGET)
        return result

    monkeypatch.setattr(breakglass, "hash_password", hash_then_delete)

    assert run(*ARGV) == breakglass.EXIT_REFUSED

    assert bao.store == {"username": TARGET, "password": SEEDED}


def test_an_account_whose_pending_role_is_cleared_under_the_lock_is_refused(
    db_engine, bao, monkeypatch
):
    # Eligible at the plain read only through a pending role (no marker); the
    # role is cleared before the lock, so the recheck must refuse it.
    make_user(db_engine, TARGET, "lector", pending_role="editor")
    before = row(db_engine, TARGET)
    real_hash = breakglass.hash_password

    def hash_then_clear(password):
        result = real_hash(password)
        sql(
            db_engine,
            "UPDATE users SET pending_role = NULL WHERE username = :n",
            n=TARGET,
        )
        return result

    monkeypatch.setattr(breakglass, "hash_password", hash_then_clear)

    assert run(*ARGV) == breakglass.EXIT_REFUSED

    after = row(db_engine, TARGET)
    assert after["password_hash"] == before["password_hash"]
    assert bao.store == {"username": TARGET, "password": SEEDED}


@pytest.mark.parametrize(
    "store",
    [
        {},
        {"username": TARGET},
        {"password": SEEDED},
        {"username": TARGET, "password": ""},
        {"username": TARGET, "password": "too-short"},
        {"username": TARGET, "password": 12345678901234567890},
        {"username": 7, "password": SEEDED},
        {"username": TARGET, "password": "x" * 129},
    ],
)
def test_a_missing_or_malformed_secret_changes_nothing(
    db_engine, monkeypatch, clock, capsys, store
):
    make_user(db_engine, TARGET, "editor")
    before = row(db_engine, TARGET)
    fake = FakeBao(dict(store))
    monkeypatch.setattr(breakglass, "login_client", lambda: fake)

    assert run(*ARGV) == breakglass.EXIT_FAILED

    assert row(db_engine, TARGET) == before
    assert fake.store == store
    assert capsys.readouterr().err.strip() == breakglass.INPUT_UNAVAILABLE


def test_a_secret_seeded_for_another_account_is_refused(
    db_engine, monkeypatch, clock, capsys
):
    make_user(db_engine, TARGET, "editor")
    make_user(db_engine, BYSTANDER, "editor")
    before = row(db_engine, TARGET), row(db_engine, BYSTANDER)
    fake = FakeBao({"username": BYSTANDER, "password": SEEDED})
    monkeypatch.setattr(breakglass, "login_client", lambda: fake)

    assert run(*ARGV) == breakglass.EXIT_FAILED

    assert (row(db_engine, TARGET), row(db_engine, BYSTANDER)) == before
    assert fake.store == {"username": BYSTANDER, "password": SEEDED}
    err = capsys.readouterr().err
    assert err.strip() == breakglass.WRONG_TARGET
    assert BYSTANDER not in err


def test_a_decomposed_password_is_checked_after_normalization(
    db_engine, monkeypatch, clock
):
    make_user(db_engine, TARGET, "editor")
    password = "e\u0301" * 7
    assert len(password) == 14
    fake = FakeBao({"username": TARGET, "password": password})
    monkeypatch.setattr(breakglass, "login_client", lambda: fake)

    assert run(*ARGV) == breakglass.EXIT_FAILED

    assert fake.store == {"username": TARGET, "password": password}


def test_a_login_failure_is_a_fixed_error(db_engine, monkeypatch, clock, capsys):
    def failing_login():
        raise breakglass.SecretsError("AppRole login to OpenBao failed")

    monkeypatch.setattr(breakglass, "login_client", failing_login)

    assert run(*ARGV) == breakglass.EXIT_FAILED

    assert capsys.readouterr().err.strip() == breakglass.INPUT_UNAVAILABLE


def test_a_destroy_failure_rolls_the_reset_back_and_keeps_the_secret(
    db_engine, monkeypatch, clock, requester, capsys
):
    user_id = make_user(db_engine, TARGET, "editor", mfa_enabled_at=clock())
    give_state(db_engine, user_id, requester)
    before, state = row(db_engine, TARGET), counts(db_engine, user_id)
    fake = FakeBao(destroy_error=hvac.exceptions.Forbidden("http://secret-url"))
    monkeypatch.setattr(breakglass, "login_client", lambda: fake)

    assert run(*ARGV) == breakglass.EXIT_DESTROY_FAILED

    # The password changes and the secret is destroyed in one step or neither.
    assert row(db_engine, TARGET) == before
    assert counts(db_engine, user_id) == state
    assert fake.store == {"username": TARGET, "password": SEEDED}
    err = capsys.readouterr().err
    assert err.strip() == breakglass.DESTROY_FAILED
    assert "secret-url" not in err
    assert fake.logged_out is True


@pytest.mark.parametrize(
    "error",
    [
        hvac.exceptions.InternalServerError("http://secret-url"),
        hvac.exceptions.BadGateway("http://secret-url"),
        hvac.exceptions.VaultDown("http://secret-url"),
        requests.exceptions.Timeout("http://secret-url"),
        requests.exceptions.ConnectionError("http://secret-url"),
    ],
    ids=["500", "502", "503", "timeout", "connection"],
)
def test_a_delete_without_a_definite_answer_is_uncertain(
    db_engine, monkeypatch, clock, requester, capsys, error
):
    user_id = make_user(db_engine, TARGET, "editor")
    give_state(db_engine, user_id, requester)
    before, state = row(db_engine, TARGET), counts(db_engine, user_id)
    fake = FakeBao(destroy_error=error)
    monkeypatch.setattr(breakglass, "login_client", lambda: fake)

    assert run(*ARGV) == breakglass.EXIT_DESTROY_UNCERTAIN

    assert row(db_engine, TARGET) == before
    assert counts(db_engine, user_id) == state
    err = capsys.readouterr().err
    assert err.strip() == breakglass.DESTROY_UNCERTAIN
    assert "secret-url" not in err


@pytest.mark.parametrize(
    "error",
    [
        hvac.exceptions.InternalServerError("http://secret-url"),
        requests.exceptions.Timeout("http://secret-url"),
        requests.exceptions.ConnectionError("http://secret-url"),
    ],
    ids=["500", "timeout", "connection"],
)
def test_an_uncertain_verification_rolls_back_and_does_not_promise_the_secret(
    db_engine, monkeypatch, clock, capsys, error
):
    make_user(db_engine, TARGET, "editor")
    before = row(db_engine, TARGET)
    fake = FakeBao(verify_error=error)
    monkeypatch.setattr(breakglass, "login_client", lambda: fake)

    assert run(*ARGV) == breakglass.EXIT_DESTROY_UNCERTAIN

    assert row(db_engine, TARGET) == before
    err = capsys.readouterr().err
    assert err.strip() == breakglass.DESTROY_UNCERTAIN
    assert "intact" not in err


def test_reset_failed_says_the_account_may_or_may_not_be_reset():
    # A COMMIT can be applied by PostgreSQL and still fail on the client when
    # the connection drops, so the message must not promise "nothing changed".
    assert "may or may not" in breakglass.RESET_FAILED
    assert "reseed" in breakglass.RESET_FAILED


def test_a_failed_commit_after_the_destroy_leaves_no_secret_and_a_fixed_error(
    db_engine, bao, monkeypatch, capsys
):
    make_user(db_engine, TARGET, "editor")
    before = row(db_engine, TARGET)
    real_commit = breakglass.Session.commit

    def failing_commit(self):
        raise breakglass.SQLAlchemyError("boom")

    monkeypatch.setattr(breakglass.Session, "commit", failing_commit)

    assert run(*ARGV) == breakglass.EXIT_FAILED

    monkeypatch.setattr(breakglass.Session, "commit", real_commit)
    # For this simulated failure the commit never reached PostgreSQL, so the
    # account is as before. No secret remains either way; the person reseeds.
    assert row(db_engine, TARGET) == before
    assert bao.store == {}
    assert capsys.readouterr().err.strip() == breakglass.RESET_FAILED


def test_a_busy_user_row_is_a_fixed_error_and_changes_nothing(
    db_engine, bao, monkeypatch, capsys
):
    make_user(db_engine, TARGET, "editor")
    before = row(db_engine, TARGET)
    monkeypatch.setattr(breakglass, "LOCK_TIMEOUT", "200ms")
    held = threading.Event()
    release = threading.Event()

    def hold_the_row():
        with db_engine.begin() as conn:
            conn.execute(
                text("SELECT id FROM users WHERE username = :n FOR UPDATE"),
                {"n": TARGET},
            )
            held.set()
            release.wait(timeout=30)

    holder = threading.Thread(target=hold_the_row)
    holder.start()
    try:
        assert held.wait(timeout=30)
        assert run(*ARGV) == breakglass.EXIT_FAILED
    finally:
        release.set()
        holder.join()

    assert row(db_engine, TARGET) == before
    assert bao.store == {"username": TARGET, "password": SEEDED}
    assert capsys.readouterr().err.strip() == breakglass.BUSY


def test_a_database_failure_is_a_fixed_error(bao, monkeypatch, capsys):
    monkeypatch.delenv("GATEWAY_DATABASE_URL")
    breakglass.get_engine.cache_clear()
    try:
        assert run(*ARGV) == breakglass.EXIT_FAILED
    finally:
        breakglass.get_engine.cache_clear()

    assert capsys.readouterr().err.strip() == breakglass.RESET_FAILED
    assert bao.store == {"username": TARGET, "password": SEEDED}


def test_no_output_or_log_carries_the_secret_the_hash_or_the_username(
    db_engine, bao, capsys, caplog
):
    caplog.set_level(logging.DEBUG)
    make_user(db_engine, TARGET, "editor")

    assert run(*ARGV) == 0

    captured = capsys.readouterr()
    everything = captured.out + captured.err + caplog.text
    assert SEEDED not in everything
    assert row(db_engine, TARGET)["password_hash"] not in everything
    assert TARGET not in everything
    assert "security_event event=break_glass_reset" in caplog.text
    assert captured.out.strip() == breakglass.SUCCESS


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--username", TARGET],
        ["--break-glass"],
        ["--username", "--break-glass"],
        ["--username", "ab", "--break-glass"],
        ["--username", "UPPER", "--break-glass"],
        ["--username", "a" * 33, "--break-glass"],
        ["--username", TARGET, "--break-glass", "extra"],
        ["--username", TARGET, "--break-glass", "--password", "secret-on-argv"],
        ["--username", TARGET, "--password", "secret-on-argv"],
        ["--username", TARGET, "--break-glass=1"],
        ["--break-glass", "--username"],
        ["--password", "secret-on-argv", "--break-glass"],
        ["--username", TARGET, "--username", TARGET, "--break-glass"],
    ],
)
def test_bad_arguments_print_only_the_usage(db_engine, bao, capsys, argv):
    make_user(db_engine, TARGET, "editor")
    before = row(db_engine, TARGET)

    assert run(*argv) == breakglass.EXIT_USAGE

    captured = capsys.readouterr()
    assert captured.err.strip() == breakglass.USAGE
    assert "secret-on-argv" not in captured.err
    assert row(db_engine, TARGET) == before
    assert bao.store == {"username": TARGET, "password": SEEDED}


def test_the_flag_may_come_first(db_engine, bao):
    make_user(db_engine, TARGET, "editor")

    assert run("--break-glass", "--username", TARGET) == 0


def test_the_fixed_messages_carry_no_variable_text():
    assert all("{" not in message for message in FIXED_MESSAGES)


def test_running_the_module_exits_with_the_status_of_main(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["gateway.breakglass"])
    sys.modules.pop("gateway.breakglass")

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("gateway.breakglass", run_name="__main__")

    assert excinfo.value.code == breakglass.EXIT_USAGE
    assert capsys.readouterr().err.strip() == breakglass.USAGE
