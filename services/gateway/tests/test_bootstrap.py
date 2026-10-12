"""python -m gateway.bootstrap: the first administrator, from a one-shot secret.

The secret store is a fake that mimics the hvac calls the command makes, because
no credential available to the tests may write `secret/bootstrap/admin` (the
bootstrap role only reads and destroys it). The policy itself is proven against
the real OpenBao in test_bootstrap_openbao.py, and the real login and the
missing-secret path are proven here with the real bootstrap AppRole.
"""

import logging
import runpy
import sys
import threading
from datetime import UTC, datetime, timedelta

import hvac
import pytest
from sqlalchemy import text

from gateway import bootstrap
from gateway.passwords import verify_password

SEEDED = "correct-horse-battery-staple-9"
USERNAME = "first-admin"
FIXED_MESSAGES = (
    bootstrap.USAGE,
    bootstrap.REFUSED,
    bootstrap.INPUT_UNAVAILABLE,
    bootstrap.CREATE_FAILED,
    bootstrap.DESTROY_FAILED,
)


class FakeBao:
    """Just enough of hvac's KV v2 client for the bootstrap."""

    def __init__(self, password=SEEDED, *, destroy_error=None, shared=None):
        self.store = shared if shared is not None else {"password": password}
        self.destroy_error = destroy_error
        self.logged_out = False
        self.secrets = self
        self.kv = self
        self.v2 = self

    def read_secret_version(self, path, mount_point, raise_on_deleted_version=True):
        assert (path, mount_point) == ("bootstrap/admin", "secret")
        if not self.store:
            raise hvac.exceptions.InvalidPath
        return {"data": {"data": dict(self.store)}}

    def delete_metadata_and_all_versions(self, path, mount_point):
        assert (path, mount_point) == ("bootstrap/admin", "secret")
        if self.destroy_error is not None:
            raise self.destroy_error
        self.store.clear()

    def logout(self, revoke_token=False):
        assert revoke_token is True
        self.logged_out = True


@pytest.fixture
def bao(monkeypatch):
    fake = FakeBao()
    monkeypatch.setattr(bootstrap, "login_client", lambda: fake)
    return fake


def run(*argv):
    return bootstrap.main(list(argv))


def users(db_engine, role="administrador"):
    with db_engine.begin() as conn:
        return conn.execute(
            text(
                "SELECT id, username, password_hash, role, must_change_password, "
                "mfa_enroll_until, tokens_valid_since, mfa_enabled_at "
                "FROM users WHERE role = :r"
            ),
            {"r": role},
        ).all()


def test_creates_the_administrator_and_destroys_the_secret(db_engine, bao):
    before = datetime.now(UTC)

    assert run("--username", USERNAME) == 0

    (admin,) = users(db_engine)
    assert admin.username == USERNAME
    assert admin.must_change_password is True
    assert admin.mfa_enabled_at is None
    assert verify_password(admin.password_hash, SEEDED)
    window = admin.mfa_enroll_until - before
    assert timedelta(hours=23, minutes=59) < window < timedelta(hours=24, minutes=1)
    assert before - timedelta(seconds=1) <= admin.tokens_valid_since
    assert bao.store == {}
    assert bao.logged_out is True


def test_a_second_run_refuses_and_leaves_the_secret_alone(db_engine, bao):
    assert run("--username", USERNAME) == 0
    bao.store.update(password=SEEDED)

    assert run("--username", "second-admin") == bootstrap.EXIT_REFUSED

    assert [row.username for row in users(db_engine)] == [USERNAME]
    assert bao.store == {"password": SEEDED}
    assert bao.logged_out is True


def test_refuses_when_any_administrator_exists(db_engine, bao, capsys):
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES ('someone', 'x', 'administrador')"
            )
        )

    assert run("--username", USERNAME) == bootstrap.EXIT_REFUSED

    assert [row.username for row in users(db_engine)] == ["someone"]
    assert bao.store == {"password": SEEDED}
    assert capsys.readouterr().err.strip() == bootstrap.REFUSED


def test_simultaneous_runs_create_at_most_one_administrator(db_engine, monkeypatch):
    shared = {"password": SEEDED}
    clients = [FakeBao(shared=shared) for _ in range(2)]
    pending = list(clients)
    monkeypatch.setattr(bootstrap, "login_client", lambda: pending.pop())
    start = threading.Barrier(2)
    codes = []

    def worker(name):
        start.wait()
        codes.append(run("--username", name))

    threads = [threading.Thread(target=worker, args=(f"racer-{i}",)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(users(db_engine)) == 1
    assert codes.count(0) == 1
    assert all(code != 0 for code in codes if code != 0)
    assert shared == {}


def test_destroy_failure_rolls_the_creation_back_and_keeps_the_secret(
    db_engine, monkeypatch, capsys
):
    fake = FakeBao(destroy_error=hvac.exceptions.Forbidden("http://secret-url"))
    monkeypatch.setattr(bootstrap, "login_client", lambda: fake)

    assert run("--username", USERNAME) == bootstrap.EXIT_DESTROY_FAILED

    # The user is created and the secret destroyed in one step or neither: a
    # live password in OpenBao next to an existing account is the one outcome
    # that must not happen.
    assert users(db_engine) == []
    assert fake.store == {"password": SEEDED}
    err = capsys.readouterr().err
    assert err.strip() == bootstrap.DESTROY_FAILED
    assert "secret-url" not in err
    assert fake.logged_out is True


def test_a_failed_commit_after_the_destroy_leaves_no_credential_anywhere(
    db_engine, bao, monkeypatch, capsys
):
    real_commit = bootstrap.Session.commit

    def failing_commit(self):
        raise bootstrap.SQLAlchemyError("boom")

    monkeypatch.setattr(bootstrap.Session, "commit", failing_commit)

    assert run("--username", USERNAME) == bootstrap.EXIT_FAILED

    monkeypatch.setattr(bootstrap.Session, "commit", real_commit)
    # Safe failure: no account and no secret; the person seeds a new one.
    assert users(db_engine) == []
    assert bao.store == {}
    assert capsys.readouterr().err.strip() == bootstrap.CREATE_FAILED


@pytest.mark.parametrize(
    "store",
    [
        {},
        {"password": ""},
        {"password": "too-short"},
        {"password": 12345678901234567890},
        {"other": SEEDED},
        {"password": "x" * 129},
    ],
)
def test_missing_or_invalid_secret_is_a_fixed_error_and_stays_untouched(
    db_engine, monkeypatch, capsys, store
):
    fake = FakeBao(shared=dict(store))
    monkeypatch.setattr(bootstrap, "login_client", lambda: fake)

    assert run("--username", USERNAME) == bootstrap.EXIT_FAILED

    assert users(db_engine) == []
    assert fake.store == store
    assert capsys.readouterr().err.strip() == bootstrap.INPUT_UNAVAILABLE


def test_decomposed_password_is_checked_after_normalization(
    db_engine, monkeypatch, capsys
):
    # 14 characters once composed: it must be refused like a short password.
    password = "é" * 7
    assert len(password) == 14
    fake = FakeBao(password)
    monkeypatch.setattr(bootstrap, "login_client", lambda: fake)

    assert run("--username", USERNAME) == bootstrap.EXIT_FAILED

    assert users(db_engine) == []
    assert fake.store == {"password": password}


def test_login_failure_is_a_fixed_error(db_engine, monkeypatch, capsys):
    def failing_login():
        raise bootstrap.SecretsError("AppRole login to OpenBao failed")

    monkeypatch.setattr(bootstrap, "login_client", failing_login)

    assert run("--username", USERNAME) == bootstrap.EXIT_FAILED

    assert capsys.readouterr().err.strip() == bootstrap.INPUT_UNAVAILABLE
    assert users(db_engine) == []


def test_a_taken_username_fails_without_destroying_the_secret(db_engine, bao, capsys):
    with db_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (username, password_hash) VALUES (:u, 'x')"),
            {"u": USERNAME},
        )

    assert run("--username", USERNAME) == bootstrap.EXIT_FAILED

    assert users(db_engine) == []
    assert bao.store == {"password": SEEDED}
    assert capsys.readouterr().err.strip() == bootstrap.CREATE_FAILED


def test_no_output_or_log_carries_the_password_or_the_hash(
    db_engine, bao, capsys, caplog
):
    caplog.set_level(logging.DEBUG)

    assert run("--username", USERNAME) == 0

    (admin,) = users(db_engine)
    captured = capsys.readouterr()
    everything = captured.out + captured.err + caplog.text
    assert SEEDED not in everything
    assert admin.password_hash not in everything
    assert "security_event event=bootstrap_admin_created" in caplog.text
    assert str(admin.id) in caplog.text


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--username"],
        ["--username", "ab"],
        ["--username", "UPPER"],
        ["--username", "a" * 33],
        ["--username", "ok-name", "--password", "whatever"],
        ["--username", "ok-name", "extra"],
        ["--password", "secret-on-argv"],
    ],
)
def test_bad_arguments_print_only_the_usage(db_engine, bao, capsys, argv):
    assert run(*argv) == bootstrap.EXIT_USAGE

    captured = capsys.readouterr()
    assert captured.err.strip() == bootstrap.USAGE
    assert "secret-on-argv" not in captured.err
    assert "whatever" not in captured.err
    assert users(db_engine) == []
    assert bao.store == {"password": SEEDED}


def test_database_failure_is_a_fixed_error(bao, monkeypatch, capsys):
    monkeypatch.delenv("GATEWAY_DATABASE_URL")
    bootstrap.get_engine.cache_clear()
    try:
        assert run("--username", USERNAME) == bootstrap.EXIT_FAILED
    finally:
        bootstrap.get_engine.cache_clear()

    err = capsys.readouterr().err
    assert err.strip() == bootstrap.CREATE_FAILED
    assert bao.store == {"password": SEEDED}


def test_real_openbao_without_the_secret_is_a_fixed_error(
    db_engine, openbao_env, bootstrap_files, monkeypatch, capsys
):
    # The real bootstrap AppRole logs in; nothing is stored at the path, so the
    # read is a 404 and the command stops without touching anything.
    for name, value in {**openbao_env, **bootstrap_files}.items():
        monkeypatch.setenv(name, value)

    assert run("--username", USERNAME) == bootstrap.EXIT_FAILED

    assert capsys.readouterr().err.strip() == bootstrap.INPUT_UNAVAILABLE
    assert users(db_engine) == []


def test_real_openbao_login_with_a_wrong_secret_id_is_a_fixed_error(
    db_engine, openbao_env, bootstrap_files, monkeypatch, tmp_path, capsys
):
    wrong = tmp_path / "secret-id"
    wrong.write_text("wrong-secret-id")
    for name, value in {**openbao_env, **bootstrap_files}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_SECRET_ID_FILE", str(wrong))

    assert run("--username", USERNAME) == bootstrap.EXIT_FAILED

    err = capsys.readouterr().err
    assert err.strip() == bootstrap.INPUT_UNAVAILABLE
    assert "wrong-secret-id" not in err


def test_the_fixed_messages_carry_no_variable_text():
    assert all("{" not in message for message in FIXED_MESSAGES)


def test_running_the_module_exits_with_the_status_of_main(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["gateway.bootstrap"])
    sys.modules.pop("gateway.bootstrap")

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("gateway.bootstrap", run_name="__main__")

    assert excinfo.value.code == bootstrap.EXIT_USAGE
    assert capsys.readouterr().err.strip() == bootstrap.USAGE
