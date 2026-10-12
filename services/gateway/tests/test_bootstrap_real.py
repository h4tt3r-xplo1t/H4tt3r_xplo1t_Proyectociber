"""python -m gateway.bootstrap against the real OpenBao.

The secret is seeded through the DEV/CI-only `bootstrap-seed` AppRole (create and
update on `secret/bootstrap/admin`, nothing else). Absence afterwards is proven
with the bootstrap role, the only one that can read the path: a read of the
latest version and of version 1 must both be 404. No role can read the metadata
(the bootstrap role may only delete it), but `metadata delete` removes the key
with all its versions, so a 404 on every version is the observable proof.

A failing destroy cannot be induced against the real server without changing a
policy, so that case stays in test_bootstrap.py with the fake store.
"""

import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import hvac
import pytest
from sqlalchemy import text

from gateway import bootstrap
from gateway.passwords import verify_password
from gateway.secrets import login

SEEDED = "a-long-random-bootstrap-value-42"
USERNAME = "first-admin"
SHORT = "too-short"


def _login(openbao_env, role_file, secret_file):
    return login(
        openbao_env["GATEWAY_OPENBAO_ADDR"],
        Path(role_file).read_text().strip(),
        Path(secret_file).read_text().strip(),
    )


@pytest.fixture
def env(openbao_env, bootstrap_files, monkeypatch):
    for name, value in {**openbao_env, **bootstrap_files}.items():
        monkeypatch.setenv(name, value)
    return openbao_env


@pytest.fixture
def reader(env, bootstrap_files):
    return _login(
        env,
        bootstrap_files["GATEWAY_BOOTSTRAP_ROLE_ID_FILE"],
        bootstrap_files["GATEWAY_BOOTSTRAP_SECRET_ID_FILE"],
    )


@pytest.fixture
def seed(env, seed_files, reader):
    writer = _login(env, seed_files["role_id"], seed_files["secret_id"])

    def put(value=SEEDED):
        writer.secrets.kv.v2.create_or_update_secret(
            path="bootstrap/admin", secret={"password": value}, mount_point="secret"
        )

    yield put
    # Leave nothing behind whatever the test did.
    reader.secrets.kv.v2.delete_metadata_and_all_versions(
        path="bootstrap/admin", mount_point="secret"
    )


def assert_no_version_left(reader):
    for version in (None, 1):
        with pytest.raises(hvac.exceptions.InvalidPath):
            reader.secrets.kv.v2.read_secret_version(
                path="bootstrap/admin",
                version=version,
                mount_point="secret",
                raise_on_deleted_version=True,
            )


def admins(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT username, password_hash, must_change_password, "
                "mfa_enroll_until FROM users WHERE role = 'administrador'"
            )
        ).all()


def test_real_run_creates_the_administrator_and_leaves_no_version(
    db_engine, seed, reader
):
    seed()
    seed()  # two versions: all of them must go
    before = datetime.now(UTC)

    assert bootstrap.main(["--username", USERNAME]) == 0

    (admin,) = admins(db_engine)
    assert admin.username == USERNAME
    assert admin.must_change_password is True
    assert verify_password(admin.password_hash, SEEDED)
    window = admin.mfa_enroll_until - before
    assert timedelta(hours=23, minutes=59) < window < timedelta(hours=24, minutes=1)
    assert_no_version_left(reader)


def test_real_second_run_is_refused_and_creates_nothing(db_engine, seed, reader):
    seed()
    assert bootstrap.main(["--username", USERNAME]) == 0
    seed()

    assert bootstrap.main(["--username", "second-admin"]) == bootstrap.EXIT_REFUSED

    assert [row.username for row in admins(db_engine)] == [USERNAME]
    # Refused: the new secret was not touched.
    data = reader.secrets.kv.v2.read_secret_version(
        path="bootstrap/admin", mount_point="secret", raise_on_deleted_version=True
    )
    assert data["data"]["data"]["password"] == SEEDED


def test_real_simultaneous_runs_create_one_administrator(
    db_engine, seed, reader, capsys, monkeypatch
):
    seed()
    start = threading.Barrier(2)
    codes = []
    # main() reads the secret before taking the advisory lock. Hold both runs
    # until each has read it, so the loser cannot read after the winner destroyed
    # the secret (that would be INPUT_UNAVAILABLE, a different valid outcome).
    read_password = bootstrap._read_password
    read_done = threading.Barrier(2, timeout=30)

    def read_then_wait(client):
        password = read_password(client)
        read_done.wait()
        return password

    monkeypatch.setattr(bootstrap, "_read_password", read_then_wait)

    errors = []

    def worker(name):
        try:
            start.wait()
            codes.append(bootstrap.main(["--username", name]))
        except BaseException as error:
            # Release the other run instead of leaving it to time out, so the
            # failure shows its root cause.
            errors.append(error)
            start.abort()
            read_done.abort()

    threads = [threading.Thread(target=worker, args=(f"racer-{i}",)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(admins(db_engine)) == 1
    # One run wins; the other is refused with the fixed message and nothing else.
    assert sorted(codes) == [0, bootstrap.EXIT_REFUSED]
    assert capsys.readouterr().err == bootstrap.REFUSED + "\n"
    assert_no_version_left(reader)


def test_real_invalid_secret_is_left_untouched(db_engine, seed, reader):
    seed(SHORT)

    assert bootstrap.main(["--username", USERNAME]) == bootstrap.EXIT_FAILED

    assert admins(db_engine) == []
    data = reader.secrets.kv.v2.read_secret_version(
        path="bootstrap/admin", mount_point="secret", raise_on_deleted_version=True
    )
    assert data["data"]["data"]["password"] == SHORT
