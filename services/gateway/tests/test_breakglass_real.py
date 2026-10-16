"""python -m gateway.breakglass against the real OpenBao.

The secret is seeded through the DEV/CI-only `breakglass-seed` AppRole (create
and update on `secret/breakglass/account`, nothing else). Absence afterwards is
proven with the break-glass role, the only one that can read the path: a read of
the latest version and of version 1 must both be 404. A failing destroy cannot
be induced against the real server without changing a policy, so that case
stays in test_breakglass.py with the fake store.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import hvac
import pytest
from sqlalchemy import text

from gateway import breakglass
from gateway.passwords import verify_password
from gateway.secrets import login

SEEDED = "a-long-random-break-glass-value-42"
USERNAME = "locked-out-editor"
PATH = "breakglass/account"
OLD = "old-hash"
SHORT = "too-short"


def _login(openbao_env, role_file, secret_file):
    return login(
        openbao_env["GATEWAY_OPENBAO_ADDR"],
        Path(role_file).read_text().strip(),
        Path(secret_file).read_text().strip(),
    )


@pytest.fixture
def env(openbao_env, breakglass_files, monkeypatch):
    for name, value in {**openbao_env, **breakglass_files}.items():
        monkeypatch.setenv(name, value)
    return openbao_env


@pytest.fixture
def reader(env, breakglass_files):
    return _login(
        env,
        breakglass_files["GATEWAY_BREAKGLASS_ROLE_ID_FILE"],
        breakglass_files["GATEWAY_BREAKGLASS_SECRET_ID_FILE"],
    )


@pytest.fixture
def seed(env, breakglass_seed_files, reader):
    writer = _login(
        env, breakglass_seed_files["role_id"], breakglass_seed_files["secret_id"]
    )

    def put(username=USERNAME, password=SEEDED):
        writer.secrets.kv.v2.create_or_update_secret(
            path=PATH,
            secret={"username": username, "password": password},
            mount_point="secret",
        )

    yield put
    # Leave nothing behind whatever the test did.
    reader.secrets.kv.v2.delete_metadata_and_all_versions(
        path=PATH, mount_point="secret"
    )


def assert_no_version_left(reader):
    for version in (None, 1):
        with pytest.raises(hvac.exceptions.InvalidPath):
            reader.secrets.kv.v2.read_secret_version(
                path=PATH,
                version=version,
                mount_point="secret",
                raise_on_deleted_version=True,
            )


def stored(reader):
    response = reader.secrets.kv.v2.read_secret_version(
        path=PATH, mount_point="secret", raise_on_deleted_version=True
    )
    return response["data"]["data"]


def make_user(db_engine, role="editor"):
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, password_hash, role, privileged_at) "
                "VALUES (:u, :h, :r, now())"
            ),
            {"u": USERNAME, "h": OLD, "r": role},
        )


def account(db_engine):
    with db_engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT password_hash, must_change_password, mfa_enroll_until "
                    "FROM users WHERE username = :u"
                ),
                {"u": USERNAME},
            )
            .mappings()
            .one()
        )


ARGV = ["--username", USERNAME, "--break-glass"]


def test_real_run_resets_the_account_and_leaves_no_version(db_engine, seed, reader):
    make_user(db_engine)
    seed()
    seed()  # two versions: all of them must go
    before = datetime.now(UTC)

    assert breakglass.main(ARGV) == 0

    row = account(db_engine)
    assert verify_password(row["password_hash"], SEEDED)
    assert row["must_change_password"] is True
    window = row["mfa_enroll_until"] - before
    assert timedelta(hours=23, minutes=59) < window < timedelta(hours=24, minutes=1)
    assert_no_version_left(reader)


def test_real_run_refuses_an_account_that_never_was_privileged(
    db_engine, seed, reader, capsys
):
    with db_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (username, password_hash) VALUES (:u, :h)"),
            {"u": USERNAME, "h": OLD},
        )
    seed()

    assert breakglass.main(ARGV) == breakglass.EXIT_REFUSED

    assert account(db_engine)["password_hash"] == OLD
    assert stored(reader) == {"username": USERNAME, "password": SEEDED}
    assert capsys.readouterr().err.strip() == breakglass.REFUSED


def test_real_run_refuses_a_secret_seeded_for_another_account(
    db_engine, seed, reader, capsys
):
    make_user(db_engine)
    seed(username="somebody-else")

    assert breakglass.main(ARGV) == breakglass.EXIT_FAILED

    assert account(db_engine)["password_hash"] == OLD
    assert stored(reader) == {"username": "somebody-else", "password": SEEDED}
    assert capsys.readouterr().err.strip() == breakglass.WRONG_TARGET


def test_real_invalid_secret_is_left_untouched(db_engine, seed, reader):
    make_user(db_engine)
    seed(password=SHORT)

    assert breakglass.main(ARGV) == breakglass.EXIT_FAILED

    assert account(db_engine)["password_hash"] == OLD
    assert stored(reader)["password"] == SHORT


def test_real_openbao_without_the_secret_is_a_fixed_error(
    db_engine, env, breakglass_files, capsys
):
    make_user(db_engine)

    assert breakglass.main(ARGV) == breakglass.EXIT_FAILED

    assert capsys.readouterr().err.strip() == breakglass.INPUT_UNAVAILABLE
    assert account(db_engine)["password_hash"] == OLD


def test_real_login_with_a_wrong_secret_id_is_a_fixed_error(
    db_engine, env, monkeypatch, tmp_path, capsys
):
    wrong = tmp_path / "secret-id"
    wrong.write_text("wrong-secret-id")
    monkeypatch.setenv("GATEWAY_BREAKGLASS_SECRET_ID_FILE", str(wrong))

    assert breakglass.main(ARGV) == breakglass.EXIT_FAILED

    err = capsys.readouterr().err
    assert err.strip() == breakglass.INPUT_UNAVAILABLE
    assert "wrong-secret-id" not in err
