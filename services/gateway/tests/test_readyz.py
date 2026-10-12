"""GET /readyz: ready only while the database answers; /healthz never asks it."""

import logging

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError

from gateway import main

UNAVAILABLE = {"status": "unavailable"}


def test_readyz_is_ready_when_the_database_answers(client):
    response = client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert response.headers["cache-control"] == "no-store"


def test_readyz_runs_a_bounded_trivial_query(client):
    seen = []
    engine = main.get_engine()

    @event.listens_for(engine, "before_cursor_execute")
    def capture(conn, cursor, statement, parameters, context, executemany):
        seen.append(statement)

    try:
        assert client.get("/readyz").status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", capture)

    assert any("statement_timeout" in statement for statement in seen)
    assert "SELECT 1" in seen


def test_readyz_answers_503_with_a_fixed_body_when_the_database_is_unreachable(
    client, monkeypatch, caplog
):
    # A real connection failure: nothing listens on port 1.
    dead = create_engine(
        "postgresql+psycopg://svc:hunter2-not-a-secret@127.0.0.1:1/nowhere",
        connect_args={"connect_timeout": 1},
        hide_parameters=True,
    )
    monkeypatch.setattr(main, "get_engine", lambda: dead)
    caplog.set_level(logging.DEBUG)

    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == UNAVAILABLE
    assert response.headers["cache-control"] == "no-store"
    everything = response.text + caplog.text
    for leak in ("hunter2", "svc", "127.0.0.1", "nowhere", "Traceback"):
        assert leak not in everything
    assert "event=readyz_failed" in caplog.text
    dead.dispose()


@pytest.mark.parametrize(
    "error",
    [
        OperationalError("SELECT 1", {}, Exception("host=db user=gateway pw=x")),
        RuntimeError("GATEWAY_DATABASE_URL is not set"),
    ],
    ids=["operational", "not-configured"],
)
def test_readyz_answers_503_for_any_failure_without_the_error_text(
    client, monkeypatch, caplog, error
):
    def failing_engine():
        raise error

    monkeypatch.setattr(main, "get_engine", failing_engine)
    caplog.set_level(logging.DEBUG)

    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == UNAVAILABLE
    assert "GATEWAY_DATABASE_URL" not in response.text + caplog.text
    assert "pw=x" not in response.text + caplog.text


def test_healthz_stays_up_when_the_database_is_down(client, monkeypatch):
    def failing_engine():
        raise RuntimeError("database down")

    monkeypatch.setattr(main, "get_engine", failing_engine)

    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").status_code == 503
