import pytest
from fastapi.testclient import TestClient

from gateway.main import create_app

DOCS_PATHS = ["/docs", "/redoc", "/openapi.json"]


@pytest.mark.parametrize("path", DOCS_PATHS)
def test_docs_are_disabled_by_default(monkeypatch, path):
    monkeypatch.delenv("GATEWAY_DOCS_ENABLED", raising=False)
    client = TestClient(create_app())

    assert client.get(path).status_code == 404


@pytest.mark.parametrize("value", ["", "false", "1", "yes", "TRUE "])
def test_docs_stay_disabled_unless_flag_is_exactly_true(monkeypatch, value):
    monkeypatch.setenv("GATEWAY_DOCS_ENABLED", value)
    client = TestClient(create_app())

    assert client.get("/openapi.json").status_code == 404


@pytest.mark.parametrize("path", DOCS_PATHS)
def test_docs_are_served_when_enabled(monkeypatch, path):
    monkeypatch.setenv("GATEWAY_DOCS_ENABLED", "true")
    client = TestClient(create_app())

    assert client.get(path).status_code == 200
