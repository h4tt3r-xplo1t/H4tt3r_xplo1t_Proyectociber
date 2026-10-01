import pytest

from tests.conftest import ensure_disposable_database

BASE = "postgresql+psycopg://u:p@127.0.0.1:5432/"  # noqa: S105  (fake credentials)


@pytest.mark.parametrize("name", ["gateway_test", "gateway_ci", "x_test"])
def test_test_databases_are_allowed(name):
    ensure_disposable_database(BASE + name)


@pytest.mark.parametrize("name", ["gateway", "gateway_prod", "test_gateway", ""])
def test_other_databases_are_refused(name):
    with pytest.raises(pytest.fail.Exception, match="refusing to run"):
        ensure_disposable_database(BASE + name)
