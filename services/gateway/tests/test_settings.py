import pytest

from gateway import settings

REQUIRED = {
    "GATEWAY_JWT_ISSUER": settings.get_jwt_issuer,
    "GATEWAY_JWT_AUDIENCE": settings.get_jwt_audience,
    "GATEWAY_ALLOWED_ORIGIN": settings.get_allowed_origin,
}


@pytest.mark.parametrize("name", REQUIRED)
def test_value_is_read_from_the_environment(name, monkeypatch):
    monkeypatch.setenv(name, "from-test")

    assert REQUIRED[name]() == "from-test"


@pytest.mark.parametrize("name", REQUIRED)
@pytest.mark.parametrize("value", [None, ""])
def test_missing_or_empty_value_fails_closed(name, value, monkeypatch):
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match=f"^{name} is not set$"):
        REQUIRED[name]()


def test_the_test_environment_provides_fake_values_without_the_shell():
    assert settings.get_jwt_issuer() == "h4tt3r-gateway-test"
    assert settings.get_jwt_audience() == "h4tt3r-web-test"
    assert settings.get_allowed_origin() == "https://testserver"
