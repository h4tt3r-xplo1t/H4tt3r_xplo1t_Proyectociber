import os


def get_database_url() -> str:
    """Return the database URL from GATEWAY_DATABASE_URL.

    There is no default on purpose: a missing value must stop the service
    instead of silently connecting somewhere else.
    """
    url = os.environ.get("GATEWAY_DATABASE_URL")
    if not url:
        raise RuntimeError("GATEWAY_DATABASE_URL is not set")
    return url


def _required(name: str) -> str:
    # Same rule as the database URL: no default, fixed message.
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set")
    return value


def get_jwt_issuer() -> str:
    """Value of the `iss` claim the gateway issues and requires."""
    return _required("GATEWAY_JWT_ISSUER")


def get_jwt_audience() -> str:
    """Value of the `aud` claim the gateway issues and requires."""
    return _required("GATEWAY_JWT_AUDIENCE")


def get_allowed_origin() -> str:
    """The single origin (scheme://host[:port]) of the SPA, for the Origin check."""
    return _required("GATEWAY_ALLOWED_ORIGIN")
