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
