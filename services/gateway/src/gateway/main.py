import os

from fastapi import FastAPI


def create_app() -> FastAPI:
    """Build the gateway app.

    The interactive docs and the OpenAPI schema describe every route, so they
    are off unless GATEWAY_DOCS_ENABLED is exactly "true" (development only).
    """
    docs_enabled = os.environ.get("GATEWAY_DOCS_ENABLED") == "true"
    app = FastAPI(
        title="gateway",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Liveness probe: answers without touching any dependency."""
        return {"status": "ok"}

    return app


# The flag is read once, at import time: changing it needs a restart.
app = create_app()
