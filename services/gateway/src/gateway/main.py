import logging
import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from gateway.admin import router as admin_router
from gateway.auth import NO_STORE, ServiceBusy, log_service_busy
from gateway.auth import router as auth_router
from gateway.db import get_engine
from gateway.passwords import HashingBusy
from gateway.transit import TransitError

logger = logging.getLogger("gateway.main")

# Longest the readiness query may run. Connecting is bounded separately by the
# engine's connect_timeout, so a dead database answers 503 in a few seconds.
READY_STATEMENT_TIMEOUT = "2s"


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

    app.include_router(auth_router)
    app.include_router(admin_router)

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # FastAPI's default body echoes the rejected input, which would leak
        # passwords. Return only where and why a field failed.
        errors = [
            {"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]}
            for e in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    busy_body = {"detail": "Service busy; try again later"}

    # Two causes, one answer: clients must not tell them apart, so the cause
    # only goes to the security log.
    @app.exception_handler(HashingBusy)
    async def hashing_busy(request: Request, exc: HashingBusy) -> JSONResponse:
        log_service_busy("hash_saturated")
        return JSONResponse(status_code=503, content=busy_body)

    @app.exception_handler(ServiceBusy)
    async def service_busy(request: Request, exc: ServiceBusy) -> JSONResponse:
        log_service_busy(exc.cause)
        return JSONResponse(status_code=503, content=busy_body)

    # TransitError covers every failed transit call (unreachable, timeout,
    # refused, a ciphertext that does not decrypt), so the cause says "failed",
    # not "unavailable". Its message is fixed and never reaches the log.
    @app.exception_handler(TransitError)
    async def transit_failed(request: Request, exc: TransitError) -> JSONResponse:
        log_service_busy("transit_failed")
        return JSONResponse(status_code=503, content=busy_body)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Liveness probe: answers without touching any dependency."""
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        """Readiness probe: ready only while the database answers a trivial query.

        A failure is one fixed 503 and one fixed log line: the exception text can
        carry the host, the user or the URL, so it is never logged or returned.
        """
        try:
            with get_engine().connect() as conn:
                conn.execute(
                    text(f"SET LOCAL statement_timeout = '{READY_STATEMENT_TIMEOUT}'")
                )
                conn.execute(text("SELECT 1"))
        except Exception:
            logger.warning("event=readyz_failed cause=database_unavailable")
            return JSONResponse(
                status_code=503, content={"status": "unavailable"}, headers=NO_STORE
            )
        return JSONResponse(content={"status": "ready"}, headers=NO_STORE)

    return app


# The flag is read once, at import time: changing it needs a restart.
app = create_app()
