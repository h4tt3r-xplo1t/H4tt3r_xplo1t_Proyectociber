import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from gateway.auth import ServiceBusy, log_service_busy
from gateway.auth import router as auth_router
from gateway.passwords import HashingBusy


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

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Liveness probe: answers without touching any dependency."""
        return {"status": "ok"}

    return app


# The flag is read once, at import time: changing it needs a restart.
app = create_app()
