from fastapi import FastAPI

app = FastAPI(title="gateway")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe: answers without touching any dependency."""
    return {"status": "ok"}
