from fastapi import FastAPI
from app.limiter import limiter
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi

from app.routes import router as auth_router

app = FastAPI(
    title="Enhanced JWT safeguards API",
    version="0.1",
)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    lambda r, e: JSONResponse(status_code=429, content={"detail": "Too many requests"})
)

app.include_router(auth_router)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    for path in openapi_schema["paths"].values():
        for method in path.values():
            method["security"] = [{"BearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
