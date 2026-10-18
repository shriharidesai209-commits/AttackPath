"""FastAPI application factory, lifespan lifecycle management, and error handling."""

from contextlib import asynccontextmanager
import logging
from typing import Any
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from attackpath.api.routes.graph import router as graph_router
from attackpath.api.routes.health import router as health_router
from attackpath.api.routes.investigate import router as investigate_router
from attackpath.api.routes.paths import router as paths_router
from attackpath.api.routes.remediate import router as remediate_router
from attackpath.config import get_settings
from attackpath.database.connection import FalkorDBConnectionError

logger = logging.getLogger("attackpath.api")


def _status_code_to_error_code(status_code: int) -> str:
  """Maps standard HTTP status codes to machine-readable error codes."""
  mapping = {
      status.HTTP_400_BAD_REQUEST: "BAD_REQUEST",
      status.HTTP_401_UNAUTHORIZED: "UNAUTHORIZED",
      status.HTTP_403_FORBIDDEN: "FORBIDDEN",
      status.HTTP_404_NOT_FOUND: "NOT_FOUND",
      status.HTTP_409_CONFLICT: "CONFLICT",
      422: "VALIDATION_ERROR",
      status.HTTP_500_INTERNAL_SERVER_ERROR: "INTERNAL_SERVER_ERROR",
      status.HTTP_502_BAD_GATEWAY: "BAD_GATEWAY",
      status.HTTP_503_SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
  }
  return mapping.get(status_code, "ERROR")


@asynccontextmanager
async def lifespan(app: FastAPI):
  """FastAPI lifespan managing application startup and graceful shutdown."""
  settings = get_settings()
  logger.info(
      "Starting AttackPath API backend (env=%s, graph=%s)",
      settings.APP_ENV,
      settings.FALKORDB_BASELINE_GRAPH,
  )
  yield
  logger.info("Shutting down AttackPath API backend")


def create_app() -> FastAPI:
  """Application factory configuring routes, lifecycle, and strict security exception handlers."""
  settings = get_settings()

  application = FastAPI(
      title="AttackPath Backend API",
      description="Graph-powered attack-path discovery, evidence explanation, and remediation simulation API.",
      version="0.1.0",
      lifespan=lifespan,
      docs_url="/docs",
      redoc_url="/redoc",
      openapi_url="/openapi.json",
  )

  # CORS configuration for cross-origin frontend requests
  application.add_middleware(
      CORSMiddleware,
      allow_origins=["*"],
      allow_credentials=True,
      allow_methods=["*"],
      allow_headers=["*"],
  )

  # Exception Handlers
  @application.exception_handler(HTTPException)
  async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    error_code = _status_code_to_error_code(exc.status_code)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": error_code,
                "message": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
                "details": exc.detail if not isinstance(exc.detail, str) else None,
            }
        },
    )

  @application.exception_handler(RequestValidationError)
  async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request schema or parameters.",
                "details": exc.errors(),
            }
        },
    )

  @application.exception_handler(FalkorDBConnectionError)
  async def falkordb_connection_error_handler(request: Request, exc: FalkorDBConnectionError) -> JSONResponse:
    # Sanitized message; never expose credentials or internal connection strings
    logger.error("FalkorDB database connectivity failure: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": {
                "code": "DATABASE_UNAVAILABLE",
                "message": "Graph database service is currently unreachable.",
                "details": None,
            }
        },
    )

  @application.exception_handler(ConnectionError)
  async def generic_connection_error_handler(request: Request, exc: ConnectionError) -> JSONResponse:
    logger.error("Network connection error encountered: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": {
                "code": "DATABASE_UNAVAILABLE",
                "message": "Graph database service is currently unreachable.",
                "details": None,
            }
        },
    )

  @application.exception_handler(Exception)
  async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled internal exception in API handler: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected internal server error occurred.",
                "details": None,
            }
        },
    )

  # Register Routers
  # Health endpoints at root
  application.include_router(health_router)

  # Core API v1 endpoints
  api_v1_prefix = "/api/v1"
  application.include_router(graph_router, prefix=api_v1_prefix)
  application.include_router(paths_router, prefix=api_v1_prefix)
  application.include_router(investigate_router, prefix=api_v1_prefix)
  application.include_router(remediate_router, prefix=api_v1_prefix)

  return application


# Global application instance for uvicorn
app = create_app()
