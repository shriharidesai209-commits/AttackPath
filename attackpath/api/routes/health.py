"""Health and readiness check endpoints."""

import logging
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from attackpath.api.dependencies import get_falkordb_client, get_settings
from attackpath.api.schemas import HealthResponse, ReadyResponse
from attackpath.config import Settings
from attackpath.database.connection import ping_falkordb

logger = logging.getLogger("attackpath.api.routes.health")

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
    description="Returns process liveness state without querying external dependencies.",
)
def get_liveness(settings: Settings = Depends(get_settings)) -> HealthResponse:
  """Liveness check indicating process is running."""
  return HealthResponse(
      status="ok",
      app="AttackPath",
      environment=settings.APP_ENV,
  )


@router.get(
    "/health/ready",
    response_model=ReadyResponse,
    responses={
        503: {"description": "Graph database dependency is not reachable"},
    },
    summary="Readiness probe",
    description="Verifies connectivity to the configured FalkorDB graph database instance.",
)
def get_readiness(
    settings: Settings = Depends(get_settings),
    client: Any = Depends(get_falkordb_client),
) -> ReadyResponse:
  """Readiness check verifying active connectivity to FalkorDB."""
  try:
    is_responsive = ping_falkordb(client)
    if not is_responsive:
      logger.warning("FalkorDB ping returned false for readiness check")
      raise HTTPException(
          status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
          detail="Graph database service is not responsive.",
      )
  except HTTPException:
    raise
  except Exception as exc:
    logger.error("Error pinging FalkorDB during readiness check: %s", exc)
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Graph database service is not reachable.",
    ) from exc

  return ReadyResponse(
      status="ready",
      database="connected",
      graph=settings.FALKORDB_BASELINE_GRAPH,
  )
