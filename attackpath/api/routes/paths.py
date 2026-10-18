"""Attack-path discovery endpoints."""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query, status
from attackpath.api.dependencies import get_discovery_service
from attackpath.domain.service_models import DiscoveryResult
from attackpath.services.discovery_service import DiscoveryService

logger = logging.getLogger("attackpath.api.routes.paths")

router = APIRouter(prefix="/paths", tags=["Paths"])


@router.get(
    "/discover",
    response_model=DiscoveryResult,
    responses={
        400: {"description": "Invalid input query parameters"},
        404: {"description": "Source or target entity not found in graph"},
        503: {"description": "Database query failure"},
    },
    summary="Discover attack paths between entities",
    description="Finds bounded directed multi-hop attack paths from source identity to target asset.",
)
def discover_attack_paths(
    source_id: str = Query(..., min_length=1, max_length=128, description="Source entity ID"),
    target_id: str = Query(..., min_length=1, max_length=128, description="Target entity ID"),
    max_depth: int = Query(default=6, ge=1, le=6, description="Maximum traversal depth (hard ceiling 6)"),
    limit: int = Query(default=10, ge=1, le=50, description="Maximum paths to return"),
    discovery_svc: DiscoveryService = Depends(get_discovery_service),
) -> DiscoveryResult:
  """Discovers attack paths using bounded parameterized graph traversal."""
  result = discovery_svc.discover_paths(
      source_id=source_id,
      target_id=target_id,
      max_depth=max_depth,
      limit=limit,
  )

  if result.status == "INVALID_REQUEST":
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=result.details or "Invalid request parameters for path discovery.",
    )

  if result.status == "ENTITY_NOT_FOUND":
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=result.details or "One or more specified entities not found in the graph.",
    )

  if result.status == "DATABASE_ERROR":
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Graph database query failure during path discovery.",
    )

  # Both PATHS_DISCOVERED and TARGET_UNREACHABLE return valid 200 result
  return result
