"""Graph management endpoints: synthetic seeding and topology inspection."""

import logging
from typing import Any
from fastapi import APIRouter, Depends, status
from attackpath.api.dependencies import get_repository, get_settings
from attackpath.api.schemas import SeedRequest, SeedResponse, TopologyResponse
from attackpath.config import Settings
from attackpath.database.seeder import seed_synthetic_scenario

logger = logging.getLogger("attackpath.api.routes.graph")

router = APIRouter(prefix="/graph", tags=["Graph"])


@router.post(
    "/seed",
    response_model=SeedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Seed synthetic demonstration scenario",
    description="Seeds the canonical 11-node, 11-relationship synthetic topology into the baseline graph.",
)
def seed_graph(
    req: SeedRequest = SeedRequest(),
    repo: Any = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> SeedResponse:
  """Idempotently seeds the synthetic benchmark scenario into the configured baseline graph."""
  logger.info(
      "Seeding synthetic scenario on graph '%s' (clean_first=%s)",
      settings.FALKORDB_BASELINE_GRAPH,
      req.clean_first,
  )
  if hasattr(repo, "seed_synthetic_scenario") and callable(getattr(repo, "seed_synthetic_scenario")):
    summary = repo.seed_synthetic_scenario(clean_first=req.clean_first)
  else:
    summary = seed_synthetic_scenario(repository=repo, clean_first=req.clean_first)

  return SeedResponse(
      status="success",
      graph_name=settings.FALKORDB_BASELINE_GRAPH,
      nodes_created=summary["nodes_created"],
      relationships_created=summary["relationships_created"],
      total_nodes=summary["total_nodes"],
      total_edges=summary["total_edges"],
      is_synthetic=True,
      message=f"Seeded {summary['nodes_created']} nodes and {summary['relationships_created']} relationships.",
  )


@router.get(
    "/topology",
    response_model=TopologyResponse,
    summary="Retrieve current graph topology",
    description="Returns all nodes, relationships, and summary counts from the configured baseline graph.",
)
def get_graph_topology(
    repo: Any = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> TopologyResponse:
  """Retrieves the full topology of the current baseline graph."""
  topology_data = repo.get_topology()

  is_synthetic = True
  if topology_data["nodes"]:
    is_synthetic = any(n.is_synthetic for n in topology_data["nodes"])

  return TopologyResponse(
      graph_name=settings.FALKORDB_BASELINE_GRAPH,
      total_nodes=topology_data["total_nodes"],
      total_edges=topology_data["total_edges"],
      nodes=topology_data["nodes"],
      edges=topology_data["edges"],
      is_synthetic=is_synthetic,
  )
