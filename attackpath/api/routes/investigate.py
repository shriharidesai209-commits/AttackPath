"""Attack-path investigation and explanation endpoints."""

import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from attackpath.api.dependencies import (
    get_discovery_service,
    get_evidence_service,
    get_risk_service,
)
from attackpath.api.schemas import (
    InvestigationRequest,
    InvestigationResponse,
    PathInvestigationDetail,
)
from attackpath.services.discovery_service import DiscoveryService
from attackpath.services.evidence_service import EvidenceService
from attackpath.services.risk_service import RiskPrioritizationService

logger = logging.getLogger("attackpath.api.routes.investigate")

router = APIRouter(prefix="/investigate", tags=["Investigation"])


@router.post(
    "/explain",
    response_model=InvestigationResponse,
    responses={
        400: {"description": "Invalid input parameters"},
        404: {"description": "Source or target entity not found in graph"},
        503: {"description": "Database query failure"},
    },
    summary="Investigate and explain attack paths",
    description="Discovers paths, extracts fact-grounded evidence, and evaluates deterministic risk heuristics.",
)
def investigate_and_explain_paths(
    req: InvestigationRequest,
    discovery_svc: DiscoveryService = Depends(get_discovery_service),
    evidence_svc: EvidenceService = Depends(get_evidence_service),
    risk_svc: RiskPrioritizationService = Depends(get_risk_service),
) -> InvestigationResponse:
  """Executes discovery, evidence generation, and risk prioritization in a single unified operation."""
  logger.info(
      "Investigating attack paths from '%s' to '%s' (max_depth=%d)",
      req.source_id,
      req.target_id,
      req.max_depth,
  )

  # 1. Discover paths
  disc_result = discovery_svc.discover_paths(
      source_id=req.source_id,
      target_id=req.target_id,
      max_depth=req.max_depth,
      limit=req.limit,
  )

  if disc_result.status == "INVALID_REQUEST":
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=disc_result.details or "Invalid parameters for investigation.",
    )

  if disc_result.status == "ENTITY_NOT_FOUND":
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=disc_result.details or "One or more investigation endpoints not found in graph.",
    )

  if disc_result.status == "DATABASE_ERROR":
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Graph database query failure during path investigation.",
    )

  # If target is unreachable, return empty investigation payload with status
  if disc_result.status == "TARGET_UNREACHABLE":
    return InvestigationResponse(
        status="TARGET_UNREACHABLE",
        source_id=req.source_id,
        target_id=req.target_id,
        total_paths_found=0,
        paths=[],
        is_synthetic=True,
        details=disc_result.details,
    )

  # 2. Enrich each discovered path with evidence and risk assessment
  path_details: List[PathInvestigationDetail] = []
  for path in disc_result.paths:
    evidence = evidence_svc.generate_path_evidence(path)
    risk_assessment = risk_svc.assess_path_risk(path)
    path_details.append(
        PathInvestigationDetail(
            path=path,
            evidence=evidence,
            risk_assessment=risk_assessment,
        )
    )

  is_synthetic = any(p.path.is_synthetic for p in path_details) if path_details else True

  return InvestigationResponse(
      status="PATHS_DISCOVERED",
      source_id=req.source_id,
      target_id=req.target_id,
      total_paths_found=len(path_details),
      paths=path_details,
      is_synthetic=is_synthetic,
      details=f"Discovered and analyzed {len(path_details)} attack path(s).",
  )
