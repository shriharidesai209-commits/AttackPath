"""Remediation simulation and verification endpoints."""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from attackpath.api.dependencies import get_remediation_service
from attackpath.api.schemas import RemediationSimulationRequest
from attackpath.domain.service_models import RemediationVerificationResult
from attackpath.services.remediation_service import RemediationService

logger = logging.getLogger("attackpath.api.routes.remediate")

router = APIRouter(prefix="/remediate", tags=["Remediation"])


@router.post(
    "/simulate-and-verify",
    response_model=RemediationVerificationResult,
    responses={
        400: {"description": "Invalid relationship revocation specification"},
        404: {"description": "Target relationship not found in graph"},
        409: {"description": "Ambiguous relationship match requiring disambiguation"},
        500: {"description": "Verification or baseline integrity check failure"},
    },
    summary="Simulate edge revocation and verify route impact",
    description="Atomically clones the graph, revokes the exact directed relationship, verifies residual paths, checks baseline integrity, and cleans up the temporary clone.",
)
def simulate_and_verify_remediation_endpoint(
    req: RemediationSimulationRequest,
    remediation_svc: RemediationService = Depends(get_remediation_service),
) -> RemediationVerificationResult:
  """Executes isolated remediation simulation and verification on a temporary graph clone."""
  logger.info(
      "Simulating revocation of (%s)-[%s]->(%s)",
      req.revocation.source_id,
      req.revocation.rel_type,
      req.revocation.target_id,
  )

  result = remediation_svc.simulate_and_verify_remediation(
      revocation=req.revocation,
      additional_revocations=req.additional_revocations,
      source_id=req.source_id,
      target_id=req.target_id,
      max_depth=req.max_depth,
      limit=req.limit,
  )

  if result.status == "MUTATION_REJECTED":
    # Disambiguate not found vs ambiguous vs bad request
    if "does not exist" in result.details.lower():
      raise HTTPException(
          status_code=status.HTTP_404_NOT_FOUND,
          detail=result.details,
      )
    if "ambiguous" in result.details.lower() or any("ambiguous" in w.lower() for w in result.warnings):
      msg = result.details if "ambiguous" in result.details.lower() else f"Ambiguous relationship: {result.details}"
      raise HTTPException(
          status_code=status.HTTP_409_CONFLICT,
          detail=msg,
      )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=result.details,
    )

  if result.status == "VERIFICATION_FAILED":
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=result.details or "Remediation verification checks failed.",
    )

  return result
