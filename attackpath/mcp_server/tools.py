"""Tool implementations and schemas for the AttackPath MCP server.

Exposes bounded, grounded security tools for discovering attack paths,
explaining paths with graph facts and deterministic risk scores,
simulating remediation with clone-isolated verification, and inspecting graph topology.
"""

import json
import logging
from typing import Any, List, Optional, Union
import mcp.types as types
from pydantic import BaseModel, Field
from attackpath.database.connection import FalkorDBConnectionError
from attackpath.domain.entities import BaseEntityNode
from attackpath.domain.path import AttackPath, EdgeRevocation, GraphEdge
from attackpath.domain.service_models import PathEvidence, PathRiskAssessment
from attackpath.mcp_server.dependencies import (
    get_discovery_service,
    get_evidence_service,
    get_remediation_service,
    get_repository,
    get_risk_service,
    get_settings,
)

logger = logging.getLogger("attackpath.mcp_server.tools")

DISCLAIMER_TEXT = (
    "Analyst prioritization heuristic only. Not a statistical probability of compromise."
)


# ==============================================================================
# Structured Output Envelopes
# ==============================================================================


class ToolErrorDetail(BaseModel):
  """Machine-readable and sanitized human-readable error payload."""

  code: str = Field(..., description="Stable machine-readable error code")
  message: str = Field(..., description="Sanitized human-readable error message")
  details: Optional[Any] = Field(
      default=None, description="Optional safe diagnostic context"
  )


class ToolErrorEnvelope(BaseModel):
  """Standard error envelope returned when a tool operation fails."""

  status: str = Field(default="error", description="Failure state indicator")
  is_synthetic: bool = Field(default=True, description="Synthetic data flag")
  error: ToolErrorDetail = Field(..., description="Structured error details")


class DiscoveryResponseEnvelope(BaseModel):
  """Structured outcome of attack-path discovery."""

  status: str = Field(..., description="Outcome status (PATHS_DISCOVERED, TARGET_UNREACHABLE)")
  source_id: str = Field(..., description="Source entity ID")
  target_id: str = Field(..., description="Target entity ID")
  total_paths_found: int = Field(default=0, ge=0, description="Total count of discovered paths")
  max_depth_applied: int = Field(default=6, ge=1, le=6, description="Traversal depth limit applied")
  paths: List[AttackPath] = Field(default_factory=list, description="Discovered directed attack paths")
  is_synthetic: bool = Field(default=True, description="Indicates synthetic provenance of data")
  details: Optional[str] = Field(default=None, description="Diagnostic message or context")


class PathExplanationDetail(BaseModel):
  """Consolidated investigation package for a single discovered attack path."""

  path: AttackPath = Field(..., description="Topology of the attack path")
  evidence: PathEvidence = Field(..., description="Fact-grounded evidence and provenance")
  risk_assessment: PathRiskAssessment = Field(..., description="Deterministic risk heuristic assessment")


class ExplanationResponseEnvelope(BaseModel):
  """Structured outcome of attack-path investigation and explanation."""

  status: str = Field(..., description="Outcome status (PATHS_DISCOVERED, TARGET_UNREACHABLE)")
  source_id: str = Field(..., description="Source entity ID")
  target_id: str = Field(..., description="Target entity ID")
  total_paths_found: int = Field(default=0, ge=0, description="Total count of analyzed paths")
  paths: List[PathExplanationDetail] = Field(default_factory=list, description="Analyzed path explanations")
  is_synthetic: bool = Field(default=True, description="Indicates synthetic provenance of data")
  disclaimer: str = Field(
      default=DISCLAIMER_TEXT,
      description="Analytical heuristic disclaimer",
  )
  details: Optional[str] = Field(default=None, description="Diagnostic summary")


class RemediationResponseEnvelope(BaseModel):
  """Structured outcome of an isolated remediation simulation and verification."""

  status: str = Field(..., description="Verification status (VERIFIED_SEVERED, VERIFIED_UNAFFECTED, CLEANUP_WARNING)")
  success: bool = Field(..., description="True if simulation succeeded and baseline remained intact")
  baseline_intact: bool = Field(..., description="True if baseline node and edge counts remained unchanged")
  original_path_severed: bool = Field(..., description="True if the investigated path containing the edge was severed")
  target_still_reachable: bool = Field(..., description="True if alternative routes remain to target")
  before_paths_count: int = Field(default=0, ge=0, description="Path count prior to remediation")
  residual_paths_count: int = Field(default=0, ge=0, description="Path count after remediation")
  residual_paths: List[AttackPath] = Field(default_factory=list, description="Residual paths remaining in clone")
  clone_name: str = Field(..., description="Temporary clone graph key used during simulation")
  clone_cleaned_up: bool = Field(..., description="True if temporary clone was deleted")
  warnings: List[str] = Field(default_factory=list, description="Diagnostic warnings or cleanup notices")
  details: str = Field(..., description="Detailed explanation of verification outcome")
  is_synthetic: bool = Field(default=True, description="Indicates synthetic provenance of data")


class TopologyResponseEnvelope(BaseModel):
  """Current graph topology consisting of nodes, relationships, and metadata."""

  graph_name: str = Field(..., description="Baseline graph name")
  total_nodes: int = Field(default=0, ge=0, description="Total node count in graph")
  total_edges: int = Field(default=0, ge=0, description="Total edge count in graph")
  nodes: List[BaseEntityNode] = Field(default_factory=list, description="Graph nodes with properties")
  edges: List[GraphEdge] = Field(default_factory=list, description="Directed relationships with attributes")
  is_synthetic: bool = Field(default=True, description="Indicates synthetic provenance of data")


def _make_error_result(
    code: str,
    message: str,
    details: Optional[Any] = None,
) -> types.CallToolResult:
  """Builds a structured error result complying with MCP SDK protocol conventions."""
  err_env = ToolErrorEnvelope(
      error=ToolErrorDetail(code=code, message=message, details=details)
  )
  return types.CallToolResult(
      content=[
          types.TextContent(
              type="text",
              text=err_env.model_dump_json(indent=2),
          )
      ],
      structured_content=err_env.model_dump(),
      isError=True,
  )


# ==============================================================================
# Tool Handlers
# ==============================================================================


def discover_attack_paths(
    source_id: str,
    target_id: str,
    max_depth: int = 6,
    limit: int = 10,
) -> DiscoveryResponseEnvelope:
  """Discovers directed, multi-hop attack paths connecting a source identity to a destination data asset in the graph.

  Inputs:
  - source_id (string, required): Non-empty unique identifier of the source entity (e.g. 'usr_jdoe').
  - target_id (string, required): Non-empty unique identifier of the target data asset (e.g. 'db_customer_vault').
  - max_depth (integer, optional, default=6): Maximum traversal hop count, bounded between 1 and 6.
  - limit (integer, optional, default=10): Maximum number of paths to return, bounded between 1 and 50.

  Operational characteristics:
  - READ-ONLY: Does not modify the graph database or any infrastructure.
  - SYNTHETIC DATA: Operates on synthetic cybersecurity benchmark data.
  - Distinguishes missing entities (status: 'ENTITY_NOT_FOUND') from reachable/unreachable entities (status: 'PATHS_DISCOVERED' or 'TARGET_UNREACHABLE').
  - Never fabricates paths; returns an explicit empty list when target is unreachable within max_depth.
  """
  clean_src = (source_id or "").strip()
  clean_tgt = (target_id or "").strip()

  if not clean_src or not clean_tgt:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="source_id and target_id must be non-empty strings.",
    )

  if not isinstance(max_depth, int) or max_depth < 1 or max_depth > 6:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="max_depth must be an integer between 1 and 6.",
    )

  if not isinstance(limit, int) or limit < 1 or limit > 50:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="limit must be an integer between 1 and 50.",
    )

  try:
    disc_svc = get_discovery_service()
    disc_res = disc_svc.discover_paths(
        source_id=clean_src,
        target_id=clean_tgt,
        max_depth=max_depth,
        limit=limit,
    )

    if disc_res.status == "INVALID_REQUEST":
      return _make_error_result(
          code="INVALID_REQUEST",
          message=disc_res.details or "Invalid parameters for path discovery.",
      )

    if disc_res.status == "ENTITY_NOT_FOUND":
      return _make_error_result(
          code="ENTITY_NOT_FOUND",
          message=disc_res.details or "One or more requested entities do not exist in the graph.",
      )

    if disc_res.status == "DATABASE_ERROR":
      return _make_error_result(
          code="DATABASE_UNAVAILABLE",
          message="Graph database query failure during path discovery.",
      )

    if disc_res.status == "TARGET_UNREACHABLE":
      return DiscoveryResponseEnvelope(
          status="TARGET_UNREACHABLE",
          source_id=clean_src,
          target_id=clean_tgt,
          total_paths_found=0,
          max_depth_applied=max_depth,
          paths=[],
          is_synthetic=True,
          details=disc_res.details,
      )

    return DiscoveryResponseEnvelope(
        status="PATHS_DISCOVERED",
        source_id=clean_src,
        target_id=clean_tgt,
        total_paths_found=len(disc_res.paths),
        max_depth_applied=max_depth,
        paths=disc_res.paths,
        is_synthetic=disc_res.is_synthetic,
        details=disc_res.details,
    )

  except (FalkorDBConnectionError, ConnectionError) as exc:
    logger.error("Database connection failure in discover_attack_paths: %s", exc)
    return _make_error_result(
        code="DATABASE_UNAVAILABLE",
        message="Graph database service is currently unreachable.",
    )
  except Exception as exc:
    logger.exception("Unexpected error in discover_attack_paths: %s", exc)
    return _make_error_result(
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected error occurred during path discovery.",
    )


def explain_attack_path(
    source_id: str,
    target_id: str,
    max_depth: int = 6,
    limit: int = 10,
) -> ExplanationResponseEnvelope:
  """Generates a comprehensive, evidence-backed security explanation for discovered attack paths between two entities.

  Inputs:
  - source_id (string, required): Non-empty unique identifier of the source entity (e.g. 'usr_jdoe').
  - target_id (string, required): Non-empty unique identifier of the target data asset (e.g. 'db_customer_vault').
  - max_depth (integer, optional, default=6): Maximum traversal hop count (1 to 6).
  - limit (integer, optional, default=10): Maximum number of paths to explain (1 to 50).

  Operational characteristics:
  - READ-ONLY: Does not mutate the graph or production systems.
  - GROUNDED EVIDENCE: Returns structured node and edge evidence categorized by provenance (OBSERVED_GRAPH_FACT, DERIVED_INTERPRETATION, SYNTHETIC_DATA_METADATA).
  - DETERMINISTIC RISK SCORING: Evaluates deterministic rule weights to calculate an explainable risk score (0-100) and risk tier (CRITICAL, PRIORITY, MONITOR, INFORMATIONAL).
  - DISCLAIMER: Risk scores are analyst prioritization heuristics only, NOT statistical probabilities of compromise or ML predictions.
  - SYNTHETIC DATA: Clearly identified as synthetic demonstration infrastructure.
  """
  clean_src = (source_id or "").strip()
  clean_tgt = (target_id or "").strip()

  if not clean_src or not clean_tgt:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="source_id and target_id must be non-empty strings.",
    )

  if not isinstance(max_depth, int) or max_depth < 1 or max_depth > 6:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="max_depth must be an integer between 1 and 6.",
    )

  if not isinstance(limit, int) or limit < 1 or limit > 50:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="limit must be an integer between 1 and 50.",
    )

  try:
    disc_svc = get_discovery_service()
    evidence_svc = get_evidence_service()
    risk_svc = get_risk_service()

    disc_res = disc_svc.discover_paths(
        source_id=clean_src,
        target_id=clean_tgt,
        max_depth=max_depth,
        limit=limit,
    )

    if disc_res.status == "INVALID_REQUEST":
      return _make_error_result(
          code="INVALID_REQUEST",
          message=disc_res.details or "Invalid parameters for path explanation.",
      )

    if disc_res.status == "ENTITY_NOT_FOUND":
      return _make_error_result(
          code="ENTITY_NOT_FOUND",
          message=disc_res.details or "One or more requested entities do not exist in the graph.",
      )

    if disc_res.status == "DATABASE_ERROR":
      return _make_error_result(
          code="DATABASE_UNAVAILABLE",
          message="Graph database query failure during path explanation.",
      )

    if disc_res.status == "TARGET_UNREACHABLE":
      return ExplanationResponseEnvelope(
          status="TARGET_UNREACHABLE",
          source_id=clean_src,
          target_id=clean_tgt,
          total_paths_found=0,
          paths=[],
          is_synthetic=True,
          disclaimer=DISCLAIMER_TEXT,
          details=disc_res.details,
      )

    path_explanations: List[PathExplanationDetail] = []
    for path in disc_res.paths:
      evidence = evidence_svc.generate_path_evidence(path)
      risk = risk_svc.assess_path_risk(path)
      path_explanations.append(
          PathExplanationDetail(
              path=path,
              evidence=evidence,
              risk_assessment=risk,
          )
      )

    is_synthetic = any(p.path.is_synthetic for p in path_explanations) if path_explanations else True

    return ExplanationResponseEnvelope(
        status="PATHS_DISCOVERED",
        source_id=clean_src,
        target_id=clean_tgt,
        total_paths_found=len(path_explanations),
        paths=path_explanations,
        is_synthetic=is_synthetic,
        disclaimer=DISCLAIMER_TEXT,
        details=f"Discovered and analyzed {len(path_explanations)} attack path(s).",
    )

  except (FalkorDBConnectionError, ConnectionError) as exc:
    logger.error("Database connection failure in explain_attack_path: %s", exc)
    return _make_error_result(
        code="DATABASE_UNAVAILABLE",
        message="Graph database service is currently unreachable.",
    )
  except Exception as exc:
    logger.exception("Unexpected error in explain_attack_path: %s", exc)
    return _make_error_result(
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected error occurred during path explanation.",
    )


def simulate_remediation_and_verify(
    source_id: str,
    rel_type: str,
    target_id: str,
    path_source_id: Optional[str] = None,
    path_target_id: Optional[str] = None,
    max_depth: int = 6,
    limit: int = 10,
) -> RemediationResponseEnvelope:
  """Simulates the revocation of a specific directed graph relationship in an isolated temporary clone to verify whether an attack path is severed.

  Inputs:
  - source_id (string, required): Source entity ID of the relationship to revoke (e.g. 'role_order_service').
  - rel_type (string, required): Type of the relationship to revoke (e.g. 'CAN_ACCESS', 'AUTHENTICATES_TO').
  - target_id (string, required): Target entity ID of the relationship to revoke (e.g. 'db_customer_vault').
  - path_source_id (string, optional): Source entity ID of the attack path under investigation (e.g. 'usr_jdoe').
  - path_target_id (string, optional): Target entity ID of the attack path under investigation (e.g. 'db_customer_vault').
  - max_depth (integer, optional, default=6): Traversal depth for rediscovering residual paths (1 to 6).
  - limit (integer, optional, default=10): Limit for rediscovering residual paths (1 to 50).

  Operational characteristics:
  - SIMULATION ONLY: Never modifies the canonical baseline graph or real-world infrastructure (no real IAM or firewall mutations).
  - SYNTHETIC DATA: Operates on synthetic security graph data.
  - ATOMIC ISOLATION: Clones the baseline graph into an ephemeral snapshot ('attackpath_baseline_sim_*'), verifies clone count parity, deletes only the exact matching relationship, rediscovers residual paths, checks signature-based path severance, verifies baseline integrity, and deletes the clone in a finally block.
  - AMBIGUITY SAFEGUARD: Rejects revocation if multiple edges match the specification or if the relationship does not exist.
  - Returns comprehensive verification metrics including baseline integrity, residual path count, and clone cleanup confirmation.
  """
  clean_src = (source_id or "").strip()
  clean_rel = (rel_type or "").strip()
  clean_tgt = (target_id or "").strip()

  if not clean_src or not clean_rel or not clean_tgt:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="source_id, rel_type, and target_id must be non-empty strings.",
    )

  if not isinstance(max_depth, int) or max_depth < 1 or max_depth > 6:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="max_depth must be an integer between 1 and 6.",
    )

  if not isinstance(limit, int) or limit < 1 or limit > 50:
    return _make_error_result(
        code="INVALID_REQUEST",
        message="limit must be an integer between 1 and 50.",
    )

  clean_path_src = path_source_id.strip() if path_source_id else None
  clean_path_tgt = path_target_id.strip() if path_target_id else None

  try:
    remediation_svc = get_remediation_service()
    revocation = EdgeRevocation(
        source_id=clean_src,
        rel_type=clean_rel,
        target_id=clean_tgt,
    )

    result = remediation_svc.simulate_and_verify_remediation(
        revocation=revocation,
        source_id=clean_path_src,
        target_id=clean_path_tgt,
        max_depth=max_depth,
        limit=limit,
    )

    if result.status == "MUTATION_REJECTED":
      detail_lower = result.details.lower()
      if "does not exist" in detail_lower or "not found" in detail_lower:
        return _make_error_result(
            code="NOT_FOUND",
            message=result.details,
        )
      if "ambiguous" in detail_lower or "disambiguation" in detail_lower or any("ambiguous" in w.lower() for w in result.warnings):
        msg = result.details if "ambiguous" in detail_lower else f"Ambiguous relationship: {result.details}"
        return _make_error_result(
            code="CONFLICT",
            message=msg,
        )
      return _make_error_result(
          code="BAD_REQUEST",
          message=result.details,
      )

    if result.status == "VERIFICATION_FAILED":
      return _make_error_result(
          code="VERIFICATION_FAILED",
          message=result.details or "Remediation verification checks failed.",
          details={"warnings": result.warnings},
      )

    return RemediationResponseEnvelope(
        status=result.status,
        success=result.success,
        baseline_intact=result.baseline_intact,
        original_path_severed=result.original_path_severed,
        target_still_reachable=result.target_still_reachable,
        before_paths_count=result.before_paths_count,
        residual_paths_count=result.residual_paths_count,
        residual_paths=result.residual_paths,
        clone_name=result.clone_name,
        clone_cleaned_up=result.clone_cleaned_up,
        warnings=result.warnings,
        details=result.details,
        is_synthetic=True,
    )

  except (FalkorDBConnectionError, ConnectionError) as exc:
    logger.error("Database connection failure in simulate_remediation_and_verify: %s", exc)
    return _make_error_result(
        code="DATABASE_UNAVAILABLE",
        message="Graph database service is currently unreachable.",
    )
  except Exception as exc:
    logger.exception("Unexpected error in simulate_remediation_and_verify: %s", exc)
    return _make_error_result(
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected error occurred during remediation simulation.",
    )


def get_graph_topology() -> TopologyResponseEnvelope:
  """Retrieves the complete topology (nodes, directed relationships, counts, and metadata) of the active baseline graph.

  Inputs: None.

  Operational characteristics:
  - READ-ONLY: Inspects the configured baseline graph key only.
  - SECURITY BOUNDARY: No arbitrary graph key selection is allowed; credentials, passwords, and raw URIs are never exposed.
  - SYNTHETIC DATA: Operates on synthetic demonstration data.
  - Returns all graph nodes with properties, directed edges with attributes, and total counts.
  """
  try:
    settings = get_settings()
    repo = get_repository(settings)
    topology_data = repo.get_topology()

    is_synthetic = True
    if topology_data.get("nodes"):
      is_synthetic = any(n.is_synthetic for n in topology_data["nodes"])

    return TopologyResponseEnvelope(
        graph_name=settings.FALKORDB_BASELINE_GRAPH,
        total_nodes=topology_data["total_nodes"],
        total_edges=topology_data["total_edges"],
        nodes=topology_data["nodes"],
        edges=topology_data["edges"],
        is_synthetic=is_synthetic,
    )

  except (FalkorDBConnectionError, ConnectionError) as exc:
    logger.error("Database connection failure in get_graph_topology: %s", exc)
    return _make_error_result(
        code="DATABASE_UNAVAILABLE",
        message="Graph database service is currently unreachable.",
    )
  except Exception as exc:
    logger.exception("Unexpected error in get_graph_topology: %s", exc)
    return _make_error_result(
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected error occurred retrieving graph topology.",
    )
