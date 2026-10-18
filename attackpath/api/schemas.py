"""Pydantic schemas and API contracts for AttackPath FastAPI routes."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from attackpath.domain.entities import BaseEntityNode
from attackpath.domain.path import AttackPath, EdgeRevocation, GraphEdge
from attackpath.domain.service_models import (
    PathEvidence,
    PathRiskAssessment,
)


# Standardized Error Schemas
class ErrorDetail(BaseModel):
  """Structured machine-readable and human-readable error payload."""

  code: str = Field(..., description="Machine-readable error classification code")
  message: str = Field(..., description="Human-readable explanation of error")
  details: Optional[Any] = Field(default=None, description="Optional diagnostic details or validation errors")


class ErrorResponse(BaseModel):
  """Canonical error response format returned for all error status codes."""

  error: ErrorDetail


# Health & Readiness Schemas
class HealthResponse(BaseModel):
  """Application process liveness information."""

  status: str = Field(default="ok", description="Process liveness state")
  app: str = Field(default="AttackPath", description="Application service name")
  environment: str = Field(..., description="Current deployment environment")


class ReadyResponse(BaseModel):
  """Database connection and subsystem readiness information."""

  status: str = Field(default="ready", description="Subsystem readiness state")
  database: str = Field(default="connected", description="FalkorDB connection state")
  graph: str = Field(..., description="Active canonical graph key")


# Graph Management Schemas
class SeedRequest(BaseModel):
  """Request specification for synthetic scenario graph seeding."""

  clean_first: bool = Field(
      default=False,
      description="Whether to clear graph before seeding. Defaults to False (safe idempotent MERGE).",
  )


class SeedResponse(BaseModel):
  """Summary outcome of graph seeding execution."""

  status: str = Field(default="success")
  graph_name: str
  nodes_created: int
  relationships_created: int
  total_nodes: int
  total_edges: int
  is_synthetic: bool = Field(default=True)
  message: str


class TopologyResponse(BaseModel):
  """Current graph topology consisting of nodes, directed relationships, and counts."""

  graph_name: str
  total_nodes: int
  total_edges: int
  nodes: List[BaseEntityNode]
  edges: List[GraphEdge]
  is_synthetic: bool = Field(default=True)


# Investigation Schemas
class InvestigationRequest(BaseModel):
  """Request to discover, extract evidence, and prioritize risk for routes between endpoints."""

  source_id: str = Field(..., min_length=1, max_length=128, description="Source identity entity ID")
  target_id: str = Field(..., min_length=1, max_length=128, description="Destination target asset ID")
  max_depth: int = Field(default=6, ge=1, le=6, description="Maximum traversal depth (capped at 6)")
  limit: int = Field(default=10, ge=1, le=50, description="Maximum paths to discover")


class PathInvestigationDetail(BaseModel):
  """Consolidated investigation package for a single discovered attack path."""

  path: AttackPath
  evidence: PathEvidence
  risk_assessment: PathRiskAssessment


class InvestigationResponse(BaseModel):
  """Complete investigation result across all discovered paths between requested endpoints."""

  status: str = Field(..., description="High-level investigation outcome status")
  source_id: str
  target_id: str
  total_paths_found: int
  paths: List[PathInvestigationDetail] = Field(default_factory=list)
  is_synthetic: bool = Field(default=True)
  disclaimer: str = Field(
      default="Analyst prioritization heuristic only. Not a statistical probability of compromise."
  )
  details: Optional[str] = None


# Remediation Schemas
class RemediationSimulationRequest(BaseModel):
  """Request to simulate revoking a relationship on a temporary graph clone and verify route impact."""

  revocation: EdgeRevocation = Field(..., description="The exact directed relationship to simulate revoking")
  additional_revocations: Optional[List[EdgeRevocation]] = Field(
      default=None,
      description="Optional additional relationships to revoke in compound simulation",
  )
  source_id: Optional[str] = Field(default=None, description="Source entity ID of the route under investigation")
  target_id: Optional[str] = Field(default=None, description="Target entity ID of the route under investigation")
  max_depth: int = Field(default=6, ge=1, le=6, description="Maximum traversal depth for residual path verification")
  limit: int = Field(default=10, ge=1, le=50, description="Maximum residual paths to return")
