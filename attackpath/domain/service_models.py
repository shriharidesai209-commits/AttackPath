"""Service-level domain models for discovery, evidence, risk, and remediation."""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator
from attackpath.domain.entities import BaseEntityNode
from attackpath.domain.path import AttackPath, EdgeRevocation, GraphEdge

# Discovery Status
DiscoveryStatus = Literal[
    "PATHS_DISCOVERED",
    "TARGET_UNREACHABLE",
    "ENTITY_NOT_FOUND",
    "INVALID_REQUEST",
    "DATABASE_ERROR",
]


class DiscoveryRequest(BaseModel):
  """Validated input request for attack-path discovery."""

  source_id: str = Field(..., min_length=1, max_length=128, description="Source entity identifier")
  target_id: str = Field(..., min_length=1, max_length=128, description="Target entity identifier")
  max_depth: int = Field(default=6, ge=1, le=6, description="Maximum traversal depth (capped at 6)")
  limit: int = Field(default=10, ge=1, le=50, description="Maximum paths to return")

  @field_validator("source_id", "target_id")
  @classmethod
  def sanitize_ids(cls, v: str) -> str:
    cleaned = v.strip()
    if not cleaned:
      raise ValueError("Entity ID cannot be empty or blank")
    return cleaned


class DiscoveryResult(BaseModel):
  """Structured outcome from attack-path discovery."""

  status: DiscoveryStatus = Field(..., description="High-level discovery outcome status")
  source_id: str = Field(..., description="Requested source ID")
  target_id: str = Field(..., description="Requested target ID")
  paths: List[AttackPath] = Field(default_factory=list, description="Discovered attack paths")
  total_paths_found: int = Field(default=0, ge=0)
  max_depth_applied: int = Field(default=6)
  is_synthetic: bool = Field(default=True, description="Indicates synthetic provenance of the data")
  details: Optional[str] = Field(default=None, description="Diagnostic message or context")


# Evidence Models
FactProvenance = Literal[
    "OBSERVED_GRAPH_FACT",
    "DERIVED_INTERPRETATION",
    "SYNTHETIC_DATA_METADATA",
]


class EvidenceFact(BaseModel):
  """Atomic evidence fact with explicit provenance."""

  statement: str = Field(..., description="Deterministic factual statement")
  provenance: FactProvenance = Field(..., description="Origin of this claim")
  supporting_attributes: Dict[str, Any] = Field(
      default_factory=dict, description="Raw graph attributes supporting this statement"
  )


class NodeEvidence(BaseModel):
  """Evidence representation for a traversed graph node."""

  node_id: str
  label: str
  name: str
  properties: Dict[str, Any] = Field(default_factory=dict)
  observed_facts: List[str] = Field(default_factory=list)


class EdgeEvidence(BaseModel):
  """Evidence representation for a traversed relationship."""

  source_id: str
  target_id: str
  rel_type: str
  properties: Dict[str, Any] = Field(default_factory=dict)
  observed_facts: List[str] = Field(default_factory=list)


class PathEvidence(BaseModel):
  """Complete evidence package explaining an attack path."""

  path_id: str
  hop_count: int
  ordered_nodes: List[NodeEvidence]
  ordered_edges: List[EdgeEvidence]
  route_summary: str
  factual_claims: List[EvidenceFact] = Field(default_factory=list)
  is_synthetic: bool = Field(default=True)


# Risk Prioritization Models
RiskTier = Literal["INFORMATIONAL", "MONITOR", "PRIORITY", "CRITICAL"]


class RuleContribution(BaseModel):
  """Individual rule score adjustment with rationale and graph facts."""

  rule_id: str
  rule_name: str
  score_delta: float
  rationale: str
  graph_facts: Dict[str, Any] = Field(default_factory=dict)


class RiskScoringConfig(BaseModel):
  """Centralized configuration for deterministic risk prioritization."""

  base_score: float = Field(default=10.0, ge=0.0, le=100.0)

  # Rule weights
  weight_compromised_identity: float = Field(default=25.0)
  weight_mfa_disabled: float = Field(default=15.0)
  weight_exposed_credentials: float = Field(default=20.0)
  weight_internet_facing_workload: float = Field(default=15.0)
  weight_privileged_role: float = Field(default=15.0)
  weight_wildcard_permission: float = Field(default=20.0)
  weight_crown_jewel_target: float = Field(default=25.0)
  weight_confidential_target: float = Field(default=10.0)
  weight_unencrypted_target: float = Field(default=15.0)
  weight_short_path_bonus: float = Field(default=5.0)

  # Risk tier cutoffs
  threshold_critical: float = Field(default=75.0)
  threshold_priority: float = Field(default=50.0)
  threshold_monitor: float = Field(default=25.0)


class PathRiskAssessment(BaseModel):
  """Risk prioritization result for an attack path."""

  path_id: str
  score: float = Field(..., ge=0.0, le=100.0, description="Heuristic prioritization score (0-100)")
  risk_tier: RiskTier = Field(..., description="Prioritization tier")
  contributions: List[RuleContribution] = Field(default_factory=list)
  uncertainties: List[str] = Field(
      default_factory=list, description="Uncertainties due to missing or conservative properties"
  )
  is_synthetic: bool = Field(default=True)
  disclaimer: str = Field(
      default="Analyst prioritization heuristic only. Not a statistical probability of compromise."
  )


# Remediation Models
RemediationStatus = Literal[
    "VERIFIED_SEVERED",
    "VERIFIED_UNAFFECTED",
    "MUTATION_REJECTED",
    "VERIFICATION_FAILED",
    "CLEANUP_WARNING",
]


class RemediationVerificationResult(BaseModel):
  """Structured outcome of an isolated remediation simulation and verification."""

  status: RemediationStatus
  success: bool = Field(..., description="True if operation completed and baseline integrity held")
  revocation: EdgeRevocation
  baseline_counts_before: Dict[str, int]
  baseline_counts_after: Dict[str, int]
  baseline_intact: bool
  clone_name: str
  clone_cleaned_up: bool
  original_path_severed: bool
  target_still_reachable: bool
  before_paths_count: int
  residual_paths_count: int
  residual_paths: List[AttackPath] = Field(default_factory=list)
  residual_risk_score: Optional[float] = Field(
      default=None,
      description="Risk prioritization score for residual paths, or 0.0 if all routes severed",
  )
  residual_risk_tier: Optional[str] = Field(
      default=None,
      description="Risk tier for residual paths (CRITICAL, PRIORITY, MONITOR, INFORMATIONAL)",
  )
  warnings: List[str] = Field(default_factory=list)
  details: str
