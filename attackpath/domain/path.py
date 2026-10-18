"""Domain models representing graph edges, attack paths, and edge revocations."""

from typing import Any, List, Literal
from pydantic import BaseModel, Field, model_validator
from attackpath.domain.entities import BaseEntityNode


RelationshipType = Literal[
    "AUTHENTICATES_TO",
    "EXECUTES_AS",
    "CAN_ASSUME",
    "CAN_ACCESS",
    "NETWORK_REACHABLE",
]


class GraphEdge(BaseModel):
  """Represents a directed relationship between two graph entities."""

  source: str = Field(..., min_length=1, description="Source node identifier")
  target: str = Field(
      ..., min_length=1, description="Target/Destination node identifier"
  )
  type: RelationshipType = Field(
      ..., description="Standardized security relationship type"
  )
  properties: dict[str, Any] = Field(
      default_factory=dict, description="Edge security telemetry and attributes"
  )
  is_synthetic: bool = Field(
      default=True,
      description="Explicit indicator of synthetic security provenance",
  )


class AttackPath(BaseModel):
  """Represents a discovered multi-hop path from a source identity to a target data asset."""

  path_id: str = Field(..., min_length=1, description="Unique path identifier")
  hop_count: int = Field(
      ..., ge=1, le=10, description="Total number of hops (edges) in the path"
  )
  nodes: List[BaseEntityNode] = Field(
      ..., description="Ordered list of nodes traversed"
  )
  edges: List[GraphEdge] = Field(
      ..., description="Ordered list of directed relationships traversed"
  )
  is_synthetic: bool = Field(
      default=True,
      description="Explicit indicator of synthetic security provenance",
  )

  @model_validator(mode="after")
  def validate_path_topology(self) -> "AttackPath":
    """Validates that the path consists of alternating nodes and edges forming a connected sequence."""
    if len(self.nodes) != len(self.edges) + 1:
      raise ValueError(
          f"Inconsistent path topology: {len(self.nodes)} nodes must connect via exactly {len(self.nodes) - 1} edges (got {len(self.edges)})"
      )
    if self.hop_count != len(self.edges):
      raise ValueError(
          f"hop_count ({self.hop_count}) must match edges length ({len(self.edges)})"
      )
    # Validate connectivity
    for idx, edge in enumerate(self.edges):
      src_node = self.nodes[idx]
      dst_node = self.nodes[idx + 1]
      if edge.source != src_node.id:
        raise ValueError(
            f"Edge {idx} source '{edge.source}' does not match preceding node id '{src_node.id}'"
        )
      if edge.target != dst_node.id:
        raise ValueError(
            f"Edge {idx} target '{edge.target}' does not match following node id '{dst_node.id}'"
        )
    return self

  @property
  def signature(self) -> str:
    """Returns a deterministic string representation of the exact sequence of nodes and edges."""
    parts = []
    for idx, edge in enumerate(self.edges):
      parts.append(f"({self.nodes[idx].id})-[{edge.type}]->")
    parts.append(f"({self.nodes[-1].id})")
    return "".join(parts)


class EdgeRevocation(BaseModel):
  """Specification of a relationship to be removed during remediation simulation."""

  source_id: str = Field(..., min_length=1)
  rel_type: str = Field(..., min_length=1)
  target_id: str = Field(..., min_length=1)
