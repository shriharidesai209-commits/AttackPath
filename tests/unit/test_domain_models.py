"""Unit tests for domain entity models, graph edges, and attack path validation."""

import pytest
from pydantic import ValidationError
from attackpath.domain.entities import (
    BaseEntityNode,
    DataAssetNode,
    IAMRoleNode,
    IdentityNode,
    WorkloadNode,
)
from attackpath.domain.path import AttackPath, EdgeRevocation, GraphEdge


def test_identity_node_validation():
  """Verify IdentityNode validation constraints."""
  node = IdentityNode(
      id="usr_jdoe",
      name="John Doe",
      email="jdoe@enterprise.internal",
      department="IT Support",
      compromised=True,
      mfa_enabled=False,
  )
  assert node.id == "usr_jdoe"
  assert node.label == "Identity"
  assert node.compromised is True
  assert node.is_synthetic is True

  # Invalid empty ID
  with pytest.raises(ValidationError):
    IdentityNode(id="   ", name="John", email="j@e.com")

  # Invalid kind
  with pytest.raises(ValidationError):
    IdentityNode(id="usr_1", name="J", email="j@e.com", kind="invalid_kind")  # type: ignore[arg-type]


def test_workload_node_validation():
  """Verify WorkloadNode validation constraints."""
  workload = WorkloadNode(
      id="srv_app_prod",
      name="App-Server-Prod",
      kind="virtual_machine",
      ip_address="10.0.1.15",
      is_internet_facing=True,
      os="Ubuntu 22.04 LTS",
  )
  assert workload.label == "Workload"
  assert workload.is_internet_facing is True

  # Invalid kind
  with pytest.raises(ValidationError):
    WorkloadNode(id="w1", name="W", kind="mainframe")  # type: ignore[arg-type]


def test_iam_role_node_validation():
  """Verify IAMRoleNode validation constraints."""
  role = IAMRoleNode(
      id="role_order_service",
      name="OrderServiceRole",
      arn="arn:aws:iam::123456789012:role/OrderServiceRole",
      is_privileged=True,
  )
  assert role.label == "IAMRole"
  assert role.is_privileged is True

  # Too short ARN
  with pytest.raises(ValidationError):
    IAMRoleNode(id="r1", name="R", arn="arn")


def test_data_asset_node_validation():
  """Verify DataAssetNode classification and encryption validation."""
  asset = DataAssetNode(
      id="db_customer_vault",
      name="Customer-Vault-DB",
      kind="database",
      classification="crown_jewel",
      is_encrypted=True,
  )
  assert asset.label == "DataAsset"
  assert asset.classification == "crown_jewel"

  # Invalid classification
  with pytest.raises(ValidationError):
    DataAssetNode(id="d1", name="D", classification="top_secret_invalid")  # type: ignore[arg-type]


def test_graph_edge_validation():
  """Verify GraphEdge relationship validation."""
  edge = GraphEdge(
      source="usr_jdoe",
      target="srv_app_prod",
      type="AUTHENTICATES_TO",
      properties={"method": "SSH"},
  )
  assert edge.source == "usr_jdoe"
  assert edge.target == "srv_app_prod"
  assert edge.type == "AUTHENTICATES_TO"

  # Invalid relationship type
  with pytest.raises(ValidationError):
    GraphEdge(source="a", target="b", type="KNOWS_NOTHING")  # type: ignore[arg-type]


def test_attack_path_topology_validation():
  """Verify AttackPath topological integrity (alternating nodes and edges)."""
  n1 = BaseEntityNode(id="usr_jdoe", label="Identity", name="John")
  n2 = BaseEntityNode(id="srv_app_prod", label="Workload", name="Server")
  n3 = BaseEntityNode(id="role_order", label="IAMRole", name="Role")

  e1 = GraphEdge(source="usr_jdoe", target="srv_app_prod", type="AUTHENTICATES_TO")
  e2 = GraphEdge(source="srv_app_prod", target="role_order", type="EXECUTES_AS")

  # Valid 2-hop path
  path = AttackPath(
      path_id="path_1",
      hop_count=2,
      nodes=[n1, n2, n3],
      edges=[e1, e2],
  )
  assert path.hop_count == 2

  # Mismatched lengths: 3 nodes with only 1 edge
  with pytest.raises(ValidationError):
    AttackPath(path_id="p", hop_count=1, nodes=[n1, n2, n3], edges=[e1])

  # Disconnected sequence: edge target doesn't match next node
  bad_e2 = GraphEdge(source="srv_app_prod", target="different_node", type="EXECUTES_AS")
  with pytest.raises(ValidationError):
    AttackPath(path_id="p", hop_count=2, nodes=[n1, n2, n3], edges=[e1, bad_e2])


def test_edge_revocation_validation():
  """Verify EdgeRevocation model."""
  rev = EdgeRevocation(source_id="role_order", rel_type="CAN_ACCESS", target_id="db_vault")
  assert rev.source_id == "role_order"
  assert rev.target_id == "db_vault"

  with pytest.raises(ValidationError):
    EdgeRevocation(source_id="", rel_type="CAN_ACCESS", target_id="db")
