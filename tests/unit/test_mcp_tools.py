"""Unit tests for AttackPath MCP server tools using an offline adapter and dependency injection."""

from unittest.mock import MagicMock
import pytest
from attackpath.database.connection import FalkorDBConnectionError
from attackpath.domain.path import AttackPath, EdgeRevocation, GraphEdge
from attackpath.domain.service_models import RemediationVerificationResult
from attackpath.mcp_server.dependencies import (
    clear_dependency_overrides,
    set_dependency_override,
)
from attackpath.mcp_server.tools import (
    DISCLAIMER_TEXT,
    DiscoveryResponseEnvelope,
    ExplanationResponseEnvelope,
    RemediationResponseEnvelope,
    TopologyResponseEnvelope,
    discover_attack_paths,
    explain_attack_path,
    get_graph_topology,
    simulate_remediation_and_verify,
)
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def offline_adapter():
  """Provides a clean, seeded in-memory NetworkX adapter and registers it as dependency override."""
  adapter = NetworkXTestAdapter(graph_name="offline_test_baseline")
  adapter.seed_synthetic_scenario(clean_first=True)
  set_dependency_override("repository", adapter)
  yield adapter
  clear_dependency_overrides()


# ==============================================================================
# Tool A: discover_attack_paths Unit Tests
# ==============================================================================


def test_discover_attack_paths_success(offline_adapter):
  """Verifies successful bounded path discovery returns expected two paths and synthetic labeling."""
  result = discover_attack_paths(
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
      limit=10,
  )

  assert isinstance(result, DiscoveryResponseEnvelope)
  assert result.status == "PATHS_DISCOVERED"
  assert result.source_id == "usr_jdoe"
  assert result.target_id == "db_customer_vault"
  assert result.total_paths_found == 2
  assert len(result.paths) == 2
  assert result.is_synthetic is True

  # Verify primary route (3 hops)
  p1 = result.paths[0]
  assert p1.hop_count == 3
  assert [n.id for n in p1.nodes] == [
      "usr_jdoe",
      "srv_app_prod",
      "role_order_service",
      "db_customer_vault",
  ]
  assert [e.type for e in p1.edges] == [
      "AUTHENTICATES_TO",
      "EXECUTES_AS",
      "CAN_ACCESS",
  ]

  # Verify secondary route (4 hops)
  p2 = result.paths[1]
  assert p2.hop_count == 4
  assert [n.id for n in p2.nodes] == [
      "usr_jdoe",
      "srv_app_prod",
      "srv_analytics_worker",
      "role_analytics_readonly",
      "db_customer_vault",
  ]


@pytest.mark.parametrize(
    "src,tgt,depth,limit",
    [
        ("", "db_customer_vault", 6, 10),
        ("   ", "db_customer_vault", 6, 10),
        ("usr_jdoe", "", 6, 10),
        ("usr_jdoe", "   ", 6, 10),
        ("usr_jdoe", "db_customer_vault", 0, 10),
        ("usr_jdoe", "db_customer_vault", 7, 10),
        ("usr_jdoe", "db_customer_vault", 6, 0),
        ("usr_jdoe", "db_customer_vault", 6, 51),
    ],
)
def test_discover_attack_paths_input_validation(offline_adapter, src, tgt, depth, limit):
  """Rejects empty strings and out-of-bounds traversal parameters safely."""
  res = discover_attack_paths(source_id=src, target_id=tgt, max_depth=depth, limit=limit)
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "INVALID_REQUEST"


def test_discover_attack_paths_missing_entity(offline_adapter):
  """Distinguishes missing entities from unreachable targets with explicit error."""
  res = discover_attack_paths(source_id="nonexistent_user", target_id="db_customer_vault")
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "ENTITY_NOT_FOUND"
  assert "nonexistent_user" in res.structured_content["error"]["message"]


def test_discover_attack_paths_unreachable_target(offline_adapter):
  """Returns an explicit empty path result when target exists but is disconnected."""
  # Add isolated node that exists in the graph
  offline_adapter.g.add_node(
      "isolated_db",
      id="isolated_db",
      name="Isolated Database",
      label="DataAsset",
      classification="crown_jewel",
      is_synthetic=True,
  )

  res = discover_attack_paths(source_id="usr_jdoe", target_id="isolated_db")
  assert isinstance(res, DiscoveryResponseEnvelope)
  assert res.status == "TARGET_UNREACHABLE"
  assert res.total_paths_found == 0
  assert len(res.paths) == 0
  assert res.is_synthetic is True
  assert "unreachable" in str(res.details).lower()


def test_discover_attack_paths_database_failure():
  """Handles database connection failures safely without leaking connection secrets."""
  mock_repo = MagicMock()
  mock_repo.find_paths.side_effect = FalkorDBConnectionError(
      message="Connection refused",
      diagnostic_uri="rediss://***@secret-cluster:6380/baseline",
  )
  set_dependency_override("repository", mock_repo)

  res = discover_attack_paths("usr_jdoe", "db_customer_vault")
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "DATABASE_UNAVAILABLE"
  # Confirm secrets / URI are not leaked to the MCP caller
  assert "secret-cluster" not in res.structured_content["error"]["message"]
  assert "6380" not in res.structured_content["error"]["message"]


# ==============================================================================
# Tool B: explain_attack_path Unit Tests
# ==============================================================================


def test_explain_attack_path_success(offline_adapter):
  """Verifies explanation contains ordered evidence, graph facts, deterministic risk scores, and disclaimers."""
  result = explain_attack_path(
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
      limit=10,
  )

  assert isinstance(result, ExplanationResponseEnvelope)
  assert result.status == "PATHS_DISCOVERED"
  assert result.total_paths_found == 2
  assert len(result.paths) == 2
  assert result.is_synthetic is True
  assert result.disclaimer == DISCLAIMER_TEXT

  primary = result.paths[0]
  # Path evidence verification
  assert primary.evidence.path_id == "path_1"
  assert primary.evidence.hop_count == 3
  assert len(primary.evidence.ordered_nodes) == 4
  assert len(primary.evidence.ordered_edges) == 3

  # Provenance checks
  provenances = {c.provenance for c in primary.evidence.factual_claims}
  assert "OBSERVED_GRAPH_FACT" in provenances
  assert "SYNTHETIC_DATA_METADATA" in provenances

  # Risk assessment verification
  assert primary.risk_assessment.risk_tier == "CRITICAL"
  assert primary.risk_assessment.score == 100.0
  assert primary.risk_assessment.disclaimer == DISCLAIMER_TEXT
  rule_ids = {c.rule_id for c in primary.risk_assessment.contributions}
  assert "RULE_COMPROMISED_IDENTITY" in rule_ids
  assert "RULE_CROWN_JEWEL_TARGET" in rule_ids
  assert "RULE_WILDCARD_PERMISSION" in rule_ids


def test_explain_attack_path_unreachable_target(offline_adapter):
  """Returns TARGET_UNREACHABLE with empty path explanations when no route connects valid endpoints."""
  offline_adapter.g.add_node(
      "isolated_node",
      id="isolated_node",
      name="Isolated Asset",
      label="DataAsset",
      classification="internal",
      is_synthetic=True,
  )

  res = explain_attack_path("usr_jdoe", "isolated_node")
  assert isinstance(res, ExplanationResponseEnvelope)
  assert res.status == "TARGET_UNREACHABLE"
  assert res.total_paths_found == 0
  assert len(res.paths) == 0
  assert res.disclaimer == DISCLAIMER_TEXT


def test_explain_attack_path_missing_entity(offline_adapter):
  """Rejects request with ENTITY_NOT_FOUND if endpoint node does not exist."""
  res = explain_attack_path("usr_unknown", "db_customer_vault")
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "ENTITY_NOT_FOUND"


def test_explain_attack_path_invalid_inputs(offline_adapter):
  """Rejects blank identifiers for explain_attack_path."""
  res = explain_attack_path("", "db_customer_vault")
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "INVALID_REQUEST"


# ==============================================================================
# Tool C: simulate_remediation_and_verify Unit Tests
# ==============================================================================


def test_simulate_remediation_primary_route_severance(offline_adapter):
  """Simulates revoking primary path CAN_ACCESS edge on clone.

  Must sever primary route, leave 4-hop alternative route reachable,
  prove baseline immutability, and clean up temporary clone.
  """
  initial_nodes = offline_adapter.count_nodes()
  initial_edges = offline_adapter.count_edges()

  result = simulate_remediation_and_verify(
      source_id="role_order_service",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
      path_source_id="usr_jdoe",
      path_target_id="db_customer_vault",
  )

  assert isinstance(result, RemediationResponseEnvelope)
  assert result.status == "VERIFIED_SEVERED"
  assert result.success is True
  assert result.original_path_severed is True
  assert result.target_still_reachable is True
  assert result.before_paths_count == 2
  assert result.residual_paths_count == 1
  assert len(result.residual_paths) == 1

  # Residual path is the alternative route
  assert result.residual_paths[0].hop_count == 4

  # Baseline graph immutability verified
  assert result.baseline_intact is True
  assert offline_adapter.count_nodes() == initial_nodes
  assert offline_adapter.count_edges() == initial_edges

  # Ephemeral clone deleted
  assert result.clone_cleaned_up is True


def test_simulate_remediation_shared_entry_severance(offline_adapter):
  """Simulates revoking shared entry AUTHENTICATES_TO edge.

  Must sever all routes to target, leaving residual_paths_count == 0.
  """
  result = simulate_remediation_and_verify(
      source_id="usr_jdoe",
      rel_type="AUTHENTICATES_TO",
      target_id="srv_app_prod",
      path_source_id="usr_jdoe",
      path_target_id="db_customer_vault",
  )

  assert isinstance(result, RemediationResponseEnvelope)
  assert result.status == "VERIFIED_SEVERED"
  assert result.original_path_severed is True
  assert result.target_still_reachable is False
  assert result.residual_paths_count == 0
  assert len(result.residual_paths) == 0
  assert result.baseline_intact is True
  assert result.clone_cleaned_up is True


def test_simulate_remediation_nonexistent_edge(offline_adapter):
  """Rejects revocation of relationship that does not exist in graph."""
  res = simulate_remediation_and_verify(
      source_id="usr_jdoe",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "NOT_FOUND"


def test_simulate_remediation_ambiguous_edge(offline_adapter):
  """Safely rejects revocation when multiple relationships match endpoints and type."""
  # Add duplicate edge
  offline_adapter.g.add_edge(
      "role_order_service",
      "db_customer_vault",
      key="duplicate_access_edge",
      source="role_order_service",
      target="db_customer_vault",
      type="CAN_ACCESS",
      permission="rds:ReadOnly",
  )

  res = simulate_remediation_and_verify(
      source_id="role_order_service",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "CONFLICT"
  assert "ambiguous" in res.structured_content["error"]["message"].lower()


@pytest.mark.parametrize(
    "src,rel,tgt,depth,limit",
    [
        ("", "CAN_ACCESS", "db_customer_vault", 6, 10),
        ("role_order_service", "", "db_customer_vault", 6, 10),
        ("role_order_service", "CAN_ACCESS", "", 6, 10),
        ("role_order_service", "CAN_ACCESS", "db_customer_vault", 0, 10),
        ("role_order_service", "CAN_ACCESS", "db_customer_vault", 7, 10),
        ("role_order_service", "CAN_ACCESS", "db_customer_vault", 6, 51),
    ],
)
def test_simulate_remediation_input_validation(offline_adapter, src, rel, tgt, depth, limit):
  """Validates revocation inputs and bounds."""
  res = simulate_remediation_and_verify(
      source_id=src,
      rel_type=rel,
      target_id=tgt,
      max_depth=depth,
      limit=limit,
  )
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "INVALID_REQUEST"


def test_simulate_remediation_baseline_integrity_failure():
  """Handles baseline integrity failure safely and marks error with VERIFICATION_FAILED."""
  mock_service = MagicMock()
  mock_service.simulate_and_verify_remediation.return_value = RemediationVerificationResult(
      status="VERIFICATION_FAILED",
      success=False,
      revocation=EdgeRevocation(source_id="a", rel_type="R", target_id="b"),
      baseline_counts_before={"node_count": 10, "edge_count": 10},
      baseline_counts_after={"node_count": 9, "edge_count": 9},
      baseline_intact=False,
      clone_name="sim_clone",
      clone_cleaned_up=True,
      original_path_severed=False,
      target_still_reachable=True,
      before_paths_count=1,
      residual_paths_count=1,
      residual_paths=[],
      warnings=["Baseline graph counts changed!"],
      details="Baseline integrity check failed.",
  )
  set_dependency_override("remediation_service", mock_service)

  res = simulate_remediation_and_verify(
      source_id="a",
      rel_type="R",
      target_id="b",
  )
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "VERIFICATION_FAILED"
  assert "Baseline integrity check failed." in res.structured_content["error"]["message"]


# ==============================================================================
# Tool D: get_graph_topology Unit Tests
# ==============================================================================


def test_get_graph_topology_success(offline_adapter):
  """Inspects graph topology and returns correct counts and synthetic labeling."""
  result = get_graph_topology()

  assert isinstance(result, TopologyResponseEnvelope)
  assert result.total_nodes == 11
  assert result.total_edges == 11
  assert len(result.nodes) == 11
  assert len(result.edges) == 11
  assert result.is_synthetic is True
  assert result.graph_name == "attackpath_baseline"


def test_get_graph_topology_database_error():
  """Returns sanitized DATABASE_UNAVAILABLE error when topology query fails."""
  mock_repo = MagicMock()
  mock_repo.get_topology.side_effect = ConnectionError("Connection refused by peer")
  set_dependency_override("repository", mock_repo)

  res = get_graph_topology()
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "DATABASE_UNAVAILABLE"


# ==============================================================================
# Unexpected Exception Sanitization Test
# ==============================================================================


def test_unexpected_exception_sanitization():
  """Ensures unexpected internal exceptions return INTERNAL_SERVER_ERROR without leaking secrets."""
  mock_service = MagicMock()
  mock_service.discover_paths.side_effect = RuntimeError("Critical secret in memory: super_secret_token_123")
  set_dependency_override("discovery_service", mock_service)

  res = discover_attack_paths("usr_jdoe", "db_customer_vault")
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "INTERNAL_SERVER_ERROR"
  assert "super_secret_token_123" not in res.structured_content["error"]["message"]
