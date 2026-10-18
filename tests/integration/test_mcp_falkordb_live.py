"""Live integration tests for AttackPath MCP server tools executing against real FalkorDB Cloud."""

import pytest
from attackpath.config import get_settings as config_get_settings
from attackpath.database.connection import (
    create_falkordb_client,
    ping_falkordb,
)
from attackpath.database.repository import FalkorDBRepository
from attackpath.database.seeder import (
    SYNTHETIC_EDGE_COUNT,
    SYNTHETIC_NODE_COUNT,
    seed_synthetic_scenario,
)
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

TEST_GRAPH_KEY = "attackpath_milestone5_mcp_live_test"


def _check_live_falkordb() -> tuple[bool, str]:
  """Checks whether the configured FalkorDB instance is live and accessible."""
  try:
    config_get_settings.cache_clear()
    settings = config_get_settings()
    client = create_falkordb_client(settings)
    if ping_falkordb(client):
      return True, f"Responsive at {settings.falkordb_connection_uri}"
    return False, f"Ping check failed on {settings.falkordb_connection_uri}"
  except Exception as exc:
    settings = config_get_settings()
    return False, f"Connection refused/failed on {settings.falkordb_connection_uri} ({exc})"


FALKORDB_AVAILABLE, REASON_DETAIL = _check_live_falkordb()
BLOCKED_REASON = (
    f"BLOCKED: Live FalkorDB server is unreachable. Target: {REASON_DETAIL}. "
    "To unblock: configure environment variables in .env: "
    "FALKORDB_HOST=<host>, FALKORDB_PORT=<port>, FALKORDB_PASSWORD=<password>, FALKORDB_SSL=true/false"
)


@pytest.fixture(scope="module")
def live_mcp_context():
  """Sets up a seeded isolated test graph on real FalkorDB Cloud and registers dependency overrides."""
  if not FALKORDB_AVAILABLE:
    pytest.skip(BLOCKED_REASON)

  settings = config_get_settings()
  test_settings = settings.model_copy(update={"FALKORDB_BASELINE_GRAPH": TEST_GRAPH_KEY})

  client = create_falkordb_client(test_settings)
  repo = FalkorDBRepository(client, graph_name=TEST_GRAPH_KEY)
  seed_synthetic_scenario(repo, clean_first=True)

  set_dependency_override("settings", test_settings)
  set_dependency_override("repository", repo)

  yield {"repo": repo, "client": client, "settings": test_settings}

  clear_dependency_overrides()
  try:
    repo.clear_graph()
  except Exception:
    pass


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_mcp_get_graph_topology(live_mcp_context):
  """Verifies get_graph_topology tool on real FalkorDB Cloud returns exact 11 nodes and 11 edges."""
  result = get_graph_topology()

  assert isinstance(result, TopologyResponseEnvelope)
  assert result.graph_name == TEST_GRAPH_KEY
  assert result.total_nodes == SYNTHETIC_NODE_COUNT == 11
  assert result.total_edges == SYNTHETIC_EDGE_COUNT == 11
  assert len(result.nodes) == 11
  assert len(result.edges) == 11
  assert result.is_synthetic is True


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_mcp_discover_attack_paths_two_paths(live_mcp_context):
  """Verifies discover_attack_paths on real FalkorDB Cloud returns exactly the expected two paths."""
  result = discover_attack_paths(
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
      limit=10,
  )

  assert isinstance(result, DiscoveryResponseEnvelope)
  assert result.status == "PATHS_DISCOVERED"
  assert result.total_paths_found == 2
  assert len(result.paths) == 2
  assert result.is_synthetic is True

  # Primary path: 3 hops
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

  # Alternative path: 4 hops
  p2 = result.paths[1]
  assert p2.hop_count == 4
  assert [n.id for n in p2.nodes] == [
      "usr_jdoe",
      "srv_app_prod",
      "srv_analytics_worker",
      "role_analytics_readonly",
      "db_customer_vault",
  ]
  assert [e.type for e in p2.edges] == [
      "AUTHENTICATES_TO",
      "NETWORK_REACHABLE",
      "EXECUTES_AS",
      "CAN_ACCESS",
  ]


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_mcp_explain_attack_path(live_mcp_context):
  """Verifies explain_attack_path generates grounded evidence and deterministic risk scores on real graph."""
  result = explain_attack_path(
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
      limit=10,
  )

  assert isinstance(result, ExplanationResponseEnvelope)
  assert result.status == "PATHS_DISCOVERED"
  assert result.total_paths_found == 2
  assert result.is_synthetic is True
  assert result.disclaimer == DISCLAIMER_TEXT

  primary = result.paths[0]
  assert primary.path.hop_count == 3
  assert primary.evidence.path_id == "path_1"
  assert len(primary.evidence.ordered_nodes) == 4
  assert len(primary.evidence.ordered_edges) == 3

  # Graph facts
  src_facts = " ".join(primary.evidence.ordered_nodes[0].observed_facts)
  assert "compromised" in src_facts

  access_facts = " ".join(primary.evidence.ordered_edges[2].observed_facts)
  assert "rds:FullAccess" in access_facts

  # Risk score
  assert primary.risk_assessment.risk_tier == "CRITICAL"
  assert primary.risk_assessment.score == 100.0
  assert primary.risk_assessment.disclaimer == DISCLAIMER_TEXT


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_mcp_simulate_remediation_primary_route(live_mcp_context):
  """Verifies isolated remediation simulation on real FalkorDB Cloud.

  Revoking role_order_service -> db_customer_vault CAN_ACCESS edge must sever
  primary route, leave 4-hop alternative route reachable, preserve baseline graph,
  and clean up ephemeral clone.
  """
  repo = live_mcp_context["repo"]
  initial_nodes = repo.count_nodes()
  initial_edges = repo.count_edges()

  result = simulate_remediation_and_verify(
      source_id="role_order_service",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
      path_source_id="usr_jdoe",
      path_target_id="db_customer_vault",
      max_depth=6,
      limit=10,
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

  # Baseline graph immutability verified on real FalkorDB
  assert result.baseline_intact is True
  assert repo.count_nodes() == initial_nodes == 11
  assert repo.count_edges() == initial_edges == 11

  # Clone deleted
  assert result.clone_cleaned_up is True


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_mcp_simulate_remediation_shared_entry(live_mcp_context):
  """Verifies revoking shared entry relationship leaves zero residual routes on real FalkorDB Cloud."""
  repo = live_mcp_context["repo"]

  result = simulate_remediation_and_verify(
      source_id="usr_jdoe",
      rel_type="AUTHENTICATES_TO",
      target_id="srv_app_prod",
      path_source_id="usr_jdoe",
      path_target_id="db_customer_vault",
  )

  assert isinstance(result, RemediationResponseEnvelope)
  assert result.status == "VERIFIED_SEVERED"
  assert result.success is True
  assert result.original_path_severed is True
  assert result.target_still_reachable is False
  assert result.residual_paths_count == 0
  assert len(result.residual_paths) == 0

  # Baseline immutability
  assert result.baseline_intact is True
  assert repo.count_nodes() == 11
  assert repo.count_edges() == 11
  assert result.clone_cleaned_up is True


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_mcp_simulate_remediation_nonexistent_edge(live_mcp_context):
  """Verifies revocation of nonexistent relationship fails safely with NOT_FOUND on real FalkorDB."""
  res = simulate_remediation_and_verify(
      source_id="usr_jdoe",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )
  assert hasattr(res, "is_error") and res.is_error is True
  assert res.structured_content["error"]["code"] == "NOT_FOUND"


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_mcp_baseline_integrity_preserved(live_mcp_context):
  """Verifies that baseline test graph key remains unchanged and retains both paths after all live simulations."""
  repo = live_mcp_context["repo"]
  assert repo.count_nodes() == 11
  assert repo.count_edges() == 11

  disc = discover_attack_paths("usr_jdoe", "db_customer_vault")
  assert isinstance(disc, DiscoveryResponseEnvelope)
  assert disc.total_paths_found == 2
