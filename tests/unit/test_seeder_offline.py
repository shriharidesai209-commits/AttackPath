"""Unit tests verifying the synthetic benchmark scenario specification and idempotency using the explicit offline test adapter."""

from attackpath.database.seeder import (
    SYNTHETIC_EDGE_COUNT,
    SYNTHETIC_NODE_COUNT,
)
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


def test_synthetic_seed_exact_counts():
  """Assert that the synthetic scenario generates exactly 11 nodes and 11 relationships."""
  adapter = NetworkXTestAdapter()
  summary = adapter.seed_synthetic_scenario(clean_first=True)

  assert summary["total_nodes"] == SYNTHETIC_NODE_COUNT == 11
  assert summary["total_edges"] == SYNTHETIC_EDGE_COUNT == 11
  assert adapter.count_nodes() == 11
  assert adapter.count_edges() == 11


def test_seeding_idempotency():
  """Assert that rerunning the seeder does not create duplicate nodes or edges."""
  adapter = NetworkXTestAdapter()

  # Initial seed
  adapter.seed_synthetic_scenario(clean_first=True)
  assert adapter.count_nodes() == 11
  assert adapter.count_edges() == 11

  # Second seed without clearing
  adapter.seed_synthetic_scenario(clean_first=False)
  assert adapter.count_nodes() == 11, "Idempotent re-seed must not duplicate nodes"
  assert adapter.count_edges() == 11, "Idempotent re-seed must not duplicate edges"


def test_synthetic_topology_path_discovery():
  """Verify that discovery from usr_jdoe to db_customer_vault returns exactly two expected paths."""
  adapter = NetworkXTestAdapter()
  adapter.seed_synthetic_scenario(clean_first=True)

  paths = adapter.find_paths(source_id="usr_jdoe", target_id="db_customer_vault")

  # 1. Exactly two paths must be found
  assert len(paths) == 2, f"Expected exactly 2 attack paths, found {len(paths)}"

  # 2. Path 1: Primary 3-hop path
  p1 = paths[0]
  assert p1.hop_count == 3
  assert len(p1.nodes) == 4
  assert len(p1.edges) == 3
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
  assert p1.is_synthetic is True

  # 3. Path 2: Alternative 4-hop path
  p2 = paths[1]
  assert p2.hop_count == 4
  assert len(p2.nodes) == 5
  assert len(p2.edges) == 4
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
  assert p2.is_synthetic is True


def test_nonexistent_endpoints_return_empty_paths():
  """Verify that querying nonexistent endpoints returns an empty list."""
  adapter = NetworkXTestAdapter()
  adapter.seed_synthetic_scenario(clean_first=True)

  paths = adapter.find_paths(source_id="usr_unknown", target_id="db_customer_vault")
  assert paths == []

  paths = adapter.find_paths(source_id="usr_jdoe", target_id="db_unknown")
  assert paths == []
