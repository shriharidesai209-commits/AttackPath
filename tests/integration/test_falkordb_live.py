"""Live integration tests executed against a real FalkorDB server instance.

WARNING:
- These tests require an active, responsive FalkorDB server (e.g. FalkorDB Cloud or remote instance).
- If the server is unreachable, tests are explicitly marked as BLOCKED / SKIPPED and NOT claimed as passed.
"""

import pytest
from attackpath.config import get_settings
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


def _check_live_falkordb() -> tuple[bool, str]:
  """Checks whether the configured FalkorDB instance is live and accessible."""
  try:
    get_settings.cache_clear()
    settings = get_settings()
    client = create_falkordb_client(settings)
    if ping_falkordb(client):
      return True, f"Responsive at {settings.falkordb_connection_uri}"
    return False, f"Ping check failed on {settings.falkordb_connection_uri}"
  except Exception as exc:
    settings = get_settings()
    return False, f"Connection refused/failed on {settings.falkordb_connection_uri} ({exc})"


FALKORDB_AVAILABLE, REASON_DETAIL = _check_live_falkordb()
BLOCKED_REASON = (
    f"BLOCKED: Live FalkorDB server is unreachable. Target: {REASON_DETAIL}. "
    "To unblock: configure environment variables in .env or shell: "
    "FALKORDB_HOST=<host>, FALKORDB_PORT=<port>, FALKORDB_PASSWORD=<password>, FALKORDB_SSL=true/false"
)


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_falkordb_connection_and_ping():
  """Verifies connection and ping to a live FalkorDB instance."""
  settings = get_settings()
  client = create_falkordb_client(settings)
  assert ping_falkordb(client) is True


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_falkordb_seeder_and_exact_counts():
  """Verifies synthetic seeder against real FalkorDB, asserting exactly 11 nodes and 11 edges."""
  settings = get_settings()
  client = create_falkordb_client(settings)
  repo = FalkorDBRepository(client, graph_name="attackpath_integration_test")

  try:
    summary = seed_synthetic_scenario(repo, clean_first=True)
    assert summary["total_nodes"] == SYNTHETIC_NODE_COUNT == 11
    assert summary["total_edges"] == SYNTHETIC_EDGE_COUNT == 11

    # Verify counts via direct Cypher calls
    assert repo.count_nodes() == 11
    assert repo.count_edges() == 11

    # Verify idempotency
    seed_synthetic_scenario(repo, clean_first=False)
    assert repo.count_nodes() == 11
    assert repo.count_edges() == 11
  finally:
    repo.clear_graph()


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_falkordb_path_discovery():
  """Verifies bounded Cypher path discovery on real FalkorDB returns exactly 2 paths."""
  settings = get_settings()
  client = create_falkordb_client(settings)
  repo = FalkorDBRepository(client, graph_name="attackpath_integration_test")

  try:
    seed_synthetic_scenario(repo, clean_first=True)

    paths = repo.find_paths(source_id="usr_jdoe", target_id="db_customer_vault", max_depth=6)

    assert len(paths) == 2, f"Expected exactly 2 paths, got {len(paths)}"

    # Primary path (3 hops)
    assert paths[0].hop_count == 3
    assert [n.id for n in paths[0].nodes] == [
        "usr_jdoe",
        "srv_app_prod",
        "role_order_service",
        "db_customer_vault",
    ]

    # Alternative path (4 hops)
    assert paths[1].hop_count == 4
    assert [n.id for n in paths[1].nodes] == [
        "usr_jdoe",
        "srv_app_prod",
        "srv_analytics_worker",
        "role_analytics_readonly",
        "db_customer_vault",
    ]
  finally:
    repo.clear_graph()


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_falkordb_graph_copy_and_delete():
  """Verifies graph.copy() and graph.delete() behavior on real FalkorDB."""
  settings = get_settings()
  client = create_falkordb_client(settings)
  base_repo = FalkorDBRepository(client, graph_name="attackpath_base_copy_test")
  clone_name = "attackpath_clone_copy_test"

  try:
    seed_synthetic_scenario(base_repo, clean_first=True)
    assert base_repo.count_nodes() == 11

    # Copy to new graph key
    base_repo.copy_graph(clone_name)
    clone_repo = FalkorDBRepository(client, graph_name=clone_name)

    # Verify clone counts
    assert clone_repo.count_nodes() == 11
    assert clone_repo.count_edges() == 11

    # Clean up clone
    clone_repo.delete_graph()
  finally:
    base_repo.clear_graph()
