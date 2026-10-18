"""Live integration tests for FastAPI REST API endpoints executing against real FalkorDB Cloud."""

import pytest
from fastapi.testclient import TestClient
from attackpath.api.app import app
from attackpath.api.dependencies import get_settings
from attackpath.config import get_settings as config_get_settings
from attackpath.database.connection import (
    create_falkordb_client,
    ping_falkordb,
)
from attackpath.database.repository import FalkorDBRepository
from attackpath.database.seeder import seed_synthetic_scenario

TEST_GRAPH_KEY = "attackpath_milestone4_api_live_test"


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
def live_client():
  """Configures FastAPI TestClient against live FalkorDB dedicated test graph key."""
  if not FALKORDB_AVAILABLE:
    pytest.skip(BLOCKED_REASON)

  settings = config_get_settings()
  test_settings = settings.model_copy(update={"FALKORDB_BASELINE_GRAPH": TEST_GRAPH_KEY})
  app.dependency_overrides[get_settings] = lambda: test_settings

  client = create_falkordb_client(test_settings)
  repo = FalkorDBRepository(client, graph_name=TEST_GRAPH_KEY)
  seed_synthetic_scenario(repo, clean_first=True)

  with TestClient(app) as test_client:
    yield test_client

  try:
    repo.clear_graph()
  except Exception:
    pass
  app.dependency_overrides.clear()


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_api_health_and_readiness(live_client):
  """Verifies /health and /health/ready against live FalkorDB Cloud."""
  h_resp = live_client.get("/health")
  assert h_resp.status_code == 200
  assert h_resp.json()["status"] == "ok"

  r_resp = live_client.get("/health/ready")
  assert r_resp.status_code == 200
  r_data = r_resp.json()
  assert r_data["status"] == "ready"
  assert r_data["database"] == "connected"
  assert r_data["graph"] == TEST_GRAPH_KEY


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_api_graph_seed_and_topology(live_client):
  """Verifies POST /api/v1/graph/seed and GET /api/v1/graph/topology against live FalkorDB Cloud."""
  # Seed idempotently
  seed_resp = live_client.post("/api/v1/graph/seed", json={"clean_first": False})
  assert seed_resp.status_code == 201
  s_data = seed_resp.json()
  assert s_data["total_nodes"] == 11
  assert s_data["total_edges"] == 11
  assert s_data["is_synthetic"] is True

  # Query topology
  topo_resp = live_client.get("/api/v1/graph/topology")
  assert topo_resp.status_code == 200
  t_data = topo_resp.json()
  assert t_data["total_nodes"] == 11
  assert t_data["total_edges"] == 11
  assert len(t_data["nodes"]) == 11
  assert len(t_data["edges"]) == 11
  assert t_data["is_synthetic"] is True


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_api_paths_discover(live_client):
  """Verifies GET /api/v1/paths/discover against live FalkorDB Cloud."""
  resp = live_client.get("/api/v1/paths/discover?source_id=usr_jdoe&target_id=db_customer_vault&max_depth=6")
  assert resp.status_code == 200
  data = resp.json()
  assert data["status"] == "PATHS_DISCOVERED"
  assert data["total_paths_found"] == 2
  assert len(data["paths"]) == 2

  # Check primary (3 hops) and alternative (4 hops)
  assert data["paths"][0]["hop_count"] == 3
  assert data["paths"][1]["hop_count"] == 4


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_api_investigate_explain(live_client):
  """Verifies POST /api/v1/investigate/explain on live FalkorDB returns evidence and risk heuristics."""
  payload = {
      "source_id": "usr_jdoe",
      "target_id": "db_customer_vault",
      "max_depth": 6,
      "limit": 10,
  }
  resp = live_client.post("/api/v1/investigate/explain", json=payload)
  assert resp.status_code == 200
  data = resp.json()

  assert data["status"] == "PATHS_DISCOVERED"
  assert data["total_paths_found"] == 2
  assert len(data["paths"]) == 2
  assert data["is_synthetic"] is True
  assert "heuristic only" in data["disclaimer"].lower()

  # Check evidence and risk details on primary route
  primary = data["paths"][0]
  assert primary["path"]["hop_count"] == 3
  assert len(primary["evidence"]["ordered_nodes"]) == 4
  assert len(primary["evidence"]["ordered_edges"]) == 3
  assert primary["risk_assessment"]["risk_tier"] == "CRITICAL"
  assert primary["risk_assessment"]["score"] == 100.0


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_api_remediate_primary_route(live_client):
  """Simulates revoking role_order_service CAN_ACCESS db_customer_vault on live FalkorDB clone."""
  payload = {
      "revocation": {
          "source_id": "role_order_service",
          "rel_type": "CAN_ACCESS",
          "target_id": "db_customer_vault",
      },
      "source_id": "usr_jdoe",
      "target_id": "db_customer_vault",
  }
  resp = live_client.post("/api/v1/remediate/simulate-and-verify", json=payload)
  assert resp.status_code == 200
  data = resp.json()

  assert data["status"] == "VERIFIED_SEVERED"
  assert data["success"] is True
  assert data["original_path_severed"] is True
  assert data["target_still_reachable"] is True
  assert data["residual_paths_count"] == 1
  assert data["baseline_intact"] is True
  assert data["clone_cleaned_up"] is True


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_api_remediate_shared_entry_route(live_client):
  """Simulates revoking usr_jdoe AUTHENTICATES_TO srv_app_prod on live FalkorDB clone."""
  payload = {
      "revocation": {
          "source_id": "usr_jdoe",
          "rel_type": "AUTHENTICATES_TO",
          "target_id": "srv_app_prod",
      },
      "source_id": "usr_jdoe",
      "target_id": "db_customer_vault",
  }
  resp = live_client.post("/api/v1/remediate/simulate-and-verify", json=payload)
  assert resp.status_code == 200
  data = resp.json()

  assert data["status"] == "VERIFIED_SEVERED"
  assert data["success"] is True
  assert data["original_path_severed"] is True
  assert data["target_still_reachable"] is False
  assert data["residual_paths_count"] == 0
  assert data["baseline_intact"] is True
  assert data["clone_cleaned_up"] is True
