"""Unit tests for /api/v1/investigate/explain endpoint."""

import pytest
from fastapi.testclient import TestClient
from attackpath.api.app import app
from attackpath.api.dependencies import get_discovery_service, get_repository
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def offline_repo():
  repo = NetworkXTestAdapter("offline_investigate_api_test")
  repo.seed_synthetic_scenario(clean_first=True)
  return repo


@pytest.fixture
def client(offline_repo):
  app.dependency_overrides[get_repository] = lambda: offline_repo
  with TestClient(app) as test_client:
    yield test_client
  app.dependency_overrides.clear()


def test_investigate_explain_success(client):
  """Ensures POST /api/v1/investigate/explain returns complete investigation package."""
  payload = {
      "source_id": "usr_jdoe",
      "target_id": "db_customer_vault",
      "max_depth": 6,
      "limit": 10,
  }
  resp = client.post("/api/v1/investigate/explain", json=payload)
  assert resp.status_code == 200
  data = resp.json()

  assert data["status"] == "PATHS_DISCOVERED"
  assert data["total_paths_found"] == 2
  assert len(data["paths"]) == 2
  assert data["is_synthetic"] is True
  assert "heuristic only" in data["disclaimer"].lower()

  # Check primary path details
  primary = data["paths"][0]
  assert primary["path"]["hop_count"] == 3
  assert primary["evidence"]["path_id"] == "path_1"
  assert len(primary["evidence"]["ordered_nodes"]) == 4
  assert len(primary["evidence"]["ordered_edges"]) == 3
  assert "Step 1:" in primary["evidence"]["route_summary"]

  # Check risk assessment details
  risk = primary["risk_assessment"]
  assert risk["risk_tier"] == "CRITICAL"
  assert risk["score"] == 100.0
  assert len(risk["contributions"]) > 0
  assert any(c["rule_id"] == "RULE_COMPROMISED_IDENTITY" for c in risk["contributions"])
  assert any(c["rule_id"] == "RULE_CROWN_JEWEL_TARGET" for c in risk["contributions"])


def test_investigate_explain_unreachable_target(client):
  """Ensures unreachable target returns 200 with TARGET_UNREACHABLE status."""
  payload = {
      "source_id": "sa_deployer",
      "target_id": "db_customer_vault",
  }
  resp = client.post("/api/v1/investigate/explain", json=payload)
  assert resp.status_code == 200
  data = resp.json()
  assert data["status"] == "TARGET_UNREACHABLE"
  assert data["total_paths_found"] == 0
  assert len(data["paths"]) == 0


def test_investigate_explain_missing_entity_returns_404(client):
  """Ensures nonexistent entity returns 404 Not Found."""
  payload = {
      "source_id": "usr_nonexistent",
      "target_id": "db_customer_vault",
  }
  resp = client.post("/api/v1/investigate/explain", json=payload)
  assert resp.status_code == 404
  data = resp.json()
  assert data["error"]["code"] == "NOT_FOUND"
  assert "does not exist" in data["error"]["message"].lower()


def test_investigate_explain_database_error_returns_503(client):
  """Ensures database outage during investigation returns 503 Service Unavailable."""
  class FailingDiscoveryService:
    def discover_paths(self, *args, **kwargs):
      from attackpath.domain.service_models import DiscoveryResult
      return DiscoveryResult(
          status="DATABASE_ERROR",
          source_id="usr_jdoe",
          target_id="db_customer_vault",
          details="Simulated database outage",
      )

  app.dependency_overrides[get_discovery_service] = lambda: FailingDiscoveryService()

  payload = {
      "source_id": "usr_jdoe",
      "target_id": "db_customer_vault",
  }
  resp = client.post("/api/v1/investigate/explain", json=payload)
  assert resp.status_code == 503
  data = resp.json()
  assert data["error"]["code"] == "SERVICE_UNAVAILABLE"
