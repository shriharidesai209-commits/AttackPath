"""Unit tests for /api/v1/paths/discover endpoint."""

import pytest
from fastapi.testclient import TestClient
from attackpath.api.app import app
from attackpath.api.dependencies import get_discovery_service, get_repository
from attackpath.services.discovery_service import DiscoveryService
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def offline_repo():
  repo = NetworkXTestAdapter("offline_paths_api_test")
  repo.seed_synthetic_scenario(clean_first=True)
  return repo


@pytest.fixture
def client(offline_repo):
  app.dependency_overrides[get_repository] = lambda: offline_repo
  with TestClient(app) as test_client:
    yield test_client
  app.dependency_overrides.clear()


def test_paths_discover_success(client):
  """Ensures GET /api/v1/paths/discover returns the expected 2 paths with 200 status."""
  resp = client.get("/api/v1/paths/discover?source_id=usr_jdoe&target_id=db_customer_vault")
  assert resp.status_code == 200
  data = resp.json()
  assert data["status"] == "PATHS_DISCOVERED"
  assert data["total_paths_found"] == 2
  assert len(data["paths"]) == 2
  assert data["paths"][0]["hop_count"] == 3
  assert data["paths"][1]["hop_count"] == 4


def test_paths_discover_unreachable_target(client):
  """Ensures unreachable targets return 200 with TARGET_UNREACHABLE status and 0 paths."""
  resp = client.get("/api/v1/paths/discover?source_id=sa_deployer&target_id=db_customer_vault")
  assert resp.status_code == 200
  data = resp.json()
  assert data["status"] == "TARGET_UNREACHABLE"
  assert data["total_paths_found"] == 0
  assert len(data["paths"]) == 0


def test_paths_discover_missing_entity_returns_404(client):
  """Ensures nonexistent source or target returns 404 Not Found."""
  resp = client.get("/api/v1/paths/discover?source_id=usr_ghost&target_id=db_customer_vault")
  assert resp.status_code == 404
  data = resp.json()
  assert "error" in data
  assert data["error"]["code"] == "NOT_FOUND"
  assert "does not exist" in data["error"]["message"].lower()


def test_paths_discover_validation_bounds_capped_at_6(client):
  """Ensures query parameter validation rejects max_depth > 6 with 422."""
  resp = client.get("/api/v1/paths/discover?source_id=usr_jdoe&target_id=db_customer_vault&max_depth=10")
  assert resp.status_code == 422
  data = resp.json()
  assert data["error"]["code"] == "VALIDATION_ERROR"


def test_paths_discover_database_error_returns_503(client):
  """Ensures database query failure returns 503 Service Unavailable."""
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

  resp = client.get("/api/v1/paths/discover?source_id=usr_jdoe&target_id=db_customer_vault")
  assert resp.status_code == 503
  data = resp.json()
  assert data["error"]["code"] == "SERVICE_UNAVAILABLE"
