"""Unit tests for /health and /health/ready endpoints using dependency overrides."""

import pytest
from fastapi.testclient import TestClient
from attackpath.api.app import app
from attackpath.api.dependencies import get_falkordb_client, get_settings
from attackpath.config import Settings
from attackpath.database.connection import FalkorDBConnectionError


@pytest.fixture
def client():
  with TestClient(app) as test_client:
    yield test_client
  app.dependency_overrides.clear()


def test_health_liveness_endpoint(client):
  """Ensures /health returns 200 ok independent of database connectivity and leaks no secrets."""
  resp = client.get("/health")
  assert resp.status_code == 200
  data = resp.json()
  assert data["status"] == "ok"
  assert data["app"] == "AttackPath"
  assert "environment" in data

  # Ensure no credentials or connection string fragments leaked
  body_text = resp.text.lower()
  assert "password" not in body_text
  assert "secret" not in body_text
  assert "falkordb://" not in body_text
  assert "redis://" not in body_text


def test_health_readiness_database_connected(client):
  """Ensures /health/ready returns 200 when FalkorDB is responsive."""
  class MockHealthyClient:
    def list_graphs(self):
      return ["attackpath_baseline"]

  app.dependency_overrides[get_falkordb_client] = lambda: MockHealthyClient()

  resp = client.get("/health/ready")
  assert resp.status_code == 200
  data = resp.json()
  assert data["status"] == "ready"
  assert data["database"] == "connected"
  assert "graph" in data


def test_health_readiness_database_unresponsive(client):
  """Ensures /health/ready returns 503 when FalkorDB ping fails."""
  class MockUnresponsiveClient:
    def list_graphs(self):
      raise TimeoutError("Connection timed out")

  app.dependency_overrides[get_falkordb_client] = lambda: MockUnresponsiveClient()

  resp = client.get("/health/ready")
  assert resp.status_code == 503
  data = resp.json()
  assert "error" in data
  assert data["error"]["code"] == "SERVICE_UNAVAILABLE"
  assert "not responsive" in data["error"]["message"].lower() or "not reachable" in data["error"]["message"].lower()


def test_health_readiness_connection_error_redaction(client):
  """Ensures database connection errors return 503 and sanitize diagnostic URI secrets."""
  def mock_failing_client():
    raise FalkorDBConnectionError(
        message="Connection failed to cluster",
        diagnostic_uri="rediss://admin:SECRET_PASSWORD@cloud.falkordb.com:6380/test",
    )

  app.dependency_overrides[get_falkordb_client] = mock_failing_client

  resp = client.get("/health/ready")
  assert resp.status_code == 503
  data = resp.json()
  assert data["error"]["code"] == "DATABASE_UNAVAILABLE"

  # Ensure raw exception message and password were not exposed to client
  body_text = resp.text
  assert "SECRET_PASSWORD" not in body_text
  assert "cloud.falkordb.com" not in body_text
