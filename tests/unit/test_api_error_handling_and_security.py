"""Unit tests verifying error response formatting, schema validation, and secret redaction."""

import pytest
from fastapi.testclient import TestClient
from attackpath.api.app import app
from attackpath.api.dependencies import get_repository


@pytest.fixture
def client():
  with TestClient(app) as test_client:
    yield test_client
  app.dependency_overrides.clear()


def test_schema_validation_error_format(client):
  """Ensures 422 validation errors match standardized error format."""
  # Missing required body
  resp = client.post("/api/v1/investigate/explain", json={})
  assert resp.status_code == 422
  data = resp.json()

  assert "error" in data
  assert data["error"]["code"] == "VALIDATION_ERROR"
  assert "details" in data["error"]
  assert isinstance(data["error"]["details"], list)


def test_unhandled_exception_sanitization():
  """Ensures unhandled 500 exceptions return safe message and leak no internal stack traces."""
  class ExplodingRepo:
    def get_topology(self):
      raise RuntimeError("Unexpected internal crash with internal_token=SECRET_123456")

  app.dependency_overrides[get_repository] = lambda: ExplodingRepo()

  try:
    with TestClient(app, raise_server_exceptions=False) as safe_client:
      resp = safe_client.get("/api/v1/graph/topology")
      assert resp.status_code == 500
      data = resp.json()

      assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
      assert "unexpected internal server error" in data["error"]["message"].lower()

      # Ensure stack trace and secret token were redacted from client response
      body_text = resp.text
      assert "SECRET_123456" not in body_text
      assert "Traceback" not in body_text
  finally:
    app.dependency_overrides.clear()


def test_generic_connection_error_sanitization(client):
  """Ensures connection error returns 503 DATABASE_UNAVAILABLE without leaking connection strings."""
  class ConnectionFailingRepo:
    def get_topology(self):
      raise ConnectionError("Failed to reach rediss://user:SUPER_SECRET_PASS@redis.cloud:6379")

  app.dependency_overrides[get_repository] = lambda: ConnectionFailingRepo()

  resp = client.get("/api/v1/graph/topology")
  assert resp.status_code == 503
  data = resp.json()

  assert data["error"]["code"] == "DATABASE_UNAVAILABLE"
  body_text = resp.text
  assert "SUPER_SECRET_PASS" not in body_text
  assert "rediss://" not in body_text
