"""Unit tests for /api/v1/graph/seed and /api/v1/graph/topology endpoints."""

import pytest
from fastapi.testclient import TestClient
from attackpath.api.app import app
from attackpath.api.dependencies import get_repository
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def offline_repo():
  repo = NetworkXTestAdapter("offline_graph_api_test")
  return repo


@pytest.fixture
def client(offline_repo):
  app.dependency_overrides[get_repository] = lambda: offline_repo
  with TestClient(app) as test_client:
    yield test_client
  app.dependency_overrides.clear()


def test_graph_seed_default_idempotent(client, offline_repo):
  """Ensures POST /api/v1/graph/seed with default parameters seeds safely without duplicates on retry."""
  resp = client.post("/api/v1/graph/seed", json={})
  assert resp.status_code == 201
  data = resp.json()
  assert data["status"] == "success"
  assert data["nodes_created"] == 11
  assert data["relationships_created"] == 11
  assert data["total_nodes"] == 11
  assert data["total_edges"] == 11
  assert data["is_synthetic"] is True

  # Retry seeding (idempotency check)
  resp2 = client.post("/api/v1/graph/seed", json={"clean_first": False})
  assert resp2.status_code == 201
  data2 = resp2.json()
  assert data2["total_nodes"] == 11
  assert data2["total_edges"] == 11


def test_graph_seed_clean_first(client, offline_repo):
  """Ensures POST /api/v1/graph/seed with explicit clean_first=True re-clears and seeds."""
  resp = client.post("/api/v1/graph/seed", json={"clean_first": True})
  assert resp.status_code == 201
  data = resp.json()
  assert data["total_nodes"] == 11
  assert data["total_edges"] == 11


def test_graph_topology_endpoint(client, offline_repo):
  """Ensures GET /api/v1/graph/topology returns complete topology with synthetic metadata."""
  offline_repo.seed_synthetic_scenario(clean_first=True)

  resp = client.get("/api/v1/graph/topology")
  assert resp.status_code == 200
  data = resp.json()
  assert data["total_nodes"] == 11
  assert data["total_edges"] == 11
  assert len(data["nodes"]) == 11
  assert len(data["edges"]) == 11
  assert data["is_synthetic"] is True

  # Validate node structure
  first_node = data["nodes"][0]
  assert "id" in first_node
  assert "label" in first_node
  assert "name" in first_node
  assert "is_synthetic" in first_node

  # Validate edge structure
  first_edge = data["edges"][0]
  assert "source" in first_edge
  assert "target" in first_edge
  assert "type" in first_edge
  assert "is_synthetic" in first_edge


def test_graph_topology_empty_graph(client, offline_repo):
  """Ensures GET /api/v1/graph/topology handles an empty graph safely without errors."""
  offline_repo.clear_graph()

  resp = client.get("/api/v1/graph/topology")
  assert resp.status_code == 200
  data = resp.json()
  assert data["total_nodes"] == 0
  assert data["total_edges"] == 0
  assert data["nodes"] == []
  assert data["edges"] == []
