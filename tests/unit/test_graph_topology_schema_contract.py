"""Unit tests ensuring topology and investigation API schema contracts match frontend expectations.

Validates that:
1. Discovered path nodes and edges conform to frontend BaseEntityNode and GraphEdge schemas.
2. Discovered paths can be cleanly extracted into unique nodes and edges without missing endpoints.
3. Every edge references valid source and target nodes within the path node set.
4. Topology data matches discovered path data entity IDs and labels.
"""

import pytest
from fastapi.testclient import TestClient
from attackpath.api.app import app
from attackpath.api.dependencies import get_repository
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def offline_repo():
  repo = NetworkXTestAdapter("contract_test_graph")
  repo.seed_synthetic_scenario(clean_first=True)
  return repo


@pytest.fixture
def client(offline_repo):
  app.dependency_overrides[get_repository] = lambda: offline_repo
  with TestClient(app) as test_client:
    yield test_client
  app.dependency_overrides.clear()


def test_investigation_and_topology_schema_contract(client):
  """Verify that topology and investigation endpoints provide all fields required by the frontend canvas."""
  # 1. Fetch Topology
  topo_resp = client.get("/api/v1/graph/topology")
  assert topo_resp.status_code == 200
  topo = topo_resp.json()

  assert "nodes" in topo
  assert "edges" in topo
  assert len(topo["nodes"]) > 0
  assert len(topo["edges"]) > 0

  topo_node_ids = {n["id"] for n in topo["nodes"]}
  topo_labels = {n["id"]: n["label"] for n in topo["nodes"]}

  for edge in topo["edges"]:
    assert "source" in edge
    assert "target" in edge
    assert "type" in edge
    assert edge["source"] in topo_node_ids, f"Edge source {edge['source']} missing from topology nodes"
    assert edge["target"] in topo_node_ids, f"Edge target {edge['target']} missing from topology nodes"

  # 2. Fetch Investigation
  inv_resp = client.post(
      "/api/v1/investigate/explain",
      json={
          "source_id": "usr_jdoe",
          "target_id": "db_customer_vault",
          "max_depth": 6,
          "limit": 10,
      },
  )
  assert inv_resp.status_code == 200
  inv = inv_resp.json()

  assert inv["status"] == "PATHS_DISCOVERED"
  assert len(inv["paths"]) > 0

  # Simulate the frontend useMemo logic to collect unique nodes and edges
  node_map = {}
  edge_map = {}

  for path_item in inv["paths"]:
    path = path_item["path"]
    assert "nodes" in path
    assert "edges" in path
    assert "hop_count" in path

    for node in path["nodes"]:
      assert "id" in node
      assert "label" in node
      assert "name" in node
      node_map[node["id"]] = node

      # Validate against topology
      assert node["id"] in topo_node_ids
      assert node["label"] == topo_labels[node["id"]]

    for edge in path["edges"]:
      assert "source" in edge
      assert "target" in edge
      assert "type" in edge
      edge_key = f"{edge['source']}->{edge['target']}"
      edge_map[edge_key] = edge

  # Verify every collected edge connects known collected nodes
  for edge_key, edge in edge_map.items():
    assert edge["source"] in node_map, f"Discovered edge {edge_key} references unmapped source {edge['source']}"
    assert edge["target"] in node_map, f"Discovered edge {edge_key} references unmapped target {edge['target']}"

  # Verify expected benchmark scenario nodes are all present
  expected_ids = {"usr_jdoe", "srv_app_prod", "role_order_service", "db_customer_vault"}
  assert expected_ids.issubset(set(node_map.keys()))
