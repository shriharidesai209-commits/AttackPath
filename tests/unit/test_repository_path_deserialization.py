"""Focused unit regression tests for FalkorDB path deserialization.

Verifies that FalkorDBRepository.find_paths correctly maps internal node IDs
returned by falkordb 1.7.1 runtime Edge endpoints (where raw_edge.src_node and
raw_edge.dest_node are internal integers) to stable application entity IDs,
satisfying AttackPath continuity validation.
"""

from unittest.mock import MagicMock
import falkordb
import pytest
from attackpath.database.repository import FalkorDBRepository
from attackpath.domain.path import AttackPath


def _create_mock_repo() -> FalkorDBRepository:
  """Creates a FalkorDBRepository with a mocked client and graph."""
  mock_client = MagicMock(spec=falkordb.FalkorDB)
  mock_graph = MagicMock(spec=falkordb.Graph)
  mock_client.select_graph.return_value = mock_graph
  return FalkorDBRepository(mock_client, graph_name="test_graph")


def test_path_deserialization_with_internal_integer_endpoints():
  """Reproduces the runtime endpoint representation where FalkorDB Edge endpoints are internal ints.

  Before the fix, this raised:
  ValidationError: Edge 0 source '10' does not match preceding node id 'usr_jdoe'
  """
  repo = _create_mock_repo()

  # Real falkordb.Node instances with internal numeric IDs and properties dict
  node_user = falkordb.Node(
      node_id=10,
      labels=["Identity"],
      properties={
          "id": "usr_jdoe",
          "name": "John Doe",
          "kind": "human",
          "is_synthetic": True,
      },
  )
  node_server = falkordb.Node(
      node_id=7,
      labels=["Workload"],
      properties={
          "id": "srv_app_prod",
          "name": "App-Server-Prod",
          "kind": "virtual_machine",
          "is_synthetic": True,
      },
  )
  node_role = falkordb.Node(
      node_id=4,
      labels=["IAMRole"],
      properties={
          "id": "role_order_service",
          "name": "OrderServiceRole",
          "is_synthetic": True,
      },
  )
  node_db = falkordb.Node(
      node_id=1,
      labels=["DataAsset"],
      properties={
          "id": "db_customer_vault",
          "name": "Customer-Vault-DB",
          "is_synthetic": True,
      },
  )

  # FalkorDB client 1.7.1 __parse_edge produces Edge instances with integer src_node and dest_node
  edge_auth = falkordb.Edge(
      src_node=10,
      relation="AUTHENTICATES_TO",
      dest_node=7,
      edge_id=101,
      properties={"method": "SSH", "is_synthetic": True},
  )
  edge_exec = falkordb.Edge(
      src_node=7,
      relation="EXECUTES_AS",
      dest_node=4,
      edge_id=102,
      properties={"source": "IMDS", "is_synthetic": True},
  )
  edge_access = falkordb.Edge(
      src_node=4,
      relation="CAN_ACCESS",
      dest_node=1,
      edge_id=103,
      properties={"permission": "rds:FullAccess", "is_synthetic": True},
  )

  # Real falkordb.Path object
  path_obj = falkordb.Path(
      nodes=[node_user, node_server, node_role, node_db],
      edges=[edge_auth, edge_exec, edge_access],
  )

  mock_result = MagicMock()
  mock_result.result_set = [[path_obj, 3]]
  repo.ro_query = MagicMock(return_value=mock_result)

  paths = repo.find_paths("usr_jdoe", "db_customer_vault")

  assert len(paths) == 1
  path = paths[0]
  assert isinstance(path, AttackPath)
  assert path.hop_count == 3
  assert len(path.nodes) == 4
  assert len(path.edges) == 3

  # Verify nodes use stable entity IDs
  assert [n.id for n in path.nodes] == [
      "usr_jdoe",
      "srv_app_prod",
      "role_order_service",
      "db_customer_vault",
  ]

  # Verify edge sources and targets match stable entity IDs and consecutive nodes
  assert path.edges[0].source == "usr_jdoe"
  assert path.edges[0].target == "srv_app_prod"
  assert path.edges[0].type == "AUTHENTICATES_TO"
  assert path.edges[0].properties["method"] == "SSH"
  assert path.edges[0].is_synthetic is True

  assert path.edges[1].source == "srv_app_prod"
  assert path.edges[1].target == "role_order_service"
  assert path.edges[1].type == "EXECUTES_AS"

  assert path.edges[2].source == "role_order_service"
  assert path.edges[2].target == "db_customer_vault"
  assert path.edges[2].type == "CAN_ACCESS"


def test_path_deserialization_with_node_instance_endpoints():
  """Verifies deserialization when edges are constructed with Node instances instead of ints."""
  repo = _create_mock_repo()

  node_a = falkordb.Node(
      node_id=20,
      labels=["Identity"],
      properties={"id": "usr_alice", "name": "Alice", "is_synthetic": True},
  )
  node_b = falkordb.Node(
      node_id=21,
      labels=["Workload"],
      properties={"id": "srv_web", "name": "Web", "is_synthetic": True},
  )

  edge_ab = falkordb.Edge(
      src_node=node_a,
      relation="AUTHENTICATES_TO",
      dest_node=node_b,
      edge_id=201,
      properties={"is_synthetic": True},
  )

  path_obj = falkordb.Path(nodes=[node_a, node_b], edges=[edge_ab])
  mock_result = MagicMock()
  mock_result.result_set = [[path_obj, 1]]
  repo.ro_query = MagicMock(return_value=mock_result)

  paths = repo.find_paths("usr_alice", "srv_web")

  assert len(paths) == 1
  path = paths[0]
  assert path.edges[0].source == "usr_alice"
  assert path.edges[0].target == "srv_web"


def test_resolve_endpoint_semantics_and_fallbacks():
  """Direct unit tests for FalkorDBRepository._resolve_endpoint."""
  node_id_map = {10: "usr_jdoe", "10": "usr_jdoe", "usr_jdoe": "usr_jdoe"}

  # 1. Node instance with properties['id']
  n_with_props = falkordb.Node(node_id=10, properties={"id": "usr_jdoe"})
  assert FalkorDBRepository._resolve_endpoint(n_with_props, node_id_map, "fb") == "usr_jdoe"

  # 2. Node instance with empty properties, resolved via node.id
  n_empty_props = falkordb.Node(node_id=10, properties={})
  assert FalkorDBRepository._resolve_endpoint(n_empty_props, node_id_map, "fb") == "usr_jdoe"

  # 3. Direct int endpoint (FalkorDB runtime client format)
  assert FalkorDBRepository._resolve_endpoint(10, node_id_map, "fb") == "usr_jdoe"

  # 4. Direct str internal ID
  assert FalkorDBRepository._resolve_endpoint("10", node_id_map, "fb") == "usr_jdoe"

  # 5. Direct stable entity ID str
  assert FalkorDBRepository._resolve_endpoint("usr_jdoe", node_id_map, "fb") == "usr_jdoe"

  # 6. Fallback when unknown or None
  assert FalkorDBRepository._resolve_endpoint(None, node_id_map, "fb") == "fb"
  assert FalkorDBRepository._resolve_endpoint(999, node_id_map, "fb") == "fb"
