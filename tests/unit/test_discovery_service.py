"""Unit tests for the AttackPath DiscoveryService using offline adapter."""

import pytest
from attackpath.domain.service_models import DiscoveryResult
from attackpath.services.discovery_service import DiscoveryService
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def offline_repo():
  repo = NetworkXTestAdapter("offline_discovery_test")
  repo.seed_synthetic_scenario(clean_first=True)
  return repo


@pytest.fixture
def discovery_service(offline_repo):
  return DiscoveryService(repository=offline_repo)


def test_discovery_valid_two_paths(discovery_service):
  """Verifies that discovery on the seeded topology finds exactly 2 paths."""
  res = discovery_service.discover_paths(
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
      limit=10,
  )

  assert isinstance(res, DiscoveryResult)
  assert res.status == "PATHS_DISCOVERED"
  assert res.total_paths_found == 2
  assert len(res.paths) == 2
  assert res.is_synthetic is True

  # Primary path (3 hops)
  p1 = res.paths[0]
  assert p1.hop_count == 3
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

  # Alternative path (4 hops)
  p2 = res.paths[1]
  assert p2.hop_count == 4
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


def test_discovery_enforces_max_depth_cap(discovery_service):
  """Ensures max_depth cannot exceed the hard ceiling of 6."""
  res = discovery_service.discover_paths(
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=15,  # Exceeds max allowable
  )
  assert res.max_depth_applied == 6
  assert res.status == "PATHS_DISCOVERED"


def test_discovery_input_validation_empty_or_blank_ids(discovery_service):
  """Ensures invalid or empty entity IDs result in INVALID_REQUEST status."""
  res1 = discovery_service.discover_paths(source_id="", target_id="db_customer_vault")
  assert res1.status == "INVALID_REQUEST"
  assert res1.total_paths_found == 0

  res2 = discovery_service.discover_paths(source_id="   ", target_id="db_customer_vault")
  assert res2.status == "INVALID_REQUEST"

  res3 = discovery_service.discover_paths(source_id="usr_jdoe", target_id="   ")
  assert res3.status == "INVALID_REQUEST"


def test_discovery_missing_entity_distinction(discovery_service):
  """Ensures ENTITY_NOT_FOUND is returned when one or both entities are not in the graph."""
  # Nonexistent source
  res1 = discovery_service.discover_paths(
      source_id="usr_ghost",
      target_id="db_customer_vault",
  )
  assert res1.status == "ENTITY_NOT_FOUND"
  assert "Source entity 'usr_ghost' does not exist" in res1.details

  # Nonexistent target
  res2 = discovery_service.discover_paths(
      source_id="usr_jdoe",
      target_id="asset_nonexistent",
  )
  assert res2.status == "ENTITY_NOT_FOUND"
  assert "Target entity 'asset_nonexistent' does not exist" in res2.details

  # Neither exists
  res3 = discovery_service.discover_paths(
      source_id="usr_nonexistent",
      target_id="asset_nonexistent",
  )
  assert res3.status == "ENTITY_NOT_FOUND"
  assert "Neither source entity" in res3.details


def test_discovery_unreachable_target_distinction(offline_repo, discovery_service):
  """Ensures TARGET_UNREACHABLE is returned when both entities exist but no path connects them."""
  # In the synthetic scenario, sa_deployer cannot reach db_customer_vault
  res = discovery_service.discover_paths(
      source_id="sa_deployer",
      target_id="db_customer_vault",
      max_depth=6,
  )
  assert res.status == "TARGET_UNREACHABLE"
  assert res.total_paths_found == 0
  assert "is unreachable from source" in res.details


def test_discovery_database_error_handling(offline_repo):
  """Ensures database failures produce a structured DATABASE_ERROR rather than swallowing or crashing."""
  class FailingRepo:
    def find_paths(self, *args, **kwargs):
      raise ConnectionError("Simulated FalkorDB connection timeout")

  service = DiscoveryService(repository=FailingRepo())
  res = service.discover_paths(source_id="usr_jdoe", target_id="db_customer_vault")

  assert res.status == "DATABASE_ERROR"
  assert "Simulated FalkorDB connection timeout" in res.details
