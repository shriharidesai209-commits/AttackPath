"""Unit tests for the isolated RemediationService using offline adapter."""

import pytest
from attackpath.domain.path import EdgeRevocation
from attackpath.services.remediation_service import RemediationService
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def offline_repo():
  repo = NetworkXTestAdapter("offline_remediation_test")
  repo.seed_synthetic_scenario(clean_first=True)
  return repo


@pytest.fixture
def remediation_service(offline_repo):
  return RemediationService(repository=offline_repo)


def test_remediation_input_validation(remediation_service):
  """Ensures empty or whitespace relationship endpoints are rejected safely."""
  rev = EdgeRevocation(source_id="   ", rel_type="CAN_ACCESS", target_id="db_customer_vault")
  res = remediation_service.simulate_and_verify_remediation(revocation=rev)

  assert res.status == "MUTATION_REJECTED"
  assert res.success is False
  assert res.baseline_intact is True
  assert "cannot be empty" in res.details


def test_remediation_primary_path_severed_alternative_remains(offline_repo, remediation_service):
  """Simulates revoking role_order_service CAN_ACCESS db_customer_vault.

  Must sever the 3-hop primary path while preserving the 4-hop alternative path.
  Baseline graph must remain completely untouched.
  """
  initial_nodes = offline_repo.count_nodes()
  initial_edges = offline_repo.count_edges()

  rev = EdgeRevocation(
      source_id="role_order_service",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )

  res = remediation_service.simulate_and_verify_remediation(
      revocation=rev,
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
  )

  assert res.status == "VERIFIED_SEVERED"
  assert res.success is True
  assert res.original_path_severed is True
  assert res.target_still_reachable is True
  assert res.before_paths_count == 2
  assert res.residual_paths_count == 1
  assert len(res.residual_paths) == 1

  # Residual path must be the 4-hop alternative path
  residual = res.residual_paths[0]
  assert residual.hop_count == 4
  assert [n.id for n in residual.nodes] == [
      "usr_jdoe",
      "srv_app_prod",
      "srv_analytics_worker",
      "role_analytics_readonly",
      "db_customer_vault",
  ]

  # Verify baseline immutability
  assert res.baseline_intact is True
  assert offline_repo.count_nodes() == initial_nodes
  assert offline_repo.count_edges() == initial_edges
  assert res.clone_cleaned_up is True


def test_remediation_shared_entry_edge_severs_all_paths(offline_repo, remediation_service):
  """Simulates revoking usr_jdoe AUTHENTICATES_TO srv_app_prod.

  Must sever all routes, leaving target completely unreachable.
  """
  initial_nodes = offline_repo.count_nodes()
  initial_edges = offline_repo.count_edges()

  rev = EdgeRevocation(
      source_id="usr_jdoe",
      rel_type="AUTHENTICATES_TO",
      target_id="srv_app_prod",
  )

  res = remediation_service.simulate_and_verify_remediation(
      revocation=rev,
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
  )

  assert res.status == "VERIFIED_SEVERED"
  assert res.success is True
  assert res.original_path_severed is True
  assert res.target_still_reachable is False
  assert res.residual_paths_count == 0
  assert len(res.residual_paths) == 0

  # Verify baseline immutability
  assert res.baseline_intact is True
  assert offline_repo.count_nodes() == initial_nodes
  assert offline_repo.count_edges() == initial_edges
  assert res.clone_cleaned_up is True


def test_remediation_nonexistent_relationship_rejected(offline_repo, remediation_service):
  """Ensures trying to revoke a nonexistent edge fails safely without mutating anything."""
  initial_nodes = offline_repo.count_nodes()
  initial_edges = offline_repo.count_edges()

  rev = EdgeRevocation(
      source_id="usr_jdoe",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )

  res = remediation_service.simulate_and_verify_remediation(
      revocation=rev,
      source_id="usr_jdoe",
      target_id="db_customer_vault",
  )

  assert res.status == "MUTATION_REJECTED"
  assert res.success is False
  assert "does not exist" in res.details
  assert offline_repo.count_nodes() == initial_nodes
  assert offline_repo.count_edges() == initial_edges


def test_remediation_ambiguous_relationship_rejected(offline_repo, remediation_service):
  """Ensures ambiguous relationships (multiple edges between same nodes with same type) are rejected."""
  # Add a second parallel edge between same pair with same type in the repository
  offline_repo.g.add_edge(
      "role_order_service",
      "db_customer_vault",
      key="second_can_access",
      type="CAN_ACCESS",
      permission="rds:ReadOnly",
  )

  rev = EdgeRevocation(
      source_id="role_order_service",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )

  res = remediation_service.simulate_and_verify_remediation(
      revocation=rev,
      source_id="usr_jdoe",
      target_id="db_customer_vault",
  )

  assert res.status == "MUTATION_REJECTED"
  assert res.success is False
  assert "Ambiguous relationship" in res.warnings[0]


def test_remediation_clone_cleanup_on_injected_failure(offline_repo):
  """Verifies that temporary clone is deleted even when an error occurs during simulation."""
  class FailingCloneRepo:
    def __init__(self, inner):
      self.inner = inner
      self.deleted = False

    def count_nodes(self):
      return self.inner.count_nodes()

    def count_edges(self):
      return self.inner.count_edges()

    def find_relationships(self, *args, **kwargs):
      # Injected failure mid-process
      raise RuntimeError("Injected runtime failure during edge lookup")

    def delete_graph(self):
      self.deleted = True
      self.inner.delete_graph()

  class CustomRepo(NetworkXTestAdapter):
    def create_clone_repository(self, clone_name):
      clone = super().create_clone_repository(clone_name)
      self.failing_clone = FailingCloneRepo(clone)
      return self.failing_clone

  repo = CustomRepo("injected_fail_test")
  repo.seed_synthetic_scenario(clean_first=True)
  svc = RemediationService(repository=repo)

  rev = EdgeRevocation(
      source_id="role_order_service",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )

  with pytest.raises(RuntimeError, match="Injected runtime failure"):
    svc.simulate_and_verify_remediation(revocation=rev)

  # Check that clone's delete_graph was still executed in finally block!
  assert repo.failing_clone.deleted is True


def test_remediation_compound_severance_outcome_a(offline_repo, remediation_service):
  """Simulates compound revocation: role_order_service CAN_ACCESS db_customer_vault

  AND srv_app_prod NETWORK_REACHABLE srv_analytics_worker.
  Must achieve Outcome A: zero remaining routes, target completely unreachable,
  residual risk score 0.0, and baseline graph unchanged.
  """
  initial_nodes = offline_repo.count_nodes()
  initial_edges = offline_repo.count_edges()

  primary_rev = EdgeRevocation(
      source_id="role_order_service",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )
  analytics_rev = EdgeRevocation(
      source_id="srv_app_prod",
      rel_type="NETWORK_REACHABLE",
      target_id="srv_analytics_worker",
  )

  res = remediation_service.simulate_and_verify_remediation(
      revocation=primary_rev,
      additional_revocations=[analytics_rev],
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
  )

  assert res.status == "VERIFIED_SEVERED"
  assert res.success is True
  assert res.original_path_severed is True
  assert res.target_still_reachable is False
  assert res.residual_paths_count == 0
  assert len(res.residual_paths) == 0
  assert res.residual_risk_score == 0.0
  assert res.residual_risk_tier == "INFORMATIONAL"

  # Baseline graph immutability
  assert res.baseline_intact is True
  assert offline_repo.count_nodes() == initial_nodes
  assert offline_repo.count_edges() == initial_edges
  assert res.clone_cleaned_up is True
