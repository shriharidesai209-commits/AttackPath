"""Live integration tests for Milestone 3 application services on FalkorDB Cloud."""

import pytest
from attackpath.config import get_settings
from attackpath.database.connection import (
    create_falkordb_client,
    ping_falkordb,
)
from attackpath.database.repository import FalkorDBRepository
from attackpath.database.seeder import (
    SYNTHETIC_EDGE_COUNT,
    SYNTHETIC_NODE_COUNT,
    seed_synthetic_scenario,
)
from attackpath.domain.path import EdgeRevocation
from attackpath.services.discovery_service import DiscoveryService
from attackpath.services.evidence_service import EvidenceService
from attackpath.services.remediation_service import RemediationService
from attackpath.services.risk_service import RiskPrioritizationService


def _check_live_falkordb() -> tuple[bool, str]:
  """Checks whether the configured FalkorDB instance is live and accessible."""
  try:
    get_settings.cache_clear()
    settings = get_settings()
    client = create_falkordb_client(settings)
    if ping_falkordb(client):
      return True, f"Responsive at {settings.falkordb_connection_uri}"
    return False, f"Ping check failed on {settings.falkordb_connection_uri}"
  except Exception as exc:
    settings = get_settings()
    return False, f"Connection refused/failed on {settings.falkordb_connection_uri} ({exc})"


FALKORDB_AVAILABLE, REASON_DETAIL = _check_live_falkordb()
BLOCKED_REASON = (
    f"BLOCKED: Live FalkorDB server is unreachable. Target: {REASON_DETAIL}. "
    "To unblock: configure environment variables in .env: "
    "FALKORDB_HOST=<host>, FALKORDB_PORT=<port>, FALKORDB_PASSWORD=<password>, FALKORDB_SSL=true/false"
)

TEST_GRAPH_KEY = "attackpath_milestone3_live_test"


@pytest.fixture
def live_repository():
  """Provides a fresh seeded test graph on real FalkorDB, ensuring cleanup after test."""
  settings = get_settings()
  client = create_falkordb_client(settings)
  repo = FalkorDBRepository(client, graph_name=TEST_GRAPH_KEY)
  seed_synthetic_scenario(repo, clean_first=True)
  yield repo
  try:
    repo.clear_graph()
  except Exception:
    pass


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_discovery_service_two_paths(live_repository):
  """Verifies DiscoveryService on real FalkorDB returns exactly the expected two paths."""
  service = DiscoveryService(repository=live_repository)
  result = service.discover_paths(
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
  )

  assert result.status == "PATHS_DISCOVERED"
  assert result.total_paths_found == 2
  assert len(result.paths) == 2
  assert result.is_synthetic is True

  # Primary path: 3 hops
  p1 = result.paths[0]
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

  # Alternative path: 4 hops
  p2 = result.paths[1]
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


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_evidence_and_risk_services(live_repository):
  """Verifies EvidenceService and RiskPrioritizationService on real FalkorDB paths."""
  discovery_svc = DiscoveryService(repository=live_repository)
  evidence_svc = EvidenceService()
  risk_svc = RiskPrioritizationService()

  disc_res = discovery_svc.discover_paths("usr_jdoe", "db_customer_vault")
  assert disc_res.total_paths_found == 2

  primary_path = disc_res.paths[0]

  # Evidence Verification
  evidence = evidence_svc.generate_path_evidence(primary_path)
  assert evidence.path_id == "path_1"
  assert evidence.hop_count == 3
  assert evidence.is_synthetic is True
  assert len(evidence.ordered_nodes) == 4
  assert len(evidence.ordered_edges) == 3

  # Assert graph facts in evidence
  src_facts = " ".join(evidence.ordered_nodes[0].observed_facts)
  assert "compromised" in src_facts
  assert "disabled" in src_facts or "MFA" in src_facts

  access_edge_facts = " ".join(evidence.ordered_edges[2].observed_facts)
  assert "rds:FullAccess" in access_edge_facts
  assert "wildcard: True" in access_edge_facts

  # Risk Prioritization Verification
  risk_res = risk_svc.assess_path_risk(primary_path)
  assert risk_res.risk_tier == "CRITICAL"
  assert risk_res.score == 100.0
  assert risk_res.is_synthetic is True

  contributions = {c.rule_id for c in risk_res.contributions}
  assert "RULE_COMPROMISED_IDENTITY" in contributions
  assert "RULE_WILDCARD_PERMISSION" in contributions
  assert "RULE_CROWN_JEWEL_TARGET" in contributions


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_remediation_primary_route_revocation(live_repository):
  """Simulates revoking primary path's CAN_ACCESS edge on real FalkorDB clone.

  Must sever primary path, leave alternative 4-hop path reachable,
  preserve baseline graph (11 nodes, 11 edges), and delete the temporary clone.
  """
  initial_nodes = live_repository.count_nodes()
  initial_edges = live_repository.count_edges()
  assert initial_nodes == SYNTHETIC_NODE_COUNT == 11
  assert initial_edges == SYNTHETIC_EDGE_COUNT == 11

  remediation_svc = RemediationService(repository=live_repository)
  revocation = EdgeRevocation(
      source_id="role_order_service",
      rel_type="CAN_ACCESS",
      target_id="db_customer_vault",
  )

  res = remediation_svc.simulate_and_verify_remediation(
      revocation=revocation,
      source_id="usr_jdoe",
      target_id="db_customer_vault",
      max_depth=6,
  )

  # Verification Results
  assert res.status == "VERIFIED_SEVERED"
  assert res.success is True
  assert res.original_path_severed is True
  assert res.target_still_reachable is True
  assert res.before_paths_count == 2
  assert res.residual_paths_count == 1
  assert len(res.residual_paths) == 1

  # Residual path is the alternative route
  residual = res.residual_paths[0]
  assert residual.hop_count == 4
  assert [n.id for n in residual.nodes] == [
      "usr_jdoe",
      "srv_app_prod",
      "srv_analytics_worker",
      "role_analytics_readonly",
      "db_customer_vault",
  ]

  # Baseline graph immutability verified
  assert res.baseline_intact is True
  assert live_repository.count_nodes() == 11
  assert live_repository.count_edges() == 11

  # Temporary clone was deleted
  assert res.clone_cleaned_up is True


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_remediation_shared_entry_revocation(live_repository):
  """Simulates revoking shared entry AUTHENTICATES_TO edge on real FalkorDB clone.

  Must leave customer vault completely unreachable from usr_jdoe,
  preserve baseline graph (11 nodes, 11 edges), and delete the temporary clone.
  """
  remediation_svc = RemediationService(repository=live_repository)
  revocation = EdgeRevocation(
      source_id="usr_jdoe",
      rel_type="AUTHENTICATES_TO",
      target_id="srv_app_prod",
  )

  res = remediation_svc.simulate_and_verify_remediation(
      revocation=revocation,
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

  # Baseline graph immutability verified
  assert res.baseline_intact is True
  assert live_repository.count_nodes() == 11
  assert live_repository.count_edges() == 11
  assert res.clone_cleaned_up is True


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_baseline_retains_paths_after_simulations(live_repository):
  """Ensures baseline graph retains both paths after multiple simulations."""
  remediation_svc = RemediationService(repository=live_repository)
  discovery_svc = DiscoveryService(repository=live_repository)

  # Run two simulations back to back
  remediation_svc.simulate_and_verify_remediation(
      revocation=EdgeRevocation(
          source_id="role_order_service",
          rel_type="CAN_ACCESS",
          target_id="db_customer_vault",
      ),
      source_id="usr_jdoe",
      target_id="db_customer_vault",
  )

  remediation_svc.simulate_and_verify_remediation(
      revocation=EdgeRevocation(
          source_id="usr_jdoe",
          rel_type="AUTHENTICATES_TO",
          target_id="srv_app_prod",
      ),
      source_id="usr_jdoe",
      target_id="db_customer_vault",
  )

  # Verify baseline graph is still 100% intact with exactly 2 paths
  disc_res = discovery_svc.discover_paths("usr_jdoe", "db_customer_vault")
  assert disc_res.status == "PATHS_DISCOVERED"
  assert disc_res.total_paths_found == 2
  assert live_repository.count_nodes() == 11
  assert live_repository.count_edges() == 11


@pytest.mark.skipif(not FALKORDB_AVAILABLE, reason=BLOCKED_REASON)
def test_live_remediation_compound_severance_outcome_a(live_repository):
  """Simulates compound revocation on live FalkorDB:

  role_order_service CAN_ACCESS db_customer_vault
  AND srv_app_prod NETWORK_REACHABLE srv_analytics_worker.
  Must achieve Outcome A: zero residual paths, target unreachable,
  residual risk score 0.0, baseline 11 nodes & 11 edges intact.
  """
  remediation_svc = RemediationService(repository=live_repository)
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

  res = remediation_svc.simulate_and_verify_remediation(
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
  assert live_repository.count_nodes() == 11
  assert live_repository.count_edges() == 11
  assert res.clone_cleaned_up is True
