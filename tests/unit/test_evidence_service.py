"""Unit tests for the AttackPath EvidenceService."""

import pytest
from attackpath.domain.entities import BaseEntityNode
from attackpath.domain.path import AttackPath, GraphEdge
from attackpath.services.evidence_service import EvidenceService
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def evidence_service():
  return EvidenceService()


@pytest.fixture
def sample_paths():
  repo = NetworkXTestAdapter("offline_evidence_test")
  repo.seed_synthetic_scenario(clean_first=True)
  return repo.find_paths("usr_jdoe", "db_customer_vault", max_depth=6)


def test_evidence_extraction_primary_path(evidence_service, sample_paths):
  """Verifies factual evidence extraction on the 3-hop primary attack path."""
  p1 = sample_paths[0]
  evidence = evidence_service.generate_path_evidence(p1)

  assert evidence.path_id == "path_1"
  assert evidence.hop_count == 3
  assert len(evidence.ordered_nodes) == 4
  assert len(evidence.ordered_edges) == 3
  assert evidence.is_synthetic is True

  # Verify Node Evidence details
  src_evidence = evidence.ordered_nodes[0]
  assert src_evidence.node_id == "usr_jdoe"
  assert src_evidence.label == "Identity"
  assert any("compromised" in f for f in src_evidence.observed_facts)
  assert any("MFA" in f for f in src_evidence.observed_facts)

  # Verify Edge Evidence details
  edge0 = evidence.ordered_edges[0]
  assert edge0.source_id == "usr_jdoe"
  assert edge0.target_id == "srv_app_prod"
  assert edge0.rel_type == "AUTHENTICATES_TO"
  assert any("SSH" in f for f in edge0.observed_facts)
  assert any("EXPOSED_PRIVATE_KEY" in f for f in edge0.observed_facts)

  edge2 = evidence.ordered_edges[2]
  assert edge2.source_id == "role_order_service"
  assert edge2.target_id == "db_customer_vault"
  assert edge2.rel_type == "CAN_ACCESS"
  assert any("rds:FullAccess" in f for f in edge2.observed_facts)
  assert any("wildcard: True" in f for f in edge2.observed_facts)


def test_evidence_provenance_distinction(evidence_service, sample_paths):
  """Ensures evidence distinguishes observed graph facts, derived heuristics, and synthetic metadata."""
  p1 = sample_paths[0]
  evidence = evidence_service.generate_path_evidence(p1)

  provenances = {claim.provenance for claim in evidence.factual_claims}
  assert "OBSERVED_GRAPH_FACT" in provenances
  assert "DERIVED_INTERPRETATION" in provenances
  assert "SYNTHETIC_DATA_METADATA" in provenances

  # Verify synthetic data explicit claim
  synthetic_claims = [c for c in evidence.factual_claims if c.provenance == "SYNTHETIC_DATA_METADATA"]
  assert len(synthetic_claims) >= 1
  assert "synthetic" in synthetic_claims[0].statement.lower()

  # Verify derived interpretation claim
  derived_claims = [c for c in evidence.factual_claims if c.provenance == "DERIVED_INTERPRETATION"]
  assert len(derived_claims) >= 1
  assert "crown-jewel" in derived_claims[0].statement.lower()


def test_evidence_missing_properties_reported_as_unknown(evidence_service):
  """Ensures missing properties are reported as unknown rather than invented."""
  # Construct a minimal path with bare entities lacking optional properties
  n1 = BaseEntityNode(id="usr_bare", label="Identity", name="Bare User", is_synthetic=False, properties={})
  n2 = BaseEntityNode(id="db_bare", label="DataAsset", name="Bare DB", is_synthetic=False, properties={})
  edge = GraphEdge(source="usr_bare", target="db_bare", type="CAN_ACCESS", is_synthetic=False, properties={})

  bare_path = AttackPath(
      path_id="path_bare",
      hop_count=1,
      nodes=[n1, n2],
      edges=[edge],
      is_synthetic=False,
  )

  evidence = evidence_service.generate_path_evidence(bare_path)

  # Check that identity missing compromise/mfa are reported as unknown
  src_facts = " ".join(evidence.ordered_nodes[0].observed_facts)
  assert "compromise status is unknown" in src_facts
  assert "MFA enforcement status is unknown" in src_facts

  # Check that destination missing classification is reported as unknown
  dst_facts = " ".join(evidence.ordered_nodes[1].observed_facts)
  assert "classification tier is unknown" in dst_facts
  assert "encryption status is unknown" in dst_facts
