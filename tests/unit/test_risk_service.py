"""Unit tests for the deterministic RiskPrioritizationService."""

import pytest
from attackpath.domain.entities import BaseEntityNode
from attackpath.domain.path import AttackPath, GraphEdge
from attackpath.domain.service_models import RiskScoringConfig
from attackpath.services.risk_service import RiskPrioritizationService
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def risk_service():
  return RiskPrioritizationService()


@pytest.fixture
def synthetic_paths():
  repo = NetworkXTestAdapter("offline_risk_test")
  repo.seed_synthetic_scenario(clean_first=True)
  return repo.find_paths("usr_jdoe", "db_customer_vault", max_depth=6)


def test_primary_path_risk_assessment_critical(risk_service, synthetic_paths):
  """Verifies that the primary risky 3-hop path receives a CRITICAL tier and max score."""
  p1 = synthetic_paths[0]
  assessment = risk_service.assess_path_risk(p1)

  assert assessment.path_id == "path_1"
  assert assessment.score == 100.0  # Normalized/clamped to 100
  assert assessment.risk_tier == "CRITICAL"
  assert assessment.is_synthetic is True

  # Verify rule contributions
  rule_ids = {c.rule_id for c in assessment.contributions}
  assert "RULE_BASE_SCORE" in rule_ids
  assert "RULE_COMPROMISED_IDENTITY" in rule_ids
  assert "RULE_MFA_DISABLED" in rule_ids
  assert "RULE_EXPOSED_CREDENTIALS" in rule_ids
  assert "RULE_INTERNET_FACING_WORKLOAD" in rule_ids
  assert "RULE_PRIVILEGED_ROLE" in rule_ids
  assert "RULE_WILDCARD_PERMISSION" in rule_ids
  assert "RULE_CROWN_JEWEL_TARGET" in rule_ids
  assert "RULE_SHORT_PATH_BONUS" in rule_ids

  # Ensure disclaimer is present
  assert "heuristic" in assessment.disclaimer.lower()


def test_risk_tier_boundaries():
  """Verifies deterministic mapping of scores to tiers across boundary values."""
  # Custom config for testing exact boundaries
  cfg = RiskScoringConfig(
      base_score=0.0,
      threshold_critical=75.0,
      threshold_priority=50.0,
      threshold_monitor=25.0,
  )
  svc = RiskPrioritizationService(config=cfg)

  # Helper to generate dummy 1-hop path with specific score
  def assess_with_target_classification(classification: str, is_compromised: bool) -> str:
    n1 = BaseEntityNode(
        id="u1", label="Identity", name="U1", properties={"compromised": is_compromised, "mfa_enabled": True}
    )
    n2 = BaseEntityNode(
        id="d1", label="DataAsset", name="D1", properties={"classification": classification, "is_encrypted": True}
    )
    edge = GraphEdge(source="u1", target="d1", type="CAN_ACCESS", properties={})
    p = AttackPath(path_id="p", hop_count=1, nodes=[n1, n2], edges=[edge])
    return svc.assess_path_risk(p).risk_tier

  # Crown jewel (25) + Short path bonus (5) = 30 -> MONITOR (>= 25 and < 50)
  tier_monitor = assess_with_target_classification("crown_jewel", is_compromised=False)
  assert tier_monitor == "MONITOR"

  # Crown jewel (25) + Short path (5) + Compromised (25) = 55 -> PRIORITY (>= 50 and < 75)
  tier_priority = assess_with_target_classification("crown_jewel", is_compromised=True)
  assert tier_priority == "PRIORITY"

  # Confidential (10) + Short path (5) = 15 -> INFORMATIONAL (< 25)
  tier_info = assess_with_target_classification("confidential", is_compromised=False)
  assert tier_info == "INFORMATIONAL"


def test_missing_properties_handled_conservatively(risk_service):
  """Ensures missing properties do not trigger penalties and are recorded as uncertainties."""
  # Path where entities lack attributes
  n1 = BaseEntityNode(id="u_unknown", label="Identity", name="U Unknown", properties={})
  n2 = BaseEntityNode(id="w_unknown", label="Workload", name="W Unknown", properties={})
  n3 = BaseEntityNode(id="d_unknown", label="DataAsset", name="D Unknown", properties={})
  e1 = GraphEdge(source="u_unknown", target="w_unknown", type="AUTHENTICATES_TO", properties={})
  e2 = GraphEdge(source="w_unknown", target="d_unknown", type="CAN_ACCESS", properties={})

  p = AttackPath(path_id="p_unknown", hop_count=2, nodes=[n1, n2, n3], edges=[e1, e2])
  assessment = risk_service.assess_path_risk(p)

  # Check uncertainties list contains notes on missing attributes
  assert len(assessment.uncertainties) >= 3
  uncertainty_text = " ".join(assessment.uncertainties)
  assert "compromised" in uncertainty_text
  assert "mfa_enabled" in uncertainty_text
  assert "classification" in uncertainty_text


def test_deterministic_scoring_stability(risk_service, synthetic_paths):
  """Ensures multiple runs on the same path yield identical numerical scores and tiers."""
  p = synthetic_paths[0]
  res1 = risk_service.assess_path_risk(p)
  res2 = risk_service.assess_path_risk(p)

  assert res1.score == res2.score
  assert res1.risk_tier == res2.risk_tier
  assert len(res1.contributions) == len(res2.contributions)
