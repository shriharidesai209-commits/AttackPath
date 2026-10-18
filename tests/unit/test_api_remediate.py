"""Unit tests for /api/v1/remediate/simulate-and-verify endpoint."""

import pytest
from fastapi.testclient import TestClient
from attackpath.api.app import app
from attackpath.api.dependencies import get_remediation_service, get_repository
from tests.adapters.networkx_test_adapter import NetworkXTestAdapter


@pytest.fixture
def offline_repo():
  repo = NetworkXTestAdapter("offline_remediation_api_test")
  repo.seed_synthetic_scenario(clean_first=True)
  return repo


@pytest.fixture
def client(offline_repo):
  app.dependency_overrides[get_repository] = lambda: offline_repo
  with TestClient(app) as test_client:
    yield test_client
  app.dependency_overrides.clear()


def test_remediate_primary_route_severance(client):
  """Simulates revoking role_order_service CAN_ACCESS db_customer_vault via API."""
  payload = {
      "revocation": {
          "source_id": "role_order_service",
          "rel_type": "CAN_ACCESS",
          "target_id": "db_customer_vault",
      },
      "source_id": "usr_jdoe",
      "target_id": "db_customer_vault",
      "max_depth": 6,
      "limit": 10,
  }
  resp = client.post("/api/v1/remediate/simulate-and-verify", json=payload)
  assert resp.status_code == 200
  data = resp.json()

  assert data["status"] == "VERIFIED_SEVERED"
  assert data["success"] is True
  assert data["original_path_severed"] is True
  assert data["target_still_reachable"] is True
  assert data["before_paths_count"] == 2
  assert data["residual_paths_count"] == 1
  assert len(data["residual_paths"]) == 1
  assert data["baseline_intact"] is True
  assert data["clone_cleaned_up"] is True


def test_remediate_shared_entry_route_severance(client):
  """Simulates revoking usr_jdoe AUTHENTICATES_TO srv_app_prod via API."""
  payload = {
      "revocation": {
          "source_id": "usr_jdoe",
          "rel_type": "AUTHENTICATES_TO",
          "target_id": "srv_app_prod",
      },
      "source_id": "usr_jdoe",
      "target_id": "db_customer_vault",
  }
  resp = client.post("/api/v1/remediate/simulate-and-verify", json=payload)
  assert resp.status_code == 200
  data = resp.json()

  assert data["status"] == "VERIFIED_SEVERED"
  assert data["success"] is True
  assert data["original_path_severed"] is True
  assert data["target_still_reachable"] is False
  assert data["residual_paths_count"] == 0
  assert data["baseline_intact"] is True
  assert data["clone_cleaned_up"] is True


def test_remediate_nonexistent_relationship_returns_404(client):
  """Ensures revoking a nonexistent edge returns 404 Not Found."""
  payload = {
      "revocation": {
          "source_id": "usr_jdoe",
          "rel_type": "CAN_ACCESS",
          "target_id": "db_customer_vault",
      },
  }
  resp = client.post("/api/v1/remediate/simulate-and-verify", json=payload)
  assert resp.status_code == 404
  data = resp.json()
  assert data["error"]["code"] == "NOT_FOUND"
  assert "does not exist" in data["error"]["message"].lower()


def test_remediate_ambiguous_relationship_returns_409(client, offline_repo):
  """Ensures ambiguous relationship matches return 409 Conflict."""
  offline_repo.g.add_edge(
      "role_order_service",
      "db_customer_vault",
      key="second_edge",
      type="CAN_ACCESS",
      permission="rds:ReadOnly",
  )

  payload = {
      "revocation": {
          "source_id": "role_order_service",
          "rel_type": "CAN_ACCESS",
          "target_id": "db_customer_vault",
      },
  }
  resp = client.post("/api/v1/remediate/simulate-and-verify", json=payload)
  assert resp.status_code == 409
  data = resp.json()
  assert data["error"]["code"] == "CONFLICT"
  assert "ambiguous" in data["error"]["message"].lower()


def test_remediate_verification_failure_returns_500(client):
  """Ensures simulation verification failure produces 500 Internal Server Error."""
  class FailingRemediationService:
    def simulate_and_verify_remediation(self, *args, **kwargs):
      from attackpath.domain.path import EdgeRevocation
      from attackpath.domain.service_models import RemediationVerificationResult
      return RemediationVerificationResult(
          status="VERIFICATION_FAILED",
          success=False,
          revocation=EdgeRevocation(source_id="a", rel_type="R", target_id="b"),
          baseline_counts_before={},
          baseline_counts_after={},
          baseline_intact=False,
          clone_name="sim_fail",
          clone_cleaned_up=True,
          original_path_severed=False,
          target_still_reachable=False,
          before_paths_count=0,
          residual_paths_count=0,
          details="Simulated clone verification failure",
      )

  app.dependency_overrides[get_remediation_service] = lambda: FailingRemediationService()

  payload = {
      "revocation": {
          "source_id": "usr_jdoe",
          "rel_type": "AUTHENTICATES_TO",
          "target_id": "srv_app_prod",
      },
  }
  resp = client.post("/api/v1/remediate/simulate-and-verify", json=payload)
  assert resp.status_code == 500
  data = resp.json()
  assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
