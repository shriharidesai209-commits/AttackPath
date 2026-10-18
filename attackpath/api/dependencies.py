"""Centralized dependency injection providers for FastAPI routes."""

from typing import Any
import falkordb
from fastapi import Depends
from attackpath.config import Settings, get_settings as config_get_settings
from attackpath.database.connection import create_falkordb_client
from attackpath.database.repository import FalkorDBRepository
from attackpath.services.discovery_service import DiscoveryService
from attackpath.services.evidence_service import EvidenceService
from attackpath.services.remediation_service import RemediationService
from attackpath.services.risk_service import RiskPrioritizationService


def get_settings() -> Settings:
  """Dependency providing application settings."""
  return config_get_settings()


def get_falkordb_client(settings: Settings = Depends(get_settings)) -> falkordb.FalkorDB:
  """Dependency providing a connected FalkorDB client.

  Raises FalkorDBConnectionError if the host is unreachable.
  """
  return create_falkordb_client(settings)


def get_repository(
    client: falkordb.FalkorDB = Depends(get_falkordb_client),
    settings: Settings = Depends(get_settings),
) -> Any:
  """Dependency providing the graph repository initialized for the configured baseline graph."""
  return FalkorDBRepository(client, graph_name=settings.FALKORDB_BASELINE_GRAPH)


def get_discovery_service(
    repo: Any = Depends(get_repository),
) -> DiscoveryService:
  """Dependency providing the attack-path discovery service."""
  return DiscoveryService(repository=repo)


def get_evidence_service() -> EvidenceService:
  """Dependency providing the fact-grounded evidence extraction service."""
  return EvidenceService()


def get_risk_service(
    settings: Settings = Depends(get_settings),
) -> RiskPrioritizationService:
  """Dependency providing the deterministic risk prioritization service."""
  return RiskPrioritizationService()


def get_remediation_service(
    repo: Any = Depends(get_repository),
) -> RemediationService:
  """Dependency providing the isolated remediation simulation and verification service."""
  return RemediationService(repository=repo)
