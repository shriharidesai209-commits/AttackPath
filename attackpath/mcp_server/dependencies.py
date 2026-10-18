"""Dependency providers and injection container for AttackPath MCP server tools."""

import logging
from typing import Any, Dict, Optional
import falkordb
from attackpath.config import Settings, get_settings as config_get_settings
from attackpath.database.connection import create_falkordb_client
from attackpath.database.repository import FalkorDBRepository
from attackpath.services.discovery_service import DiscoveryService
from attackpath.services.evidence_service import EvidenceService
from attackpath.services.remediation_service import RemediationService
from attackpath.services.risk_service import RiskPrioritizationService

logger = logging.getLogger("attackpath.mcp_server.dependencies")

# Registry for testing overrides
_dependency_overrides: Dict[str, Any] = {}


def set_dependency_override(key: str, override: Any) -> None:
  """Registers a test dependency override (e.g. mock repository or service)."""
  _dependency_overrides[key] = override


def clear_dependency_overrides() -> None:
  """Clears all active test dependency overrides."""
  _dependency_overrides.clear()


def get_settings() -> Settings:
  """Provides application settings, checking for overrides first."""
  if "settings" in _dependency_overrides:
    return _dependency_overrides["settings"]
  return config_get_settings()


def get_falkordb_client(settings: Optional[Settings] = None) -> falkordb.FalkorDB:
  """Provides a connected FalkorDB client instance on demand.

  Raises FalkorDBConnectionError if the host is unreachable.
  """
  if "client" in _dependency_overrides:
    return _dependency_overrides["client"]
  cfg = settings or get_settings()
  return create_falkordb_client(cfg)


def get_repository(
    settings: Optional[Settings] = None,
    client: Optional[falkordb.FalkorDB] = None,
) -> Any:
  """Provides the graph repository initialized for the configured baseline graph."""
  if "repository" in _dependency_overrides:
    return _dependency_overrides["repository"]
  cfg = settings or get_settings()
  falkor_client = client or get_falkordb_client(cfg)
  return FalkorDBRepository(client=falkor_client, graph_name=cfg.FALKORDB_BASELINE_GRAPH)


def get_discovery_service(repo: Optional[Any] = None) -> DiscoveryService:
  """Provides the attack-path discovery service."""
  if "discovery_service" in _dependency_overrides:
    return _dependency_overrides["discovery_service"]
  repository = repo or get_repository()
  return DiscoveryService(repository=repository)


def get_evidence_service() -> EvidenceService:
  """Provides the deterministic evidence extraction service."""
  if "evidence_service" in _dependency_overrides:
    return _dependency_overrides["evidence_service"]
  return EvidenceService()


def get_risk_service() -> RiskPrioritizationService:
  """Provides the deterministic risk prioritization service."""
  if "risk_service" in _dependency_overrides:
    return _dependency_overrides["risk_service"]
  return RiskPrioritizationService()


def get_remediation_service(repo: Optional[Any] = None) -> RemediationService:
  """Provides the isolated remediation simulation and verification service."""
  if "remediation_service" in _dependency_overrides:
    return _dependency_overrides["remediation_service"]
  repository = repo or get_repository()
  return RemediationService(repository=repository)
