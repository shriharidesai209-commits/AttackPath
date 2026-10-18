"""Application service for bounded attack-path discovery across graph entities."""

import logging
from typing import Any, Optional
from attackpath.domain.service_models import (
    DiscoveryRequest,
    DiscoveryResult,
    DiscoveryStatus,
)

logger = logging.getLogger("attackpath.services.discovery")


class DiscoveryService:
  """Orchestrates bounded, directed attack-path discovery between graph entities."""

  def __init__(self, repository: Any):
    self.repository = repository

  def discover_paths(
      self,
      source_id: str,
      target_id: str,
      max_depth: int = 6,
      limit: int = 10,
  ) -> DiscoveryResult:
    """Discovers directed multi-hop attack paths from source_id to target_id.

    Enforces maximum traversal depth of 6 and strict bounding.
    Distinguishes invalid inputs, missing entities, unreachable targets, and database errors.
    """
    # 1. Clamp depth and limit to safe bounds
    safe_depth = min(max(1, max_depth), 6) if isinstance(max_depth, int) else 6
    safe_limit = min(max(1, limit), 50) if isinstance(limit, int) else 10

    # 2. Input validation
    try:
      req = DiscoveryRequest(
          source_id=source_id,
          target_id=target_id,
          max_depth=safe_depth,
          limit=safe_limit,
      )
    except Exception as exc:
      logger.warning("Invalid discovery request: source='%s', target='%s': %s", source_id, target_id, exc)
      return DiscoveryResult(
          status="INVALID_REQUEST",
          source_id=str(source_id),
          target_id=str(target_id),
          paths=[],
          total_paths_found=0,
          max_depth_applied=safe_depth,
          is_synthetic=True,
          details=f"Validation error: {exc}",
      )

    bounded_depth = req.max_depth
    bounded_limit = req.limit

    # 2. Query paths via repository
    try:
      paths = self.repository.find_paths(
          source_id=req.source_id,
          target_id=req.target_id,
          max_depth=bounded_depth,
          limit=bounded_limit,
      )
    except Exception as exc:
      logger.error(
          "Database query failed discovering paths between '%s' and '%s': %s",
          req.source_id,
          req.target_id,
          exc,
      )
      return DiscoveryResult(
          status="DATABASE_ERROR",
          source_id=req.source_id,
          target_id=req.target_id,
          paths=[],
          total_paths_found=0,
          max_depth_applied=bounded_depth,
          is_synthetic=True,
          details=f"Database query failure: {exc}",
      )

    # If paths are found, avoid unnecessary extra queries
    if paths:
      is_all_synthetic = all(p.is_synthetic for p in paths)
      return DiscoveryResult(
          status="PATHS_DISCOVERED",
          source_id=req.source_id,
          target_id=req.target_id,
          paths=paths,
          total_paths_found=len(paths),
          max_depth_applied=bounded_depth,
          is_synthetic=is_all_synthetic,
          details=f"Discovered {len(paths)} attack path(s) within {bounded_depth} hops.",
      )

    # 3. If no paths found, disambiguate missing entity vs unreachable target
    try:
      src_node = self.repository.get_node(req.source_id)
      dst_node = self.repository.get_node(req.target_id)
    except Exception as exc:
      logger.error("Database query failed verifying endpoint nodes: %s", exc)
      return DiscoveryResult(
          status="DATABASE_ERROR",
          source_id=req.source_id,
          target_id=req.target_id,
          paths=[],
          total_paths_found=0,
          max_depth_applied=bounded_depth,
          is_synthetic=True,
          details=f"Database query failure verifying entities: {exc}",
      )

    if src_node is None and dst_node is None:
      return DiscoveryResult(
          status="ENTITY_NOT_FOUND",
          source_id=req.source_id,
          target_id=req.target_id,
          paths=[],
          total_paths_found=0,
          max_depth_applied=bounded_depth,
          is_synthetic=True,
          details=f"Neither source entity '{req.source_id}' nor target entity '{req.target_id}' exists in the graph.",
      )
    if src_node is None:
      return DiscoveryResult(
          status="ENTITY_NOT_FOUND",
          source_id=req.source_id,
          target_id=req.target_id,
          paths=[],
          total_paths_found=0,
          max_depth_applied=bounded_depth,
          is_synthetic=True,
          details=f"Source entity '{req.source_id}' does not exist in the graph.",
      )
    if dst_node is None:
      return DiscoveryResult(
          status="ENTITY_NOT_FOUND",
          source_id=req.source_id,
          target_id=req.target_id,
          paths=[],
          total_paths_found=0,
          max_depth_applied=bounded_depth,
          is_synthetic=True,
          details=f"Target entity '{req.target_id}' does not exist in the graph.",
      )

    return DiscoveryResult(
        status="TARGET_UNREACHABLE",
        source_id=req.source_id,
        target_id=req.target_id,
        paths=[],
        total_paths_found=0,
        max_depth_applied=bounded_depth,
        is_synthetic=True,
        details=f"Target entity '{req.target_id}' is unreachable from source '{req.source_id}' within {bounded_depth} hops.",
    )
