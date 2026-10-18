"""Application service for isolated remediation simulation and verification using temporary graph clones."""

import logging
from typing import Any, List, Optional
import uuid
from attackpath.domain.path import AttackPath, EdgeRevocation
from attackpath.domain.service_models import (
    RemediationStatus,
    RemediationVerificationResult,
)

logger = logging.getLogger("attackpath.services.remediation")


class RemediationService:
  """Executes atomic remediation simulations on isolated temporary graph copies.

  Guarantees zero mutation to the baseline graph and executes strict cleanup in finally blocks.
  """

  def __init__(self, repository: Any):
    self.repository = repository

  def simulate_and_verify_remediation(
      self,
      revocation: EdgeRevocation,
      additional_revocations: Optional[List[EdgeRevocation]] = None,
      source_id: Optional[str] = None,
      target_id: Optional[str] = None,
      max_depth: int = 6,
      limit: int = 10,
  ) -> RemediationVerificationResult:
    """Atomically simulates the revocation of one or more directed relationships on a temporary graph clone.

    Lifecycle:
    1. Validate input revocation request and parameters.
    2. Record pre-remediation baseline node and edge counts.
    3. If route endpoints provided, discover baseline pre-remediation paths.
    4. Create a uniquely named temporary graph clone.
    5. Verify clone counts match baseline before mutation.
    6. Locate exact relationships (reject if missing or ambiguous).
    7. Revoke targeted relationships in the temporary graph clone.
    8. Re-run bounded path discovery in the temporary graph.
    9. Explicitly verify whether original path(s) remain using signature checks.
    10. Re-check baseline graph counts to prove baseline immutability.
    11. Clean up temporary graph in finally block.
    12. Return structured verification outcome with residual risk score.
    """
    # 1. Input Validation
    all_revocations = [revocation] + (additional_revocations or [])
    for rev in all_revocations:
      if not rev.source_id.strip() or not rev.target_id.strip() or not rev.rel_type.strip():
        return RemediationVerificationResult(
            status="MUTATION_REJECTED",
            success=False,
            revocation=revocation,
            baseline_counts_before={},
            baseline_counts_after={},
            baseline_intact=True,
            clone_name="",
            clone_cleaned_up=True,
            original_path_severed=False,
            target_still_reachable=False,
            before_paths_count=0,
            residual_paths_count=0,
            residual_paths=[],
            warnings=["Invalid relationship revocation specification."],
            details="Source ID, target ID, and relationship type cannot be empty or blank.",
        )

    bounded_depth = min(max(1, max_depth), 6)
    bounded_limit = min(max(1, limit), 50)

    # 2. Record Baseline Counts
    try:
      baseline_nodes_before = self.repository.count_nodes()
      baseline_edges_before = self.repository.count_edges()
    except Exception as exc:
      logger.error("Failed to query baseline graph counts: %s", exc)
      return RemediationVerificationResult(
          status="VERIFICATION_FAILED",
          success=False,
          revocation=revocation,
          baseline_counts_before={},
          baseline_counts_after={},
          baseline_intact=False,
          clone_name="",
          clone_cleaned_up=True,
          original_path_severed=False,
          target_still_reachable=False,
          before_paths_count=0,
          residual_paths_count=0,
          residual_paths=[],
          warnings=[f"Failed to access baseline graph: {exc}"],
          details="Could not retrieve pre-simulation baseline counts.",
      )

    baseline_before_dict = {
        "node_count": baseline_nodes_before,
        "edge_count": baseline_edges_before,
    }

    if baseline_nodes_before == 0:
      return RemediationVerificationResult(
          status="MUTATION_REJECTED",
          success=False,
          revocation=revocation,
          baseline_counts_before=baseline_before_dict,
          baseline_counts_after=baseline_before_dict,
          baseline_intact=True,
          clone_name="",
          clone_cleaned_up=True,
          original_path_severed=False,
          target_still_reachable=False,
          before_paths_count=0,
          residual_paths_count=0,
          residual_paths=[],
          warnings=["Baseline graph is empty."],
          details="Cannot simulate remediation against an empty baseline graph.",
      )

    # 3. Discover Pre-Remediation Paths on Baseline
    before_paths: List[AttackPath] = []
    before_signatures: List[str] = []
    if source_id and target_id:
      try:
        before_paths = self.repository.find_paths(
            source_id=source_id,
            target_id=target_id,
            max_depth=bounded_depth,
            limit=bounded_limit,
        )
        before_signatures = [p.signature for p in before_paths]
      except Exception as exc:
        logger.error("Failed to discover baseline paths before remediation: %s", exc)

    # 4. Generate Unique Clone Key
    clone_id = uuid.uuid4().hex[:8]
    base_name = getattr(self.repository, "graph_name", "attackpath")
    clone_name = f"{base_name}_sim_{clone_id}"

    clone_repo = None
    clone_cleaned_up = False
    warnings: List[str] = []
    result: Optional[RemediationVerificationResult] = None

    try:
      # Create Clone
      logger.info("Creating temporary clone graph '%s' from baseline '%s'", clone_name, base_name)
      clone_repo = self.repository.create_clone_repository(clone_name)

      # 5. Verify Clone Integrity Against Baseline
      clone_nodes = clone_repo.count_nodes()
      clone_edges = clone_repo.count_edges()

      if clone_nodes != baseline_nodes_before or clone_edges != baseline_edges_before:
        logger.error(
            "Clone graph '%s' counts (%d nodes, %d edges) do not match baseline (%d nodes, %d edges)",
            clone_name,
            clone_nodes,
            clone_edges,
            baseline_nodes_before,
            baseline_edges_before,
        )
        result = RemediationVerificationResult(
            status="VERIFICATION_FAILED",
            success=False,
            revocation=revocation,
            baseline_counts_before=baseline_before_dict,
            baseline_counts_after=baseline_before_dict,
            baseline_intact=True,
            clone_name=clone_name,
            clone_cleaned_up=False,
            original_path_severed=False,
            target_still_reachable=len(before_paths) > 0,
            before_paths_count=len(before_paths),
            residual_paths_count=0,
            residual_paths=[],
            warnings=["Clone graph integrity check failed prior to mutation."],
            details="Clone node or edge count did not match baseline graph.",
        )
        return result

      # 6 & 7. Locate and Revoke All Targeted Relationships in Clone
      total_deleted = 0
      for rev in all_revocations:
        matches = clone_repo.find_relationships(
            source_id=rev.source_id,
            rel_type=rev.rel_type,
            target_id=rev.target_id,
        )

        if len(matches) == 0:
          logger.warning(
              "Relationship (%s)-[%s]->(%s) not found in clone graph",
              rev.source_id,
              rev.rel_type,
              rev.target_id,
          )
          result = RemediationVerificationResult(
              status="MUTATION_REJECTED",
              success=False,
              revocation=revocation,
              baseline_counts_before=baseline_before_dict,
              baseline_counts_after=baseline_before_dict,
              baseline_intact=True,
              clone_name=clone_name,
              clone_cleaned_up=False,
              original_path_severed=False,
              target_still_reachable=len(before_paths) > 0,
              before_paths_count=len(before_paths),
              residual_paths_count=len(before_paths),
              residual_paths=before_paths,
              residual_risk_score=100.0 if before_paths else 0.0,
              residual_risk_tier="CRITICAL" if before_paths else "INFORMATIONAL",
              warnings=["Target relationship not found in graph."],
              details=f"Relationship ({rev.source_id})-[{rev.rel_type}]->({rev.target_id}) does not exist.",
          )
          return result

        if len(matches) > 1:
          logger.warning(
              "Ambiguous match: found %d relationships (%s)-[%s]->(%s)",
              len(matches),
              rev.source_id,
              rev.rel_type,
              rev.target_id,
          )
          result = RemediationVerificationResult(
              status="MUTATION_REJECTED",
              success=False,
              revocation=revocation,
              baseline_counts_before=baseline_before_dict,
              baseline_counts_after=baseline_before_dict,
              baseline_intact=True,
              clone_name=clone_name,
              clone_cleaned_up=False,
              original_path_severed=False,
              target_still_reachable=len(before_paths) > 0,
              before_paths_count=len(before_paths),
              residual_paths_count=len(before_paths),
              residual_paths=before_paths,
              residual_risk_score=100.0 if before_paths else 0.0,
              residual_risk_tier="CRITICAL" if before_paths else "INFORMATIONAL",
              warnings=["Ambiguous relationship: multiple matching edges between endpoints."],
              details=f"Found {len(matches)} relationships of type '{rev.rel_type}' between '{rev.source_id}' and '{rev.target_id}'. Refusing to revoke without disambiguation.",
          )
          return result

        exact_match = matches[0]
        deleted_count = clone_repo.delete_relationship_by_id(exact_match["rel_id"])

        if deleted_count != 1:
          # Fallback to endpoints delete if ID delete did not catch
          deleted_count = clone_repo.delete_relationship(
              source_id=rev.source_id,
              rel_type=rev.rel_type,
              target_id=rev.target_id,
          )

        if deleted_count != 1:
          result = RemediationVerificationResult(
              status="VERIFICATION_FAILED",
              success=False,
              revocation=revocation,
              baseline_counts_before=baseline_before_dict,
              baseline_counts_after=baseline_before_dict,
              baseline_intact=True,
              clone_name=clone_name,
              clone_cleaned_up=False,
              original_path_severed=False,
              target_still_reachable=len(before_paths) > 0,
              before_paths_count=len(before_paths),
              residual_paths_count=0,
              residual_paths=[],
              warnings=[f"Expected 1 deleted edge in clone, got {deleted_count}."],
              details=f"Revocation execution failed to remove edge ({rev.source_id})-[{rev.rel_type}]->({rev.target_id}).",
          )
          return result
        total_deleted += deleted_count

      # 8. Re-run Bounded Path Discovery in Clone
      residual_paths: List[AttackPath] = []
      residual_signatures: List[str] = []
      if source_id and target_id:
        residual_paths = clone_repo.find_paths(
            source_id=source_id,
            target_id=target_id,
            max_depth=bounded_depth,
            limit=bounded_limit,
        )
        residual_signatures = [p.signature for p in residual_paths]

      # 9. Explicit Path Severance Verification
      # Check if any original path containing any revoked edge survived
      # Do not rely on absence from capped list alone; check signatures and verify edge deletion
      revoked_edge_keys = {(r.source_id, r.rel_type, r.target_id) for r in all_revocations}
      original_paths_containing_revoked_edge = [
          p
          for p in before_paths
          if any(
              (e.source, e.type, e.target) in revoked_edge_keys
              for e in p.edges
          )
      ]

      if original_paths_containing_revoked_edge:
        # Verify none of these specific paths exist in residual paths
        original_path_severed = all(p.signature not in residual_signatures for p in original_paths_containing_revoked_edge)
      else:
        # If no investigated before_path used any revoked edge, the edge revocation did not target these paths
        original_path_severed = False

      target_still_reachable = len(residual_paths) > 0

      # Compute genuine residual risk score heuristic from backend RiskPrioritizationService
      residual_risk_score: Optional[float] = None
      residual_risk_tier: Optional[str] = None
      if residual_paths:
        try:
          from attackpath.services.risk_service import RiskPrioritizationService
          risk_svc = RiskPrioritizationService()
          top_residual_risk = risk_svc.assess_path_risk(residual_paths[0])
          residual_risk_score = float(top_residual_risk.score)
          residual_risk_tier = top_residual_risk.risk_tier
        except Exception as exc:
          logger.warning("Could not assess residual path risk: %s", exc)
          residual_risk_score = 100.0
          residual_risk_tier = "CRITICAL"
      else:
        residual_risk_score = 0.0
        residual_risk_tier = "INFORMATIONAL"

      # Determine status & description
      rev_desc = ", ".join(f"({r.source_id})-[{r.rel_type}]->({r.target_id})" for r in all_revocations)
      if not original_paths_containing_revoked_edge and before_paths:
        status: RemediationStatus = "VERIFIED_UNAFFECTED"
        details = (
            f"Relationship(s) {rev_desc} revoked, but none of the investigated paths relied on them."
        )
      elif original_path_severed and not target_still_reachable:
        status = "VERIFIED_SEVERED"
        details = (
            f"Target '{target_id}' is completely unreachable after revoking {rev_desc}. All paths severed."
        )
      elif original_path_severed and target_still_reachable:
        status = "VERIFIED_SEVERED"
        details = (
            f"Primary route successfully severed by revoking {rev_desc}. "
            f"{len(residual_paths)} alternative residual path(s) remain reachable."
        )
      else:
        status = "VERIFICATION_FAILED"
        details = "Revocation completed, but original route verification checks failed."

      # 10. Recheck Baseline Counts to Prove Immutability
      baseline_nodes_after = self.repository.count_nodes()
      baseline_edges_after = self.repository.count_edges()
      baseline_intact = (
          baseline_nodes_after == baseline_nodes_before
          and baseline_edges_after == baseline_edges_before
      )

      if not baseline_intact:
        warnings.append(
            f"CRITICAL: Baseline graph changed! Before: {baseline_before_dict}, "
            f"After: {{'node_count': {baseline_nodes_after}, 'edge_count': {baseline_edges_after}}}"
        )
        status = "VERIFICATION_FAILED"

      baseline_after_dict = {
          "node_count": baseline_nodes_after,
          "edge_count": baseline_edges_after,
      }

      result = RemediationVerificationResult(
          status=status,
          success=baseline_intact and (total_deleted == len(all_revocations)) and (status != "VERIFICATION_FAILED"),
          revocation=revocation,
          baseline_counts_before=baseline_before_dict,
          baseline_counts_after=baseline_after_dict,
          baseline_intact=baseline_intact,
          clone_name=clone_name,
          clone_cleaned_up=False,
          original_path_severed=original_path_severed,
          target_still_reachable=target_still_reachable,
          before_paths_count=len(before_paths),
          residual_paths_count=len(residual_paths),
          residual_paths=residual_paths,
          residual_risk_score=residual_risk_score,
          residual_risk_tier=residual_risk_tier,
          warnings=warnings,
          details=details,
      )
      return result

    finally:
      # 11. Cleanup Temporary Clone
      if clone_repo is not None:
        try:
          logger.info("Cleaning up temporary clone graph '%s'", clone_name)
          clone_repo.delete_graph()
          clone_cleaned_up = True
        except Exception as exc:
          logger.error(
              "CLEANUP FAILURE: Failed to delete temporary graph '%s': %s",
              clone_name,
              exc,
          )
          warnings.append(
              f"Orphaned temporary graph '{clone_name}' could not be deleted automatically: {exc}"
          )
          clone_cleaned_up = False

      if result is not None:
        result.clone_cleaned_up = clone_cleaned_up
        if not clone_cleaned_up:
          result.warnings.append(
              f"Orphaned temporary graph '{clone_name}' could not be deleted automatically."
          )
          if result.status == "VERIFIED_SEVERED":
            result.status = "CLEANUP_WARNING"

  def simulate_and_verify(
      self,
      revocation: EdgeRevocation,
      additional_revocations: Optional[List[EdgeRevocation]] = None,
      source_id: Optional[str] = None,
      target_id: Optional[str] = None,
      max_depth: int = 6,
      limit: int = 10,
  ) -> RemediationVerificationResult:
    """Convenience alias for simulate_and_verify_remediation."""
    res = self.simulate_and_verify_remediation(
        revocation=revocation,
        additional_revocations=additional_revocations,
        source_id=source_id,
        target_id=target_id,
        max_depth=max_depth,
        limit=limit,
    )
    # Ensure clone_cleaned_up reflects final state
    return res
