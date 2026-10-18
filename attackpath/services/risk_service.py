"""Deterministic, configurable risk-prioritization heuristic for attack paths."""

import logging
from typing import List, Optional
from attackpath.domain.path import AttackPath
from attackpath.domain.service_models import (
    PathRiskAssessment,
    RiskScoringConfig,
    RiskTier,
    RuleContribution,
)

logger = logging.getLogger("attackpath.services.risk")


class RiskPrioritizationService:
  """Calculates an explainable analyst risk score and tier for discovered attack paths.

  DISCLAIMER:
  This is an analyst prioritization heuristic based on graph facts and structural reachability.
  It is NOT a calibrated statistical probability of compromise or a machine-learning score.
  """

  def __init__(self, config: Optional[RiskScoringConfig] = None):
    self.config = config or RiskScoringConfig()

  def assess_path_risk(self, path: AttackPath) -> PathRiskAssessment:
    """Evaluates an AttackPath against deterministic risk rules with full contribution breakdown."""
    score = self.config.base_score
    contributions: List[RuleContribution] = []
    uncertainties: List[str] = []

    # Record base baseline contribution
    contributions.append(
        RuleContribution(
            rule_id="RULE_BASE_SCORE",
            rule_name="Baseline Path Score",
            score_delta=self.config.base_score,
            rationale="Initial baseline prioritization weight assigned to any discovered traversable path.",
            graph_facts={"hop_count": path.hop_count},
        )
    )

    # 1. Source Identity Assessment
    src_node = path.nodes[0]
    src_props = src_node.properties or {}

    if src_node.label == "Identity":
      # Check compromised state
      if "compromised" in src_props:
        if bool(src_props["compromised"]):
          score += self.config.weight_compromised_identity
          contributions.append(
              RuleContribution(
                  rule_id="RULE_COMPROMISED_IDENTITY",
                  rule_name="Compromised Origin Identity",
                  score_delta=self.config.weight_compromised_identity,
                  rationale=f"Origin identity '{src_node.id}' is actively flagged as compromised in directory.",
                  graph_facts={"node_id": src_node.id, "compromised": True},
              )
          )
      else:
        uncertainties.append(
            f"Origin identity '{src_node.id}' lacks 'compromised' attribute; treated conservatively as not compromised."
        )

      # Check MFA enforcement
      if "mfa_enabled" in src_props:
        if not bool(src_props["mfa_enabled"]):
          score += self.config.weight_mfa_disabled
          contributions.append(
              RuleContribution(
                  rule_id="RULE_MFA_DISABLED",
                  rule_name="MFA Disabled on Origin Identity",
                  score_delta=self.config.weight_mfa_disabled,
                  rationale=f"Origin identity '{src_node.id}' does not have Multi-Factor Authentication enforced.",
                  graph_facts={"node_id": src_node.id, "mfa_enabled": False},
              )
          )
      else:
        uncertainties.append(
            f"Origin identity '{src_node.id}' lacks 'mfa_enabled' attribute; treated conservatively as enabled."
        )

    # 2. Traversed Workloads Assessment
    for node in path.nodes[1:-1]:
      props = node.properties or {}
      if node.label == "Workload":
        if "is_internet_facing" in props:
          if bool(props["is_internet_facing"]):
            score += self.config.weight_internet_facing_workload
            contributions.append(
                RuleContribution(
                    rule_id="RULE_INTERNET_FACING_WORKLOAD",
                    rule_name="Internet-Facing Intermediate Workload",
                    score_delta=self.config.weight_internet_facing_workload,
                    rationale=f"Intermediate workload '{node.id}' is directly exposed to public traffic.",
                    graph_facts={"node_id": node.id, "is_internet_facing": True},
                )
            )
        else:
          uncertainties.append(
              f"Workload '{node.id}' lacks 'is_internet_facing' attribute; treated conservatively as internal."
          )

      elif node.label == "IAMRole":
        if "is_privileged" in props:
          if bool(props["is_privileged"]):
            score += self.config.weight_privileged_role
            contributions.append(
                RuleContribution(
                    rule_id="RULE_PRIVILEGED_ROLE",
                    rule_name="High-Privilege IAM Role",
                    score_delta=self.config.weight_privileged_role,
                    rationale=f"Traversed IAM role '{node.id}' possesses elevated/administrative privileges.",
                    graph_facts={"node_id": node.id, "is_privileged": True},
                )
            )
        else:
          uncertainties.append(
              f"IAM role '{node.id}' lacks 'is_privileged' attribute; treated conservatively as unprivileged."
          )

    # 3. Relationship Attributes Assessment
    for edge in path.edges:
      eprops = edge.properties or {}

      # Check for leaked/exposed credentials
      cred_type = str(eprops.get("credential_type", "")).upper()
      if "EXPOSED" in cred_type or "LEAK" in cred_type or "COMPROMISED" in cred_type:
        score += self.config.weight_exposed_credentials
        contributions.append(
            RuleContribution(
                rule_id="RULE_EXPOSED_CREDENTIALS",
                rule_name="Exposed / Leaked Credential Used",
                score_delta=self.config.weight_exposed_credentials,
                rationale=f"Edge '{edge.source}' -> '{edge.target}' exploits exposed credential type '{cred_type}'.",
                graph_facts={"source": edge.source, "target": edge.target, "credential_type": cred_type},
            )
        )

      # Check for wildcard access
      is_wildcard = eprops.get("is_wildcard")
      perm = str(eprops.get("permission", ""))
      if is_wildcard is True or "FullAccess" in perm or "*" in perm:
        score += self.config.weight_wildcard_permission
        contributions.append(
            RuleContribution(
                rule_id="RULE_WILDCARD_PERMISSION",
                rule_name="Wildcard / FullAccess Permissions",
                score_delta=self.config.weight_wildcard_permission,
                rationale=f"Edge '{edge.source}' -> '{edge.target}' grants unrestricted wildcard/FullAccess rights ({perm}).",
                graph_facts={"source": edge.source, "target": edge.target, "permission": perm, "is_wildcard": is_wildcard},
            )
        )

    # 4. Target Asset Assessment
    dst_node = path.nodes[-1]
    dst_props = dst_node.properties or {}

    if dst_node.label == "DataAsset":
      classification = dst_props.get("classification")
      if classification == "crown_jewel":
        score += self.config.weight_crown_jewel_target
        contributions.append(
            RuleContribution(
                rule_id="RULE_CROWN_JEWEL_TARGET",
                rule_name="Crown-Jewel Destination Asset",
                score_delta=self.config.weight_crown_jewel_target,
                rationale=f"Destination asset '{dst_node.id}' is classified as a top-tier crown-jewel data store.",
                graph_facts={"target_id": dst_node.id, "classification": "crown_jewel"},
            )
        )
      elif classification == "confidential":
        score += self.config.weight_confidential_target
        contributions.append(
            RuleContribution(
                rule_id="RULE_CONFIDENTIAL_TARGET",
                rule_name="Confidential Destination Asset",
                score_delta=self.config.weight_confidential_target,
                rationale=f"Destination asset '{dst_node.id}' is classified as confidential corporate data.",
                graph_facts={"target_id": dst_node.id, "classification": "confidential"},
            )
        )
      elif not classification:
        uncertainties.append(
            f"Destination asset '{dst_node.id}' lacks 'classification' attribute; treated conservatively as internal."
        )

      if "is_encrypted" in dst_props and dst_props["is_encrypted"] is False:
        score += self.config.weight_unencrypted_target
        contributions.append(
            RuleContribution(
                rule_id="RULE_UNENCRYPTED_TARGET",
                rule_name="Unencrypted Destination Asset",
                score_delta=self.config.weight_unencrypted_target,
                rationale=f"Destination asset '{dst_node.id}' is stored without at-rest encryption.",
                graph_facts={"target_id": dst_node.id, "is_encrypted": False},
            )
        )

    # 5. Path Hop Brevity Assessment
    if path.hop_count <= 3:
      score += self.config.weight_short_path_bonus
      contributions.append(
          RuleContribution(
              rule_id="RULE_SHORT_PATH_BONUS",
              rule_name="Short Attack Vector (<= 3 hops)",
              score_delta=self.config.weight_short_path_bonus,
              rationale=f"Short path ({path.hop_count} hops) presents fewer defensive choke-points and higher urgency.",
              graph_facts={"hop_count": path.hop_count},
          )
      )

    # Normalize score to 0..100
    final_score = max(0.0, min(100.0, round(score, 2)))

    # Determine risk tier
    if final_score >= self.config.threshold_critical:
      tier: RiskTier = "CRITICAL"
    elif final_score >= self.config.threshold_priority:
      tier = "PRIORITY"
    elif final_score >= self.config.threshold_monitor:
      tier = "MONITOR"
    else:
      tier = "INFORMATIONAL"

    return PathRiskAssessment(
        path_id=path.path_id,
        score=final_score,
        risk_tier=tier,
        contributions=contributions,
        uncertainties=uncertainties,
        is_synthetic=path.is_synthetic,
    )
