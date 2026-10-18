"""Application service for extracting and explaining graph evidence supporting attack paths."""

import logging
from typing import Any, Dict, List
from attackpath.domain.path import AttackPath
from attackpath.domain.service_models import (
    EdgeEvidence,
    EvidenceFact,
    NodeEvidence,
    PathEvidence,
)

logger = logging.getLogger("attackpath.services.evidence")


class EvidenceService:
  """Extracts deterministic, fact-grounded evidence from discovered attack paths."""

  def generate_path_evidence(self, path: AttackPath) -> PathEvidence:
    """Produces structured evidence for an AttackPath, distinguishing observed facts,

    derived interpretations, and synthetic data provenance.
    """
    node_evidences: List[NodeEvidence] = []
    factual_claims: List[EvidenceFact] = []

    # 1. Parse Node Evidence
    for node in path.nodes:
      props = node.properties or {}
      observed: List[str] = []

      # Basic topological identification
      observed.append(f"Entity '{node.id}' with label '{node.label}' and display name '{node.name}'.")
      factual_claims.append(
          EvidenceFact(
              statement=f"Entity '{node.id}' exists with label '{node.label}'.",
              provenance="OBSERVED_GRAPH_FACT",
              supporting_attributes={"id": node.id, "label": node.label, "name": node.name},
          )
      )

      # Label-specific observed properties
      if node.label == "Identity":
        if "compromised" in props:
          status_str = "compromised" if props["compromised"] else "not compromised"
          observed.append(f"Identity compromise status: {status_str}.")
          factual_claims.append(
              EvidenceFact(
                  statement=f"Identity '{node.id}' compromise state is {props['compromised']}.",
                  provenance="OBSERVED_GRAPH_FACT",
                  supporting_attributes={"node_id": node.id, "compromised": props["compromised"]},
              )
          )
        else:
          observed.append("Identity compromise status is unknown.")

        if "mfa_enabled" in props:
          mfa_str = "enabled" if props["mfa_enabled"] else "disabled"
          observed.append(f"Multi-Factor Authentication (MFA): {mfa_str}.")
          factual_claims.append(
              EvidenceFact(
                  statement=f"Identity '{node.id}' MFA enforcement is {props['mfa_enabled']}.",
                  provenance="OBSERVED_GRAPH_FACT",
                  supporting_attributes={"node_id": node.id, "mfa_enabled": props["mfa_enabled"]},
              )
          )
        else:
          observed.append("MFA enforcement status is unknown.")

      elif node.label == "Workload":
        if "is_internet_facing" in props:
          net_str = "publicly internet-facing" if props["is_internet_facing"] else "internal-only"
          observed.append(f"Network exposure: {net_str}.")
          factual_claims.append(
              EvidenceFact(
                  statement=f"Workload '{node.id}' internet exposure is {props['is_internet_facing']}.",
                  provenance="OBSERVED_GRAPH_FACT",
                  supporting_attributes={"node_id": node.id, "is_internet_facing": props["is_internet_facing"]},
              )
          )
        else:
          observed.append("Internet exposure status is unknown.")

        if "ip_address" in props:
          observed.append(f"Assigned IP address: {props['ip_address']}.")

      elif node.label == "IAMRole":
        if "is_privileged" in props:
          priv_str = "privileged/administrative" if props["is_privileged"] else "standard/unprivileged"
          observed.append(f"IAM privilege scope: {priv_str}.")
          factual_claims.append(
              EvidenceFact(
                  statement=f"IAM Role '{node.id}' privileged status is {props['is_privileged']}.",
                  provenance="OBSERVED_GRAPH_FACT",
                  supporting_attributes={"node_id": node.id, "is_privileged": props["is_privileged"]},
              )
          )
        else:
          observed.append("IAM privilege scope is unknown.")

        if "arn" in props:
          observed.append(f"IAM ARN: {props['arn']}.")

      elif node.label == "DataAsset":
        if "classification" in props:
          observed.append(f"Data classification tier: {props['classification']}.")
          factual_claims.append(
              EvidenceFact(
                  statement=f"Data Asset '{node.id}' is classified as {props['classification']}.",
                  provenance="OBSERVED_GRAPH_FACT",
                  supporting_attributes={"node_id": node.id, "classification": props["classification"]},
              )
          )
        else:
          observed.append("Data classification tier is unknown.")

        if "is_encrypted" in props:
          enc_str = "active" if props["is_encrypted"] else "inactive"
          observed.append(f"At-rest encryption: {enc_str}.")
        else:
          observed.append("At-rest encryption status is unknown.")

      node_evidences.append(
          NodeEvidence(
              node_id=node.id,
              label=node.label,
              name=node.name,
              properties=props,
              observed_facts=observed,
          )
      )

    # 2. Parse Edge Evidence
    edge_evidences: List[EdgeEvidence] = []
    step_descriptions: List[str] = []

    for idx, edge in enumerate(path.edges):
      props = edge.properties or {}
      src_node = path.nodes[idx]
      dst_node = path.nodes[idx + 1]
      observed = []

      rel_type = edge.type
      observed.append(f"Traverses directed '{rel_type}' edge from '{edge.source}' to '{edge.target}'.")

      step_detail = f"Step {idx + 1}: {src_node.label} '{src_node.id}' connects to {dst_node.label} '{dst_node.id}' via {rel_type}"

      if rel_type == "AUTHENTICATES_TO":
        method = props.get("method", "unspecified method")
        cred_type = props.get("credential_type", "unspecified credential")
        observed.append(f"Authentication method: {method}; Credential mechanism: {cred_type}.")
        step_detail += f" using {method} ({cred_type})"
        factual_claims.append(
            EvidenceFact(
                statement=f"Edge '{edge.source}' -> '{edge.target}' authenticates via {method} with {cred_type}.",
                provenance="OBSERVED_GRAPH_FACT",
                supporting_attributes={"method": method, "credential_type": cred_type},
            )
        )
      elif rel_type == "EXECUTES_AS":
        source_mech = props.get("source", "unspecified source")
        observed.append(f"Role execution origin: {source_mech}.")
        step_detail += f" via {source_mech}"
        factual_claims.append(
            EvidenceFact(
                statement=f"Edge '{edge.source}' -> '{edge.target}' assumes execution context via {source_mech}.",
                provenance="OBSERVED_GRAPH_FACT",
                supporting_attributes={"source": source_mech},
            )
        )
      elif rel_type == "CAN_ACCESS":
        permission = props.get("permission", "unspecified permission")
        is_wildcard = props.get("is_wildcard", "unknown")
        observed.append(f"Granted access permission: {permission} (wildcard: {is_wildcard}).")
        step_detail += f" with permission {permission} (wildcard={is_wildcard})"
        factual_claims.append(
            EvidenceFact(
                statement=f"Edge '{edge.source}' -> '{edge.target}' grants {permission} (wildcard: {is_wildcard}).",
                provenance="OBSERVED_GRAPH_FACT",
                supporting_attributes={"permission": permission, "is_wildcard": is_wildcard},
            )
        )
      elif rel_type == "NETWORK_REACHABLE":
        port = props.get("port", "unspecified")
        proto = props.get("protocol", "TCP")
        observed.append(f"Network reachability over {proto}/{port}.")
        step_detail += f" over {proto}/{port}"
        factual_claims.append(
            EvidenceFact(
                statement=f"Edge '{edge.source}' -> '{edge.target}' is network reachable via {proto}/{port}.",
                provenance="OBSERVED_GRAPH_FACT",
                supporting_attributes={"protocol": proto, "port": port},
            )
        )
      elif rel_type == "CAN_ASSUME":
        policy = props.get("policy_name", "unspecified policy")
        observed.append(f"Role assumption policy: {policy}.")
        step_detail += f" under policy {policy}"

      step_descriptions.append(step_detail + ".")
      edge_evidences.append(
          EdgeEvidence(
              source_id=edge.source,
              target_id=edge.target,
              rel_type=rel_type,
              properties=props,
              observed_facts=observed,
          )
      )

    # 3. Provenance and Synthetic Data Labeling
    is_synthetic = path.is_synthetic or any(n.is_synthetic for n in path.nodes)
    if is_synthetic:
      factual_claims.append(
          EvidenceFact(
              statement="This attack path traverses synthetic demonstration security data.",
              provenance="SYNTHETIC_DATA_METADATA",
              supporting_attributes={"is_synthetic": True},
          )
      )

    # 4. Derived Interpretation
    route_summary = " ".join(step_descriptions)
    src_compromised = bool(path.nodes[0].properties.get("compromised", False))
    target_crown_jewel = path.nodes[-1].properties.get("classification") == "crown_jewel"

    if src_compromised and target_crown_jewel:
      factual_claims.append(
          EvidenceFact(
              statement="Route links an already compromised identity directly or indirectly to a crown-jewel asset.",
              provenance="DERIVED_INTERPRETATION",
              supporting_attributes={
                  "source_id": path.nodes[0].id,
                  "source_compromised": True,
                  "target_id": path.nodes[-1].id,
                  "target_classification": "crown_jewel",
              },
          )
      )

    return PathEvidence(
        path_id=path.path_id,
        hop_count=path.hop_count,
        ordered_nodes=node_evidences,
        ordered_edges=edge_evidences,
        route_summary=route_summary,
        factual_claims=factual_claims,
        is_synthetic=is_synthetic,
    )
