"""Synthetic enterprise topology generator and idempotent FalkorDB seeder."""

import logging
from typing import Any, Dict, List, Tuple
from attackpath.database.repository import FalkorDBRepository


logger = logging.getLogger("attackpath.database.seeder")

# Constants for exact topology assertions
SYNTHETIC_NODE_COUNT = 11
SYNTHETIC_EDGE_COUNT = 11

# Node Definitions: (Label, ID, Name, Properties)
SYNTHETIC_NODES: List[Tuple[str, str, str, Dict[str, Any]]] = [
    # 3 Identities
    ("Identity", "usr_jdoe", "John Doe", {
        "kind": "human",
        "email": "jdoe@enterprise.internal",
        "department": "IT Support",
        "compromised": True,
        "mfa_enabled": False,
        "is_synthetic": True,
        "simulated_audit_source": "hr_directory_2026",
    }),
    ("Identity", "usr_asmith", "Alice Smith", {
        "kind": "human",
        "email": "asmith@enterprise.internal",
        "department": "Engineering",
        "compromised": False,
        "mfa_enabled": True,
        "is_synthetic": True,
        "simulated_audit_source": "hr_directory_2026",
    }),
    ("Identity", "sa_deployer", "CI/CD Deployer", {
        "kind": "service_account",
        "email": "deployer@ci.internal",
        "department": "DevOps",
        "compromised": False,
        "mfa_enabled": False,
        "is_synthetic": True,
        "simulated_audit_source": "iam_service_accounts",
    }),
    # 3 Workloads
    ("Workload", "srv_app_prod", "App-Server-Prod", {
        "kind": "virtual_machine",
        "ip_address": "10.0.1.15",
        "is_internet_facing": True,
        "os": "Ubuntu 22.04 LTS",
        "is_synthetic": True,
        "simulated_cve": "CVE-2023-38606",
    }),
    ("Workload", "srv_analytics_worker", "Analytics-Worker-01", {
        "kind": "container",
        "ip_address": "10.0.2.44",
        "is_internet_facing": False,
        "os": "Alpine Linux 3.19",
        "is_synthetic": True,
        "simulated_cluster": "k8s-analytics-prod",
    }),
    ("Workload", "srv_internal_wiki", "Internal-Wiki", {
        "kind": "virtual_machine",
        "ip_address": "10.0.3.10",
        "is_internet_facing": False,
        "os": "Debian 12",
        "is_synthetic": True,
        "simulated_zone": "internal-dmz",
    }),
    # 3 IAM Roles
    ("IAMRole", "role_order_service", "OrderServiceRole", {
        "arn": "arn:aws:iam::123456789012:role/OrderServiceRole",
        "is_privileged": True,
        "is_synthetic": True,
        "simulated_policy_scope": "orders_backend",
    }),
    ("IAMRole", "role_analytics_readonly", "AnalyticsReadOnlyRole", {
        "arn": "arn:aws:iam::123456789012:role/AnalyticsReadOnly",
        "is_privileged": False,
        "is_synthetic": True,
        "simulated_policy_scope": "read_only_reports",
    }),
    ("IAMRole", "role_wiki_reader", "WikiReaderRole", {
        "arn": "arn:aws:iam::123456789012:role/WikiReader",
        "is_privileged": False,
        "is_synthetic": True,
        "simulated_policy_scope": "confluence_read",
    }),
    # 2 Data Assets
    ("DataAsset", "db_customer_vault", "Customer-Vault-DB", {
        "kind": "database",
        "classification": "crown_jewel",
        "is_encrypted": True,
        "is_synthetic": True,
        "simulated_records_count": 500000,
        "simulated_engine": "PostgreSQL 16",
    }),
    ("DataAsset", "s3_audit_archive", "Audit-Log-Archive", {
        "kind": "object_store",
        "classification": "confidential",
        "is_encrypted": True,
        "is_synthetic": True,
        "simulated_records_count": 1200000,
        "simulated_bucket_name": "corp-audit-logs-encrypted",
    }),
]

# Relationship Definitions: (Source ID, Type, Target ID, Properties)
SYNTHETIC_RELATIONSHIPS: List[Tuple[str, str, str, Dict[str, Any]]] = [
    # Primary Attack Path P1 (3 hops)
    ("usr_jdoe", "AUTHENTICATES_TO", "srv_app_prod", {
        "method": "SSH",
        "credential_type": "EXPOSED_PRIVATE_KEY",
        "simulated_session_id": "sess_492",
        "is_synthetic": True,
    }),
    ("srv_app_prod", "EXECUTES_AS", "role_order_service", {
        "source": "INSTANCE_METADATA",
        "imds_version": "v1",
        "is_synthetic": True,
    }),
    ("role_order_service", "CAN_ACCESS", "db_customer_vault", {
        "permission": "rds:FullAccess",
        "policy_id": "pol_rds_all",
        "is_wildcard": True,
        "is_synthetic": True,
    }),
    # Alternative Attack Path P2 (4 hops)
    ("srv_app_prod", "NETWORK_REACHABLE", "srv_analytics_worker", {
        "port": 8080,
        "protocol": "TCP",
        "firewall_rule": "allow_internal_analytics",
        "is_synthetic": True,
    }),
    ("srv_analytics_worker", "EXECUTES_AS", "role_analytics_readonly", {
        "source": "K8S_SERVICE_ACCOUNT",
        "namespace": "analytics",
        "is_synthetic": True,
    }),
    ("role_analytics_readonly", "CAN_ACCESS", "db_customer_vault", {
        "permission": "rds:ReadOnly",
        "policy_id": "pol_rds_readonly",
        "is_wildcard": False,
        "is_synthetic": True,
    }),
    # Benign Background Traffic (5 edges)
    ("usr_asmith", "AUTHENTICATES_TO", "srv_internal_wiki", {
        "method": "WEB_SSO",
        "credential_type": "SAML_TOKEN",
        "is_synthetic": True,
    }),
    ("srv_internal_wiki", "EXECUTES_AS", "role_wiki_reader", {
        "source": "INSTANCE_METADATA",
        "is_synthetic": True,
    }),
    ("role_wiki_reader", "CAN_ACCESS", "s3_audit_archive", {
        "permission": "s3:GetObject",
        "policy_id": "pol_wiki_docs",
        "is_synthetic": True,
    }),
    ("role_analytics_readonly", "CAN_ACCESS", "s3_audit_archive", {
        "permission": "s3:GetObject",
        "policy_id": "pol_analytics_archive",
        "is_synthetic": True,
    }),
    ("sa_deployer", "CAN_ASSUME", "role_wiki_reader", {
        "policy_name": "AssumeWikiReader",
        "mfa_required": False,
        "is_synthetic": True,
    }),
]


def seed_synthetic_scenario(
    repository: FalkorDBRepository,
    clean_first: bool = True,
) -> Dict[str, int]:
  """Seeds the canonical synthetic benchmark topology into FalkorDB.

  Uses parameterized queries to ensure zero injection risk.
  If clean_first is True, the graph is cleared before seeding.
  If clean_first is False, uses idempotent MERGE commands so rerunning
  does not produce duplicate nodes or relationships.
  """
  if clean_first:
    repository.clear_graph()

  # 1. Seed Nodes idempotently via MERGE
  for label, node_id, name, props in SYNTHETIC_NODES:
    merged_props = {"id": node_id, "name": name, **props}
    cypher = f"""
        MERGE (n:{label} {{id: $id}})
        ON CREATE SET n = $props
        ON MATCH SET n = $props
        """
    repository.query(cypher, params={"id": node_id, "props": merged_props})

  # 2. Seed Relationships idempotently via MERGE
  for src_id, rel_type, dst_id, props in SYNTHETIC_RELATIONSHIPS:
    cypher = f"""
        MATCH (src {{id: $src_id}}), (dst {{id: $dst_id}})
        MERGE (src)-[r:{rel_type}]->(dst)
        ON CREATE SET r = $props
        ON MATCH SET r = $props
        """
    repository.query(cypher, params={"src_id": src_id, "dst_id": dst_id, "props": props})

  total_nodes = repository.count_nodes()
  total_edges = repository.count_edges()

  logger.info(
      "Seeding complete for graph '%s': %d nodes, %d relationships",
      repository.graph_name,
      total_nodes,
      total_edges,
  )

  return {
      "nodes_created": len(SYNTHETIC_NODES),
      "relationships_created": len(SYNTHETIC_RELATIONSHIPS),
      "total_nodes": total_nodes,
      "total_edges": total_edges,
  }
