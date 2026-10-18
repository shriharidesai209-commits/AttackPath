/**
 * TypeScript mirror of AttackPath Python Pydantic Domain & API Schemas
 * Source: attackpath/domain/ and attackpath/api/schemas.py
 */

export type RelationshipType =
  | "AUTHENTICATES_TO"
  | "EXECUTES_AS"
  | "CAN_ASSUME"
  | "CAN_ACCESS"
  | "NETWORK_REACHABLE";

export function formatRelationshipLabel(relType: string): string {
  switch (relType) {
    case "AUTHENTICATES_TO":
      return "Signs In To";
    case "EXECUTES_AS":
      return "Runs With Permissions Of";
    case "CAN_ASSUME":
      return "Can Assume Role";
    case "CAN_ACCESS":
      return "Can Access";
    case "NETWORK_REACHABLE":
      return "Can Connect To";
    default:
      return relType ? relType.replace(/_/g, " ") : "";
  }
}

export type EntityLabel = "Identity" | "Workload" | "IAMRole" | "DataAsset";

export interface BaseEntityNode {
  id: string;
  label: EntityLabel | string;
  name: string;
  is_synthetic?: boolean;
  properties?: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: RelationshipType | string;
  properties?: Record<string, any>;
  is_synthetic?: boolean;
}

export interface AttackPath {
  path_id: string;
  hop_count: number;
  nodes: BaseEntityNode[];
  edges: GraphEdge[];
  is_synthetic: boolean;
  signature?: string;
}

export type DiscoveryStatus =
  | "PATHS_DISCOVERED"
  | "TARGET_UNREACHABLE"
  | "ENTITY_NOT_FOUND"
  | "INVALID_REQUEST"
  | "DATABASE_ERROR";

export interface DiscoveryResult {
  status: DiscoveryStatus;
  source_id: string;
  target_id: string;
  paths: AttackPath[];
  total_paths_found: number;
  max_depth_applied: number;
  is_synthetic: boolean;
  details?: string | null;
}

export type FactProvenance =
  | "OBSERVED_GRAPH_FACT"
  | "DERIVED_INTERPRETATION"
  | "SYNTHETIC_DATA_METADATA";

export interface EvidenceFact {
  statement: string;
  provenance: FactProvenance;
  supporting_attributes?: Record<string, any>;
}

export interface NodeEvidence {
  node_id: string;
  label: string;
  name: string;
  properties?: Record<string, any>;
  observed_facts: string[];
}

export interface EdgeEvidence {
  source_id: string;
  target_id: string;
  rel_type: string;
  properties?: Record<string, any>;
  observed_facts: string[];
}

export interface PathEvidence {
  path_id: string;
  hop_count: number;
  ordered_nodes: NodeEvidence[];
  ordered_edges: EdgeEvidence[];
  route_summary: string;
  factual_claims: EvidenceFact[];
  is_synthetic: boolean;
}

export type RiskTier = "INFORMATIONAL" | "MONITOR" | "PRIORITY" | "CRITICAL";

export interface RuleContribution {
  rule_id: string;
  rule_name: string;
  score_delta: number;
  rationale: string;
  graph_facts?: Record<string, any>;
}

export interface PathRiskAssessment {
  path_id: string;
  score: number;
  risk_tier: RiskTier;
  contributions: RuleContribution[];
  uncertainties: string[];
  is_synthetic: boolean;
  disclaimer: string;
}

export interface PathInvestigationDetail {
  path: AttackPath;
  evidence: PathEvidence;
  risk_assessment: PathRiskAssessment;
}

export interface InvestigationResponse {
  status: string;
  source_id: string;
  target_id: string;
  total_paths_found: number;
  paths: PathInvestigationDetail[];
  is_synthetic: boolean;
  disclaimer: string;
  details?: string | null;
}

export interface EdgeRevocation {
  source_id: string;
  rel_type: string;
  target_id: string;
}

export type RemediationStatus =
  | "VERIFIED_SEVERED"
  | "VERIFIED_UNAFFECTED"
  | "MUTATION_REJECTED"
  | "VERIFICATION_FAILED"
  | "CLEANUP_WARNING";

export interface RemediationVerificationResult {
  status: RemediationStatus;
  success: boolean;
  revocation: EdgeRevocation;
  baseline_counts_before: Record<string, number>;
  baseline_counts_after: Record<string, number>;
  baseline_intact: boolean;
  clone_name: string;
  clone_cleaned_up: boolean;
  original_path_severed: boolean;
  target_still_reachable: boolean;
  before_paths_count: number;
  residual_paths_count: number;
  residual_paths: AttackPath[];
  residual_risk_score?: number | null;
  residual_risk_tier?: string | null;
  warnings: string[];
  details: string;
}

export interface HealthResponse {
  status: string;
  app: string;
  environment: string;
}

export interface ReadyResponse {
  status: string;
  database: string;
  graph: string;
}

export interface TopologyResponse {
  graph_name: string;
  total_nodes: number;
  total_edges: number;
  nodes: BaseEntityNode[];
  edges: GraphEdge[];
  is_synthetic: boolean;
}

export interface SeedResponse {
  status: string;
  graph_name: string;
  nodes_created: number;
  relationships_created: number;
  total_nodes: number;
  total_edges: number;
  is_synthetic: boolean;
  message: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: any;
}
