/**
 * AttackPath Typed API Client
 * Interfaces with FastAPI endpoints via Next.js proxy rewrites
 */

import {
  ApiError,
  DiscoveryResult,
  HealthResponse,
  InvestigationResponse,
  ReadyResponse,
  RemediationVerificationResult,
  SeedResponse,
  TopologyResponse,
  EdgeRevocation,
} from "./types";

export class AttackPathApiError extends Error {
  code: string;
  details?: any;

  constructor(error: ApiError) {
    super(error.message);
    this.name = "AttackPathApiError";
    this.code = error.code;
    this.details = error.details;
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(endpoint, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    let errorPayload: ApiError = {
      code: "HTTP_ERROR",
      message: `Request failed with status ${res.status}`,
    };

    try {
      const data = await res.json();
      if (data && data.error) {
        errorPayload = data.error;
      }
    } catch {
      // Fallback to text message
      const text = await res.text().catch(() => "");
      if (text) errorPayload.message = text;
    }

    throw new AttackPathApiError(errorPayload);
  }

  return res.json() as Promise<T>;
}

export const api = {
  /** Check process liveness */
  async getHealth(): Promise<HealthResponse> {
    return request<HealthResponse>("/health");
  },

  /** Check database connectivity and readiness */
  async getReadiness(): Promise<ReadyResponse> {
    return request<ReadyResponse>("/health/ready");
  },

  /** Retrieve full baseline graph topology */
  async getTopology(): Promise<TopologyResponse> {
    return request<TopologyResponse>("/api/v1/graph/topology");
  },

  /**
   * Explicitly seed the benchmark synthetic demonstration scenario
   * Note: NEVER call this automatically on page load.
   */
  async seedGraph(cleanFirst: boolean = false): Promise<SeedResponse> {
    return request<SeedResponse>("/api/v1/graph/seed", {
      method: "POST",
      body: JSON.stringify({ clean_first: cleanFirst }),
    });
  },

  /** Discover bounded directed attack paths between entities */
  async discoverPaths(
    sourceId: string,
    targetId: string,
    maxDepth: number = 6,
    limit: number = 10
  ): Promise<DiscoveryResult> {
    const params = new URLSearchParams({
      source_id: sourceId,
      target_id: targetId,
      max_depth: maxDepth.toString(),
      limit: limit.toString(),
    });
    return request<DiscoveryResult>(`/api/v1/paths/discover?${params.toString()}`);
  },

  /** Discover, extract fact-grounded evidence, and assess deterministic risk */
  async investigateAndExplain(
    sourceId: string,
    targetId: string,
    maxDepth: number = 6,
    limit: number = 10
  ): Promise<InvestigationResponse> {
    return request<InvestigationResponse>("/api/v1/investigate/explain", {
      method: "POST",
      body: JSON.stringify({
        source_id: sourceId,
        target_id: targetId,
        max_depth: maxDepth,
        limit,
      }),
    });
  },

  /** Simulate edge revocation on an isolated graph clone and verify severance */
  async simulateRemediation(
    revocation: EdgeRevocation,
    sourceId?: string,
    targetId?: string,
    maxDepth: number = 6,
    limit: number = 10,
    additionalRevocations?: EdgeRevocation[]
  ): Promise<RemediationVerificationResult> {
    return request<RemediationVerificationResult>(
      "/api/v1/remediate/simulate-and-verify",
      {
        method: "POST",
        body: JSON.stringify({
          revocation,
          additional_revocations: additionalRevocations || null,
          source_id: sourceId || null,
          target_id: targetId || null,
          max_depth: maxDepth,
          limit,
        }),
      }
    );
  },
};
