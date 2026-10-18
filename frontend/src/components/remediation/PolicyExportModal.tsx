"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  X,
  Copy,
  Check,
  FileCode,
  ShieldAlert,
  AlertCircle,
} from "lucide-react";
import { RemediationVerificationResult } from "@/lib/types";

interface PolicyExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  compoundMode: boolean;
  sourceId: string;
  relType: string;
  targetId: string;
  simulationResult: RemediationVerificationResult | null;
}

export function PolicyExportModal({
  isOpen,
  onClose,
  compoundMode,
  sourceId,
  relType,
  targetId,
  simulationResult,
}: PolicyExportModalProps) {
  const [selectedFormat, setSelectedFormat] = useState<"terraform" | "iam_json">("terraform");
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "error">("idle");
  const [copyError, setCopyError] = useState<string | null>(null);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  // Reset copy state when modal opens or format changes
  useEffect(() => {
    setCopyStatus("idle");
    setCopyError(null);
  }, [isOpen, selectedFormat]);

  const terraformTemplate = useMemo(() => {
    if (compoundMode) {
      return `# ==============================================================================
# AttackPath Remediation Template — Compound Severance (Outcome A)
# Status: PROPOSED TEMPLATE — Requires Security Review and Environment Adaptation
# ------------------------------------------------------------------------------
# Targeted Hops for Severance:
#   1. IAM Access: (${sourceId})-[${relType}]->(${targetId})
#   2. Lateral Network: (srv_app_prod)-[NETWORK_REACHABLE]->(srv_analytics_worker:8080)
#
# Simulation Verification:
#   Verified Severed in Ephemeral Clone: ${simulationResult?.clone_name || "attackpath_sim_clone"}
#   Residual Paths to Target: 0 (Target Unreachable)
#   Residual Risk Score: 0 / 100 [INFORMATIONAL]
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# --- STEP 1: Revoke IAM Role Database Access Policy ---
# Removes CAN_ACCESS relationship between ${sourceId} and ${targetId}

resource "aws_iam_role_policy_attachment" "revoke_order_service_vault_access" {
  # To remediate: Detach or replace the overly permissive vault access policy
  role       = "${sourceId}"
  policy_arn = aws_iam_policy.restricted_vault_access.arn
}

resource "aws_iam_policy" "restricted_vault_access" {
  name        = "RestrictedVaultAccessPolicy"
  path        = "/security-remediations/"
  description = "Explicitly denies direct database credentials access for ${sourceId}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyDirectVaultAccess"
        Effect   = "Deny"
        Action   = [
          "rds-db:connect",
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:rds:*:*:db:${targetId}",
          "arn:aws:secretsmanager:*:*:secret:${targetId}/*"
        ]
      }
    ]
  })
}

# --- STEP 2: Restrict Lateral Movement Security Group Ingress ---
# Severs NETWORK_REACHABLE hop from srv_app_prod to srv_analytics_worker:8080

resource "aws_security_group_rule" "revoke_analytics_lateral_ingress" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  security_group_id        = "sg-analytics-worker-prod" # Replace with your target SG ID
  source_security_group_id = "sg-app-prod"             # Source: Production Application Server
  description              = "Sever lateral route from srv_app_prod (AttackPath Remediation INV-2025-084)"

  # Set count = 0 or remove this resource to revoke ingress in your existing module
}
`;
    }

    return `# ==============================================================================
# AttackPath Remediation Template — Single-Edge Severance (Outcome B)
# Status: PROPOSED TEMPLATE — Requires Security Review and Environment Adaptation
# ------------------------------------------------------------------------------
# Targeted Hop for Severance:
#   1. IAM Access: (${sourceId})-[${relType}]->(${targetId})
#
# Simulation Verification:
#   Verified Severed in Ephemeral Clone: ${simulationResult?.clone_name || "attackpath_sim_clone"}
#   Residual Paths to Target: ${simulationResult?.residual_paths_count ?? 1} (Lateral Route Still Live via srv_analytics_worker)
#   Residual Risk Score: ${simulationResult?.residual_risk_score ?? 100} / 100 [CRITICAL]
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# --- STEP 1: Revoke Direct IAM Database Access Policy ---
# Removes CAN_ACCESS relationship between ${sourceId} and ${targetId}

resource "aws_iam_role_policy_attachment" "revoke_order_service_vault_access" {
  role       = "${sourceId}"
  policy_arn = aws_iam_policy.deny_customer_vault_access.arn
}

resource "aws_iam_policy" "deny_customer_vault_access" {
  name        = "DenyCustomerVaultDirectAccess"
  path        = "/security-remediations/"
  description = "Explicitly revokes direct database connection rights from ${sourceId}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyCustomerVaultAccess"
        Effect   = "Deny"
        Action   = [
          "rds-db:connect",
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:rds:*:*:db:${targetId}",
          "arn:aws:secretsmanager:*:*:secret:${targetId}/*"
        ]
      }
    ]
  })
}

# NOTE: Single-edge revocation leaves lateral route active through srv_analytics_worker.
# To achieve zero reachable paths (Outcome A), apply compound network severance.
`;
  }, [compoundMode, sourceId, relType, targetId, simulationResult]);

  const iamJsonTemplate = useMemo(() => {
    if (compoundMode) {
      return JSON.stringify(
        {
          _comment: "PROPOSED TEMPLATE: Compound Severance (Outcome A) — Requires security review",
          remediation_metadata: {
            investigation_id: "INV-2025-084",
            verified_outcome: "A",
            residual_paths: 0,
            simulated_clone: simulationResult?.clone_name || "ephemeral_clone",
            generated_at: new Date().toISOString(),
          },
          iam_policy: {
            Version: "2012-10-17",
            Statement: [
              {
                Sid: "SeverOrderServiceDirectVaultAccess",
                Effect: "Deny",
                Principal: {
                  AWS: `arn:aws:iam::123456789012:role/${sourceId}`,
                },
                Action: [
                  "rds-db:connect",
                  "secretsmanager:GetSecretValue",
                ],
                Resource: [
                  `arn:aws:rds:us-east-1:123456789012:db:${targetId}`,
                  `arn:aws:secretsmanager:us-east-1:123456789012:secret:${targetId}/*`,
                ],
              },
            ],
          },
          network_security_rule: {
            action: "REVOKE_INGRESS",
            source_workload: "srv_app_prod",
            target_workload: "srv_analytics_worker",
            protocol: "tcp",
            port: 8080,
            rationale: "Sever secondary lateral traversal path to crown jewel",
          },
        },
        null,
        2
      );
    }

    return JSON.stringify(
      {
        _comment: "PROPOSED TEMPLATE: Single-Edge Severance (Outcome B) — Requires security review",
        remediation_metadata: {
          investigation_id: "INV-2025-084",
          verified_outcome: "B",
          residual_paths: simulationResult?.residual_paths_count ?? 1,
          simulated_clone: simulationResult?.clone_name || "ephemeral_clone",
          warning: "Alternative lateral path via srv_analytics_worker remains active.",
          generated_at: new Date().toISOString(),
        },
        iam_policy: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "SeverOrderServiceDirectVaultAccess",
              Effect: "Deny",
              Principal: {
                AWS: `arn:aws:iam::123456789012:role/${sourceId}`,
              },
              Action: [
                "rds-db:connect",
                "secretsmanager:GetSecretValue",
              ],
              Resource: [
                `arn:aws:rds:us-east-1:123456789012:db:${targetId}`,
                `arn:aws:secretsmanager:us-east-1:123456789012:secret:${targetId}/*`,
              ],
            },
          ],
        },
      },
      null,
      2
    );
  }, [compoundMode, sourceId, targetId, simulationResult]);

  const activeContent = selectedFormat === "terraform" ? terraformTemplate : iamJsonTemplate;

  const handleCopy = async () => {
    try {
      if (!navigator?.clipboard?.writeText) {
        throw new Error("Clipboard API not available in current browser environment.");
      }
      await navigator.clipboard.writeText(activeContent);
      setCopyStatus("copied");
      setCopyError(null);
      setTimeout(() => {
        setCopyStatus("idle");
      }, 3000);
    } catch (err: any) {
      setCopyStatus("error");
      setCopyError(
        err?.message || "Failed to copy to clipboard. Please copy template text manually."
      );
    }
  };

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-xs animate-in fade-in duration-150"
    >
      <div className="bg-[#FAF7F0] w-full max-w-3xl rounded-xl border border-[#E3DDD2] shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="bg-white px-6 py-4 flex items-center justify-between border-b border-[#E3DDD2]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#EEF7F5] text-[#32877A] flex items-center justify-center border border-[#32877A]/20">
              <FileCode className="w-4 h-4" />
            </div>
            <div>
              <h3 id="modal-title" className="text-base font-bold text-[#282B2A] tracking-tight">
                Remediation Policy &amp; Infrastructure Code Export
              </h3>
              <p className="text-xs text-[#686D6B]">
                Synthesized from simulated severance verification ({compoundMode ? "Outcome A — Compound" : "Outcome B — Single Cut"})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#686D6B] hover:text-[#282B2A] hover:bg-[#FAF7F0] transition-colors cursor-pointer"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Warning & Disclaimers Banner */}
        <div className="bg-[#FEF8EC] border-b border-[#D99A28]/40 px-6 py-3 flex items-start gap-3">
          <ShieldAlert className="w-4 h-4 text-[#D99A28] shrink-0 mt-0.5" />
          <div className="text-xs text-[#282B2A] flex flex-col gap-0.5 leading-snug">
            <span className="font-bold text-[#9B6B15] uppercase tracking-wider text-[10px]">
              PROPOSED TEMPLATE — Requires Security Review
            </span>
            <p className="text-[11px] text-[#686D6B]">
              This template was automatically derived from the in-memory graph simulation. It must be adapted to your organization&apos;s specific AWS account IDs, VPC configurations, and naming conventions. AttackPath <strong>does not</strong> automatically apply infrastructure changes or alter production cloud accounts.
            </p>
          </div>
        </div>

        {/* Format Selector & Actions Bar */}
        <div className="bg-[#FAF7F0] px-6 py-2.5 flex items-center justify-between border-b border-[#E3DDD2]">
          <div className="flex items-center gap-1.5 bg-[#EDE7DC] p-0.5 rounded-lg border border-[#E3DDD2]">
            <button
              onClick={() => setSelectedFormat("terraform")}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition-all cursor-pointer ${
                selectedFormat === "terraform"
                  ? "bg-white text-[#282B2A] shadow-xs"
                  : "text-[#686D6B] hover:text-[#282B2A]"
              }`}
            >
              Terraform (HCL)
            </button>
            <button
              onClick={() => setSelectedFormat("iam_json")}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition-all cursor-pointer ${
                selectedFormat === "iam_json"
                  ? "bg-white text-[#282B2A] shadow-xs"
                  : "text-[#686D6B] hover:text-[#282B2A]"
              }`}
            >
              AWS IAM Policy (JSON)
            </button>
          </div>

          <button
            onClick={handleCopy}
            className={`h-8 px-3.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer border shadow-xs ${
              copyStatus === "copied"
                ? "bg-[#EEF7F5] text-[#32877A] border-[#32877A]/40"
                : copyStatus === "error"
                ? "bg-[#FDF2F0] text-[#E85D4A] border-[#E85D4A]/40"
                : "bg-white hover:bg-[#FAF7F0] text-[#282B2A] border-[#E3DDD2]"
            }`}
          >
            {copyStatus === "copied" ? (
              <>
                <Check className="w-3.5 h-3.5 text-[#32877A]" />
                <span>Copied to Clipboard!</span>
              </>
            ) : copyStatus === "error" ? (
              <>
                <AlertCircle className="w-3.5 h-3.5 text-[#E85D4A]" />
                <span>Copy Failed</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-[#686D6B]" />
                <span>Copy to Clipboard</span>
              </>
            )}
          </button>
        </div>

        {/* Copy Error Notice (if any) */}
        {copyError && (
          <div className="bg-[#FDF2F0] border-b border-[#E85D4A]/30 px-6 py-2 flex items-center justify-between text-xs text-[#E85D4A]">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{copyError}</span>
            </div>
            <button
              onClick={() => setCopyError(null)}
              className="text-[10px] font-mono font-bold hover:underline"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Code Content Container */}
        <div className="p-6 overflow-y-auto flex-1 bg-[#F6F2E9]">
          <div className="relative rounded-lg border border-[#E3DDD2] bg-[#282B2A] text-[#FAF7F0] p-4 font-mono text-xs overflow-x-auto leading-relaxed shadow-inner">
            <div className="absolute top-2 right-3 text-[10px] uppercase tracking-wider text-[#FAF7F0]/40 font-mono select-none">
              {selectedFormat === "terraform" ? "HCL" : "JSON"}
            </div>
            <pre className="selection:bg-[#32877A] selection:text-white">
              <code>{activeContent}</code>
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="bg-white px-6 py-3 border-t border-[#E3DDD2] flex items-center justify-between text-xs text-[#686D6B]">
          <div className="flex items-center gap-1.5 font-mono text-[10px]">
            <span className="w-2 h-2 rounded-full bg-[#32877A]" />
            <span>Target Nodes: {sourceId} ➔ {targetId}</span>
          </div>
          <button
            onClick={onClose}
            className="h-8 px-4 rounded-lg bg-[#FAF7F0] hover:bg-[#EDE7DC] text-[#282B2A] text-xs font-semibold transition-colors border border-[#E3DDD2] cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
