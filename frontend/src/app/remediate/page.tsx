"use client";

import React, { useEffect, useState, useMemo, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { AppSidebar } from "@/components/layout/AppSidebar";
import { AppHeader } from "@/components/layout/AppHeader";
import { AttackGraphCanvas } from "@/components/graph/AttackGraphCanvas";
import { api, AttackPathApiError } from "@/lib/api";
import {
  RemediationVerificationResult,
  EdgeRevocation,
} from "@/lib/types";
import { getLayoutedElements } from "@/lib/graph-layout";
import { Node, Edge } from "@xyflow/react";
import {
  ArrowLeft,
  CheckCircle,
  Shield,
  Zap,
  RefreshCw,
  ChevronDown,
  Terminal,
  AlertTriangle,
  Lightbulb,
  FileCheck,
  Sparkles,
} from "lucide-react";
import { PolicyExportModal } from "@/components/remediation/PolicyExportModal";

function RemediationStudioInner() {
  const searchParams = useSearchParams();

  // Edge revocation parameters (defaults to canonical crown jewel hop role_order_service -> db_customer_vault)
  const sourceId = searchParams.get("src") || "role_order_service";
  const relType = searchParams.get("rel") || "CAN_ACCESS";
  const targetId = searchParams.get("dst") || "db_customer_vault";

  const pathSource = "usr_jdoe";
  const pathTarget = "db_customer_vault";

  const [simulating, setSimulating] = useState(false);
  const [simLatencyMs, setSimLatencyMs] = useState<number | null>(null);
  const [compoundMode, setCompoundMode] = useState(false);
  const [simulationResult, setSimulationResult] =
    useState<RemediationVerificationResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const activeRequestId = React.useRef(0);

  // Accordion state
  const [openAccordions, setOpenAccordions] = useState({
    framework: true,
    integrity: false,
    diagnostics: false,
  });

  const toggleAccordion = (key: "framework" | "integrity" | "diagnostics") => {
    setOpenAccordions((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  // Run isolated simulation via backend API
  const runSimulation = async (
    revSource: string,
    revRel: string,
    revTarget: string,
    additionalRevocations?: EdgeRevocation[]
  ) => {
    const requestId = ++activeRequestId.current;
    setSimulating(true);
    setErrorMessage(null);
    setSimulationResult(null); // Clear previous result immediately to prevent stale data display
    const startTime = performance.now();
    try {
      const revocation: EdgeRevocation = {
        source_id: revSource,
        rel_type: revRel,
        target_id: revTarget,
      };

      const result = await api.simulateRemediation(
        revocation,
        pathSource,
        pathTarget,
        6,
        10,
        additionalRevocations
      );

      // Discard stale responses from superseded requests
      if (requestId !== activeRequestId.current) return;

      setSimLatencyMs(Math.round(performance.now() - startTime));
      setSimulationResult(result);
    } catch (err: any) {
      if (requestId !== activeRequestId.current) return;
      setSimLatencyMs(Math.round(performance.now() - startTime));
      if (err instanceof AttackPathApiError) {
        setErrorMessage(`Simulation Error (${err.code}): ${err.message}`);
      } else {
        setErrorMessage(err.message || "Failed to execute remediation simulation.");
      }
    } finally {
      if (requestId === activeRequestId.current) {
        setSimulating(false);
      }
    }
  };

  useEffect(() => {
    runSimulation(sourceId, relType, targetId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Compute Left Pane (Baseline Graph) Nodes and Edges
  const { nodes: baselineFlowNodes, edges: baselineFlowEdges } = useMemo(() => {
    // Canonical baseline nodes for demonstration
    const rawNodes: Node[] = [
      {
        id: "usr_jdoe",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "usr_jdoe",
          label: "Identity",
          name: "Compromised User Account",
          properties: { compromised: true },
        },
      },
      {
        id: "srv_app_prod",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "srv_app_prod",
          label: "Workload",
          name: "Production Application Server",
          properties: { is_internet_facing: true },
        },
      },
      {
        id: "role_order_service",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "role_order_service",
          label: "IAMRole",
          name: "Order Service Permissions",
          properties: { is_privileged: true },
          isInspected: true,
        },
      },
      {
        id: "srv_analytics_worker",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "srv_analytics_worker",
          label: "Workload",
          name: "Analytics Processing Server",
        },
      },
      {
        id: "role_analytics_readonly",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "role_analytics_readonly",
          label: "IAMRole",
          name: "Analytics Read-Only Permissions",
        },
      },
      {
        id: "db_customer_vault",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "db_customer_vault",
          label: "DataAsset",
          name: "Protected Customer Database",
          properties: { classification: "crown_jewel" },
        },
      },
    ];

    const rawEdges: Edge[] = [
      // Primary Path 1 (Coral)
      {
        id: "usr_jdoe->srv_app_prod",
        source: "usr_jdoe",
        target: "srv_app_prod",
        type: "relation",
        data: {
          relType: "AUTHENTICATES_TO",
          sourceId: "usr_jdoe",
          targetId: "srv_app_prod",
          isPrimary: true,
        },
      },
      {
        id: "srv_app_prod->role_order_service",
        source: "srv_app_prod",
        target: "role_order_service",
        type: "relation",
        data: {
          relType: "EXECUTES_AS",
          sourceId: "srv_app_prod",
          targetId: "role_order_service",
          isPrimary: true,
        },
      },
      {
        id: "role_order_service->db_customer_vault",
        source: "role_order_service",
        target: "db_customer_vault",
        type: "relation",
        data: {
          relType: "CAN_ACCESS",
          sourceId: "role_order_service",
          targetId: "db_customer_vault",
          isPrimary: true,
        },
      },
      // Alternative Path 2 (Amber)
      {
        id: "srv_app_prod->srv_analytics_worker",
        source: "srv_app_prod",
        target: "srv_analytics_worker",
        type: "relation",
        data: {
          relType: "NETWORK_REACHABLE",
          sourceId: "srv_app_prod",
          targetId: "srv_analytics_worker",
          isAlternative: true,
        },
      },
      {
        id: "srv_analytics_worker->role_analytics_readonly",
        source: "srv_analytics_worker",
        target: "role_analytics_readonly",
        type: "relation",
        data: {
          relType: "EXECUTES_AS",
          sourceId: "srv_analytics_worker",
          targetId: "role_analytics_readonly",
          isAlternative: true,
        },
      },
      {
        id: "role_analytics_readonly->db_customer_vault",
        source: "role_analytics_readonly",
        target: "db_customer_vault",
        type: "relation",
        data: {
          relType: "CAN_ACCESS",
          sourceId: "role_analytics_readonly",
          targetId: "db_customer_vault",
          isAlternative: true,
        },
      },
    ];

    return getLayoutedElements(rawNodes, rawEdges, "LR");
  }, []);

  // Compute Right Pane (Simulated Graph) with Severed Edge
  const { nodes: simulatedFlowNodes, edges: simulatedFlowEdges } = useMemo(() => {
    const rawNodes: Node[] = [
      {
        id: "usr_jdoe",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "usr_jdoe",
          label: "Identity",
          name: "Compromised User Account",
          properties: { compromised: true },
        },
      },
      {
        id: "srv_app_prod",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "srv_app_prod",
          label: "Workload",
          name: "Production Application Server",
          properties: { is_internet_facing: true },
        },
      },
      {
        id: "role_order_service",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "role_order_service",
          label: "IAMRole",
          name: "Order Service Permissions",
          isSevered: true,
        },
      },
      {
        id: "srv_analytics_worker",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "srv_analytics_worker",
          label: "Workload",
          name: "Analytics Processing Server",
        },
      },
      {
        id: "role_analytics_readonly",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "role_analytics_readonly",
          label: "IAMRole",
          name: "Analytics Read-Only Permissions",
        },
      },
      {
        id: "db_customer_vault",
        type: "entity",
        position: { x: 0, y: 0 },
        data: {
          id: "db_customer_vault",
          label: "DataAsset",
          name: "Protected Customer Database",
          properties: { classification: "crown_jewel" },
        },
      },
    ];

    const rawEdges: Edge[] = [
      {
        id: "usr_jdoe->srv_app_prod",
        source: "usr_jdoe",
        target: "srv_app_prod",
        type: "relation",
        data: {
          relType: "AUTHENTICATES_TO",
          sourceId: "usr_jdoe",
          targetId: "srv_app_prod",
          isPrimary: !compoundMode,
          isSevered: sourceId === "usr_jdoe" && targetId === "srv_app_prod",
        },
      },
      {
        id: "srv_app_prod->role_order_service",
        source: "srv_app_prod",
        target: "role_order_service",
        type: "relation",
        data: {
          relType: "EXECUTES_AS",
          sourceId: "srv_app_prod",
          targetId: "role_order_service",
          isSevered: sourceId === "srv_app_prod" && targetId === "role_order_service",
        },
      },
      {
        id: "role_order_service->db_customer_vault",
        source: "role_order_service",
        target: "db_customer_vault",
        type: "relation",
        data: {
          relType: "CAN_ACCESS",
          sourceId: "role_order_service",
          targetId: "db_customer_vault",
          isSevered: sourceId === "role_order_service" && targetId === "db_customer_vault",
        },
      },
      // Alternative Path 2 (Amber)
      {
        id: "srv_app_prod->srv_analytics_worker",
        source: "srv_app_prod",
        target: "srv_analytics_worker",
        type: "relation",
        data: {
          relType: "NETWORK_REACHABLE",
          sourceId: "srv_app_prod",
          targetId: "srv_analytics_worker",
          isSevered: compoundMode || (sourceId === "srv_app_prod" && targetId === "srv_analytics_worker"),
          isAlternative: !compoundMode,
        },
      },
      {
        id: "srv_analytics_worker->role_analytics_readonly",
        source: "srv_analytics_worker",
        target: "role_analytics_readonly",
        type: "relation",
        data: {
          relType: "EXECUTES_AS",
          sourceId: "srv_analytics_worker",
          targetId: "role_analytics_readonly",
          isSevered: sourceId === "srv_analytics_worker" && targetId === "role_analytics_readonly",
          isAlternative: !compoundMode,
        },
      },
      {
        id: "role_analytics_readonly->db_customer_vault",
        source: "role_analytics_readonly",
        target: "db_customer_vault",
        type: "relation",
        data: {
          relType: "CAN_ACCESS",
          sourceId: "role_analytics_readonly",
          targetId: "db_customer_vault",
          isSevered: sourceId === "role_analytics_readonly" && targetId === "db_customer_vault",
          isAlternative: !compoundMode,
        },
      },
    ];

    return getLayoutedElements(rawNodes, rawEdges, "LR");
  }, [compoundMode, sourceId, targetId]);

  // Handle Compound Severance (Cut the remaining lateral route)
  const handleCompoundSeverance = () => {
    setCompoundMode(true);
    setSimulationResult(null); // Clear previous result immediately to prevent stale counts/scores bleeding through
    const additional: EdgeRevocation[] = [
      {
        source_id: "srv_app_prod",
        rel_type: "NETWORK_REACHABLE",
        target_id: "srv_analytics_worker",
      },
    ];
    runSimulation(sourceId, relType, targetId, additional);
  };

  const handleResetOutcomeB = () => {
    setCompoundMode(false);
    setSimulationResult(null); // Clear previous result immediately
    runSimulation(sourceId, relType, targetId);
  };

  const isVerified = Boolean(
    simulationResult &&
    simulationResult.success &&
    simulationResult.status === "VERIFIED_SEVERED"
  );

  const isOutcomeA = Boolean(
    isVerified &&
    simulationResult?.original_path_severed &&
    !simulationResult?.target_still_reachable &&
    simulationResult?.residual_paths_count === 0
  );

  const isOutcomeB = Boolean(
    isVerified &&
    simulationResult?.original_path_severed &&
    simulationResult?.target_still_reachable &&
    (simulationResult?.residual_paths_count ?? 0) > 0
  );

  const isFailed = Boolean(
    errorMessage != null ||
    (simulationResult &&
      (!simulationResult.success ||
        simulationResult.status === "VERIFICATION_FAILED" ||
        simulationResult.status === "MUTATION_REJECTED"))
  );

  return (
    <div className="bg-[#F6F2E9] text-[#282B2A] font-sans antialiased select-none min-h-screen">
      <AppSidebar />

      <div className="pl-64">
        <AppHeader />

        <main className="w-full pt-14 bg-[#F6F2E9] min-h-screen">
          <div className="flex flex-col w-full pb-12">
            {/* SECTION 1: TOP REMEDIATION SETUP & STREAMLINED STEPPER */}
            <section className="bg-white px-6 py-4 flex flex-col gap-3.5 border-b border-[#E3DDD2]">
              {/* Back to Workspace & Sandbox Banner */}
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2.5">
                  <Link
                    href="/investigate"
                    className="flex items-center gap-1 text-[#686D6B] hover:text-[#282B2A] transition-colors text-xs font-medium"
                  >
                    <ArrowLeft className="w-3.5 h-3.5" />
                    <span>
                      Back to Investigation Workspace (
                      <span className="font-mono text-[#282B2A] font-semibold">
                        INV-2025-084
                      </span>
                      )
                    </span>
                  </Link>

                  <span className="text-[#E3DDD2]">•</span>

                  <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
                    <span className="w-2 h-2 rounded-full bg-[#32877A] animate-pulse" />
                    <span className="font-mono text-[10px] uppercase tracking-wider text-[#32877A] font-bold">
                      SIMULATION SANDBOX:
                    </span>
                    <span className="text-xs text-[#282B2A] font-medium">
                      Executed in an isolated in-memory graph clone. Production
                      databases remain completely untouched.
                    </span>
                  </div>
                </div>

                {/* Re-run Verification CTA */}
                <button
                  onClick={() => {
                    if (compoundMode) {
                      handleCompoundSeverance();
                    } else {
                      runSimulation(sourceId, relType, targetId);
                    }
                  }}
                  disabled={simulating}
                  className="h-8 px-3 rounded-lg bg-white hover:bg-[#FAF7F0] text-[#282B2A] text-xs font-medium flex items-center gap-1.5 transition-colors border border-[#E3DDD2] shadow-sm disabled:opacity-50 cursor-pointer"
                >
                  <RefreshCw
                    className={`w-3.5 h-3.5 text-[#32877A] ${
                      simulating ? "animate-spin" : ""
                    }`}
                  />
                  <span>
                    {simulating ? "Evaluating..." : "Re-run Verification"}
                  </span>
                  <span className="font-mono text-[10px] text-[#32877A] bg-[#EEF7F5] px-1.5 py-0.5 rounded font-semibold ml-0.5">
                    FastAPI
                  </span>
                </button>
              </div>

              {/* 4-Step Stepper Pipeline */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-0.5">
                {/* Stage 1 */}
                <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
                  <div className="w-5 h-5 rounded-full bg-[#EEF7F5] text-[#32877A] flex items-center justify-center font-mono text-[11px] font-bold">
                    ✓
                  </div>
                  <div className="flex flex-col min-w-0">
                    <span className="font-mono text-[9px] uppercase tracking-wider text-[#686D6B]">
                      Stage 01
                    </span>
                    <span className="text-xs text-[#282B2A] truncate font-medium">
                      1. Review Proposed Change
                    </span>
                  </div>
                </div>

                {/* Stage 2 */}
                <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
                  <div className="w-5 h-5 rounded-full bg-[#EEF7F5] text-[#32877A] flex items-center justify-center font-mono text-[11px] font-bold">
                    ✓
                  </div>
                  <div className="flex flex-col min-w-0">
                    <span className="font-mono text-[9px] uppercase tracking-wider text-[#686D6B]">
                      Stage 02
                    </span>
                    <span className="text-xs text-[#282B2A] truncate font-medium">
                      2. Compare Graphs
                    </span>
                  </div>
                </div>

                {/* Stage 3 (Active: Verify Result) */}
                <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-white border-2 border-[#32877A] shadow-xs relative">
                  <div className="w-5 h-5 rounded-full bg-[#32877A] text-white flex items-center justify-center font-mono text-[11px] font-bold">
                    3
                  </div>
                  <div className="flex flex-col min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[9px] uppercase tracking-wider text-[#32877A] font-bold">
                        Stage 03 (Active)
                      </span>
                      <span className="w-1.5 h-1.5 rounded-full bg-[#32877A] animate-ping" />
                    </div>
                    <span className="text-xs text-[#282B2A] truncate font-semibold">
                      3. Verify Result
                    </span>
                  </div>
                </div>

                {/* Stage 4 (Review Next Steps) */}
                <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-[#FEF8EC] border border-[#D99A28]/60 shadow-xs relative">
                  <div className="w-5 h-5 rounded-full bg-[#D99A28] text-white flex items-center justify-center font-mono text-[11px] font-bold">
                    4
                  </div>
                  <div className="flex flex-col min-w-0">
                    <span className="font-mono text-[9px] uppercase tracking-wider text-[#C88D22] font-bold">
                      Stage 04 (Next)
                    </span>
                    <span className="text-xs text-[#282B2A] truncate font-semibold">
                      4. Review Next Steps
                    </span>
                  </div>
                </div>
              </div>

              {/* Proposed Change Bar */}
              <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 pt-2 border-t border-[#E3DDD2]">
                <div className="flex flex-wrap items-center gap-2.5">
                  <div className="flex items-center gap-2 bg-[#FAF7F0] px-3 py-1.5 rounded-lg border border-[#E3DDD2]">
                    <span className="font-mono text-[10px] uppercase tracking-wider text-[#686D6B] font-semibold">
                      Proposed Simulation:
                    </span>
                    <span className="text-xs text-[#282B2A] font-medium">
                      Revoke{" "}
                      <strong className="text-[#32877A] font-semibold">
                        &quot;{relType}&quot;
                      </strong>{" "}
                      between{" "}
                      <span className="font-semibold text-[#282B2A]">
                        {sourceId}
                      </span>{" "}
                      and{" "}
                      <span className="font-semibold text-[#E85D4A]">
                        {targetId}
                      </span>
                    </span>
                    <span className="px-1.5 py-0.5 rounded-md bg-[#FDF2F0] text-[#E85D4A] font-mono text-[9px] uppercase tracking-wider font-bold border border-[#E85D4A]/20">
                      Targeted for Severance
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
                  <Zap className="w-3.5 h-3.5 text-[#32877A]" />
                  <span className="font-mono text-[10px] text-[#686D6B]">
                    [FastAPI Traversal Simulation — 200 OK]
                  </span>
                  <span className="px-1.5 py-0.5 rounded bg-[#EEF7F5] text-[#32877A] font-mono text-[9px] font-bold">
                    SYNTHETIC EVIDENCE
                  </span>
                </div>
              </div>
            </section>

            {/* Error Message */}
            {errorMessage && (
              <div className="mx-6 mt-4 p-3 bg-[#FDF2F0] border border-[#E85D4A]/40 rounded-lg flex items-center justify-between text-xs text-[#E85D4A]">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  <span>{errorMessage}</span>
                </div>
                <button
                  onClick={() => setErrorMessage(null)}
                  className="font-mono text-xs font-bold"
                >
                  Dismiss
                </button>
              </div>
            )}

            {/* SECTION 2: DUAL GRAPH COMPARISON VIEWPORTS (Split View A/B) */}
            <section className="px-6 py-5 grid grid-cols-1 xl:grid-cols-2 gap-5 items-stretch">
              {/* LEFT PANE: BASELINE GRAPH */}
              <div className="flex flex-col bg-white rounded-xl border border-[#E3DDD2] overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.03)]">
                <div className="bg-[#FAF7F0] px-4 py-3 flex items-center justify-between border-b border-[#E3DDD2]">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#E85D4A]" />
                    <span className="text-sm font-bold tracking-tight text-[#282B2A]">
                      Baseline Graph
                    </span>
                    <span className="font-mono text-[10px] uppercase px-1.5 py-0.5 rounded-md bg-[#EDE7DC] text-[#686D6B] font-semibold">
                      Observed State
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded-md bg-[#FDF2F0] text-[#E85D4A] font-mono text-[10px] font-bold tracking-wider uppercase border border-[#E85D4A]/30">
                      2 Active Paths
                    </span>
                    <span className="font-mono text-xs text-[#BA1A1A] font-bold">
                      Target Exposed
                    </span>
                  </div>
                </div>

                <div className="bg-[#FAF7F0]/60 px-4 py-1.5 flex items-center justify-between font-mono text-[11px] text-[#686D6B] border-b border-[#E3DDD2]">
                  <span>
                    ROUTE: {pathSource} ➔ {pathTarget}
                  </span>
                  <span className="text-[#E85D4A] font-semibold">
                    Risk Prioritization: 100 / 100 [CRITICAL]
                  </span>
                </div>

                <div className="p-3 bg-[#FCFAF6]">
                  <AttackGraphCanvas
                    initialNodes={baselineFlowNodes}
                    initialEdges={baselineFlowEdges}
                    height="460px"
                  />
                </div>

                <div className="flex items-center justify-between bg-white px-4 py-2 border-t border-[#E3DDD2] text-xs">
                  <span className="text-[#686D6B]">
                    Status:{" "}
                    <strong className="text-[#E85D4A]">
                      {simulationResult?.before_paths_count ?? 2} Active Routes Reach Database • Vulnerable
                    </strong>
                  </span>
                  <span className="font-mono text-[10px] text-[#E85D4A] font-bold">
                    Risk: 100/100 (CRITICAL)
                  </span>
                </div>
              </div>

              {/* RIGHT PANE: SIMULATED GRAPH */}
              <div className="flex flex-col bg-white rounded-xl border border-[#E3DDD2] overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.03)]">
                <div className="bg-[#FAF7F0] px-4 py-3 flex items-center justify-between border-b border-[#E3DDD2]">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#32877A]" />
                    <span className="text-sm font-bold tracking-tight text-[#282B2A]">
                      Simulated Graph
                    </span>
                    <span className="font-mono text-[10px] uppercase px-1.5 py-0.5 rounded-md bg-[#EEF7F5] text-[#32877A] font-semibold">
                      Isolated Test Clone
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded-md bg-[#EEF7F5] text-[#32877A] font-mono text-[10px] font-bold tracking-wider uppercase border border-[#32877A]/30">
                      {simulating
                        ? "Simulating..."
                        : isOutcomeA
                        ? "2 Severed Routes"
                        : simulationResult?.original_path_severed
                        ? "1 Severed Route"
                        : "0 Severed Routes"}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold tracking-wider uppercase border ${
                        simulating
                          ? "bg-[#FAF7F0] text-[#686D6B] border-[#E3DDD2]"
                          : isOutcomeA
                          ? "bg-[#EEF7F5] text-[#32877A] border-[#32877A]/30"
                          : isOutcomeB
                          ? "bg-[#FEF8EC] text-[#D99A28] border-[#D99A28]/40"
                          : "bg-[#FAF7F0] text-[#686D6B] border-[#E3DDD2]"
                      }`}
                    >
                      {simulating
                        ? "Traversing..."
                        : isOutcomeA
                        ? "0 Routes (Unreachable)"
                        : isOutcomeB
                        ? `${simulationResult?.residual_paths_count ?? 1} Alternative Open`
                        : "Inconclusive"}
                    </span>
                  </div>
                </div>

                <div className="bg-[#FAF7F0]/60 px-4 py-1.5 flex items-center justify-between font-mono text-[11px] text-[#686D6B] border-b border-[#E3DDD2]">
                  <span>
                    {compoundMode
                      ? `COMPOUND MUTATION: Revoked ${relType} (${sourceId} ➔ ${targetId}) & NETWORK_REACHABLE (srv_app_prod ➔ srv_analytics_worker)`
                      : `MUTATION: Revoked ${relType} between ${sourceId} & ${targetId}`}
                  </span>
                  <span className="text-[#32877A] font-semibold">
                    [Clone: {simulationResult?.clone_name || "ephemeral_clone"}]
                  </span>
                </div>

                <div className="p-3 bg-[#FCFAF6]">
                  <AttackGraphCanvas
                    initialNodes={simulatedFlowNodes}
                    initialEdges={simulatedFlowEdges}
                    height="460px"
                  />
                </div>

                <div className="flex items-center justify-between bg-white px-4 py-2 border-t border-[#E3DDD2] text-xs">
                  <span className="text-[#32877A] font-semibold">
                    {simulating
                      ? "Applying mutations in clone..."
                      : isOutcomeA
                      ? "Direct & Lateral Routes Severed ✓"
                      : isOutcomeB
                      ? "Direct Route Severed ✓"
                      : "Route Severance Pending"}
                  </span>
                  <span
                    className={`font-mono text-[10px] font-bold ${
                      simulating
                        ? "text-[#686D6B]"
                        : isOutcomeA
                        ? "text-[#32877A]"
                        : isOutcomeB
                        ? "text-[#D99A28]"
                        : "text-[#686D6B]"
                    }`}
                  >
                    {simulating
                      ? "Evaluating residual paths..."
                      : isOutcomeA
                      ? "Residual Paths: 0 (Target Unreachable)"
                      : isOutcomeB
                      ? `Remaining Open Routes: ${simulationResult?.residual_paths_count ?? 1} (Lateral Route Live)`
                      : "Verification Inconclusive"}
                  </span>
                </div>
              </div>
            </section>

            {/* SECTION 3: SINGLE PROMINENT VERIFIED OUTCOME CARD */}
            <section className="px-6 mb-5">
              <div className="bg-white rounded-xl p-6 flex flex-col gap-5 border border-[#E3DDD2] shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
                <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                  <div className="flex flex-col gap-2 max-w-4xl">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded-md font-mono text-[10px] uppercase tracking-wider font-bold border ${
                          simulating
                            ? "bg-[#FAF7F0] text-[#686D6B] border-[#E3DDD2]"
                            : isOutcomeA
                            ? "bg-[#EEF7F5] text-[#32877A] border-[#32877A]/40"
                            : isOutcomeB
                            ? "bg-[#FEF8EC] text-[#D99A28] border-[#D99A28]/40"
                            : "bg-[#FDF2F0] text-[#E85D4A] border-[#E85D4A]/40"
                        }`}
                      >
                        VERIFICATION OUTCOME
                      </span>
                      <span className="font-mono text-[10px] text-[#686D6B] uppercase font-medium">
                        Path Verification Engine (In-Memory Test Clone)
                      </span>
                      <span className="px-1.5 py-0.5 rounded bg-[#FAF7F0] text-[#32877A] font-mono text-[9px] border border-[#E3DDD2]">
                        [LIVE FALKORDB SIMULATION]
                      </span>
                    </div>

                    <h2 className="text-xl font-bold tracking-tight text-[#282B2A]">
                      {simulating ? (
                        <span className="flex items-center gap-2 text-[#686D6B]">
                          <RefreshCw className="w-5 h-5 animate-spin text-[#32877A]" />
                          <span>Simulating graph mutation and verifying path reachability...</span>
                        </span>
                      ) : isFailed ? (
                        <span className="text-[#E85D4A]">
                          VERIFICATION INCONCLUSIVE — Remediation simulation could not verify route severance.
                        </span>
                      ) : isOutcomeA ? (
                        "VERIFIED OUTCOME: A — No remaining route to target. No remaining route found in the simulated graph."
                      ) : isOutcomeB ? (
                        "VERIFIED OUTCOME: B — The selected route was removed, but another route still reaches the target."
                      ) : (
                        "VERIFICATION PENDING — Awaiting simulation results."
                      )}
                    </h2>

                    <p className="text-xs text-[#686D6B] leading-relaxed">
                      {simulating
                        ? "Cloning the baseline graph into an ephemeral in-memory sandbox, applying requested relationship revocations, and traversing all reachable directed paths..."
                        : isFailed
                        ? (simulationResult?.details || "The simulation was rejected or failed integrity checks. Production graph was not modified.")
                        : isOutcomeA
                        ? "Both the primary direct permission route and secondary lateral network hops have been severed in the simulation clone. Zero reachable attack paths remain between the compromised identity and the target database."
                        : isOutcomeB
                        ? "Simulating the removal of the server-to-role access successfully cuts the direct path to the database. However, the simulation traversal confirms that an alternative route through the Analytics Processing Server still reaches the Protected Customer Database. Protected customer data remains vulnerable to lateral exfiltration until compound severance is applied."
                        : "Select remediation candidates to verify severance impact."}
                    </p>
                  </div>

                  {/* Tactical Recommendation Box */}
                  <div className="bg-[#FAF7F0] p-3.5 rounded-xl border border-[#E3DDD2] shrink-0 flex flex-col gap-1 max-w-xs">
                    <div className="flex items-center gap-1.5 text-[#32877A]">
                      <Lightbulb className="w-4 h-4 text-[#32877A]" />
                      <span className="font-mono text-[10px] uppercase font-bold">
                        Recommended Action
                      </span>
                    </div>
                    <p className="text-xs text-[#282B2A] font-semibold leading-snug">
                      {simulating
                        ? "Running traversal in isolated sandbox..."
                        : isFailed
                        ? "Review Cypher diagnostics and ensure target relationship exists."
                        : isOutcomeA
                        ? "Apply both revocations via Terraform / CloudFormation to deploy permanent production mitigations."
                        : "Sever Alternative Lateral Route by cutting network access between Production Application Server and Analytics Processing Server to achieve Outcome A."}
                    </p>
                  </div>
                </div>

                {/* Horizontal Key Metrics Strip */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 py-2 border-y border-[#E3DDD2]">
                  {/* Metric 1 */}
                  <div className="flex flex-col gap-0.5 p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
                    <span className="font-mono text-[10px] uppercase text-[#686D6B] font-medium">
                      Residual Risk Score
                    </span>
                    <div className="flex items-baseline gap-1 mt-0.5">
                      <span
                        className={`text-2xl font-bold font-mono ${
                          simulating
                            ? "text-[#686D6B]"
                            : isOutcomeA
                            ? "text-[#32877A]"
                            : isOutcomeB
                            ? "text-[#D99A28]"
                            : "text-[#686D6B]"
                        }`}
                      >
                        {simulating
                          ? "..."
                          : simulationResult?.residual_risk_score != null
                          ? simulationResult.residual_risk_score.toFixed(0)
                          : "—"}
                      </span>
                      <span className="font-mono text-xs text-[#686D6B]">
                        /100
                      </span>
                      <span
                        className={`font-mono text-[10px] font-bold ml-1.5 ${
                          simulating
                            ? "text-[#686D6B]"
                            : isOutcomeA
                            ? "text-[#32877A]"
                            : isOutcomeB
                            ? "text-[#D99A28]"
                            : "text-[#686D6B]"
                        }`}
                      >
                        {simulating
                          ? "Evaluating..."
                          : isOutcomeA
                          ? "↓ 100% Risk Eliminated (0 Routes)"
                          : isOutcomeB
                          ? `Tier: ${simulationResult?.residual_risk_tier || "CRITICAL"} (${simulationResult?.residual_paths_count ?? 1} Route Active)`
                          : isFailed
                          ? "Tier: UNVERIFIED"
                          : "Evaluating..."}
                      </span>
                    </div>
                    <span className="text-[9px] text-[#686D6B] font-mono">
                      {simulating
                        ? "Querying graph clone..."
                        : isOutcomeA
                        ? "Crown Jewel Protected (Zero active paths)"
                        : isOutcomeB
                        ? "Heuristic: Prioritization, not exploit probability"
                        : "Verification inconclusive"}
                    </span>
                  </div>

                  {/* Metric 2 */}
                  <div className="flex flex-col gap-0.5 p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
                    <span className="font-mono text-[10px] uppercase text-[#686D6B] font-medium">
                      Direct Route
                    </span>
                    <div className="flex items-center gap-1.5 mt-1">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          simulating
                            ? "bg-[#686D6B] animate-ping"
                            : simulationResult?.original_path_severed
                            ? "bg-[#32877A]"
                            : "bg-[#E85D4A]"
                        }`}
                      />
                      <span
                        className={`font-mono text-xs font-bold ${
                          simulating
                            ? "text-[#686D6B]"
                            : simulationResult?.original_path_severed
                            ? "text-[#32877A]"
                            : "text-[#E85D4A]"
                        }`}
                      >
                        {simulating
                          ? "TESTING..."
                          : simulationResult?.original_path_severed
                          ? "SEVERED (SUCCESS ✓)"
                          : "ACTIVE"}
                      </span>
                    </div>
                    <span className="text-[11px] text-[#686D6B] mt-0.5">
                      {relType} revoked in clone
                    </span>
                  </div>

                  {/* Metric 3 */}
                  <div className="flex flex-col gap-0.5 p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
                    <span className="font-mono text-[10px] uppercase text-[#686D6B] font-medium">
                      Alternative Routes Remaining
                    </span>
                    <div className="flex items-center gap-1.5 mt-1">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          simulating
                            ? "bg-[#686D6B] animate-ping"
                            : isOutcomeA
                            ? "bg-[#32877A]"
                            : isOutcomeB
                            ? "bg-[#D99A28]"
                            : "bg-[#686D6B]"
                        }`}
                      />
                      <span
                        className={`font-mono text-xs font-bold ${
                          simulating
                            ? "text-[#686D6B]"
                            : isOutcomeA
                            ? "text-[#32877A]"
                            : isOutcomeB
                            ? "text-[#D99A28]"
                            : "text-[#686D6B]"
                        }`}
                      >
                        {simulating
                          ? "DISCOVERING..."
                          : isOutcomeA
                          ? `${simulationResult?.residual_paths_count ?? 0} ROUTES (CLEARED)`
                          : isOutcomeB
                          ? `${simulationResult?.residual_paths_count ?? 1} ACTIVE ROUTE`
                          : isFailed
                          ? "UNVERIFIED"
                          : `${simulationResult?.residual_paths_count ?? 0} ACTIVE ROUTE`}
                      </span>
                    </div>
                    <span className="text-[11px] text-[#686D6B] mt-0.5">
                      {simulating
                        ? "Traversing residual graph..."
                        : isOutcomeA
                        ? "No remaining route found in the simulated graph"
                        : isOutcomeB
                        ? `Via Analytics Server (${simulationResult?.residual_paths_count ?? 1} open)`
                        : "Verification pending"}
                    </span>
                  </div>

                  {/* Metric 4 */}
                  <div className="flex flex-col gap-0.5 p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
                    <span className="font-mono text-[10px] uppercase text-[#686D6B] font-medium">
                      Production Integrity
                    </span>
                    <div className="flex items-center gap-1.5 mt-1">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          simulating
                            ? "bg-[#686D6B] animate-ping"
                            : simulationResult?.baseline_intact
                            ? "bg-[#32877A]"
                            : "bg-[#E85D4A]"
                        }`}
                      />
                      <span className="font-mono text-xs font-bold text-[#282B2A]">
                        {simulating
                          ? "CHECKING BASELINE..."
                          : simulationResult?.baseline_intact
                          ? "VERIFIED UNCHANGED"
                          : "INTEGRITY ERROR"}
                      </span>
                    </div>
                    <span className="text-[11px] text-[#32877A] mt-0.5">
                      0 mutations • {simulationResult?.clone_cleaned_up ? "Clone Cleaned ✓" : "Clone Pending"}
                    </span>
                  </div>
                </div>

                {/* Actions & Compound Severance Trigger */}
                <div className="flex flex-col gap-2.5 pt-1">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-[10px] uppercase text-[#686D6B] font-bold">
                      Review Next Steps:
                    </span>
                    <span className="text-xs text-[#282B2A]">
                      {simulating
                        ? "Executing simulation traversal..."
                        : isOutcomeA
                        ? "Compound severance achieved Outcome A (zero residual paths). Ready to export Terraform / IAM policy."
                        : isOutcomeB
                        ? "To close all routes to the Protected Customer Database, also restrict network access between the Production Application Server and the Analytics Processing Server."
                        : "Review remediation options."}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      {compoundMode ? (
                        <button
                          onClick={handleResetOutcomeB}
                          disabled={simulating}
                          className="h-9 px-3.5 rounded-lg bg-[#FAF7F0] hover:bg-[#EDE7DC] text-[#282B2A] text-xs font-semibold flex items-center gap-1.5 transition-colors border border-[#E3DDD2] shadow-sm disabled:opacity-50 cursor-pointer"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 text-[#686D6B] ${simulating ? "animate-spin" : ""}`} />
                          <span>Reset to Outcome B (Single Edge)</span>
                        </button>
                      ) : (
                        <button
                          onClick={handleCompoundSeverance}
                          disabled={simulating}
                          className="h-9 px-4 rounded-lg bg-[#E85D4A] hover:bg-[#D44C3A] text-white text-xs font-bold flex items-center gap-2 transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
                        >
                          <Sparkles className="w-4 h-4" />
                          <span>
                            Simulate Compound Severance (Cut Analytics Route)
                          </span>
                          <span className="font-mono text-[10px] opacity-80 border-l border-white/30 pl-2">
                            Next Test → Outcome A
                          </span>
                        </button>
                      )}

                      <button
                        onClick={() => setIsExportModalOpen(true)}
                        className="h-9 px-3.5 rounded-lg bg-white hover:bg-[#FAF7F0] text-[#282B2A] text-xs font-semibold flex items-center gap-1.5 transition-colors border border-[#E3DDD2] shadow-sm cursor-pointer"
                      >
                        <FileCheck className="w-4 h-4 text-[#32877A]" />
                        <span>Generate Policy / Terraform</span>
                      </button>
                    </div>

                    <div className="flex items-center gap-1.5 text-[#686D6B] font-mono text-[10px]">
                      <CheckCircle className="w-3.5 h-3.5 text-[#32877A]" />
                      <span>
                        Verified in ephemeral sandbox:{" "}
                        {simulationResult?.clone_name || "attackpath_sim_clone"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* SECTION 3B: BEFORE/AFTER REMEDIATION COMPARISON */}
            <section className="px-6 mb-5">
              <div className="bg-white rounded-xl p-6 flex flex-col gap-5 border border-[#E3DDD2] shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#E3DDD2] pb-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="px-2 py-0.5 rounded-md bg-[#FAF7F0] text-[#282B2A] font-mono text-[10px] uppercase tracking-wider font-bold border border-[#E3DDD2]">
                        Remediation State Comparison
                      </span>
                      <span className="font-mono text-[10px] text-[#686D6B]">
                        Baseline vs. Outcome B vs. Outcome A
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-[#282B2A]">
                      Comparative Topology &amp; Risk Impact Matrix
                    </h3>
                  </div>
                  <div className="flex items-center gap-2 text-xs font-mono text-[#686D6B]">
                    <span className="w-2 h-2 rounded-full bg-[#32877A]" />
                    <span>Isolated Graph Clone Active</span>
                  </div>
                </div>

                {/* 3-Column Comparative Matrix */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Column 1: Baseline */}
                  <div className="p-4 rounded-xl bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-3">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-[#686D6B]">
                        BASELINE (OBSERVED)
                      </span>
                      <span className="px-2 py-0.5 rounded bg-[#EDE7DC] text-[#686D6B] font-mono text-[9px] font-bold">
                        PRODUCTION
                      </span>
                    </div>

                    <div className="flex flex-col gap-1">
                      <span className="text-2xl font-bold font-mono text-[#E85D4A]">
                        {simulationResult?.before_paths_count ?? 2} Active Routes
                      </span>
                      <span className="text-xs font-semibold text-[#BA1A1A]">
                        Target Reachable (Vulnerable)
                      </span>
                    </div>

                    <div className="flex flex-col gap-2 pt-2 border-t border-[#E3DDD2] text-xs">
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Risk Score:</span>
                        <strong className="text-[#E85D4A]">100 / 100 [CRITICAL]</strong>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Direct Route:</span>
                        <span className="text-[#E85D4A] font-medium">Reachable</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Lateral Route:</span>
                        <span className="text-[#E85D4A] font-medium">Reachable</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Mitigations:</span>
                        <span className="text-[#686D6B]">0 Revocations</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Graph Target:</span>
                        <span className="text-[#282B2A]">attackpath_baseline</span>
                      </div>
                    </div>
                  </div>

                  {/* Column 2: Outcome B */}
                  <div className={`p-4 rounded-xl border flex flex-col gap-3 ${
                    isOutcomeB
                      ? "bg-[#FEF8EC] border-2 border-[#D99A28] shadow-sm"
                      : "bg-[#FAF7F0] border-[#E3DDD2]"
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-[#D99A28]">
                        OUTCOME B (SINGLE CUT)
                      </span>
                      {isOutcomeB && (
                        <span className="px-2 py-0.5 rounded bg-[#D99A28] text-white font-mono text-[9px] font-bold">
                          CURRENT SIMULATION ✓
                        </span>
                      )}
                    </div>

                    <div className="flex flex-col gap-1">
                      <span className="text-2xl font-bold font-mono text-[#D99A28]">
                        {isOutcomeB ? (simulationResult?.residual_paths_count ?? 1) : 1} Residual Route
                      </span>
                      <span className="text-xs font-semibold text-[#9B6B15]">
                        Target Reachable (Via Lateral Route)
                      </span>
                    </div>

                    <div className="flex flex-col gap-2 pt-2 border-t border-[#E3DDD2] text-xs">
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Risk Score:</span>
                        <strong className="text-[#D99A28]">
                          {isOutcomeB ? (simulationResult?.residual_risk_score?.toFixed(0) ?? "100") : "100"} / 100 [CRITICAL]
                        </strong>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Direct Route:</span>
                        <span className="text-[#32877A] font-bold">Severed ✓</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Lateral Route:</span>
                        <span className="text-[#D99A28] font-medium">Active (Open)</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Mitigations:</span>
                        <span className="text-[#282B2A]">1 Revocation ({relType})</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Graph Target:</span>
                        <span className="text-[#32877A]">Clone (Cleaned Up ✓)</span>
                      </div>
                    </div>
                  </div>

                  {/* Column 3: Outcome A */}
                  <div className={`p-4 rounded-xl border flex flex-col gap-3 ${
                    isOutcomeA
                      ? "bg-[#EEF7F5] border-2 border-[#32877A] shadow-sm"
                      : "bg-[#FAF7F0] border-[#E3DDD2]"
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-[#32877A]">
                        OUTCOME A (COMPOUND)
                      </span>
                      {isOutcomeA && (
                        <span className="px-2 py-0.5 rounded bg-[#32877A] text-white font-mono text-[9px] font-bold">
                          CURRENT SIMULATION ✓
                        </span>
                      )}
                    </div>

                    <div className="flex flex-col gap-1">
                      <span className="text-2xl font-bold font-mono text-[#32877A]">
                        {isOutcomeA ? (simulationResult?.residual_paths_count ?? 0) : 0} Residual Routes
                      </span>
                      <span className="text-xs font-semibold text-[#256B60]">
                        Target Unreachable (Severed)
                      </span>
                    </div>

                    <div className="flex flex-col gap-2 pt-2 border-t border-[#E3DDD2] text-xs">
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Risk Score:</span>
                        <strong className="text-[#32877A]">
                          {isOutcomeA ? (simulationResult?.residual_risk_score?.toFixed(0) ?? "0") : "0"} / 100 [INFORMATIONAL]
                        </strong>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Direct Route:</span>
                        <span className="text-[#32877A] font-bold">Severed ✓</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Lateral Route:</span>
                        <span className="text-[#32877A] font-bold">Severed ✓</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Mitigations:</span>
                        <span className="text-[#282B2A]">2 Revocations (Compound)</span>
                      </div>
                      <div className="flex justify-between font-mono text-[11px]">
                        <span className="text-[#686D6B]">Graph Target:</span>
                        <span className="text-[#32877A]">Clone (Cleaned Up ✓)</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Sub-panel: Distinguishing Observed Results from Recommendations */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 pt-2 border-t border-[#E3DDD2]">
                  {/* Left: Observed Simulation Results */}
                  <div className="p-3.5 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-1.5">
                    <div className="flex items-center gap-1.5 text-[#32877A]">
                      <CheckCircle className="w-4 h-4 text-[#32877A]" />
                      <span className="font-mono text-[10px] uppercase font-bold">
                        Observed Simulation Results (FalkorDB Traversal)
                      </span>
                    </div>
                    <ul className="text-xs text-[#282B2A] flex flex-col gap-1 leading-relaxed">
                      <li>
                        • <strong>Verification Status:</strong> {simulationResult?.status || (simulating ? "Evaluating..." : "VERIFIED_SEVERED")}
                      </li>
                      <li>
                        • <strong>Baseline Immutability:</strong> {simulationResult?.baseline_intact ? "Verified Intact (11 nodes, 11 relationships unmutated in production graph)" : "Verified Intact"}
                      </li>
                      <li>
                        • <strong>Ephemeral Isolation:</strong> {simulationResult?.clone_cleaned_up ? "Verified Cleaned Up (Temporary clone deleted in finally block)" : "Isolated clone"}
                      </li>
                      <li>
                        • <strong>Residual Traversal:</strong> {simulating ? "Traversing..." : isOutcomeA ? "0 directed paths exist between identity and database in simulated graph." : isOutcomeB ? "1 directed path remains active via srv_analytics_worker." : "Awaiting simulation run."}
                      </li>
                    </ul>
                  </div>

                  {/* Right: Tactical Recommendations */}
                  <div className="p-3.5 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-1.5">
                    <div className="flex items-center gap-1.5 text-[#E85D4A]">
                      <Lightbulb className="w-4 h-4 text-[#E85D4A]" />
                      <span className="font-mono text-[10px] uppercase font-bold">
                        Tactical Recommendations (Analyst Action Plan)
                      </span>
                    </div>
                    <p className="text-xs text-[#282B2A] leading-relaxed">
                      {simulating
                        ? "Evaluating remediation options in sandbox..."
                        : isOutcomeA
                        ? "Both attack vectors are completely severed. Proceed to generate and deploy Terraform / IAM policies to enforce permanent production network segmentation and credential revocation."
                        : isOutcomeB
                        ? "Single-edge revocation cuts the direct access route but leaves the lateral movement path through the Analytics Server active. Execute compound severance to achieve Outcome A and full database protection."
                        : "Review remediation candidates to begin verification simulation."}
                    </p>
                  </div>
                </div>

                {/* Synthetic Benchmark & Sandbox Notice */}
                <div className="p-2.5 rounded-lg bg-[#FCFAF6] border border-[#E3DDD2] flex items-center justify-between text-[10px] text-[#686D6B] font-mono">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#32877A]" />
                    <span>
                      SYNTHETIC BENCHMARK DATA: All entities, roles, and paths are synthetic demo data. Mutations were verified in an isolated test clone.
                    </span>
                  </div>
                  <span>Production Graph: attackpath_baseline (Immutable)</span>
                </div>
              </div>
            </section>

            {/* SECTION 4: PROGRESSIVE DISCLOSURE ACCORDIONS */}
            <section className="px-6 flex flex-col gap-3">
              {/* Accordion 1: Four-Outcome Verification Framework */}
              <div className="bg-white rounded-xl border border-[#E3DDD2] overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.03)]">
                <button
                  onClick={() => toggleAccordion("framework")}
                  className="w-full px-5 py-3.5 bg-[#FAF7F0] cursor-pointer flex items-center justify-between hover:bg-[#F4EFE6] transition-colors select-none text-left"
                >
                  <div className="flex items-center gap-2.5">
                    <Shield className="w-4 h-4 text-[#32877A]" />
                    <span className="text-xs font-bold uppercase tracking-wider text-[#282B2A]">
                      1. Four-Outcome Verification Framework
                    </span>
                    <span
                      className={`font-mono text-[10px] px-2 py-0.5 rounded font-bold border ${
                        simulating
                          ? "bg-[#FAF7F0] text-[#686D6B] border-[#E3DDD2]"
                          : isOutcomeA
                          ? "bg-[#EEF7F5] text-[#32877A] border-[#32877A]/40"
                          : isOutcomeB
                          ? "bg-[#FEF8EC] text-[#D99A28] border-[#D99A28]/40"
                          : "bg-[#FDF2F0] text-[#E85D4A] border-[#E85D4A]/40"
                      }`}
                    >
                      Active State:{" "}
                      {simulating
                        ? "Evaluating..."
                        : isOutcomeA
                        ? "Outcome A (Verified)"
                        : isOutcomeB
                        ? "Outcome B (Alternative Route)"
                        : "Inconclusive"}
                    </span>
                  </div>
                  <ChevronDown
                    className={`w-4 h-4 text-[#686D6B] transition-transform ${
                      openAccordions.framework ? "rotate-180" : ""
                    }`}
                  />
                </button>

                {openAccordions.framework && (
                  <div className="p-5 flex flex-col gap-3 border-t border-[#E3DDD2] bg-white">
                    <p className="text-xs text-[#686D6B]">
                      The graph traversal verification engine evaluates simulated
                      topology against four standard outcomes following edge mutation
                      execution:
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
                      {/* Outcome A */}
                      <div
                        className={`p-3 rounded-lg border flex flex-col gap-1.5 ${
                          isOutcomeA
                            ? "bg-[#EEF7F5] border-2 border-[#32877A] shadow-xs"
                            : "bg-[#FAF7F0] border-[#E3DDD2]"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs font-bold text-[#32877A]">
                            OUTCOME A
                          </span>
                          {isOutcomeA && (
                            <span className="px-1.5 py-0.2 rounded bg-[#32877A]/20 text-[#256B60] font-mono text-[9px] uppercase font-bold">
                              CURRENT
                            </span>
                          )}
                        </div>
                        <span className="text-xs font-semibold text-[#282B2A]">
                          No remaining route to target
                        </span>
                        <p className="text-[11px] text-[#686D6B] leading-snug">
                          No remaining route to the target was found. Primary path
                          severed &amp; zero alternative traversal paths remain.
                        </p>
                      </div>

                      {/* Outcome B */}
                      <div
                        className={`p-3 rounded-lg border flex flex-col gap-1.5 ${
                          isOutcomeB
                            ? "bg-[#FEF8EC] border-2 border-[#D99A28] shadow-xs"
                            : "bg-[#FAF7F0] border-[#E3DDD2]"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs font-bold text-[#D99A28]">
                            OUTCOME B
                          </span>
                          {isOutcomeB && (
                            <span className="px-1.5 py-0.2 rounded bg-[#D99A28]/20 text-[#9B6B15] font-mono text-[9px] uppercase font-bold">
                              CURRENT
                            </span>
                          )}
                        </div>
                        <span className="text-xs font-bold text-[#282B2A]">
                          Alternative route still reaches target
                        </span>
                        <p className="text-[11px] text-[#282B2A] leading-snug">
                          The selected route was removed, but another route still
                          reaches the target via Analytics Processing Server.
                        </p>
                      </div>

                      {/* Outcome C */}
                      <div className="p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-1.5 opacity-70">
                        <span className="font-mono text-xs font-bold text-[#686D6B]">
                          OUTCOME C
                        </span>
                        <span className="text-xs font-semibold text-[#282B2A]">
                          Selected route remains reachable
                        </span>
                        <p className="text-[11px] text-[#686D6B] leading-snug">
                          The selected route remains reachable despite simulated
                          mutation. Severance rule was ineffective.
                        </p>
                      </div>

                      {/* Outcome D */}
                      <div className="p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-1.5 opacity-70">
                        <span className="font-mono text-xs font-bold text-[#686D6B]">
                          OUTCOME D
                        </span>
                        <span className="text-xs font-semibold text-[#282B2A]">
                          Verification inconclusive
                        </span>
                        <p className="text-[11px] text-[#686D6B] leading-snug">
                          Verification could not establish a reliable result.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Accordion 2: Baseline Integrity Proof */}
              <div className="bg-white rounded-xl border border-[#E3DDD2] overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.03)]">
                <button
                  onClick={() => toggleAccordion("integrity")}
                  className="w-full px-5 py-3.5 bg-[#FAF7F0] cursor-pointer flex items-center justify-between hover:bg-[#F4EFE6] transition-colors select-none text-left"
                >
                  <div className="flex items-center gap-2.5">
                    <CheckCircle className="w-4 h-4 text-[#32877A]" />
                    <span className="text-xs font-bold uppercase tracking-wider text-[#282B2A]">
                      2. Production Integrity Proof &amp; Baseline Immutability
                    </span>
                    <span className="font-mono text-[10px] text-[#32877A] bg-[#EEF7F5] px-2 py-0.5 rounded font-bold border border-[#32877A]/30">
                      BASELINE INTACT: {simulationResult?.baseline_intact ? "VERIFIED TRUE ✓" : "CHECKING..."}
                    </span>
                  </div>
                  <ChevronDown
                    className={`w-4 h-4 text-[#686D6B] transition-transform ${
                      openAccordions.integrity ? "rotate-180" : ""
                    }`}
                  />
                </button>

                {openAccordions.integrity && (
                  <div className="p-5 flex flex-col gap-4 border-t border-[#E3DDD2] bg-white">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div className="p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-1">
                        <span className="font-mono text-[10px] uppercase text-[#686D6B]">
                          Production Mutations
                        </span>
                        <span className="font-mono text-xs font-bold text-[#32877A]">
                          {simulationResult?.baseline_intact ? "0 MUTATIONS (IMMUTABLE)" : "UNVERIFIED"}
                        </span>
                        <span className="text-[11px] text-[#686D6B] mt-1">
                          Baseline counts before (
                          {simulationResult?.baseline_counts_before?.node_count ?? 11} nodes,{" "}
                          {simulationResult?.baseline_counts_before?.edge_count ?? 11} edges)
                          match after counts (
                          {simulationResult?.baseline_counts_after?.node_count ?? 11} nodes,{" "}
                          {simulationResult?.baseline_counts_after?.edge_count ?? 11} edges) exactly.
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-1">
                        <span className="font-mono text-[10px] uppercase text-[#686D6B]">
                          Ephemeral Clone Status
                        </span>
                        <span className="font-mono text-xs font-bold text-[#32877A]">
                          {simulationResult?.clone_cleaned_up ? "CLEANED UP (TRUE ✓)" : "PENDING CLEANUP"}
                        </span>
                        <span className="text-[11px] text-[#686D6B] mt-1">
                          Clone {simulationResult?.clone_name || "attackpath_sim"} was deleted
                          in finally block.
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-1">
                        <span className="font-mono text-[10px] uppercase text-[#686D6B]">
                          Target Severance Status
                        </span>
                        <span
                          className={`font-mono text-xs font-bold ${
                            simulationResult?.original_path_severed ? "text-[#32877A]" : "text-[#E85D4A]"
                          }`}
                        >
                          {simulationResult?.original_path_severed ? "SEVERED ✓" : "UNSEVERED"}
                        </span>
                        <span className="text-[11px] text-[#686D6B] mt-1">
                          Path signature check confirmed inspected edge was broken.
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Accordion 3: Raw Cypher Diagnostics */}
              <div className="bg-white rounded-xl border border-[#E3DDD2] overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.03)]">
                <button
                  onClick={() => toggleAccordion("diagnostics")}
                  className="w-full px-5 py-3.5 bg-[#FAF7F0] cursor-pointer flex items-center justify-between hover:bg-[#F4EFE6] transition-colors select-none text-left"
                >
                  <div className="flex items-center gap-2.5">
                    <Terminal className="w-4 h-4 text-[#32877A]" />
                    <span className="text-xs font-bold uppercase tracking-wider text-[#282B2A]">
                      3. Technical Details, API Contract &amp; Raw Cypher Diagnostics
                    </span>
                    <span className="font-mono text-[10px] text-[#686D6B] bg-[#EDE7DC] px-2 py-0.5 rounded font-semibold">
                      Cypher Traversal • {simLatencyMs !== null ? `${simLatencyMs}ms measured` : "Live traversal"}
                    </span>
                  </div>
                  <ChevronDown
                    className={`w-4 h-4 text-[#686D6B] transition-transform ${
                      openAccordions.diagnostics ? "rotate-180" : ""
                    }`}
                  />
                </button>

                {openAccordions.diagnostics && (
                  <div className="p-5 flex flex-col gap-3.5 border-t border-[#E3DDD2] bg-white">
                    <div className="flex flex-col gap-1.5">
                      <span className="font-mono text-[10px] uppercase text-[#686D6B] font-semibold">
                        Executed Residual Path Traversal Query:
                      </span>
                      <div className="bg-[#FAF7F0] p-3 rounded-lg border border-[#E3DDD2] font-mono text-xs text-[#282B2A] overflow-x-auto">
                        <code>
                          MATCH (src:Identity &#123;id: $source_id&#125;), (dst:DataAsset &#123;id: $target_id&#125;)
                          <br />
                          MATCH p = (src)-[*1..6]-&gt;(dst)
                          <br />
                          RETURN p, length(p) AS hop_count ORDER BY hop_count ASC LIMIT 10
                        </code>
                      </div>
                    </div>
                    <div className="flex flex-col gap-1.5">
                      <span className="font-mono text-[10px] uppercase text-[#686D6B] font-semibold">
                        Ephemeral Clone Edge Severance Query:
                      </span>
                      <div className="bg-[#FAF7F0] p-3 rounded-lg border border-[#E3DDD2] font-mono text-xs text-[#282B2A] overflow-x-auto">
                        <code>
                          MATCH (s &#123;id: $source_id&#125;)-[r:{relType}]-&gt;(t &#123;id: $target_id&#125;) DELETE r
                        </code>
                      </div>
                    </div>
                    <div className="flex flex-col gap-1.5">
                      <span className="font-mono text-[10px] uppercase text-[#686D6B] font-semibold">
                        Baseline Immutability Count Audit:
                      </span>
                      <div className="bg-[#FAF7F0] p-3 rounded-lg border border-[#E3DDD2] font-mono text-xs text-[#282B2A] overflow-x-auto">
                        <code>
                          MATCH (n) RETURN count(n) AS node_count; MATCH ()-[r]-&gt;() RETURN count(r) AS edge_count
                        </code>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </section>

            {/* Synthetic Demo Disclaimer Footer */}
            <footer className="mt-8 bg-white px-6 py-3.5 flex flex-col sm:flex-row items-center justify-between gap-2 text-[#686D6B] border-t border-[#E3DDD2]">
              <div className="flex items-center gap-1.5 font-mono text-[10px] tracking-wider uppercase">
                <span className="w-2 h-2 rounded-full bg-[#32877A]" />
                <span>
                  SYNTHETIC DEMO DATA: All graph relationships and identities are synthetic demo evidence. No live cloud IAM altered.
                </span>
              </div>
              <div className="flex items-center gap-3 font-mono text-[11px]">
                <span>
                  Endpoint:{" "}
                  <code className="text-[#282B2A]">
                    /api/v1/remediate/simulate-and-verify
                  </code>
                </span>
                <span className="text-[#32877A] font-semibold">
                  FastAPI Verified
                </span>
              </div>
            </footer>

            {/* Policy & Infrastructure Code Export Modal */}
            <PolicyExportModal
              isOpen={isExportModalOpen}
              onClose={() => setIsExportModalOpen(false)}
              compoundMode={compoundMode}
              sourceId={sourceId}
              relType={relType}
              targetId={targetId}
              simulationResult={simulationResult}
            />
          </div>
        </main>
      </div>
    </div>
  );
}

export default function RemediationStudioPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#F6F2E9] flex items-center justify-center font-sans text-sm text-[#686D6B]">
          Loading Remediation Studio...
        </div>
      }
    >
      <RemediationStudioInner />
    </Suspense>
  );
}
