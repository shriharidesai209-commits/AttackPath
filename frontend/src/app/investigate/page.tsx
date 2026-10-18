"use client";

import React, { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AppSidebar } from "@/components/layout/AppSidebar";
import { AppHeader } from "@/components/layout/AppHeader";
import { AttackGraphCanvas } from "@/components/graph/AttackGraphCanvas";
import { EvidenceRiskInspector } from "@/components/investigation/EvidenceRiskInspector";
import { api, AttackPathApiError } from "@/lib/api";
import {
  BaseEntityNode,
  GraphEdge,
  InvestigationResponse,
} from "@/lib/types";
import { getLayoutedElements } from "@/lib/graph-layout";
import { Node, Edge, MarkerType } from "@xyflow/react";
import {
  Activity,
  CheckCircle,
  Search,
  Database,
  AlertTriangle,
  Beaker,
  ChevronUp,
  ChevronDown,
} from "lucide-react";

export default function InvestigationWorkspacePage() {
  const router = useRouter();

  // Toolbar state
  const [sourceId, setSourceId] = useState("usr_jdoe");
  const [targetId, setTargetId] = useState("db_customer_vault");
  const [maxDepth, setMaxDepth] = useState(6);
  const [availableIdentities, setAvailableIdentities] = useState<BaseEntityNode[]>([]);
  const [availableTargets, setAvailableTargets] = useState<BaseEntityNode[]>([]);

  // Loading & error state
  const [discovering, setDiscovering] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Investigation results
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [selectedPathIndex, setSelectedPathIndex] = useState(0);
  const [selectedHopIndex, setSelectedHopIndex] = useState(0);
  const [isInspectorOpen, setIsInspectorOpen] = useState(true);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  // Load initial topology to populate selectors
  const loadTopology = async () => {
    try {
      const topo = await api.getTopology();
      const idNodes = topo.nodes.filter((n) => n.label === "Identity");
      const targetNodes = topo.nodes.filter(
        (n) => n.label === "DataAsset" || n.properties?.classification
      );
      setAvailableIdentities(idNodes);
      setAvailableTargets(targetNodes);
    } catch (err: any) {
      console.warn("Could not load initial topology:", err.message);
    }
  };

  // Run discovery and explanation
  const runInvestigation = async (src: string, dst: string, depth: number) => {
    setDiscovering(true);
    setErrorMessage(null);
    try {
      const res = await api.investigateAndExplain(src, dst, depth, 10);
      setInvestigation(res);
      setSelectedPathIndex(0);
      setSelectedHopIndex(0);
    } catch (err: any) {
      if (err instanceof AttackPathApiError) {
        setErrorMessage(`Backend API (${err.code}): ${err.message}`);
      } else {
        setErrorMessage(err.message || "Failed to discover attack paths.");
      }
    } finally {
      setDiscovering(false);
    }
  };

  useEffect(() => {
    loadTopology();
    runInvestigation(sourceId, targetId, maxDepth);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Trigger smooth graph re-centering when inspector panel is toggled
  useEffect(() => {
    const timer = setTimeout(() => {
      window.dispatchEvent(new Event("resize"));
    }, 120);
    return () => clearTimeout(timer);
  }, [isInspectorOpen]);

  const handleDiscoverSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runInvestigation(sourceId, targetId, maxDepth);
  };

  const selectedPathDetail = useMemo(() => {
    if (!investigation?.paths || investigation.paths.length === 0) return null;
    return investigation.paths[selectedPathIndex] || investigation.paths[0];
  }, [investigation, selectedPathIndex]);

  // Convert graph data into React Flow nodes and edges using Dagre layout
  const { nodes: flowNodes, edges: flowEdges } = useMemo(() => {
    if (!investigation?.paths || investigation.paths.length === 0) {
      return { nodes: [], edges: [] };
    }

    const currentPath = selectedPathDetail?.path;
    const allPaths = investigation.paths.map((p) => p.path);

    // Collect all unique nodes and edges across discovered paths
    const nodeMap = new Map<string, BaseEntityNode>();
    const edgeMap = new Map<string, GraphEdge>();

    allPaths.forEach((p) => {
      p.nodes.forEach((n) => nodeMap.set(n.id, n));
      p.edges.forEach((e) => edgeMap.set(`${e.source}->${e.target}`, e));
    });

    const activeNodeIds = new Set(currentPath?.nodes.map((n) => n.id) || []);
    const activeEdgeKeys = new Set(
      currentPath?.edges.map((e) => `${e.source}->${e.target}`) || []
    );

    // Active inspected hop edge
    const activeInspectedEdge =
      currentPath?.edges &&
      selectedHopIndex >= 0 &&
      selectedHopIndex < currentPath.edges.length
        ? currentPath.edges[selectedHopIndex]
        : null;
    const activeInspectedEdgeKey = activeInspectedEdge
      ? `${activeInspectedEdge.source}->${activeInspectedEdge.target}`
      : null;

    // Raw Nodes
    const rawNodes: Node[] = Array.from(nodeMap.values()).map((n) => ({
      id: n.id,
      type: "entity",
      position: { x: 0, y: 0 },
      data: {
        id: n.id,
        label: n.label,
        name: n.name,
        properties: n.properties,
        isInspected: activeNodeIds.has(n.id),
      },
    }));

    // Raw Edges
    const rawEdges: Edge[] = Array.from(edgeMap.values()).map((e) => {
      const edgeKey = `${e.source}->${e.target}`;
      const isPrimary = activeEdgeKeys.has(edgeKey);
      const isInspected = activeInspectedEdgeKey === edgeKey;
      return {
        id: edgeKey,
        source: e.source,
        target: e.target,
        type: "relation",
        zIndex: isInspected ? 10 : isPrimary ? 5 : 1,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isInspected ? "#E85D4A" : isPrimary ? "#E85D4A" : "#D99A28",
        },
        data: {
          relType: e.type,
          sourceId: e.source,
          targetId: e.target,
          isPrimary,
          isAlternative: !isPrimary,
          isInspected,
          properties: e.properties,
        },
      };
    });

    return getLayoutedElements(rawNodes, rawEdges, "LR");
  }, [investigation, selectedPathDetail, selectedHopIndex]);

  const handleNodeClick = (nodeId: string) => {
    if (!investigation?.paths || investigation.paths.length === 0) return;

    // Check if node is in current selected path
    const currentPath = selectedPathDetail?.path;
    if (currentPath) {
      const idxInCurrent = currentPath.nodes.findIndex((n) => n.id === nodeId);
      if (idxInCurrent !== -1) {
        const hopIdx = Math.min(idxInCurrent, Math.max(0, currentPath.edges.length - 1));
        setSelectedHopIndex(hopIdx);
        setIsInspectorOpen(true);
        return;
      }
    }

    // If not in current path, search all discovered paths
    for (let pIdx = 0; pIdx < investigation.paths.length; pIdx++) {
      const pathDetail = investigation.paths[pIdx];
      const nodeIdx = pathDetail.path.nodes.findIndex((n) => n.id === nodeId);
      if (nodeIdx !== -1) {
        setSelectedPathIndex(pIdx);
        const hopIdx = Math.min(nodeIdx, Math.max(0, pathDetail.path.edges.length - 1));
        setSelectedHopIndex(hopIdx);
        setIsInspectorOpen(true);
        return;
      }
    }
  };

  const handleEdgeClick = (edgeId: string) => {
    if (!investigation?.paths || investigation.paths.length === 0) return;

    const [src, tgt] = edgeId.split("->");

    // Check if edge is in current selected path
    const currentPath = selectedPathDetail?.path;
    if (currentPath) {
      const edgeIdx = currentPath.edges.findIndex(
        (e) => `${e.source}->${e.target}` === edgeId || (e.source === src && e.target === tgt)
      );
      if (edgeIdx !== -1) {
        setSelectedHopIndex(edgeIdx);
        setIsInspectorOpen(true);
        return;
      }
    }

    // If not in current path, search all discovered paths
    for (let pIdx = 0; pIdx < investigation.paths.length; pIdx++) {
      const pathDetail = investigation.paths[pIdx];
      const edgeIdx = pathDetail.path.edges.findIndex(
        (e) => `${e.source}->${e.target}` === edgeId || (e.source === src && e.target === tgt)
      );
      if (edgeIdx !== -1) {
        setSelectedPathIndex(pIdx);
        setSelectedHopIndex(edgeIdx);
        setIsInspectorOpen(true);
        return;
      }
    }
  };

  const handleSimulateCut = (srcId: string, relType: string, dstId: string) => {
    router.push(
      `/remediate?src=${encodeURIComponent(srcId)}&rel=${encodeURIComponent(
        relType
      )}&dst=${encodeURIComponent(dstId)}`
    );
  };

  return (
    <div className="bg-[#F6F2E9] text-[#282B2A] antialiased select-none font-sans min-h-screen flex flex-col">
      <AppSidebar />

      <div className="pl-64 flex flex-col flex-1">
        <AppHeader
          onSeeded={() => {
            loadTopology();
            runInvestigation(sourceId, targetId, maxDepth);
          }}
        />

        <main className="w-full pt-14 bg-[#F6F2E9] flex-1 flex flex-col">
          {/* Workflow Stepper Bar */}
          <div className="w-full bg-white px-6 py-2 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 border-b border-[#E3DDD2]">
            <div className="flex items-center gap-4 w-full md:w-auto overflow-x-auto">
              <div className="flex items-center gap-2">
                <span className="flex items-center justify-center w-5 h-5 rounded-md bg-[#EEF7F5] text-[#32877A] font-mono text-[10px] font-bold border border-[#32877A]/30">
                  1
                </span>
                <span className="font-mono text-[11px] uppercase tracking-wider text-[#686D6B] line-through decoration-[#32877A]/60">
                  Discover
                </span>
                <CheckCircle className="w-3.5 h-3.5 text-[#32877A]" />
              </div>

              <div className="h-3 w-px bg-[#E3DDD2]" />

              <div className="flex items-center gap-2 px-2 py-0.5 rounded-md bg-[#FDF2F0] border border-[#E85D4A]/30">
                <span className="flex items-center justify-center w-5 h-5 rounded-md bg-[#E85D4A] text-white font-mono text-[10px] font-bold">
                  2
                </span>
                <span className="font-mono text-[11px] uppercase tracking-wider text-[#E85D4A] font-bold">
                  Explain (Inspecting)
                </span>
                <span className="w-1.5 h-1.5 rounded-full bg-[#E85D4A] animate-pulse" />
              </div>

              <div className="h-3 w-px bg-[#E3DDD2]" />

              <Link
                href="/remediate"
                className="flex items-center gap-2 group hover:opacity-80 transition-opacity"
              >
                <span className="flex items-center justify-center w-5 h-5 rounded-md bg-[#F4EFE6] text-[#686D6B] font-mono text-[10px]">
                  3
                </span>
                <span className="font-mono text-[11px] uppercase tracking-wider text-[#686D6B] group-hover:text-[#282B2A] transition-colors">
                  Remediate
                </span>
              </Link>

              <div className="h-3 w-px bg-[#E3DDD2]" />

              <div className="flex items-center gap-2 opacity-60">
                <span className="flex items-center justify-center w-5 h-5 rounded-md bg-[#F4EFE6] text-[#969B98] font-mono text-[10px]">
                  4
                </span>
                <span className="font-mono text-[11px] uppercase tracking-wider text-[#969B98]">
                  Verify
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between w-full md:w-auto gap-4">
              <div className="flex items-center gap-1.5 text-[12px] text-[#686D6B]">
                <span className="text-[#32877A] font-semibold">Active:</span>
                <span>
                  {discovering
                    ? "Discovering paths..."
                    : investigation?.paths && investigation.paths.length > 0
                    ? `Inspecting Path #${selectedPathIndex + 1} (${selectedPathDetail?.path?.hop_count ?? 0} hops) • ${investigation.paths.length} Path(s) Identified`
                    : investigation?.status === "TARGET_UNREACHABLE"
                    ? "Zero viable attack paths (Target unreachable)"
                    : "No attack paths identified"}
                </span>
              </div>

              <Link
                href="/remediate"
                className="h-7 px-3 rounded-lg bg-white border border-[#E3DDD2] text-[#282B2A] hover:bg-[#FAF7F0] transition-colors font-sans text-[11px] font-medium flex items-center gap-1.5 shadow-xs"
              >
                <Beaker className="w-3.5 h-3.5 text-[#32877A]" />
                <span>Simulate Remediation</span>
              </Link>
            </div>
          </div>

          {/* Primary Investigation Toolbar */}
          <form
            onSubmit={handleDiscoverSubmit}
            className="w-full bg-white px-6 py-2 flex flex-wrap items-center justify-between gap-3 border-b border-[#E3DDD2]"
          >
            <div className="flex flex-wrap items-center gap-2.5">
              {/* Source Identity Selector */}
              <div className="flex items-center bg-[#FAF7F0] px-3 py-1.5 rounded-lg gap-2.5 border border-[#E3DDD2]">
                <div className="w-6 h-6 rounded-md bg-[#EEF7F5] flex items-center justify-center text-[#32877A]">
                  <Activity className="w-3.5 h-3.5" />
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-sans text-[12px] text-[#282B2A] font-semibold">
                      Source Identity:
                    </span>
                    <select
                      value={sourceId}
                      onChange={(e) => setSourceId(e.target.value)}
                      className="bg-transparent font-mono text-[10px] font-bold text-[#282B2A] focus:outline-none cursor-pointer"
                    >
                      {availableIdentities.length > 0 ? (
                        availableIdentities.map((id) => (
                          <option key={id.id} value={id.id}>
                            {id.name} ({id.id})
                          </option>
                        ))
                      ) : (
                        <option value="usr_jdoe">John Doe (usr_jdoe)</option>
                      )}
                    </select>
                  </div>
                  <span className="text-[10px] text-[#686D6B]">
                    Compromised Entry Origin
                  </span>
                </div>
              </div>

              <span className="text-[#969B98] font-bold">➔</span>

              {/* Destination Target Selector */}
              <div className="flex items-center bg-[#FAF7F0] px-3 py-1.5 rounded-lg gap-2.5 border border-[#E3DDD2]">
                <div className="w-6 h-6 rounded-md bg-[#FCF6E8] flex items-center justify-center text-[#C88D22]">
                  <Database className="w-3.5 h-3.5" />
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-sans text-[12px] text-[#C88D22] font-semibold">
                      Destination Target:
                    </span>
                    <select
                      value={targetId}
                      onChange={(e) => setTargetId(e.target.value)}
                      className="bg-transparent font-mono text-[10px] font-bold text-[#282B2A] focus:outline-none cursor-pointer"
                    >
                      {availableTargets.length > 0 ? (
                        availableTargets.map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.name} ({t.id})
                          </option>
                        ))
                      ) : (
                        <option value="db_customer_vault">
                          Customer-Vault-DB (db_customer_vault)
                        </option>
                      )}
                    </select>
                  </div>
                  <span className="text-[10px] text-[#686D6B]">
                    Protected Crown Jewel
                  </span>
                </div>
              </div>

              {/* Max Depth */}
              <div className="flex items-center bg-[#FAF7F0] px-2.5 py-1.5 rounded-lg gap-1.5 text-[11px] border border-[#E3DDD2]">
                <span className="text-[#686D6B] font-medium">Depth:</span>
                <select
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(Number(e.target.value))}
                  className="bg-transparent text-[#282B2A] font-mono text-[11px] font-semibold focus:outline-none cursor-pointer"
                >
                  <option value={3}>3 Hops</option>
                  <option value={4}>4 Hops</option>
                  <option value={5}>5 Hops</option>
                  <option value={6}>6 Hops</option>
                </select>
              </div>
            </div>

            {/* Discovery CTA */}
            <div className="flex items-center gap-2">
              <button
                type="submit"
                disabled={discovering}
                className="h-8 px-3 rounded-lg bg-[#E85D4A] text-white hover:bg-[#D44C3A] font-sans text-[12px] font-semibold flex items-center gap-1.5 transition-colors shadow-sm disabled:opacity-50"
              >
                <Search className="w-3.5 h-3.5" />
                <span>{discovering ? "Traversing..." : "Discover Paths"}</span>
              </button>
            </div>
          </form>

          {/* Error Banner */}
          {errorMessage && (
            <div className="m-4 p-3 bg-[#FDF2F0] border border-[#E85D4A]/40 rounded-lg flex items-center justify-between text-xs text-[#E85D4A]">
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

          {/* Workbench 2-Column Viewport: Canvas + Inspector */}
          <div className="w-full flex-1 flex flex-col xl:flex-row p-4 gap-4 bg-[#F6F2E9] relative items-start">
            {/* Expanded Canvas Container */}
            <div className="flex-1 w-full flex flex-col relative bg-white rounded-xl border border-[#E3DDD2] shadow-[0_1px_3px_rgba(0,0,0,0.03)] overflow-hidden xl:sticky xl:top-[128px] h-[calc(100vh-148px)] min-h-[500px]">
              <div className="flex-1 w-full min-h-[350px] relative overflow-hidden flex flex-col">
                <AttackGraphCanvas
                  initialNodes={flowNodes}
                  initialEdges={flowEdges}
                  onNodeClick={handleNodeClick}
                  onEdgeClick={handleEdgeClick}
                  height="100%"
                />

                {/* In-Canvas Discovering Overlay */}
                {discovering && (
                  <div className="absolute inset-0 bg-white/70 backdrop-blur-xs flex flex-col items-center justify-center z-20 pointer-events-none">
                    <div className="flex items-center gap-2.5 px-4 py-2 rounded-xl bg-white border border-[#E3DDD2] shadow-sm text-xs font-medium text-[#282B2A]">
                      <div className="w-4 h-4 border-2 border-[#32877A] border-t-transparent rounded-full animate-spin" />
                      <span>Traversing graph & computing risk heuristics...</span>
                    </div>
                  </div>
                )}

                {/* In-Canvas Empty / Informational State */}
                {!discovering && flowNodes.length === 0 && (
                  <div className="absolute inset-0 bg-[#FAF7F0]/60 backdrop-blur-xs flex flex-col items-center justify-center p-6 text-center z-10 pointer-events-auto">
                    <div className="p-3 rounded-full bg-white border border-[#E3DDD2] mb-3 shadow-xs text-[#686D6B]">
                      {errorMessage ? (
                        <AlertTriangle className="w-5 h-5 text-[#E85D4A]" />
                      ) : (
                        <Search className="w-5 h-5 text-[#686D6B]" />
                      )}
                    </div>
                    <h3 className="font-sans text-sm font-semibold text-[#282B2A]">
                      {errorMessage
                        ? "Unable to Load Attack Graph"
                        : investigation?.status === "TARGET_UNREACHABLE"
                        ? "Target Unreachable"
                        : investigation?.paths && investigation.paths.length > 0
                        ? "Graph Layout Unavailable"
                        : "No Attack Paths Discovered"}
                    </h3>
                    <p className="text-xs text-[#686D6B] max-w-sm mt-1 leading-relaxed">
                      {errorMessage ||
                        (investigation?.status === "TARGET_UNREACHABLE"
                          ? `Zero viable traversal routes connect '${sourceId}' to '${targetId}' within ${maxDepth} hops.`
                          : investigation?.paths && investigation.paths.length > 0
                          ? "Discovered paths exist in the data model but could not be mapped to canvas nodes."
                          : "Select a source identity and target data asset in the toolbar above to explore potential attack vectors.")}
                    </p>
                    <div className="flex items-center gap-2 mt-4">
                      <button
                        type="button"
                        onClick={() => runInvestigation(sourceId, targetId, maxDepth)}
                        className="px-3 py-1.5 rounded-lg bg-white border border-[#E3DDD2] text-[#282B2A] hover:bg-[#FAF7F0] text-xs font-medium shadow-xs cursor-pointer flex items-center gap-1.5"
                      >
                        <Search className="w-3.5 h-3.5 text-[#32877A]" />
                        <span>Run Discovery</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Bottom Discovered Paths Drawer */}
              <div className="w-full bg-[#FAF7F0] border-t border-[#E3DDD2] z-30 transition-all mt-auto shrink-0 max-h-[45%] overflow-y-auto">
                {/* Summary Bar */}
                <div
                  onClick={() => setIsDrawerOpen(!isDrawerOpen)}
                  className="px-4 py-2 flex items-center justify-between cursor-pointer hover:bg-[#F4EFE6] transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <button className="flex items-center justify-center w-5 h-5 rounded bg-white border border-[#E3DDD2] text-[#686D6B]">
                      {isDrawerOpen ? (
                        <ChevronDown className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronUp className="w-3.5 h-3.5" />
                      )}
                    </button>
                    <div className="flex items-center gap-2">
                      <span className="font-sans text-[11px] font-bold text-[#282B2A] uppercase tracking-wider">
                        Discovered Attack Paths
                      </span>
                      <span className="text-[#E3DDD2]">•</span>
                      <span className="text-[12px] font-medium text-[#282B2A]">
                        {investigation?.paths.length || 0} Path(s) to{" "}
                        <span className="text-[#C88D22] font-semibold">
                          {targetId}
                        </span>
                      </span>

                      {investigation?.paths.map((p, idx) => (
                        <span
                          key={idx}
                          className={`px-1.5 py-0.2 rounded font-mono text-[8.5px] font-bold border ${
                            idx === selectedPathIndex
                              ? "bg-[#FDF2F0] text-[#E85D4A] border-[#E85D4A]/30"
                              : "bg-[#FEF8EC] text-[#D99A28] border-[#D99A28]/30"
                          }`}
                        >
                          Path #{idx + 1} ({Math.round(p.risk_assessment.score)}
                          )
                        </span>
                      ))}
                    </div>
                  </div>

                  <span className="px-2 py-0.5 rounded bg-white border border-[#E3DDD2] font-mono text-[8.5px] text-[#32877A] font-semibold uppercase">
                    [SYNTHETIC DEMO EVIDENCE]
                  </span>
                </div>

                {/* Expanded Drawer Rows */}
                {isDrawerOpen && (
                  <div className="px-4 pb-3 flex flex-col gap-1.5 border-t border-[#E3DDD2]/60 bg-white">
                    {investigation?.paths.map((detail, idx) => {
                      const isSelected = idx === selectedPathIndex;
                      return (
                        <div
                          key={idx}
                          onClick={() => {
                            setSelectedPathIndex(idx);
                            setSelectedHopIndex(0);
                          }}
                          className={`flex items-center justify-between py-2.5 px-3 rounded-lg border cursor-pointer transition-colors ${
                            isSelected
                              ? "bg-[#FAF7F0] border-l-4 border-l-[#E85D4A] border-[#E3DDD2]/60"
                              : "bg-white border-l-4 border-l-[#D99A28] border-[#E3DDD2]/60 hover:bg-[#FAF7F0]"
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            <span
                              className={`w-2 h-2 rounded-full ${
                                isSelected ? "bg-[#E85D4A] animate-pulse" : "bg-[#D99A28]"
                              }`}
                            />
                            <div className="flex flex-col">
                              <div className="flex items-center gap-2">
                                <span className="font-sans text-[12px] font-bold text-[#282B2A]">
                                  Path #{idx + 1}: {detail.path.signature}
                                </span>
                                <span className="px-1.5 py-0.2 rounded bg-[#FDF2F0] text-[#E85D4A] font-mono text-[8.5px] font-bold">
                                  {detail.risk_assessment.risk_tier} (
                                  {Math.round(detail.risk_assessment.score)})
                                </span>
                                {isSelected && (
                                  <span className="px-1.5 py-0.2 rounded bg-white text-[#E85D4A] font-sans text-[9px] uppercase font-bold border border-[#E85D4A]/30">
                                    Inspected
                                  </span>
                                )}
                              </div>
                              <span className="text-[11px] text-[#686D6B] mt-0.5">
                                {detail.path.hop_count} hops •{" "}
                                {detail.evidence.ordered_edges
                                  .map((e) => e.rel_type)
                                  .join(" ➔ ")}
                              </span>
                            </div>
                          </div>

                          <div className="flex items-center gap-2">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                const accessEdge = detail.path.edges[detail.path.edges.length - 1];
                                handleSimulateCut(
                                  accessEdge.source,
                                  accessEdge.type,
                                  accessEdge.target
                                );
                              }}
                              className="h-6 px-2.5 rounded-md bg-[#E85D4A] text-white font-sans text-[11px] font-semibold hover:bg-[#D44C3A] transition-colors shadow-xs"
                            >
                              Simulate Cut
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Right Docked Evidence Inspector */}
            {isInspectorOpen ? (
              <EvidenceRiskInspector
                selectedPathDetail={selectedPathDetail}
                activeHopIndex={selectedHopIndex}
                onSelectHop={setSelectedHopIndex}
                onSimulateCut={handleSimulateCut}
                onClose={() => setIsInspectorOpen(false)}
              />
            ) : (
              <button
                onClick={() => setIsInspectorOpen(true)}
                className="absolute top-6 right-6 z-20 px-3 py-1.5 rounded-lg bg-white shadow-md border border-[#E3DDD2] font-sans text-[12px] font-semibold text-[#282B2A] hover:bg-[#FAF7F0] flex items-center gap-1.5"
              >
                <Activity className="w-4 h-4 text-[#E85D4A]" />
                <span>Open Inspector</span>
              </button>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
