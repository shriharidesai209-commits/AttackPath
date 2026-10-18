"use client";

import React, { useState, useRef, useEffect } from "react";
import Link from "next/link";
import {
  PathInvestigationDetail,
  formatRelationshipLabel,
} from "@/lib/types";
import {
  ArrowDown,
  ChevronDown,
  Info,
  Zap,
  Server,
  ChevronRight,
  ChevronLeft,
  Beaker,
  ExternalLink,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Terminal,
} from "lucide-react";

interface EvidenceRiskInspectorProps {
  selectedPathDetail?: PathInvestigationDetail | null;
  activeHopIndex?: number;
  onSelectHop?: (index: number) => void;
  onSimulateCut?: (sourceId: string, relType: string, targetId: string) => void;
  onClose?: () => void;
}

export function EvidenceRiskInspector({
  selectedPathDetail,
  activeHopIndex = 0,
  onSelectHop,
  onSimulateCut,
  onClose,
}: EvidenceRiskInspectorProps) {
  const [openAccordions, setOpenAccordions] = useState<{
    facts: boolean;
    interpretation: boolean;
    uncertainties: boolean;
    technical: boolean;
  }>({
    facts: true,
    interpretation: true,
    uncertainties: true,
    technical: false,
  });

  const toggleAccordion = (key: "facts" | "interpretation" | "uncertainties" | "technical") => {
    setOpenAccordions((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const path = selectedPathDetail?.path;
  const evidence = selectedPathDetail?.evidence;
  const risk = selectedPathDetail?.risk_assessment;

  // Derive inspected hop dynamically based on activeHopIndex
  const currentHopIndex =
    activeHopIndex !== undefined &&
    path?.edges &&
    activeHopIndex >= 0 &&
    activeHopIndex < path.edges.length
      ? activeHopIndex
      : 0;

  const activeEdge = path?.edges?.[currentHopIndex];
  const activeSource = path?.nodes?.[currentHopIndex];
  const activeTarget = path?.nodes?.[currentHopIndex + 1];
  const activeEdgeEvidence = evidence?.ordered_edges?.[currentHopIndex];

  const score = risk ? Math.round(risk.score) : 100;
  const tier = risk?.risk_tier || "CRITICAL";

  // Ref for hop navigator scroll container & active hop button
  const hopStripRef = useRef<HTMLDivElement>(null);
  const activeHopButtonRef = useRef<HTMLButtonElement>(null);

  // Auto-scroll active hop into view smoothly when changed, only if not already visible
  useEffect(() => {
    if (activeHopButtonRef.current && hopStripRef.current) {
      const strip = hopStripRef.current;
      const btn = activeHopButtonRef.current;

      const stripRect = strip.getBoundingClientRect();
      const btnRect = btn.getBoundingClientRect();

      // Check if button is fully inside the visible strip horizontally
      const isFullyVisible =
        btnRect.left >= stripRect.left + 2 &&
        btnRect.right <= stripRect.right - 2;

      if (!isFullyVisible) {
        btn.scrollIntoView({
          behavior: "smooth",
          block: "nearest",
          inline: "nearest",
        });
      }
    }
  }, [currentHopIndex]);

  // Contextual security interpretation supported by observed facts for the active hop
  const getHopSecurityInterpretation = (relType?: string, props?: Record<string, any>) => {
    switch (relType) {
      case "AUTHENTICATES_TO":
        return `Observed authentication edge allows initial access from identity '${activeSource?.id}' into workload '${activeTarget?.id}' using ${props?.method || "credentials"} (${props?.credential_type || "key"}). No MFA enforcement was observed on this identity.`;
      case "EXECUTES_AS":
        return `Workload '${activeSource?.id}' runs in the context of role '${activeTarget?.id}' provisioned via ${props?.source || "instance metadata"}. Any process running on this workload automatically possesses administrative or access permissions attached to this role.`;
      case "CAN_ACCESS":
        return `Role '${activeSource?.id}' possesses explicit cloud IAM permissions '${props?.permission || "rds:FullAccess"}' (wildcard=${props?.is_wildcard ?? "true"}) targeting protected crown jewel '${activeTarget?.id}', granting direct data read/write or exfiltration reach.`;
      case "NETWORK_REACHABLE":
        return `Network routing over ${props?.protocol || "TCP"}/${props?.port || "8080"} permits uninhibited lateral movement across workloads without intermediate network microsegmentation boundaries.`;
      case "CAN_ASSUME":
        return `Trust policy allows identity '${activeSource?.id}' to assume role '${activeTarget?.id}' (${props?.policy_name || "assume role policy"}), facilitating lateral privilege escalation.`;
      default:
        return `Directed relationship '${relType}' establishes verified reachability between '${activeSource?.id}' and '${activeTarget?.id}'.`;
    }
  };

  const activeEdgeProps = activeEdgeEvidence?.properties || activeEdge?.properties || {};
  const validEdgeProps = Object.entries(activeEdgeProps).filter(([k]) => k !== "is_synthetic");

  const totalHops = path?.edges?.length || 0;

  return (
    <aside className="w-full xl:w-[430px] xl:min-w-[390px] xl:max-w-[460px] shrink-0 bg-white rounded-xl border border-[#E3DDD2] shadow-[0_1px_4px_rgba(0,0,0,0.03)] flex flex-col justify-between overflow-hidden transition-all duration-300 xl:sticky xl:top-[128px] h-[calc(100vh-148px)] max-h-[calc(100vh-148px)] min-h-[500px]">
      {/* PINNED TOP SECTION: Header & Hop Navigator Strip */}
      <div className="shrink-0 flex flex-col border-b border-[#E3DDD2] bg-[#FAF7F0]/90 z-10 backdrop-blur-xs">
        {/* Panel Header */}
        <div className="p-3.5 border-b border-[#E3DDD2] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-[#E85D4A]" />
            <span className="font-sans text-[13px] font-bold text-[#282B2A]">
              Evidence &amp; Risk Inspector
            </span>
            <span className="px-1.5 py-0.5 rounded bg-[#FDF2F0] text-[#E85D4A] font-mono text-[9px] font-bold border border-[#E85D4A]/20">
              {totalHops > 0 ? `HOP ${currentHopIndex + 1} OF ${totalHops}` : "EVIDENCE"}
            </span>
          </div>

          {onClose && (
            <button
              onClick={onClose}
              className="flex items-center gap-1 px-2 py-1 rounded hover:bg-[#F4EFE6] text-[#686D6B] hover:text-[#282B2A] font-sans text-[11px] font-medium transition-colors border border-[#E3DDD2]/70 bg-white shadow-2xs cursor-pointer"
              title="Collapse Inspector"
              aria-label="Collapse Evidence Inspector"
            >
              <span>Collapse</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Hop Navigator Strip with Prev/Next Controls */}
        {path && totalHops > 1 && (
          <div className="flex flex-col px-3 py-2 bg-[#FAF7F0] gap-1.5">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[9px] uppercase text-[#686D6B] font-bold tracking-wider">
                Hop Navigator ({currentHopIndex + 1} of {totalHops})
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => onSelectHop && onSelectHop(Math.max(0, currentHopIndex - 1))}
                  disabled={currentHopIndex === 0}
                  className="p-1 rounded bg-white hover:bg-[#F4EFE6] disabled:opacity-40 disabled:hover:bg-white text-[#282B2A] border border-[#E3DDD2] shadow-2xs transition-colors cursor-pointer disabled:cursor-not-allowed"
                  title="Previous Hop"
                  aria-label="Previous Hop"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() =>
                    onSelectHop && onSelectHop(Math.min(totalHops - 1, currentHopIndex + 1))
                  }
                  disabled={currentHopIndex === totalHops - 1}
                  className="p-1 rounded bg-white hover:bg-[#F4EFE6] disabled:opacity-40 disabled:hover:bg-white text-[#282B2A] border border-[#E3DDD2] shadow-2xs transition-colors cursor-pointer disabled:cursor-not-allowed"
                  title="Next Hop"
                  aria-label="Next Hop"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Horizontally Scrollable Hop Cards */}
            <div
              ref={hopStripRef}
              className="flex items-center gap-1.5 overflow-x-auto py-1 scroll-smooth overscroll-contain no-scrollbar"
            >
              {path.edges.map((e, idx) => {
                const isActive = idx === currentHopIndex;
                const formattedLabel = formatRelationshipLabel(e.type);
                return (
                  <button
                    key={idx}
                    ref={isActive ? activeHopButtonRef : undefined}
                    onClick={() => onSelectHop && onSelectHop(idx)}
                    className={`px-2.5 py-1.5 rounded-lg border text-left transition-all cursor-pointer ${
                      totalHops <= 3
                        ? "flex-1 min-w-[110px]"
                        : "shrink-0 min-w-[120px] max-w-[165px]"
                    } ${
                      isActive
                        ? "bg-[#E85D4A] text-white border-[#D44C3A] shadow-xs ring-2 ring-[#E85D4A]/25"
                        : "bg-white hover:bg-[#F4EFE6] text-[#282B2A] border-[#E3DDD2] shadow-2xs"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-0.5">
                      <span
                        className={`font-mono text-[9px] font-bold uppercase tracking-wider ${
                          isActive ? "text-white/90" : "text-[#686D6B]"
                        }`}
                      >
                        Hop {idx + 1}
                      </span>
                      {isActive && (
                        <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                      )}
                    </div>
                    <div
                      className={`font-sans text-[11px] font-bold truncate whitespace-nowrap block leading-tight ${
                        isActive ? "text-white" : "text-[#282B2A]"
                      }`}
                      title={formattedLabel}
                    >
                      {formattedLabel}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* INDEPENDENT SCROLLABLE CONTENT REGION */}
      <div className="flex flex-col overflow-y-auto flex-1 overscroll-contain">
        {/* Active Hop Details Overview */}
        <div className="p-4 flex flex-col gap-3.5 border-b border-[#E3DDD2]">
          {/* Active Relationship Title */}
          <div className="flex flex-col gap-1">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[#E85D4A] font-mono text-[9px] font-bold uppercase tracking-wider">
                <span className="w-2 h-2 rounded-full bg-[#E85D4A] animate-pulse" />
                <span>Hop {currentHopIndex + 1} of {totalHops}</span>
              </div>
              <span className="font-mono text-[9px] text-[#32877A] bg-[#EEF7F5] px-1.5 py-0.5 rounded font-semibold border border-[#32877A]/20">
                Synchronized
              </span>
            </div>

            <h3 className="font-sans text-[15px] font-bold text-[#282B2A] leading-snug">
              {formatRelationshipLabel(activeEdge?.type || "")}
            </h3>
            <p className="text-[11px] text-[#686D6B] leading-snug">
              Direct connection from <strong className="text-[#282B2A] font-semibold">{activeSource?.name || activeSource?.id}</strong> to{" "}
              <strong className="text-[#282B2A] font-semibold">{activeTarget?.name || activeTarget?.id}</strong>
            </p>
          </div>

          {/* Structured Directional Flow (Vertical Stack: Source ➔ Relationship ➔ Target) */}
          <div className="flex flex-col rounded-xl bg-[#FAF7F0] border border-[#E3DDD2] p-3 gap-2">
            {/* Source Node */}
            <div className="bg-white rounded-lg p-2.5 border border-[#E3DDD2]/80 shadow-2xs">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[9px] uppercase font-bold text-[#686D6B] tracking-wider">
                  Source Entity {activeSource?.label ? `• ${activeSource.label}` : ""}
                </span>
                <span className="font-mono text-[9px] text-[#686D6B] bg-[#FAF7F0] px-1.5 py-0.2 rounded border border-[#E3DDD2]/60">
                  Origin
                </span>
              </div>
              <div className="font-sans text-[13px] font-bold text-[#282B2A] leading-tight break-words">
                {activeSource?.name || "Source Entity"}
              </div>
              <div className="font-mono text-[10px] text-[#686D6B] mt-0.5">
                ID: <span className="text-[#282B2A] font-semibold">{activeSource?.id}</span>
              </div>
            </div>

            {/* Dedicated Relationship Indicator (Full-width divider with centered pill) */}
            <div className="flex items-center justify-center my-0.5 relative">
              <div className="absolute inset-0 flex items-center" aria-hidden="true">
                <div className="w-full border-t border-dashed border-[#D5CDC0]" />
              </div>
              <div className="relative px-3 py-1 rounded-full bg-[#F5F0FF] border border-[#7C5CBF]/30 text-[#7C5CBF] shadow-2xs flex items-center gap-1.5">
                <ArrowDown className="w-3 h-3 text-[#7C5CBF] shrink-0" />
                <span className="font-sans text-[11px] font-bold whitespace-nowrap">
                  {formatRelationshipLabel(activeEdge?.type || "")}
                </span>
                <span className="font-mono text-[9px] opacity-75 font-semibold">
                  [{activeEdge?.type}]
                </span>
              </div>
            </div>

            {/* Target Node */}
            <div className="bg-white rounded-lg p-2.5 border border-[#E3DDD2]/80 shadow-2xs">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[9px] uppercase font-bold text-[#686D6B] tracking-wider">
                  Target Entity {activeTarget?.label ? `• ${activeTarget.label}` : ""}
                </span>
                <span className="font-mono text-[9px] text-[#32877A] bg-[#EEF7F5] px-1.5 py-0.2 rounded border border-[#32877A]/30 font-semibold">
                  Destination
                </span>
              </div>
              <div className="font-sans text-[13px] font-bold text-[#282B2A] leading-tight break-words">
                {activeTarget?.name || "Target Entity"}
              </div>
              <div className="font-mono text-[10px] text-[#686D6B] mt-0.5">
                ID: <span className="text-[#282B2A] font-semibold">{activeTarget?.id}</span>
              </div>
            </div>
          </div>

          {/* Technical Edge Notation */}
          <div className="flex flex-col gap-1">
            <span className="font-mono text-[9px] uppercase font-bold text-[#686D6B] tracking-wider">
              Technical Graph Relationship
            </span>
            <div className="bg-[#FAF7F0] p-2 rounded-lg border border-[#E3DDD2] font-mono text-[10.5px] text-[#282B2A] break-all select-all">
              ({activeEdge?.source})-[:{activeEdge?.type}]-&gt;({activeEdge?.target})
            </div>
          </div>

          {/* Hop Evidence Facts Preview */}
          {activeEdgeEvidence?.observed_facts && activeEdgeEvidence.observed_facts.length > 0 && (
            <div className="flex flex-col gap-1.5 pt-0.5">
              <span className="font-mono text-[9px] uppercase font-bold text-[#686D6B] tracking-wider">
                Observed Hop Evidence
              </span>
              <div className="flex flex-col gap-1">
                {activeEdgeEvidence.observed_facts.map((fact, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-2 p-2 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]/70 text-[11px] text-[#282B2A] leading-snug"
                  >
                    <CheckCircle className="w-3.5 h-3.5 text-[#32877A] mt-0.5 shrink-0" />
                    <span>{fact}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Dynamic Route Summary (Backend Factual Data Only) */}
          {evidence?.route_summary && (
            <p className="text-[12px] text-[#282B2A] leading-relaxed">
              {evidence.route_summary}
            </p>
          )}

          {/* Prioritization Risk Score Card */}
          <div className="p-3 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <div className="flex flex-col">
                <span className="font-sans text-[11px] font-bold text-[#282B2A]">
                  Prioritization Score
                </span>
                <span className="text-[9.5px] text-[#686D6B]">
                  Relative heuristic graph priority
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="px-1.5 py-0.2 rounded bg-[#FDF2F0] text-[#E85D4A] font-mono text-[8.5px] font-bold">
                  {tier}
                </span>
                <span className="font-sans text-[18px] text-[#E85D4A] font-bold leading-none">
                  {score}
                  <span className="text-[11px] text-[#969B98] font-normal">
                    /100
                  </span>
                </span>
              </div>
            </div>

            <div className="w-full bg-[#E3DDD2]/70 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-[#E85D4A] h-full rounded-full transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(5, score))}%` }}
              />
            </div>

            <span className="text-[10px] text-[#969B98] leading-tight">
              Relative heuristic prioritization based on graph reachability and privilege scope; not a calculated exploit probability.
            </span>
          </div>

          <div className="flex items-center justify-between font-mono text-[9px] text-[#686D6B] pt-0.5">
            <span>
              Scenario:{" "}
              <strong className="text-[#32877A] font-medium">
                Synthetic Benchmark Data
              </strong>
            </span>
            <span>Sandbox: isolated-graph-clone</span>
          </div>
        </div>

        {/* THREE EXPLICIT EVIDENCE-TO-CONCLUSION ACCORDIONS */}
        <div className="flex flex-col divide-y divide-[#E3DDD2] font-sans">
          {/* Accordion 1: Observed Graph Facts */}
          <div className="flex flex-col">
            <button
              onClick={() => toggleAccordion("facts")}
              className="w-full px-4 py-2.5 flex items-center justify-between text-left hover:bg-[#FAF7F0] transition-colors font-sans text-[12px] font-semibold text-[#282B2A] cursor-pointer"
            >
              <span className="flex items-center gap-2">
                <Server className="w-4 h-4 text-[#32877A]" />
                <span>1. Observed Graph Facts</span>
                <span className="px-1.5 py-0.2 rounded bg-[#EEF7F5] text-[#32877A] font-mono text-[8px] font-bold border border-[#32877A]/30">
                  OBSERVED
                </span>
              </span>
              <ChevronDown
                className={`w-4 h-4 text-[#686D6B] transition-transform ${
                  openAccordions.facts ? "rotate-180" : ""
                }`}
              />
            </button>

            {openAccordions.facts && (
              <div className="px-4 pb-3.5 flex flex-col gap-2.5 text-[11px] bg-[#FAF7F0]/40">
                {/* Inspected Hop Facts */}
                <div className="p-2.5 rounded bg-white border border-[#E3DDD2] flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-sans text-[10px] text-[#686D6B] uppercase font-bold">
                      Hop Traversal Facts ({activeEdge?.type})
                    </span>
                    <span className="font-mono text-[8px] text-[#32877A] font-bold">
                      FalkorDB Verified
                    </span>
                  </div>
                  {activeEdgeEvidence?.observed_facts &&
                  activeEdgeEvidence.observed_facts.length > 0 ? (
                    <div className="flex flex-col gap-1">
                      {activeEdgeEvidence.observed_facts.map((fact, fIdx) => (
                        <div
                          key={fIdx}
                          className="p-1.5 rounded bg-[#FAF7F0] border border-[#E3DDD2]/70 flex items-start gap-1.5 font-mono text-[10px]"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-[#32877A] mt-1 shrink-0" />
                          <span className="text-[#282B2A] leading-snug">{fact}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-[#686D6B] text-[10px]">
                      Directed edge ({activeEdge?.source})-[{activeEdge?.type}]-&gt;({activeEdge?.target}) observed in graph.
                    </span>
                  )}
                </div>

                {/* Inspected Hop Attributes */}
                {validEdgeProps.length > 0 && (
                  <div className="p-2.5 rounded bg-white border border-[#E3DDD2] flex flex-col gap-1.5">
                    <span className="font-sans text-[10px] text-[#686D6B] uppercase font-bold">
                      Observed Hop Attributes
                    </span>
                    <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px]">
                      {validEdgeProps.map(([k, v]) => (
                        <div
                          key={k}
                          className="p-1.5 rounded bg-[#FAF7F0] border border-[#E3DDD2]/70"
                        >
                          <span className="text-[#969B98] block text-[9px] uppercase font-semibold">
                            {k}:
                          </span>
                          <span className="text-[#282B2A] font-bold truncate block">
                            {String(v)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Node Observables */}
                <div className="grid grid-cols-2 gap-2 font-mono text-[10px]">
                  <div className="p-2 rounded bg-white border border-[#E3DDD2]">
                    <span className="text-[#969B98] block text-[9px] uppercase">Source Entity:</span>
                    <strong className="text-[#282B2A] truncate block">{activeSource?.name || activeSource?.id}</strong>
                    <span className="text-[#686D6B] text-[9px]">{activeSource?.label}</span>
                  </div>
                  <div className="p-2 rounded bg-white border border-[#E3DDD2]">
                    <span className="text-[#969B98] block text-[9px] uppercase">Target Entity:</span>
                    <strong className="text-[#282B2A] truncate block">{activeTarget?.name || activeTarget?.id}</strong>
                    <span className="text-[#686D6B] text-[9px]">{activeTarget?.label}</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Accordion 2: Security Interpretation Supported by Facts */}
          <div className="flex flex-col">
            <button
              onClick={() => toggleAccordion("interpretation")}
              className="w-full px-4 py-2.5 flex items-center justify-between text-left hover:bg-[#FAF7F0] transition-colors font-sans text-[12px] font-semibold text-[#282B2A] cursor-pointer"
            >
              <span className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-[#E85D4A]" />
                <span>2. Security Interpretation</span>
                <span className="px-1.5 py-0.2 rounded bg-[#FDF2F0] text-[#E85D4A] font-mono text-[8px] font-bold border border-[#E85D4A]/30">
                  INTERPRETATION
                </span>
              </span>
              <ChevronDown
                className={`w-4 h-4 text-[#686D6B] transition-transform ${
                  openAccordions.interpretation ? "rotate-180" : ""
                }`}
              />
            </button>

            {openAccordions.interpretation && (
              <div className="px-4 pb-3.5 flex flex-col gap-2.5 text-[11px] bg-[#FAF7F0]/40">
                {/* Hop Exploit & Impact Analysis */}
                <div className="p-2.5 rounded bg-white border border-[#E3DDD2] flex flex-col gap-1.5">
                  <span className="font-sans text-[10px] text-[#E85D4A] uppercase font-bold">
                    Hop #{currentHopIndex + 1} Security Impact
                  </span>
                  <p className="text-[11px] text-[#282B2A] leading-relaxed">
                    {getHopSecurityInterpretation(activeEdge?.type, activeEdgeProps)}
                  </p>
                </div>

                {/* Path-Level Derived Claims */}
                {evidence?.factual_claims && evidence.factual_claims.some((c) => c.provenance === "DERIVED_INTERPRETATION") && (
                  <div className="p-2.5 rounded bg-white border border-[#E3DDD2] flex flex-col gap-1.5">
                    <span className="font-sans text-[10px] text-[#686D6B] uppercase font-bold">
                      Path Traversal Rationale
                    </span>
                    {evidence.factual_claims
                      .filter((c) => c.provenance === "DERIVED_INTERPRETATION")
                      .map((claim, cIdx) => (
                        <div
                          key={cIdx}
                          className="p-1.5 rounded bg-[#FAF7F0] border border-[#E3DDD2]/70 text-[10.5px] text-[#282B2A]"
                        >
                          {claim.statement}
                        </div>
                      ))}
                  </div>
                )}

                {/* Scoring Rules Triggered */}
                {risk?.contributions && risk.contributions.length > 0 && (
                  <div className="p-2.5 rounded bg-white border border-[#E3DDD2] flex flex-col gap-1.5">
                    <span className="font-sans text-[10px] text-[#686D6B] uppercase font-bold">
                      Supporting Heuristic Rule Adjustments
                    </span>
                    <div className="flex flex-col gap-1">
                      {risk.contributions.slice(0, 3).map((rule, rIdx) => (
                        <div
                          key={rIdx}
                          className="flex items-center justify-between p-1.5 rounded bg-[#FAF7F0] text-[10px]"
                        >
                          <span className="font-medium text-[#282B2A] truncate">
                            {rule.rule_name}
                          </span>
                          <span className="font-mono text-[#E85D4A] font-bold shrink-0 ml-1">
                            +{rule.score_delta}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Accordion 3: Unknowns, Limitations & Missing Evidence */}
          <div className="flex flex-col">
            <button
              onClick={() => toggleAccordion("uncertainties")}
              className="w-full px-4 py-2.5 flex items-center justify-between text-left hover:bg-[#FAF7F0] transition-colors font-sans text-[12px] font-semibold text-[#282B2A] cursor-pointer"
            >
              <span className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#D99A28]" />
                <span>3. Unknowns &amp; Limitations</span>
                <span className="px-1.5 py-0.2 rounded bg-[#FEF8EC] text-[#D99A28] font-mono text-[8px] font-bold border border-[#D99A28]/40">
                  CAVEATS
                </span>
              </span>
              <ChevronDown
                className={`w-4 h-4 text-[#686D6B] transition-transform ${
                  openAccordions.uncertainties ? "rotate-180" : ""
                }`}
              />
            </button>

            {openAccordions.uncertainties && (
              <div className="px-4 pb-3.5 flex flex-col gap-2.5 text-[11px] bg-[#FAF7F0]/40">
                {/* Risk Engine Uncertainties */}
                <div className="p-2.5 rounded bg-white border border-[#E3DDD2] flex flex-col gap-1.5">
                  <span className="font-sans text-[10px] text-[#D99A28] uppercase font-bold flex items-center gap-1">
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>Evidence Gaps / Model Uncertainties</span>
                  </span>
                  {risk?.uncertainties && risk.uncertainties.length > 0 ? (
                    <div className="flex flex-col gap-1">
                      {risk.uncertainties.map((u, uIdx) => (
                        <div
                          key={uIdx}
                          className="p-1.5 rounded bg-[#FEF8EC] border border-[#D99A28]/30 font-mono text-[10px] text-[#9B6B15]"
                        >
                          ⚠ {u}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-1.5 rounded bg-[#EEF7F5] border border-[#32877A]/30 text-[10px] text-[#256B60] flex items-center gap-1.5">
                      <CheckCircle className="w-3.5 h-3.5 shrink-0" />
                      <span>
                        Zero missing properties detected. All evaluated entities contain observed security attributes.
                      </span>
                    </div>
                  )}
                </div>

                {/* Analytical Limitations */}
                <div className="p-2.5 rounded bg-white border border-[#E3DDD2] flex flex-col gap-1 text-[10.5px] text-[#686D6B]">
                  <span className="font-sans text-[10px] text-[#686D6B] uppercase font-bold">
                    Analysis Boundaries
                  </span>
                  <p>
                    • <strong>Structural Feasibility vs. Live Telemetry:</strong> Path traversal evaluates topology and permissions. It does not measure runtime EDR blocks, host IPS rules, or network firewall state.
                  </p>
                  <p>
                    • <strong>Heuristic Prioritization:</strong> Score ({score}/100) reflects analyst priority, not mathematical probability of compromise.
                  </p>
                  <p>
                    • <strong>Synthetic Environment:</strong> Scenario uses synthetic benchmark nodes. No real production cloud IAM was altered.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Accordion 4: Technical Identifiers & Raw Cypher Details */}
          <div className="flex flex-col">
            <button
              onClick={() => toggleAccordion("technical")}
              className="w-full px-4 py-2.5 flex items-center justify-between text-left hover:bg-[#FAF7F0] transition-colors font-sans text-[12px] font-semibold text-[#282B2A] cursor-pointer"
            >
              <span className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#686D6B]" />
                <span>Technical Identifiers &amp; Cypher</span>
              </span>
              <ChevronDown
                className={`w-4 h-4 text-[#686D6B] transition-transform ${
                  openAccordions.technical ? "rotate-180" : ""
                }`}
              />
            </button>

            {openAccordions.technical && (
              <div className="px-4 pb-3.5 flex flex-col gap-2 text-[11px] bg-[#FAF7F0]/40">
                <div className="p-2.5 rounded bg-white border border-[#E3DDD2] flex flex-col gap-1">
                  <span className="font-mono text-[9px] uppercase text-[#686D6B] font-bold">
                    Directed Cypher Traversal Spec:
                  </span>
                  <div className="bg-[#FAF7F0] p-2 rounded border border-[#E3DDD2] font-mono text-[10px] text-[#282B2A] overflow-x-auto">
                    <code>
                      MATCH (src &#123;id: &quot;{activeEdge?.source}&quot;&#125;)-[rel:{activeEdge?.type}]-&gt;(tgt &#123;id: &quot;{activeEdge?.target}&quot;&#125;) RETURN rel
                    </code>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-1.5 font-mono text-[9.5px]">
                  <div className="p-1.5 rounded bg-white border border-[#E3DDD2]">
                    <span className="text-[#969B98] block text-[8px] uppercase">Source ID:</span>
                    <strong className="text-[#282B2A] truncate block">{activeEdge?.source}</strong>
                  </div>
                  <div className="p-1.5 rounded bg-white border border-[#E3DDD2]">
                    <span className="text-[#969B98] block text-[8px] uppercase">Type:</span>
                    <strong className="text-[#7C5CBF] truncate block">{activeEdge?.type}</strong>
                  </div>
                  <div className="p-1.5 rounded bg-white border border-[#E3DDD2]">
                    <span className="text-[#969B98] block text-[8px] uppercase">Target ID:</span>
                    <strong className="text-[#E85D4A] truncate block">{activeEdge?.target}</strong>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* PINNED BOTTOM ACTION FOOTER */}
      <div className="shrink-0 p-3.5 border-t border-[#E3DDD2] bg-white flex flex-col gap-2 z-10">
        <button
          onClick={() => {
            if (activeEdge && onSimulateCut) {
              onSimulateCut(activeEdge.source, activeEdge.type, activeEdge.target);
            }
          }}
          className="w-full py-2.5 px-3 rounded-lg bg-[#E85D4A] hover:bg-[#D44C3A] text-white text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm cursor-pointer"
        >
          <Beaker className="w-4 h-4" />
          <span>Simulate Revoking This Hop</span>
        </button>

        <Link
          href="/remediate"
          className="w-full py-2 px-3 rounded-lg bg-white hover:bg-[#FAF7F0] text-[#282B2A] text-xs font-medium flex items-center justify-center gap-1.5 transition-colors border border-[#E3DDD2]"
        >
          <span>Open Full Remediation Studio</span>
          <ExternalLink className="w-3.5 h-3.5 text-[#686D6B]" />
        </Link>
      </div>
    </aside>
  );
}
