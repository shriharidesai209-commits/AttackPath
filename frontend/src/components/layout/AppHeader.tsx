"use client";

import React, { useState } from "react";
import { api } from "@/lib/api";
import {
  AlertTriangle,
  Database,
  HelpCircle,
} from "lucide-react";

interface AppHeaderProps {
  onSeeded?: () => void;
}

export function AppHeader({ onSeeded }: AppHeaderProps) {
  const [seeding, setSeeding] = useState(false);
  const [seedMessage, setSeedMessage] = useState<string | null>(null);

  const handleSeed = async () => {
    if (seeding) return;
    setSeeding(true);
    setSeedMessage(null);
    try {
      const res = await api.seedGraph(false);
      setSeedMessage(`Seeded: ${res.nodes_created} nodes, ${res.relationships_created} edges`);
      if (onSeeded) onSeeded();
    } catch (err: any) {
      setSeedMessage(`Seed failed: ${err.message || "Unknown error"}`);
    } finally {
      setSeeding(false);
      setTimeout(() => setSeedMessage(null), 4000);
    }
  };

  return (
    <header className="fixed top-0 left-64 right-0 h-14 bg-white/95 backdrop-blur-sm z-40 flex items-center justify-between px-6 border-b border-[#E3DDD2] shadow-[0_1px_3px_rgba(0,0,0,0.02)] select-none">
      <div className="flex items-center gap-3">
        {/* Investigation Badge */}
        <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2]">
          <AlertTriangle className="w-3.5 h-3.5 text-[#E85D4A]" />
          <span className="font-mono text-[12px] font-semibold text-[#282B2A]">
            INV-2025-084
          </span>
          <span className="text-[#E3DDD2]">•</span>
          <span className="text-[12px] text-[#686D6B] truncate max-w-xs">
            Compromised Identity Traversal
          </span>
        </div>

        {/* Synthetic Environment Info */}
        <div className="hidden xl:flex items-center gap-2 px-3 py-1 rounded-lg bg-[#F4EFE6] border border-[#E3DDD2]">
          <span className="w-2 h-2 rounded-full bg-[#32877A]" />
          <span className="font-mono text-[11px] text-[#282B2A]">
            Environment:{" "}
            <span className="text-[#32877A] font-medium">
              Synthetic Scenario Sandbox
            </span>
          </span>
          <span className="text-[#969B98] text-xs">|</span>
          <span className="font-mono text-[11px] text-[#686D6B]">
            Benchmark Fixture #42
          </span>
        </div>

        {seedMessage && (
          <span className="font-mono text-[11px] px-2.5 py-1 rounded bg-[#EEF7F5] text-[#32877A] border border-[#32877A]/30">
            {seedMessage}
          </span>
        )}
      </div>

      <div className="flex items-center gap-2.5">
        <span className="px-2 py-0.5 rounded-md bg-[#FAF7F0] border border-[#E3DDD2] font-mono text-[10px] text-[#686D6B] font-semibold uppercase">
          [DEMO PREVIEW]
        </span>

        {/* Explicit Seed Demo Scenario Button */}
        <button
          onClick={handleSeed}
          disabled={seeding}
          title="Seed canonical 11-node synthetic benchmark scenario into FalkorDB"
          className="h-8 px-3 rounded-lg bg-white text-[#282B2A] text-[12px] font-medium flex items-center gap-1.5 hover:bg-[#FAF7F0] transition-colors border border-[#E3DDD2] shadow-sm disabled:opacity-50"
        >
          <Database
            className={`w-3.5 h-3.5 text-[#32877A] ${
              seeding ? "animate-spin" : ""
            }`}
          />
          <span>{seeding ? "Seeding..." : "Seed Demo Scenario"}</span>
        </button>

        <a
          href="https://github.com/FalkorDB/falkordb"
          target="_blank"
          rel="noreferrer"
          className="p-1 text-[#969B98] hover:text-[#282B2A] transition-colors flex items-center"
          title="FalkorDB Documentation & Engine"
        >
          <HelpCircle className="w-4 h-4" />
        </a>

        <div className="w-8 h-8 rounded-lg bg-[#F4EFE6] border border-[#E3DDD2] flex items-center justify-center text-[#282B2A] font-semibold text-[11px]">
          AV
        </div>
      </div>
    </header>
  );
}
