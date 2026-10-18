"use client";

import React, { memo } from "react";
import { Handle, Position } from "@xyflow/react";
import { User, Server, Key, Database, AlertCircle, ShieldCheck } from "lucide-react";

export interface EntityNodeData {
  id: string;
  label: string;
  name: string;
  properties?: Record<string, any>;
  isSynthetic?: boolean;
  isInspected?: boolean;
  isSevered?: boolean;
  hopNumber?: number;
}

export const CustomEntityNode = memo(({ data, selected }: { data: EntityNodeData; selected?: boolean }) => {
  const { id, label, name, properties, isInspected, isSevered } = data;
  const isCompromised = properties?.compromised === true;
  const isCrownJewel = properties?.classification === "crown_jewel";

  // Label configuration
  const getBadgeStyle = () => {
    switch (label) {
      case "Identity":
        return {
          badgeBg: "bg-[#EEF7F5]",
          badgeText: "text-[#32877A]",
          borderTop: "border-t-[#32877A]",
          icon: User,
          tag: "IDENTITY",
        };
      case "Workload":
        return {
          badgeBg: "bg-[#F4EFE6]",
          badgeText: "text-[#686D6B]",
          borderTop: "border-t-[#686D6B]",
          icon: Server,
          tag: "WORKLOAD",
        };
      case "IAMRole":
        return {
          badgeBg: "bg-[#F6F3FB]",
          badgeText: "text-[#7C5CBF]",
          borderTop: "border-t-[#7C5CBF]",
          icon: Key,
          tag: "ROLE PIVOT",
        };
      case "DataAsset":
        return {
          badgeBg: "bg-[#FCF6E8]",
          badgeText: "text-[#C88D22]",
          borderTop: "border-t-[#C88D22]",
          icon: Database,
          tag: "PROTECTED ASSET",
        };
      default:
        return {
          badgeBg: "bg-[#F4EFE6]",
          badgeText: "text-[#686D6B]",
          borderTop: "border-t-[#686D6B]",
          icon: AlertCircle,
          tag: "ENTITY",
        };
    }
  };

  const style = getBadgeStyle();
  const Icon = style.icon;

  return (
    <div
      className={`w-52 bg-white rounded-lg border shadow-sm p-3 transition-all select-none border-t-2 ${
        style.borderTop
      } ${
        isInspected || selected
          ? "border-2 border-[#E85D4A] ring-2 ring-[#E85D4A]/20 shadow-md -translate-y-0.5"
          : isSevered
          ? "border-dashed border-[#32877A] opacity-75"
          : "border-[#E3DDD2] hover:-translate-y-0.5"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-[#686D6B] !w-2 !h-2 !border-2 !border-white"
      />

      {/* Node Header */}
      <div className="flex items-center justify-between pb-1 mb-1.5 border-b border-[#E3DDD2]/60">
        <span
          className={`px-1.5 py-0.2 rounded font-mono text-[8.5px] font-bold uppercase tracking-wider ${style.badgeBg} ${style.badgeText}`}
        >
          {style.tag}
        </span>
        <div className="flex items-center gap-1">
          {isCompromised && (
            <span className="flex items-center text-[#E85D4A]" title="Compromised Identity">
              <AlertCircle className="w-3.5 h-3.5 text-[#E85D4A]" />
            </span>
          )}
          {isCrownJewel && (
            <span className="flex items-center text-[#C88D22]" title="Crown Jewel">
              <ShieldCheck className="w-3.5 h-3.5 text-[#C88D22]" />
            </span>
          )}
          <Icon className={`w-3.5 h-3.5 ${style.badgeText}`} />
        </div>
      </div>

      {/* Node Title */}
      <div className="font-sans text-[12px] text-[#282B2A] font-bold leading-tight line-clamp-2" title={name}>
        {name}
      </div>

      {/* ID Chip & State Badge */}
      <div className="flex items-center gap-1 mt-1 flex-wrap">
        <span className="font-mono text-[9px] text-[#686D6B] bg-[#FAF7F0] px-1 rounded border border-[#E3DDD2]/60 truncate max-w-[100px]">
          {id}
        </span>
        {isCompromised && (
          <span className="font-mono text-[8.5px] text-[#E85D4A] font-semibold bg-[#FDF2F0] px-1 rounded border border-[#E85D4A]/25">
            Compromised
          </span>
        )}
        {properties?.is_internet_facing && (
          <span className="font-mono text-[8.5px] text-[#E85D4A] font-semibold bg-[#FDF2F0] px-1 rounded border border-[#E85D4A]/25">
            Public IP
          </span>
        )}
        {properties?.is_privileged && (
          <span className="font-mono text-[8.5px] text-[#7C5CBF] font-semibold bg-[#F6F3FB] px-1 rounded border border-[#7C5CBF]/20">
            Privileged
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-[#E85D4A] !w-2 !h-2 !border-2 !border-white"
      />
    </div>
  );
});

CustomEntityNode.displayName = "CustomEntityNode";
