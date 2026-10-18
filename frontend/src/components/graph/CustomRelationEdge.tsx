"use client";

import React, { memo } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  EdgeProps,
} from "@xyflow/react";
import { formatRelationshipLabel } from "@/lib/types";

export interface CustomEdgeData {
  relType: string;
  sourceId: string;
  targetId: string;
  isPrimary?: boolean;
  isAlternative?: boolean;
  isSevered?: boolean;
  isInspected?: boolean;
  label?: string;
  subLabel?: string;
  hopNumber?: number;
  properties?: Record<string, any>;
}

export const CustomRelationEdge = memo(
  ({
    id: _id,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    style = {},
    markerEnd,
    data,
  }: EdgeProps<any>) => {
    const [edgePath, labelX, labelY] = getBezierPath({
      sourceX,
      sourceY,
      sourcePosition,
      targetPosition,
      targetX,
      targetY,
    });

    const edgeData: CustomEdgeData = data || {
      relType: "CONNECTS",
      sourceId: "",
      targetId: "",
    };
    const { relType, isPrimary, isAlternative, isSevered, isInspected, subLabel } = edgeData;

    let strokeColor = "#E3DDD2";
    let strokeWidth = 2;
    let strokeDasharray: string | undefined = undefined;

    if (isSevered) {
      strokeColor = "#32877A";
      strokeDasharray = "6 4";
      strokeWidth = 2.5;
    } else if (isInspected) {
      strokeColor = "#E85D4A";
      strokeWidth = 3.5;
    } else if (isPrimary) {
      strokeColor = "#E85D4A";
      strokeWidth = 3;
    } else if (isAlternative) {
      strokeColor = "#D99A28";
      strokeDasharray = "5 5";
      strokeWidth = 2;
    }

    const formattedLabel = formatRelationshipLabel(relType);

    return (
      <>
        <BaseEdge
          path={edgePath}
          markerEnd={markerEnd}
          style={{
            ...style,
            stroke: strokeColor,
            strokeWidth,
            strokeDasharray,
            filter: isInspected
              ? "drop-shadow(0 0 6px rgba(232, 93, 74, 0.65))"
              : undefined,
          }}
        />

        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: "all",
            }}
            className="nodrag nopan whitespace-nowrap"
            title={`${formattedLabel} (${relType})`}
          >
            {isInspected && (
              <div className="flex items-center justify-center mb-1">
                <span className="px-1.5 py-0.2 rounded-full bg-[#282B2A] text-white font-mono text-[8px] font-bold uppercase tracking-wider border border-[#E85D4A] shadow-md flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#E85D4A] animate-ping" />
                  <span>Inspected Hop</span>
                </span>
              </div>
            )}
            {isSevered ? (
              <div className="px-2 py-0.5 rounded bg-white text-[#32877A] border border-[#32877A] flex flex-col items-center shadow-sm font-mono text-[9px] font-bold whitespace-nowrap">
                <span className="line-through opacity-70">{formattedLabel}</span>
                <span className="text-[8px] text-[#32877A] font-extrabold uppercase tracking-tight">
                  REVOKED ✕
                </span>
              </div>
            ) : isPrimary ? (
              <div className="bg-[#E85D4A] text-white px-2 py-0.5 rounded shadow-sm text-center border border-[#D44C3A] whitespace-nowrap">
                <span className="font-sans text-[9px] font-bold block whitespace-nowrap">
                  {formattedLabel}
                </span>
                {subLabel && (
                  <span className="font-mono text-[7.5px] text-white/90 block whitespace-nowrap">
                    {subLabel}
                  </span>
                )}
              </div>
            ) : isAlternative ? (
              <div className="bg-white border border-[#D99A28]/70 px-2 py-0.5 rounded shadow-sm text-center whitespace-nowrap">
                <span className="font-sans text-[9px] text-[#D99A28] font-bold block whitespace-nowrap">
                  {formattedLabel}
                </span>
                {subLabel && (
                  <span className="font-mono text-[7.5px] text-[#686D6B] block whitespace-nowrap">
                    {subLabel}
                  </span>
                )}
              </div>
            ) : (
              <div className="bg-white border border-[#E3DDD2] px-1.5 py-0.5 rounded shadow-xs text-center whitespace-nowrap">
                <span className="font-sans text-[8.5px] text-[#686D6B] font-semibold block whitespace-nowrap">
                  {formattedLabel}
                </span>
              </div>
            )}
          </div>
        </EdgeLabelRenderer>
      </>
    );
  }
);

CustomRelationEdge.displayName = "CustomRelationEdge";
