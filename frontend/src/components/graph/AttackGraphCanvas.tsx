"use client";

import React, { useCallback, useMemo, useRef, useEffect } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  Node,
  Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CustomEntityNode } from "./CustomEntityNode";
import { CustomRelationEdge } from "./CustomRelationEdge";
import { Focus } from "lucide-react";

interface AttackGraphCanvasProps {
  initialNodes: Node[];
  initialEdges: Edge[];
  onNodeClick?: (nodeId: string) => void;
  onEdgeClick?: (edgeId: string) => void;
  height?: string;
  className?: string;
  showMinimap?: boolean;
}

function ViewportStabilizer({
  nodes,
  containerRef,
}: {
  nodes: Node[];
  containerRef: React.RefObject<HTMLDivElement | null>;
}) {
  const { fitView } = useReactFlow();
  const lastFingerprint = useRef("");

  // Re-fit when nodes change
  useEffect(() => {
    if (!nodes || nodes.length === 0) return;

    const fingerprint = `${nodes.length}:${nodes.map((n) => n.id).join(",")}`;
    if (fingerprint !== lastFingerprint.current) {
      lastFingerprint.current = fingerprint;

      // Immediate attempt
      requestAnimationFrame(() => {
        fitView({ padding: 0.22, duration: 200 });
      });

      // Secondary safety check once DOM measurements settle
      const timer = setTimeout(() => {
        fitView({ padding: 0.22, duration: 200 });
      }, 150);

      return () => clearTimeout(timer);
    }
  }, [nodes, fitView]);

  // Robust container-level ResizeObserver (handles inspector and drawer toggles)
  useEffect(() => {
    const el = containerRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;

    let resizeTimer: any;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.width > 50 && entry.contentRect.height > 50) {
          clearTimeout(resizeTimer);
          resizeTimer = setTimeout(() => {
            fitView({ padding: 0.22, duration: 150 });
          }, 80);
        }
      }
    });

    observer.observe(el);
    return () => {
      observer.disconnect();
      clearTimeout(resizeTimer);
    };
  }, [containerRef, fitView]);

  return null;
}

function CanvasHeaderControls() {
  const { fitView } = useReactFlow();

  return (
    <button
      type="button"
      onClick={() => fitView({ padding: 0.22, duration: 300 })}
      className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white border border-[#E3DDD2] text-[#282B2A] hover:bg-[#FAF7F0] hover:border-[#686D6B]/50 transition-all text-[11px] font-medium shadow-xs cursor-pointer"
      title="Re-center and fit graph to viewport"
    >
      <Focus className="w-3.5 h-3.5 text-[#32877A]" />
      <span>Re-center Graph</span>
    </button>
  );
}

export function AttackGraphCanvas({
  initialNodes,
  initialEdges,
  onNodeClick,
  onEdgeClick,
  height = "100%",
  className = "",
  showMinimap = false,
}: AttackGraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  useEffect(() => {
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

  const nodeTypes = useMemo(() => ({ entity: CustomEntityNode as any }), []);
  const edgeTypes = useMemo(() => ({ relation: CustomRelationEdge as any }), []);

  const handleNodeClick = useCallback(
    (_: any, node: Node) => {
      if (onNodeClick) onNodeClick(node.id);
    },
    [onNodeClick]
  );

  const handleEdgeClick = useCallback(
    (_: any, edge: Edge) => {
      if (onEdgeClick) onEdgeClick(edge.id);
    },
    [onEdgeClick]
  );

  return (
    <div
      ref={containerRef}
      style={{ height: height || "100%", minHeight: "350px" }}
      className={`relative w-full h-full bg-white rounded-xl border border-[#E3DDD2] shadow-[0_1px_3px_rgba(0,0,0,0.03)] overflow-hidden select-none ${className}`}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        onEdgeClick={handleEdgeClick}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.22, includeHiddenNodes: false }}
        defaultViewport={{ x: 0, y: 0, zoom: 0.85 }}
        minZoom={0.15}
        maxZoom={2.0}
        onlyRenderVisibleElements={false}
        proOptions={{ hideAttribution: true }}
      >
        <ViewportStabilizer nodes={nodes} containerRef={containerRef} />
        {/* Warm Dotted Grid Background */}
        <Background color="#C8C0B2" gap={24} size={1.2} />

        {/* Canvas Controls */}
        <Controls
          showZoom={true}
          showFitView={true}
          showInteractive={false}
          className="!bg-white !border !border-[#E3DDD2] !rounded-lg !shadow-sm !p-1"
        />

        {showMinimap && (
          <MiniMap
            nodeColor={(n) => {
              if (n.data?.label === "Identity") return "#32877A";
              if (n.data?.label === "Workload") return "#686D6B";
              if (n.data?.label === "IAMRole") return "#7C5CBF";
              if (n.data?.label === "DataAsset") return "#C88D22";
              return "#E3DDD2";
            }}
            maskColor="rgba(246, 242, 233, 0.7)"
            className="!bg-[#FAF7F0] !border !border-[#E3DDD2] !rounded-lg"
          />
        )}

        {/* Top-Right Quick Re-center Toolbar Action */}
        <div className="absolute top-4 right-4 z-20">
          <CanvasHeaderControls />
        </div>
      </ReactFlow>

      {/* Floating Legend Badge at Bottom Left */}
      <div className="absolute bottom-4 left-4 z-20 bg-white/95 backdrop-blur-md px-3 py-2 rounded-lg shadow-sm border border-[#E3DDD2] flex flex-wrap items-center gap-3.5 text-[11px] font-medium text-[#282B2A]">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#32877A]" />
          <span>Identity</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#686D6B]" />
          <span>Workload</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#7C5CBF]" />
          <span>Role Pivot</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#C88D22] animate-pulse" />
          <span className="text-[#C88D22] font-semibold">Protected Target</span>
        </div>
        <div className="h-3 w-px bg-[#E3DDD2]" />
        <div className="flex items-center gap-1 text-[#E85D4A] font-medium">
          <span className="w-2.5 h-0.5 bg-[#E85D4A]" />
          <span>Primary</span>
        </div>
        <div className="flex items-center gap-1 text-[#D99A28] font-medium">
          <span className="w-2.5 h-0.5 border-t border-dashed border-[#D99A28]" />
          <span>Alternative</span>
        </div>
      </div>
    </div>
  );
}
