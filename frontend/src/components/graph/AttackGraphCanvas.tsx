"use client";

import React, { useCallback, useMemo } from "react";
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

interface AttackGraphCanvasProps {
  initialNodes: Node[];
  initialEdges: Edge[];
  onNodeClick?: (nodeId: string) => void;
  onEdgeClick?: (edgeId: string) => void;
  height?: string;
  className?: string;
  showMinimap?: boolean;
}

function AutoFitOnResize() {
  const { fitView } = useReactFlow();

  React.useEffect(() => {
    let timeoutId: any;
    const handleResize = () => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => {
        fitView({ padding: 0.22, duration: 200 });
      }, 50);
    };
    window.addEventListener("resize", handleResize);
    return () => {
      window.removeEventListener("resize", handleResize);
      clearTimeout(timeoutId);
    };
  }, [fitView]);

  return null;
}

function FitViewOnNodesChange({ nodes }: { nodes: Node[] }) {
  const { fitView } = useReactFlow();
  const prevCount = React.useRef(0);

  React.useEffect(() => {
    if (nodes.length > 0 && nodes.length !== prevCount.current) {
      prevCount.current = nodes.length;
      const timer = setTimeout(() => {
        fitView({ padding: 0.22, duration: 250 });
      }, 60);
      return () => clearTimeout(timer);
    }
  }, [nodes, fitView]);

  return null;
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
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  React.useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  React.useEffect(() => {
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
      style={{ height: height || "100%" }}
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
        minZoom={0.2}
        maxZoom={2.0}
        proOptions={{ hideAttribution: true }}
      >
        <FitViewOnNodesChange nodes={nodes} />
        <AutoFitOnResize />
        {/* Warm Dotted Grid Background */}
        <Background color="#C8C0B2" gap={24} size={1.2} />

        {/* Canvas Controls */}
        <Controls
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
