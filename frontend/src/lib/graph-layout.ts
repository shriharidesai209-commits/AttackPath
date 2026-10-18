import dagre from "dagre";
import { Node, Edge, Position } from "@xyflow/react";

const NODE_WIDTH = 220;
const NODE_HEIGHT = 100;

export function getLayoutedElements(
  nodes: Node[],
  edges: Edge[],
  direction: "LR" | "TB" = "LR"
): { nodes: Node[]; edges: Edge[] } {
  if (!nodes || nodes.length === 0) {
    return { nodes: [], edges: [] };
  }

  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph({
    rankdir: direction,
    nodesep: 60,
    ranksep: 140,
    marginx: 30,
    marginy: 30,
  });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes: Node[] = nodes.map((node, index) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    const posX =
      nodeWithPosition && typeof nodeWithPosition.x === "number"
        ? nodeWithPosition.x - NODE_WIDTH / 2
        : index * (NODE_WIDTH + 60);
    const posY =
      nodeWithPosition && typeof nodeWithPosition.y === "number"
        ? nodeWithPosition.y - NODE_HEIGHT / 2
        : 100;

    return {
      ...node,
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
      targetPosition: direction === "LR" ? Position.Left : Position.Top,
      sourcePosition: direction === "LR" ? Position.Right : Position.Bottom,
      position: {
        x: posX,
        y: posY,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}
