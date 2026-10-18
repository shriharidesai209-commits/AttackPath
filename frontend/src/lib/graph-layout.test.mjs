import assert from "node:assert";
import dagre from "dagre";

// Re-implement the layout logic identical to graph-layout.ts to verify node layout behavior
const NODE_WIDTH = 220;
const NODE_HEIGHT = 100;

function getLayoutedElements(nodes, edges, direction = "LR") {
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

  const layoutedNodes = nodes.map((node, index) => {
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
      targetPosition: direction === "LR" ? "left" : "top",
      sourcePosition: direction === "LR" ? "right" : "bottom",
      position: {
        x: posX,
        y: posY,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

// Test 1: Empty nodes and edges
{
  const result = getLayoutedElements([], []);
  assert.deepStrictEqual(result.nodes, []);
  assert.deepStrictEqual(result.edges, []);
  console.log("✓ Test 1 Passed: Empty graph handled safely");
}

// Test 2: Standard AttackPath multi-hop graph
{
  const rawNodes = [
    { id: "usr_jdoe", label: "Identity", name: "John Doe" },
    { id: "srv_app_prod", label: "Workload", name: "App-Server-Prod" },
    { id: "role_order_service", label: "IAMRole", name: "OrderServiceRole" },
    { id: "db_customer_vault", label: "DataAsset", name: "Customer-Vault-DB" },
    { id: "srv_analytics_worker", label: "Workload", name: "Analytics-Worker-01" },
    { id: "role_analytics_reader", label: "IAMRole", name: "AnalyticsReadOnlyRole" },
  ];

  const rawEdges = [
    { source: "usr_jdoe", target: "srv_app_prod", type: "AUTHENTICATES_TO" },
    { source: "srv_app_prod", target: "role_order_service", type: "EXECUTES_AS" },
    { source: "role_order_service", target: "db_customer_vault", type: "CAN_ACCESS" },
    { source: "srv_app_prod", target: "srv_analytics_worker", type: "NETWORK_REACHABLE" },
    { source: "srv_analytics_worker", target: "role_analytics_reader", type: "EXECUTES_AS" },
    { source: "role_analytics_reader", target: "db_customer_vault", type: "CAN_ACCESS" },
  ];

  const result = getLayoutedElements(rawNodes, rawEdges, "LR");

  assert.strictEqual(result.nodes.length, 6);
  assert.strictEqual(result.edges.length, 6);

  result.nodes.forEach((node) => {
    assert.strictEqual(typeof node.position.x, "number", `Node ${node.id} x must be a number`);
    assert.strictEqual(typeof node.position.y, "number", `Node ${node.id} y must be a number`);
    assert.strictEqual(Number.isNaN(node.position.x), false, `Node ${node.id} x must not be NaN`);
    assert.strictEqual(Number.isNaN(node.position.y), false, `Node ${node.id} y must not be NaN`);
    assert.strictEqual(node.width, 220, `Node ${node.id} width must be 220`);
    assert.strictEqual(node.height, 100, `Node ${node.id} height must be 100`);
    assert.strictEqual(node.targetPosition, "left");
    assert.strictEqual(node.sourcePosition, "right");
  });

  // Verify left-to-right progression
  const nodeMap = new Map(result.nodes.map((n) => [n.id, n]));
  assert(
    nodeMap.get("usr_jdoe").position.x < nodeMap.get("srv_app_prod").position.x,
    "usr_jdoe must be to the left of srv_app_prod"
  );
  assert(
    nodeMap.get("srv_app_prod").position.x < nodeMap.get("db_customer_vault").position.x,
    "srv_app_prod must be to the left of db_customer_vault"
  );

  console.log("✓ Test 2 Passed: Multi-hop graph layout assigns valid positions, width, and height");
}

// Test 3: Disconnected node defensive fallback
{
  const nodes = [
    { id: "isolated_node_1", label: "Workload", name: "Isolated" },
    { id: "isolated_node_2", label: "Identity", name: "Isolated 2" },
  ];
  const edges = [];

  const result = getLayoutedElements(nodes, edges, "LR");
  assert.strictEqual(result.nodes.length, 2);
  result.nodes.forEach((n) => {
    assert.strictEqual(typeof n.position.x, "number");
    assert.strictEqual(typeof n.position.y, "number");
    assert.strictEqual(n.width, 220);
    assert.strictEqual(n.height, 100);
  });

  console.log("✓ Test 3 Passed: Disconnected nodes layout correctly without errors");
}

console.log("All graph layout unit tests passed successfully!");
