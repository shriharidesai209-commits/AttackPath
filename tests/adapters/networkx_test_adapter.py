"""STRICTLY AN EXPLICIT OFFLINE UNIT TEST ADAPTER.

This adapter provides an in-memory NetworkX implementation of the graph repository
interface solely for offline unit testing in isolated test suites.

WARNING:
- NEVER import or use this adapter in production services or API routes.
- The platform MUST NEVER silently fall back to this adapter when FalkorDB is unreachable.
"""

from typing import Any, Dict, List, Optional
import networkx as nx
from attackpath.database.seeder import (
    SYNTHETIC_NODES,
    SYNTHETIC_RELATIONSHIPS,
)
from attackpath.domain.entities import BaseEntityNode
from attackpath.domain.path import AttackPath, GraphEdge


class NetworkXTestAdapter:
  """Explicit in-memory graph adapter used solely for offline unit test execution."""

  def __init__(self, graph_name: str = "offline_test_graph"):
    self.graph_name = graph_name
    self.g = nx.MultiDiGraph()

  def count_nodes(self) -> int:
    return self.g.number_of_nodes()

  def count_edges(self) -> int:
    return self.g.number_of_edges()

  def clear_graph(self) -> None:
    self.g.clear()

  def seed_synthetic_scenario(self, clean_first: bool = True) -> Dict[str, int]:
    if clean_first:
      self.clear_graph()

    for label, node_id, name, props in SYNTHETIC_NODES:
      node_attrs = {"id": node_id, "name": name, "label": label, **props}
      self.g.add_node(node_id, **node_attrs)

    for src_id, rel_type, dst_id, props in SYNTHETIC_RELATIONSHIPS:
      # In NetworkX MultiDiGraph, key distinguishes multiple edges between same pair
      edge_key = f"{src_id}_{rel_type}_{dst_id}"
      edge_attrs = {"source": src_id, "target": dst_id, "type": rel_type, **props}
      self.g.add_edge(src_id, dst_id, key=edge_key, **edge_attrs)

    return {
        "nodes_created": len(SYNTHETIC_NODES),
        "relationships_created": len(SYNTHETIC_RELATIONSHIPS),
        "total_nodes": self.count_nodes(),
        "total_edges": self.count_edges(),
    }

  def find_paths(
      self,
      source_id: str,
      target_id: str,
      max_depth: int = 6,
      limit: int = 10,
  ) -> List[AttackPath]:
    """Finds all simple paths up to max_depth hops, returning typed AttackPath objects."""
    if not self.g.has_node(source_id) or not self.g.has_node(target_id):
      return []

    raw_paths = []
    # Enumerate all simple paths bounded by cutoff=max_depth
    for path_node_ids in nx.all_simple_paths(self.g, source=source_id, target=target_id, cutoff=max_depth):
      raw_paths.append(path_node_ids)

    # Sort paths by hop count (shortest first)
    raw_paths.sort(key=len)
    raw_paths = raw_paths[:limit]

    result: List[AttackPath] = []
    for idx, node_ids in enumerate(raw_paths):
      nodes: List[BaseEntityNode] = []
      for nid in node_ids:
        attrs = dict(self.g.nodes[nid])
        nodes.append(
            BaseEntityNode(
                id=nid,
                label=attrs.get("label", "Entity"),
                name=attrs.get("name", nid),
                is_synthetic=attrs.get("is_synthetic", True),
                properties=attrs,
            )
        )

      edges: List[GraphEdge] = []
      for i in range(len(node_ids) - 1):
        u, v = node_ids[i], node_ids[i + 1]
        # Get the first edge connecting u and v
        edge_data = list(self.g.get_edge_data(u, v).values())[0]
        edges.append(
            GraphEdge(
                source=u,
                target=v,
                type=edge_data.get("type", "CONNECTED_TO"),
                properties=edge_data,
                is_synthetic=edge_data.get("is_synthetic", True),
            )
        )

      result.append(
          AttackPath(
              path_id=f"path_{idx + 1}",
              hop_count=len(edges),
              nodes=nodes,
              edges=edges,
              is_synthetic=True,
          )
      )

    return result

  def copy_graph(self, dest_name: str) -> "NetworkXTestAdapter":
    clone = NetworkXTestAdapter(graph_name=dest_name)
    clone.g = self.g.copy()
    return clone

  def create_clone_repository(self, clone_name: str) -> "NetworkXTestAdapter":
    return self.copy_graph(clone_name)

  def delete_graph(self) -> None:
    self.clear_graph()

  def get_node(self, node_id: str) -> Optional[BaseEntityNode]:
    """Retrieves a single node by its entity id."""
    if not self.g.has_node(node_id):
      return None
    attrs = dict(self.g.nodes[node_id])
    return BaseEntityNode(
        id=node_id,
        label=attrs.get("label", "Entity"),
        name=attrs.get("name", node_id),
        is_synthetic=attrs.get("is_synthetic", True),
        properties=attrs,
    )

  def find_relationships(
      self,
      source_id: str,
      rel_type: str,
      target_id: str,
  ) -> List[Dict[str, Any]]:
    """Finds directed relationships between source and target matching rel_type."""
    if not self.g.has_edge(source_id, target_id):
      return []
    edge_dict = self.g.get_edge_data(source_id, target_id)
    matches: List[Dict[str, Any]] = []
    for edge_key, attrs in edge_dict.items():
      if attrs.get("type") == rel_type:
        matches.append({"properties": dict(attrs), "rel_id": edge_key})
    return matches

  def delete_relationship(
      self,
      source_id: str,
      rel_type: str,
      target_id: str,
  ) -> int:
    """Deletes directed relationship(s) matching endpoints and rel_type."""
    if not self.g.has_edge(source_id, target_id):
      return 0
    edge_dict = dict(self.g.get_edge_data(source_id, target_id))
    deleted = 0
    for edge_key, attrs in edge_dict.items():
      if attrs.get("type") == rel_type:
        self.g.remove_edge(source_id, target_id, key=edge_key)
        deleted += 1
    return deleted

  def delete_relationship_by_id(self, rel_id: Any) -> int:
    """Deletes an exact relationship by its key/id."""
    for u, v, key in list(self.g.edges(keys=True)):
      if key == rel_id:
        self.g.remove_edge(u, v, key=key)
        return 1
    return 0

  def get_topology(self) -> Dict[str, Any]:
    """Retrieves full topology from graph: all nodes, relationships, and summary counts."""
    nodes: List[BaseEntityNode] = []
    for nid, attrs in self.g.nodes(data=True):
      nodes.append(
          BaseEntityNode(
              id=nid,
              label=attrs.get("label", "Entity"),
              name=attrs.get("name", nid),
              is_synthetic=attrs.get("is_synthetic", True),
              properties=dict(attrs),
          )
      )

    edges: List[GraphEdge] = []
    for u, v, key, attrs in self.g.edges(keys=True, data=True):
      edges.append(
          GraphEdge(
              source=u,
              target=v,
              type=attrs.get("type", "CONNECTED_TO"),
              properties=dict(attrs),
              is_synthetic=attrs.get("is_synthetic", True),
          )
      )

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }
