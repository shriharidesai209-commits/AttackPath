"""Repository for executing bounded, parameterized Cypher queries on FalkorDB."""

import logging
from typing import Any, Dict, List, Optional
import falkordb
from attackpath.domain.entities import BaseEntityNode
from attackpath.domain.path import AttackPath, GraphEdge


logger = logging.getLogger("attackpath.database.repository")


class FalkorDBRepository:
  """Encapsulates all graph operations and parameterized openCypher queries for a named graph key."""

  def __init__(self, client: falkordb.FalkorDB, graph_name: str = "attackpath_baseline"):
    self.client = client
    self.graph_name = graph_name
    self._graph = client.select_graph(graph_name)

  @property
  def graph(self) -> falkordb.Graph:
    """Returns the underlying FalkorDB Graph handle."""
    return self._graph

  def query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> falkordb.QueryResult:
    """Executes a parameterized Cypher write/read query on the graph."""
    return self._graph.query(cypher, params=params)

  def ro_query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> falkordb.QueryResult:
    """Executes a read-only parameterized Cypher query on the graph."""
    return self._graph.ro_query(cypher, params=params)

  def count_nodes(self) -> int:
    """Returns total node count in the current graph."""
    result = self.ro_query("MATCH (n) RETURN count(n) AS node_count")
    if result.result_set and len(result.result_set) > 0:
      return int(result.result_set[0][0])
    return 0

  def count_edges(self) -> int:
    """Returns total relationship count in the current graph."""
    result = self.ro_query("MATCH ()-[r]->() RETURN count(r) AS edge_count")
    if result.result_set and len(result.result_set) > 0:
      return int(result.result_set[0][0])
    return 0

  def clear_graph(self) -> None:
    """Idempotently clears all nodes and relationships from this graph."""
    self.query("MATCH (n) DETACH DELETE n")

  def copy_graph(self, destination_graph_name: str) -> None:
    """Duplicates this graph under a new key via FalkorDB native graph copy."""
    self._graph.copy(destination_graph_name)

  def create_clone_repository(self, clone_name: str) -> "FalkorDBRepository":
    """Creates a native FalkorDB copy of this graph and returns a repository pointing to it."""
    self.copy_graph(clone_name)
    return FalkorDBRepository(client=self.client, graph_name=clone_name)

  def delete_graph(self) -> None:
    """Deletes this graph from FalkorDB storage."""
    self._graph.delete()

  def get_node(self, node_id: str) -> Optional[BaseEntityNode]:
    """Retrieves a single node by its entity id property."""
    cypher = "MATCH (n {id: $node_id}) RETURN n, labels(n) AS labels LIMIT 1"
    result = self.ro_query(cypher, params={"node_id": node_id})
    if not result.result_set:
      return None
    raw_node = result.result_set[0][0]
    props = dict(raw_node.properties) if raw_node.properties else {}
    labels = result.result_set[0][1]
    label_str = labels[0] if isinstance(labels, list) and labels else (str(labels) if labels else "Entity")
    return BaseEntityNode(
        id=str(props.get("id", node_id)),
        label=label_str,
        name=str(props.get("name", node_id)),
        is_synthetic=bool(props.get("is_synthetic", True)),
        properties=props,
    )

  def find_relationships(
      self,
      source_id: str,
      rel_type: str,
      target_id: str,
  ) -> List[Dict[str, Any]]:
    """Finds directed relationships between source and target with exact type.

    Returns list of dicts with 'properties' and 'rel_id'.
    """
    cypher = """
        MATCH (src {id: $source_id})-[r]->(dst {id: $target_id})
        WHERE type(r) = $rel_type
        RETURN properties(r) AS props, id(r) AS rel_id
        """
    result = self.ro_query(
        cypher,
        params={"source_id": source_id, "rel_type": rel_type, "target_id": target_id},
    )
    matches: List[Dict[str, Any]] = []
    for row in result.result_set:
      props = dict(row[0]) if row[0] else {}
      rel_id = row[1]
      matches.append({"properties": props, "rel_id": rel_id})
    return matches

  def delete_relationship(
      self,
      source_id: str,
      rel_type: str,
      target_id: str,
  ) -> int:
    """Deletes matching directed relationship(s) and returns count of deleted edges."""
    cypher = """
        MATCH (src {id: $source_id})-[r]->(dst {id: $target_id})
        WHERE type(r) = $rel_type
        DELETE r
        """
    res = self.query(
        cypher,
        params={"source_id": source_id, "rel_type": rel_type, "target_id": target_id},
    )
    return int(getattr(res, "relationships_deleted", 0))

  def delete_relationship_by_id(self, rel_id: int) -> int:
    """Deletes an exact relationship by its internal ID and returns count of deleted edges."""
    cypher = """
        MATCH ()-[r]->()
        WHERE id(r) = $rel_id
        DELETE r
        """
    res = self.query(cypher, params={"rel_id": rel_id})
    return int(getattr(res, "relationships_deleted", 0))

  def get_topology(self) -> Dict[str, Any]:
    """Retrieves full topology from graph: all nodes, relationships, and summary counts."""
    node_cypher = "MATCH (n) RETURN n.id, labels(n), n.name, properties(n)"
    node_res = self.ro_query(node_cypher)
    nodes: List[BaseEntityNode] = []

    if node_res.result_set:
      for row in node_res.result_set:
        raw_id = row[0]
        labels_raw = row[1]
        name_raw = row[2]
        props = dict(row[3]) if row[3] else {}
        node_id = str(raw_id) if raw_id is not None else str(props.get("id", ""))
        node_label = (
            labels_raw[0]
            if isinstance(labels_raw, list) and labels_raw
            else (str(labels_raw) if labels_raw else "Entity")
        )
        node_name = str(name_raw) if name_raw is not None else str(props.get("name", node_id))
        is_synthetic = bool(props.get("is_synthetic", True))

        nodes.append(
            BaseEntityNode(
                id=node_id,
                label=node_label,
                name=node_name,
                is_synthetic=is_synthetic,
                properties=props,
            )
        )

    edge_cypher = "MATCH (src)-[r]->(dst) RETURN src.id, type(r), dst.id, properties(r)"
    edge_res = self.ro_query(edge_cypher)
    edges: List[GraphEdge] = []

    if edge_res.result_set:
      for row in edge_res.result_set:
        src_id = str(row[0])
        rel_type = str(row[1])
        dst_id = str(row[2])
        props = dict(row[3]) if row[3] else {}
        is_synthetic = bool(props.get("is_synthetic", True))

        edges.append(
            GraphEdge(
                source=src_id,
                target=dst_id,
                type=rel_type,  # type: ignore[arg-type]
                properties=props,
                is_synthetic=is_synthetic,
            )
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }

  @staticmethod
  def _resolve_endpoint(
      endpoint: Any,
      node_id_map: Dict[Any, str],
      fallback_id: str,
  ) -> str:
    """Resolves an edge endpoint (Node instance, internal numeric ID, or entity ID) to a stable entity ID."""
    if endpoint is None:
      return fallback_id

    # 1. Direct entity ID in node properties
    if (
        hasattr(endpoint, "properties")
        and isinstance(endpoint.properties, dict)
        and "id" in endpoint.properties
        and endpoint.properties["id"]
    ):
      return str(endpoint.properties["id"])

    # 2. Node object with internal ID attribute
    if hasattr(endpoint, "id") and endpoint.id is not None:
      internal_id = endpoint.id
      try:
        if internal_id in node_id_map:
          return node_id_map[internal_id]
        if str(internal_id) in node_id_map:
          return node_id_map[str(internal_id)]
      except TypeError:
        pass

    # 3. Direct internal numeric ID or entity ID key in mapping
    try:
      if endpoint in node_id_map:
        return node_id_map[endpoint]
      if str(endpoint) in node_id_map:
        return node_id_map[str(endpoint)]
    except TypeError:
      pass

    # 4. Fallback to path sequence identifier
    return fallback_id

  def find_paths(
      self,
      source_id: str,
      target_id: str,
      max_depth: int = 6,
      limit: int = 10,
  ) -> List[AttackPath]:
    """Discovers directed multi-hop attack paths from source_id to target_id.

    Strictly bounded up to max_depth hops (default 6) and parameterized.
    """
    if max_depth > 6:
      max_depth = 6
    if max_depth < 1:
      max_depth = 1

    # Bounded parameterized Cypher traversal
    cypher = f"""
        MATCH (src:Identity {{id: $source_id}}), (dst:DataAsset {{id: $target_id}})
        MATCH p = (src)-[*1..{max_depth}]->(dst)
        RETURN p, length(p) AS hop_count
        ORDER BY hop_count ASC
        LIMIT $limit
        """
    params = {"source_id": source_id, "target_id": target_id, "limit": limit}

    result = self.ro_query(cypher, params=params)
    attack_paths: List[AttackPath] = []

    for idx, row in enumerate(result.result_set):
      path_obj = row[0]
      if not isinstance(path_obj, falkordb.Path):
        continue

      parsed_nodes: List[BaseEntityNode] = []
      node_id_map: Dict[Any, str] = {}
      for raw_node in path_obj.nodes():
        props = dict(raw_node.properties) if raw_node.properties else {}
        node_id = str(props.get("id", raw_node.id))
        label_raw = raw_node.labels
        node_label = label_raw[0] if isinstance(label_raw, list) and label_raw else (str(label_raw) if label_raw else "Entity")
        node_name = str(props.get("name", node_id))
        is_synthetic = bool(props.get("is_synthetic", True))

        parsed_nodes.append(
            BaseEntityNode(
                id=node_id,
                label=node_label,
                name=node_name,
                is_synthetic=is_synthetic,
                properties=props,
            )
        )
        if hasattr(raw_node, "id") and raw_node.id is not None:
          node_id_map[raw_node.id] = node_id
          node_id_map[str(raw_node.id)] = node_id
        node_id_map[node_id] = node_id

      parsed_edges: List[GraphEdge] = []
      for edge_idx, raw_edge in enumerate(path_obj.edges()):
        edge_props = dict(raw_edge.properties) if raw_edge.properties else {}
        edge_rel = str(raw_edge.relation)

        fallback_src = (
            parsed_nodes[edge_idx].id
            if edge_idx < len(parsed_nodes)
            else str(raw_edge.src_node)
        )
        fallback_dst = (
            parsed_nodes[edge_idx + 1].id
            if edge_idx + 1 < len(parsed_nodes)
            else str(raw_edge.dest_node)
        )

        src_id = self._resolve_endpoint(raw_edge.src_node, node_id_map, fallback_src)
        dst_id = self._resolve_endpoint(raw_edge.dest_node, node_id_map, fallback_dst)
        is_synthetic = bool(edge_props.get("is_synthetic", True))

        parsed_edges.append(
            GraphEdge(
                source=src_id,
                target=dst_id,
                type=edge_rel,  # type: ignore[arg-type]
                properties=edge_props,
                is_synthetic=is_synthetic,
            )
        )

      attack_paths.append(
          AttackPath(
              path_id=f"path_{idx + 1}",
              hop_count=len(parsed_edges),
              nodes=parsed_nodes,
              edges=parsed_edges,
              is_synthetic=True,
          )
      )

    return attack_paths
