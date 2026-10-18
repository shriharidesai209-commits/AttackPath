"""FalkorDB database connection lifecycle, diagnostics, and client factory."""

import logging
from typing import Any, Dict, Optional
import falkordb
import redis.exceptions
from attackpath.config import Settings, get_settings


logger = logging.getLogger("attackpath.database.connection")


class FalkorDBConnectionError(Exception):
  """Raised when connection to FalkorDB fails or is refused."""

  def __init__(self, message: str, diagnostic_uri: str, original_error: Optional[Exception] = None):
    self.diagnostic_uri = diagnostic_uri
    self.original_error = original_error
    super().__init__(f"{message} (Connection URI: {diagnostic_uri})")


def validate_falkordb_client_api() -> Dict[str, Any]:
  """Introspects and validates the installed FalkorDB Python client library.

  Ensures required methods and signatures are available at runtime.
  """
  from importlib.metadata import version

  pkg_version = version("falkordb")

  # Verify core classes exist
  for cls_name in ["FalkorDB", "Graph", "Path", "Node", "Edge"]:
    if not hasattr(falkordb, cls_name):
      raise RuntimeError(f"Missing required class '{cls_name}' in falkordb package")

  # Verify critical Graph methods exist
  graph_cls = falkordb.Graph
  for method_name in ["query", "ro_query", "copy", "delete"]:
    if not hasattr(graph_cls, method_name):
      raise RuntimeError(f"Missing required method '{method_name}' on falkordb.Graph")

  # Verify Path methods exist
  path_cls = falkordb.Path
  for method_name in ["nodes", "edges", "node_count", "edge_count"]:
    if not hasattr(path_cls, method_name):
      raise RuntimeError(f"Missing required method '{method_name}' on falkordb.Path")

  return {
      "falkordb_package_version": pkg_version,
      "client_api_validated": True,
      "graph_methods": ["query", "ro_query", "copy", "delete"],
      "path_methods": ["nodes", "edges", "node_count", "edge_count"],
  }


def create_falkordb_client(settings: Optional[Settings] = None) -> falkordb.FalkorDB:
  """Creates and returns a FalkorDB client instance configured from Settings.

  Raises FalkorDBConnectionError if the host is unreachable. Credentials are
  never leaked in exception messages or logs.
  """
  cfg = settings or get_settings()
  diagnostic_uri = cfg.falkordb_connection_uri
  timeout_sec = cfg.FALKORDB_TIMEOUT_MS / 1000.0

  try:
    logger.info("Initializing FalkorDB client connection to %s", diagnostic_uri)
    client = falkordb.FalkorDB(
        host=cfg.FALKORDB_HOST,
        port=cfg.FALKORDB_PORT,
        username=cfg.FALKORDB_USERNAME if cfg.FALKORDB_USERNAME else None,
        password=cfg.FALKORDB_PASSWORD if cfg.FALKORDB_PASSWORD else None,
        ssl=cfg.FALKORDB_SSL,
        socket_timeout=timeout_sec,
        socket_connect_timeout=timeout_sec,
    )
    return client
  except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, ConnectionRefusedError) as exc:
    logger.error("Failed to connect to FalkorDB at %s: %s", diagnostic_uri, exc)
    raise FalkorDBConnectionError(
        message="Unable to establish connection to FalkorDB instance",
        diagnostic_uri=diagnostic_uri,
        original_error=exc,
    ) from exc
  except Exception as exc:
    logger.error("Unexpected error connecting to FalkorDB at %s: %s", diagnostic_uri, exc)
    raise FalkorDBConnectionError(
        message="Unexpected error initializing FalkorDB client",
        diagnostic_uri=diagnostic_uri,
        original_error=exc,
    ) from exc


def ping_falkordb(client: falkordb.FalkorDB) -> bool:
  """Tests whether the connected FalkorDB instance is responsive."""
  try:
    # list_graphs is a lightweight command to verify active connection
    client.list_graphs()
    return True
  except Exception as exc:
    logger.warning("FalkorDB ping failed: %s", exc)
    return False
