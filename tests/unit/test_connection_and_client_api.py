"""Unit tests for FalkorDB client API validation, connection errors, and security masking."""

import pytest
from attackpath.config import Settings
from attackpath.database.connection import (
    FalkorDBConnectionError,
    create_falkordb_client,
    ping_falkordb,
    validate_falkordb_client_api,
)


def test_falkordb_client_api_runtime_validation():
  """Validates that the installed falkordb library exposes all required classes and methods."""
  api_info = validate_falkordb_client_api()

  assert api_info["client_api_validated"] is True
  assert "falkordb_package_version" in api_info
  assert api_info["falkordb_package_version"].startswith("1.")

  # Verify declared method contracts
  assert "query" in api_info["graph_methods"]
  assert "ro_query" in api_info["graph_methods"]
  assert "copy" in api_info["graph_methods"]
  assert "delete" in api_info["graph_methods"]

  assert "nodes" in api_info["path_methods"]
  assert "edges" in api_info["path_methods"]
  assert "node_count" in api_info["path_methods"]
  assert "edge_count" in api_info["path_methods"]


def test_connection_failure_raises_falkordb_connection_error(clean_env):
  """Verify that attempting to connect to an unreachable host raises FalkorDBConnectionError."""
  # Point to a definitely closed/unreachable local port
  settings = Settings(
      FALKORDB_HOST="127.0.0.1",
      FALKORDB_PORT=65432,  # Arbitrary closed port
      FALKORDB_PASSWORD="super_secret_password_do_not_leak",
      FALKORDB_TIMEOUT_MS=1000,
  )

  with pytest.raises(FalkorDBConnectionError) as exc_info:
    create_falkordb_client(settings)

  err = exc_info.value
  err_msg = str(err)

  # Security assertions: password MUST NOT leak in exception message
  assert "super_secret_password_do_not_leak" not in err_msg
  assert "***@" in err.diagnostic_uri
  assert "127.0.0.1:65432" in err.diagnostic_uri


def test_ping_falkordb_handles_error():
  """Verify that ping_falkordb safely catches exceptions and returns False."""
  # Create a mock object that raises on list_graphs
  class BrokenClient:
    def list_graphs(self):
      raise ConnectionError("Simulated socket drop")

  assert ping_falkordb(BrokenClient()) is False  # type: ignore[arg-type]
