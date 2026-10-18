"""Model Context Protocol (MCP) server for AttackPath.

Exposes bounded graph discovery, evidence explanation, remediation simulation,
and graph topology inspection over stdio transport.
"""

import logging
import sys
from typing import Any

# FastMCP compatibility interface across MCP SDK versions
try:
  from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
  from mcp.server.mcpserver import MCPServer as FastMCP

from attackpath.mcp_server.tools import (
    discover_attack_paths,
    explain_attack_path,
    get_graph_topology,
    simulate_remediation_and_verify,
)


def configure_logging(level: int = logging.INFO) -> None:
  """Configures logging to write strictly to stderr to keep stdio transport clean."""
  handler = logging.StreamHandler(sys.stderr)
  handler.setFormatter(
      logging.Formatter(
          "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
          datefmt="%Y-%m-%d %H:%M:%S",
      )
  )
  root_logger = logging.getLogger()
  root_logger.setLevel(level)
  # Replace existing handlers on root logger if any to avoid stdout pollution
  root_logger.handlers = [handler]


def create_mcp_server(name: str = "AttackPath") -> Any:
  """Factory creating and configuring the AttackPath MCP server.

  Registers the four approved security tools:
  1. discover_attack_paths
  2. explain_attack_path
  3. simulate_remediation_and_verify
  4. get_graph_topology

  Note: Database connections are lazily initiated when tools are invoked,
  preventing import-time network requests.
  """
  mcp = FastMCP(name=name)

  # Register approved security tools
  mcp.tool()(discover_attack_paths)
  mcp.tool()(explain_attack_path)
  mcp.tool()(simulate_remediation_and_verify)
  mcp.tool()(get_graph_topology)

  return mcp


# Module-level server instance
server = create_mcp_server()


def main() -> None:
  """Entrypoint to launch the MCP server over stdio transport."""
  configure_logging()
  logger = logging.getLogger("attackpath.mcp_server")
  logger.info("Starting AttackPath MCP server over stdio transport")
  server.run("stdio")


if __name__ == "__main__":
  main()
