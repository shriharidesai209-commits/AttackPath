"""Model Context Protocol (MCP) server package exposing controlled security tools."""

from attackpath.mcp_server.server import create_mcp_server, server
from attackpath.mcp_server.tools import (
    discover_attack_paths,
    explain_attack_path,
    get_graph_topology,
    simulate_remediation_and_verify,
)

__all__ = [
    "create_mcp_server",
    "server",
    "discover_attack_paths",
    "explain_attack_path",
    "simulate_remediation_and_verify",
    "get_graph_topology",
]
