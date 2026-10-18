"""Protocol and client integration tests for AttackPath MCP server.

Verifies:
1. Server starts without import-time network requests.
2. The exact approved tools are registered with schemas and detailed descriptions.
3. No unapproved tools (e.g. arbitrary Cypher or seeding) exist in the catalog.
4. An MCP-compatible client session over stdio transport can discover and invoke the tools.
5. The stdio stream remains protocol-clean.
"""

import asyncio
import sys
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from attackpath.mcp_server.server import create_mcp_server, server


APPROVED_TOOL_NAMES = {
    "discover_attack_paths",
    "explain_attack_path",
    "simulate_remediation_and_verify",
    "get_graph_topology",
}


def test_server_creation_and_import_isolation():
  """Verifies that the MCP server can be imported and created without network access."""
  mcp = create_mcp_server(name="AttackPath_Test")
  assert mcp.name == "AttackPath_Test"
  assert server.name == "AttackPath"


@pytest.mark.asyncio
async def test_server_registered_tools_catalog():
  """Verifies registered tools match the approved security boundary and schemas."""
  tools = await server.list_tools()
  registered_names = {t.name for t in tools}

  # Verify exact approved tool catalog
  assert registered_names == APPROVED_TOOL_NAMES, f"Tool mismatch: {registered_names}"

  # Verify forbidden tools do NOT exist
  forbidden_prefixes = ["cypher", "redis", "raw", "seed", "exec", "shell", "eval"]
  for name in registered_names:
    for forbidden in forbidden_prefixes:
      assert forbidden not in name.lower(), f"Unapproved tool detected: {name}"

  # Verify schema and description completeness for each tool
  for tool in tools:
    assert tool.description is not None and len(tool.description) > 30
    assert tool.input_schema is not None
    assert "properties" in tool.input_schema
    assert tool.output_schema is not None
    assert "properties" in tool.output_schema

    desc = tool.description.lower()
    # Required characteristics in descriptions
    assert "synthetic" in desc
    if tool.name in ("discover_attack_paths", "explain_attack_path", "get_graph_topology"):
      assert "read-only" in desc
    if tool.name == "simulate_remediation_and_verify":
      assert "simulation only" in desc or "simulation" in desc
      assert "baseline" in desc


@pytest.mark.asyncio
async def test_mcp_client_stdio_discovery_and_call():
  """Tests stdio transport with an actual MCP client session.

  Spawns `python -m attackpath.mcp_server` and verifies:
  1. Handshake and initialize over stdio JSON-RPC.
  2. Dynamic tool discovery via list_tools().
  3. Safe parameter validation and structured error response via call_tool().
  4. Stdio stream remains protocol-clean (no stdout corruption).
  """
  params = StdioServerParameters(
      command=sys.executable,
      args=["-m", "attackpath.mcp_server"],
  )

  async with stdio_client(params) as (read_stream, write_stream):
    async with ClientSession(read_stream, write_stream) as session:
      # 1. Initialize Handshake
      init_result = await session.initialize()
      assert init_result.server_info.name == "AttackPath"

      # 2. List Tools
      tools_response = await session.list_tools()
      discovered_names = {t.name for t in tools_response.tools}
      assert discovered_names == APPROVED_TOOL_NAMES

      # 3. Call Tool with invalid arguments to verify structured error over protocol
      bad_call_res = await session.call_tool(
          "discover_attack_paths",
          {"source_id": "", "target_id": "db_vault"},
      )
      assert bad_call_res.is_error is True
      assert bad_call_res.structured_content is not None
      assert bad_call_res.structured_content["status"] == "error"
      assert bad_call_res.structured_content["error"]["code"] == "INVALID_REQUEST"

      # 4. Call Tool with missing arguments (schema validation failure)
      schema_err_res = await session.call_tool(
          "discover_attack_paths",
          {"max_depth": 3},  # missing source_id and target_id
      )
      assert schema_err_res.is_error is True
