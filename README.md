# AttackPath: Graph-Powered Security Investigation Platform

> **WeMakeDevs FalkorDB Graph Hacks (October 15–18, 2026)**<br />
> Multi-hop attack path discovery, evidence explanation, isolated remediation simulation, and post-remediation verification using FalkorDB.

---

## 1. Overview & Core Workflow

AttackPath is a graph-driven cybersecurity investigation platform designed to answer four critical analyst questions:
1. **How could an attacker move from an initial compromised identity to a sensitive crown-jewel resource?**
2. **Which relationships and permissions enable that path?**
3. **What remediation would interrupt the path?**
4. **After simulating the remediation on an isolated graph snapshot, does the attack path still exist, and what alternative routes remain?**

### The Core Loop
$$\textbf{DISCOVER} \longrightarrow \textbf{EXPLAIN} \longrightarrow \textbf{REMEDIATE} \longrightarrow \textbf{VERIFY}$$

---

## 2. Architecture & Technology Stack

- **Graph Engine**: [FalkorDB](https://www.falkordb.com/) — GraphBLAS-powered graph database utilizing bounded openCypher queries (`*1..6`).
- **Backend API**: Python 3.12 + FastAPI + Pydantic v2.
- **Investigation Agent & MCP**: FastMCP exposing bounded, grounded security tools (`discover_attack_paths`, `inspect_evidence`, `simulate_and_verify_remediation`).
- **Analyst Frontend**: Streamlit with interactive Vis.js graph canvas, selected path inspector, and Before/After verification diffs.
- **Offline Testing**: NetworkX adapter strictly for local test fixtures when disconnected from FalkorDB.

---

## 3. Project Structure

```
AttackPath/
├── .env.example                  # Template configuration without secrets
├── .gitignore                    # Git exclusions (venv, .env, __pycache__)
├── pyproject.toml                # Project packaging & pytest configuration
├── requirements.txt              # Pinned core dependencies
├── README.md                     # Architecture, runbook, and verification guide
│
├── attackpath/                   # Main Application Package
│   ├── __init__.py
│   ├── config.py                 # Pydantic Settings & environment validation
│   │
│   ├── database/                 # Graph Storage Layer
│   │   ├── __init__.py
│   │   ├── connection.py         # FalkorDB client lifecycle (Milestone 2)
│   │   ├── repository.py         # Cypher execution & snapshot methods (Milestone 2)
│   │   └── seeder.py             # Synthetic benchmark scenario seeder (Milestone 2)
│   │
│   ├── domain/                   # Domain Models
│   │   ├── __init__.py
│   │   ├── entities.py           # Identity, Workload, Role, DataAsset models (Milestone 2)
│   │   └── path.py               # AttackPath, Edge, RiskScore models (Milestone 2)
│   │
│   ├── services/                 # Core Business Logic
│   │   ├── __init__.py
│   │   ├── discovery.py          # Bounded Cypher traversal engine (Milestone 3)
│   │   ├── evidence.py           # Telemetry enrichment (Milestone 3)
│   │   └── remediation.py        # Isolated simulate-and-verify engine (Milestone 3)
│   │
│   ├── api/                      # FastAPI Application
│   │   ├── __init__.py
│   │   ├── main.py               # API app, lifespan, CORS (Milestone 4)
│   │   └── routes/               # API endpoints (Milestone 4)
│   │
│   └── mcp_server/               # Model Context Protocol (Milestone 5)
│       ├── __init__.py           # Package exports
│       ├── __main__.py           # Executable entrypoint (`python -m attackpath.mcp_server`)
│       ├── server.py             # FastMCP/MCPServer factory & stdio runner
│       ├── tools.py              # Approved security tools & response envelopes
│       └── dependencies.py       # Pluggable dependency injection container
│
├── ui/                           # Streamlit Analyst Console (Milestone 6)
│   ├── __init__.py
│   └── app.py                    # Streamlit console (Milestone 6)
│
└── tests/                        # Automated Test Suite
    ├── __init__.py
    ├── conftest.py               # Test fixtures and clean environment overrides
    ├── adapters/
    │   └── networkx_test_adapter.py      # In-memory adapter for offline unit testing
    ├── unit/                     # Unit test suites
    │   ├── test_config.py
    │   ├── test_project_setup.py
    │   ├── test_domain_models.py
    │   ├── test_connection_and_client_api.py
    │   ├── test_discovery_service.py
    │   ├── test_evidence_service.py
    │   ├── test_risk_service.py
    │   ├── test_remediation_service.py
    │   ├── test_repository_path_deserialization.py
    │   ├── test_seeder_offline.py
    │   ├── test_api_health.py
    │   ├── test_api_graph.py
    │   ├── test_api_paths.py
    │   ├── test_api_investigate.py
    │   ├── test_api_remediate.py
    │   ├── test_api_error_handling_and_security.py
    │   ├── test_mcp_tools.py             # MCP tools unit test suite (Milestone 5)
    │   └── test_mcp_server_protocol.py   # MCP protocol & stdio client test suite (Milestone 5)
    └── integration/              # Live FalkorDB integration test suites
        ├── test_falkordb_live.py
        ├── test_services_falkordb_live.py
        ├── test_api_falkordb_live.py
        └── test_mcp_falkordb_live.py     # Live FalkorDB MCP test suite (Milestone 5)
```

---

## 4. Quickstart & Setup

### Prerequisites
- Python 3.12 (e.g. `py -3.12`)
- FalkorDB instance (FalkorDB Cloud or self-hosted)

### 1. Initialize Virtual Environment
```bash
py -3.12 -m venv venv
.\venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your FalkorDB host, port, and credentials
```

### 4. Run Automated Test Suite
```bash
pytest -v
```

---

## 5. Security Principles
- **No Secrets in Source Control**: Credentials are exclusively read from environment variables; `.env` is ignored by git.
- **Diagnostic URI Masking**: Connection strings displayed in logs or diagnostics mask all credentials (`rediss://***@host:port/graph`).
- **Baseline Immutability**: The canonical graph `attackpath_baseline` is read-only during what-if analysis; mutations occur exclusively on ephemeral clones (`attackpath_sim_{uuid}`).
- **Bounded Traversals**: All path discovery Cypher queries are strictly bounded (`*1..6`) and parameterized.

---

## 6. Model Context Protocol (MCP) Server Integration (Milestone 5)

AttackPath exposes an MCP-compliant server using the official Python MCP SDK (`FastMCP`/`MCPServer` interface) operating over standard I/O (`stdio`). This allows AI investigation clients to query graph topology, discover attack vectors, review fact-grounded evidence and risk scores, and simulate remediation safely.

### Architecture & Service Decoupling

- **Unified Application Core**: The MCP server and the FastAPI backend reuse the exact same deterministic services (`DiscoveryService`, `EvidenceService`, `RiskPrioritizationService`, `RemediationService`), repository layer (`FalkorDBRepository`), domain models, and configuration (`Settings`).
- **Independent Lifecycles**: The MCP server starts independently without running FastAPI or uvicorn. Starting the MCP server does not start the web server.
- **Lazy Connectivity**: Graph database connections are initiated on-demand when tools execute; importing `attackpath.mcp_server` makes zero network requests.
- **Clean Transport Protocol**: Operational logs are routed exclusively to `sys.stderr`. Standard output (`sys.stdout`) remains strictly dedicated to clean JSON-RPC protocol frames, preventing stream corruption.
- **Strict Security Boundaries**:
  - No arbitrary Cypher execution tool.
  - No raw Redis command tool.
  - No unrestricted graph name selection (only the configured baseline graph is queried).
  - No arbitrary filesystem or shell access.
  - No real-world infrastructure mutations (no real cloud IAM changes or firewall edits).

### Registered MCP Tools

| Tool Name | Operation Type | Purpose | Inputs |
| :--- | :--- | :--- | :--- |
| `discover_attack_paths` | Read-Only | Discovers directed, bounded attack routes from source identity to target data asset. | `source_id` (str), `target_id` (str), `max_depth` (1-6, default 6), `limit` (1-50, default 10) |
| `explain_attack_path` | Read-Only | Extracts ordered node/edge evidence, provenance labels, and deterministic risk prioritization. | `source_id` (str), `target_id` (str), `max_depth` (1-6, default 6), `limit` (1-50, default 10) |
| `simulate_remediation_and_verify` | Isolated Simulation | Safely clones baseline graph, revokes directed edge in clone, recalculates residual paths, and verifies severance. | `source_id` (str), `rel_type` (str), `target_id` (str), `path_source_id` (opt str), `path_target_id` (opt str), `max_depth` (1-6), `limit` (1-50) |
| `get_graph_topology` | Read-Only | Returns full graph topology (nodes, directed edges, attributes, and total counts) for the baseline graph. | None |

### Starting the MCP Server

From the project root using the activated virtual environment:

```bash
python -m attackpath.mcp_server
```

Or programmatically:

```python
from attackpath.mcp_server.server import main
main()
```

### Connecting an MCP Client

Compatible MCP clients can connect to AttackPath via `stdio`. Example client configuration template (use placeholders or environment variables for credentials):

```json
{
  "mcpServers": {
    "attackpath": {
      "command": "python",
      "args": ["-m", "attackpath.mcp_server"],
      "cwd": "E:\\AttackPath",
      "env": {
        "FALKORDB_HOST": "${FALKORDB_HOST}",
        "FALKORDB_PORT": "6379",
        "FALKORDB_PASSWORD": "${FALKORDB_PASSWORD}",
        "FALKORDB_SSL": "true",
        "FALKORDB_BASELINE_GRAPH": "attackpath_baseline"
      }
    }
  }
}
```

### Running MCP Tests

```bash
# 1. Run offline MCP tool unit tests (in-memory NetworkX adapter)
pytest tests/unit/test_mcp_tools.py -v

# 2. Run MCP protocol and stdio client integration tests
pytest tests/unit/test_mcp_server_protocol.py -v

# 3. Run live FalkorDB Cloud MCP integration tests
pytest tests/integration/test_mcp_falkordb_live.py -v

# 4. Run the entire test suite (127 tests)
pytest -v
```

### Important Disclaimers & Limitations

1. **Synthetic Data**: All identities (`usr_jdoe`), workloads (`srv_app_prod`), IAM roles (`role_order_service`), and data assets (`db_customer_vault`) are synthetic demonstration artifacts designed for security benchmark modeling.
2. **Prioritization Heuristic Disclaimer**: Risk scores (0–100) and tiers (`CRITICAL`, `PRIORITY`, `MONITOR`, `INFORMATIONAL`) generated by `explain_attack_path` are deterministic analyst prioritization heuristics based on weighted graph facts. They are **NOT** statistical probabilities of compromise or machine-learning predictions.
3. **Simulation Boundaries**: `simulate_remediation_and_verify` operates strictly on ephemeral FalkorDB graph clones (`attackpath_baseline_sim_*`). It does **NOT** alter real-world cloud IAM policies, credentials, or firewall configurations.
4. **Traversal Bounds**: Traversal depth is strictly capped at a maximum of 6 hops (`*1..6`) and 50 paths to guarantee bounded query latency on FalkorDB.
