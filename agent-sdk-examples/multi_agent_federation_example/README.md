# Multi-Agent Federation Example — 6-Agent Enterprise Workflow

Demonstrates AetherGuard's identity federation with a 6-agent delegation chain, multi-hop token exchange, and sequential multi-tool execution within a single agent session.

## What This Shows

- **6-agent federation**: CoordinatorAgent → ResearchAgent → SecurityAgent → DataAnalysisAgent → ScriptingAgent, and ResearchAgent → ReportingAgent
- **5 delegation hops**: Each hop triggers RFC 8693 Token Exchange with nested `act` claim chains
- **Multi-tool execution**: DataAnalysisAgent executes 4-5 tools sequentially in one session (database_query → risk_assessment → data_transform → database_query → risk_assessment)
- **Sandboxed script execution**: ScriptingAgent runs Python scripts in a controlled sandbox environment
- **Scope reduction**: Each child agent's `permitted_tools` is a strict subset of its parent's tools
- **SPIFFE/SPIRE identity**: Each agent receives an X.509 SVID (or KMS-backed fallback) at session start
- **JIT tokens**: 5-minute KMS-signed JWTs bound to each session, validated on every tool call
- **Workflow audit trail**: All 6 sessions share a `workflow_id` enabling full delegation graph retrieval
- **Hybrid output scanning**: Every tool output passes through heuristic + ML scanning

## Architecture

```
User Request
    │
    ▼
┌────────────────────────────────────────┐
│  CoordinatorAgent (ROOT)               │
│  (coordinator-agent)                   │
│  Tools: web_search (+ superset)        │
│  Session: SVID + JIT Token             │
└────────────┬───────────────────────────┘
             │ Hop 1: Delegates research
             ▼
┌────────────────────────────────────────┐
│  ResearchAgent                         │
│  (research-agent)                      │
│  Tools: file_read, web_search          │
│  Session: Delegated JIT (depth=1)      │
└─────┬──────────────────────┬───────────┘
      │ Hop 2                │ Hop 4 (after analysis)
      ▼                      ▼
┌──────────────────┐  ┌──────────────────┐
│  SecurityAgent   │  │  ReportingAgent  │
│  (security-agent)│  │  (reporting-agent)│
│  Tools:          │  │  Tools:          │
│  security_       │  │  report_         │
│  validation      │  │  generation      │
│  Session: depth=2│  │  Session: depth=2│
└────────┬─────────┘  └──────────────────┘
         │ Hop 3
         ▼
┌────────────────────────────────────────┐
│  DataAnalysisAgent                     │
│  (data-analysis-agent)                 │
│  Tools: database_query,                │
│         risk_assessment,               │
│         data_transform, execute_script │
│  Session: Delegated JIT (depth=3)      │
│                                        │
│  Executes 4-5 tools sequentially:      │
│  1. database_query (Q3 metrics)        │
│  2. risk_assessment (anomaly check)    │
│  3. data_transform (aggregate)         │
│  4. database_query (Q2 comparison)     │
│  5. risk_assessment (final validation) │
└────────┬───────────────────────────────┘
         │ Hop 5
         ▼
┌────────────────────────────────────────┐
│  ScriptingAgent                        │
│  (scripting-agent)                     │
│  Tools: execute_script                 │
│  Session: Delegated JIT (depth=4)      │
│                                        │
│  Runs sandboxed Python scripts:        │
│  - process_metrics.py --quarter Q3     │
│  - Generates JSON/CSV artifacts        │
└────────────────────────────────────────┘
```

## Tool Execution vs Agent Delegation

| Concept | Mechanism | Example |
|---------|-----------|---------|
| **Tool Execution** | `evaluate_tool_call()` — single agent performs an action within its session | DataAnalysisAgent calls `database_query` |
| **Agent Delegation** | `start_session(parent_session_id=...)` — transfers responsibility to another agent via token exchange | Research delegates to Security |

## Running

```bash
# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install -e "../aetherguard-agent-security[remote]"
pip install crewai python-dotenv httpx

# Set environment variables (or use .env)
export AETHERGUARD_API_URL=http://localhost:8081
export AETHERGUARD_API_KEY=<your-api-key>
export OPENAI_API_KEY=sk-...

# Run
python main.py
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AETHERGUARD_API_URL` | `http://localhost:8081` | Backend API URL |
| `AETHERGUARD_API_KEY` | _(required)_ | API key for AetherGuard backend |
| `OPENAI_MODEL` | `gpt-4o` | LLM model |
| `OPENAI_API_KEY` | _(required)_ | OpenAI API key |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | LLM base URL |
| `AETHERGUARD_TENANT_ID` | `demo-tenant` | Tenant ID |
| `AETHERGUARD_TRUST_DOMAIN` | `aetherguard.ai` | SPIFFE trust domain |
| `AETHERGUARD_JIT_TOKEN_TTL` | `300` | JIT token lifetime (seconds) |
| `AETHERGUARD_MAX_DELEGATION_DEPTH` | `5` | Max delegation nesting |
| `AETHERGUARD_ML_SCAN` | `true` | Enable ML output scanning |

## Federation Flow

1. **Init**: AetherGuard initialized with `FederationConfig(federation_enabled=True, max_delegation_depth=5)`
2. **Register**: All 6 agents registered with `ensure_agent_profile()` (idempotent)
3. **Hop 0 — Coordinator Session**: Root session auto-provisions SVID + JIT token
4. **Hop 1 — Coordinator → Research**: Token exchange mints scope-reduced token for Research
5. **Hop 2 — Research → Security**: Security receives gatekeeper-scoped token (depth=2)
6. **Hop 3 — Security → DataAnalysis**: DataAnalysis receives analysis-scoped token (depth=3)
7. **Hop 4 — Research → Reporting**: Reporting receives report-only token (depth=2)
8. **Hop 5 — DataAnalysis → Scripting**: Scripting receives execute_script-only token (depth=4)
9. **Tool Execution**: Each tool call passes through AetherGuard's 8 security controls (C1-C8)
10. **Multi-Tool Chaining**: DataAnalysisAgent executes 4-5 tools sequentially in one session
11. **Script Execution**: ScriptingAgent runs sandboxed Python scripts for artifact generation
12. **Workflow Trace**: Full parent-child delegation graph available via `get_workflow_trace()`
13. **Cleanup**: All agents deregistered, connections closed

## Agents & Responsibilities

| Agent | Role | Tools | Delegates To |
|-------|------|-------|-------------|
| CoordinatorAgent | Root orchestrator | `web_search` | ResearchAgent |
| ResearchAgent | Data gathering | `file_read` | SecurityAgent, ReportingAgent |
| SecurityAgent | Gatekeeper | `security_validation` | DataAnalysisAgent |
| DataAnalysisAgent | Processing | `database_query`, `risk_assessment`, `data_transform` | ScriptingAgent |
| ScriptingAgent | Automation | `execute_script` | _(leaf)_ |
| ReportingAgent | Report generation | `report_generation` | _(leaf)_ |

## Expected Output

When run successfully, you will see:
- Federation setup with 6 sessions created (each with SVID + JIT token)
- Delegation chain printed showing all 5 hops
- AetherGuard security evaluation logs for each tool invocation
- DataAnalysisAgent executing 4-5 tools with individual evaluation logs
- ScriptingAgent executing Python scripts in sandbox
- Hybrid output scanning results (heuristic/ML)
- Final executive report
- Workflow trace showing the complete delegation graph with hash chain verification
