# Agent Federation Example — Multi-Agent Delegation

Demonstrates AetherGuard's identity federation and multi-agent delegation capabilities.

## What This Shows

- **SPIFFE/SPIRE identity**: Each agent receives an X.509 SVID (or KMS-backed fallback) at session start
- **JIT tokens**: 5-minute KMS-signed JWTs bound to each session, validated on every tool call
- **RFC 8693 Token Exchange**: When the orchestrator delegates to a sub-agent, `parent_session_id` triggers token exchange with nested `act` claim chains
- **Scope reduction**: The delegate agent's `permitted_tools` must be a subset of the parent's tools
- **Federation discovery**: Task types are matched to delegate agent capabilities at runtime
- **Workflow audit trail**: All sessions share a `workflow_id` enabling full delegation graph retrieval

## Architecture

```
User Request
    │
    ▼
┌───────────────────────────────┐
│  Orchestrator Agent           │
│  (orchestrator-agent-v1)      │
│  Tools: analyze_data,         │
│         delegate_export,      │
│         export_data           │
│  Session: SVID + JIT Token    │
└───────────┬───────────────────┘
            │ delegate_export triggers:
            │ 1. Federation discovery
            │ 2. Token exchange (RFC 8693)
            │ 3. Delegated session start
            ▼
┌───────────────────────────────┐
│  Data Export Agent            │
│  (data-export-agent-v1)       │
│  Tools: export_data           │  ← Scope reduced
│  Session: Delegated JIT Token │
│  Act Chain: [actor, delegator]│
└───────────────────────────────┘
```

## Running

```bash
# Install dependencies
pip install -e "../aetherguard-agent-security[remote]"
pip install crewai python-dotenv httpx

# Set environment variables (or use .env)
export AETHERGUARD_API_URL=http://localhost:8081
export AETHERGUARD_API_KEY=ag_test_key_12345
export OPENAI_API_KEY=sk-...

# Run
python main.py
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AETHERGUARD_API_URL` | `http://localhost:8081` | Backend API URL |
| `AETHERGUARD_API_KEY` | `ag_test_key_12345` | API key |
| `AETHERGUARD_PROXY_URL` | `http://localhost:8080/v1` | LLM proxy URL |
| `OPENAI_MODEL` | `gpt-4o` | LLM model |
| `AETHERGUARD_TENANT_ID` | `demo-tenant` | Tenant ID |
| `AETHERGUARD_TRUST_DOMAIN` | `aetherguard.io` | SPIFFE trust domain |
| `AETHERGUARD_JIT_TOKEN_TTL` | `300` | JIT token lifetime (seconds) |
| `AETHERGUARD_MAX_DELEGATION_DEPTH` | `5` | Max delegation nesting |
| `AETHERGUARD_ML_SCAN` | `true` | Enable ML output scanning |

## Federation Flow

1. **Init**: AetherGuard initialized with `FederationConfig(federation_enabled=True)`
2. **Register**: Both agents registered with `ensure_agent_profile()` (idempotent)
3. **Session Start**: Orchestrator session auto-provisions SVID + JIT token
4. **analyze_data**: Evaluated through C1-C8 with JIT token validation
5. **delegate_export**: Triggers federation discovery → token exchange → delegated session
6. **export_data**: Runs under delegate's scope-reduced session with delegated JIT token
7. **Workflow Trace**: Full parent-child delegation graph available via `get_workflow_trace()`
8. **Cleanup**: Agents deregistered, connections closed
