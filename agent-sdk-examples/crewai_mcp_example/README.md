# README.md

# AetherGuard + CrewAI + Secured MCP Demo

This project demonstrates a production-style integration between:

* CrewAI agents
* AetherGuard Agent Security SDK
* AetherGuard LLM Proxy
* AetherGuard secured MCP transport
* Real MCP server over stdio
* HITL approval flow
* Output scanning
* Tenant-aware security sessions

The demo contains 3 agents:

| Agent             | Tool                  | Security Behavior              |
| ----------------- | --------------------- | ------------------------------ |
| Data Analyst      | `run_analysis_script` | Allowed if policy passes       |
| Payment Processor | `process_refund`      | Requires HITL approval         |
| Financial Agent   | `fetch_forex_rates`   | Calls real MCP server securely |

---

## What This Project Shows

This example demonstrates:

* AetherGuard SDK initialization
* Capability profile registration
* Idempotent agent registration (register, reactivate, or update)
* Agent deregistration on profile setup failure
* Agent deregistration at shutdown (soft-delete)
* Tenant-aware session creation
* CrewAI tool protection using `@aetherguard_secured`
* Tool call evaluation before execution
* HITL approval polling
* MCP transport wrapping using `AetherGuardMCPTransport`
* Output scanning using `scan_output_hybrid`
* LLM calls routed through AetherGuard Proxy
* Real MCP server execution using stdio

---

## Project Structure

```text
.
├── main.py
├── forex_mcp_server.py
├── requirements.txt
├── .env
└── README.md
```

---

## Required Files

### `main.py`

This is the main CrewAI + AetherGuard application.

It contains:

* AetherGuard initialization
* Capability profiles
* CrewAI agents
* CrewAI tasks
* Secured tools
* MCP client adapter
* HITL polling
* Output scanning
* Crew execution

### `forex_mcp_server.py`

This file must expose the MCP tool:

```text
fetch_forex_rates
```

Your current main code starts this MCP server using:

```python
StdioServerParameters(
    command="python",
    args=["forex_mcp_server.py"],
)
```

So this file must exist in the same folder as `main.py`.

### `.env`

Environment variables for AetherGuard, proxy, tenant, and model configuration.

### `requirements.txt`

Python dependencies required to run the project.

---

## Security Flow

The runtime flow is:

```text
CrewAI Agent
   ↓
CrewAI Tool
   ↓
@aetherguard_secured decorator
   ↓
ag.evaluate_tool_call()
   ↓
AetherGuard C1-C8 evaluation
   ↓
ALLOW / BLOCK / PENDING
   ↓
If ALLOW → execute MCP tool
   ↓
AetherGuardMCPTransport
   ↓
Real MCP ClientSession
   ↓
MCP Server Tool
   ↓
Tool response
   ↓
ag.scan_output_hybrid()
   ↓
Safe output returned to agent
```

---

## AetherGuard Controls Used

The code is designed to support the following controls:

| Control              | Purpose                                            |
| -------------------- | -------------------------------------------------- |
| C1 Firewall          | Validates whether the agent can call the tool      |
| C3 Sandbox           | Enforces tool call limits and session limits       |
| C5 Intent Validation | Compares declared intent with actual tool usage    |
| C7 HITL              | Requires human approval for sensitive tools        |
| C8 AetherSign        | Creates signed audit trail for tool execution      |
| Output Scanning      | Scans tool output before returning it to the agent |

---

## Agents

### 1. Data Analyst Agent

Agent ID:

```text
data-analyst-v1
```

Tool:

```text
run_analysis_script
```

Purpose:

```text
Run Q3 analysis script and summarize results.
```

This agent does not require human approval.

---

### 2. Payment Processor Agent

Agent ID:

```text
payment-processor-v1
```

Tool:

```text
process_refund
```

Purpose:

```text
Process customer refund for damaged order.
```

This agent requires HITL approval.

If AetherGuard returns:

```text
PENDING
```

the code polls:

```text
/api/v1/agents/approvals/{request_id}/status
```

until the request is approved, denied, or timed out.

---

### 3. Financial Agent

Agent ID:

```text
financial-agent-v1
```

Tool:

```text
fetch_forex_rates
```

Purpose:

```text
Fetch latest public forex rate from USD to PKR.
```

This agent calls the MCP server through secured AetherGuard MCP transport.

---

## Agent Lifecycle Management

The demo implements full agent lifecycle management:

### Registration (`ensure_agent_profile`)

At startup, each agent profile is handled idempotently:

* Agent does not exist → register it.
* Agent exists but is deregistered → reactivate it.
* Agent exists and profile unchanged → skip.
* Agent exists but profile hash differs → update it.
* Registration fails → deregister the agent as a safety measure.

### Deregistration (`deregister_agents`)

At shutdown, all agents are soft-deleted:

* Sets `active=False` on each agent profile.
* Profile is preserved for audit visibility.
* Agent cannot start new sessions until reactivated.
* Active sessions complete naturally (not terminated).

---

## Environment Setup

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```bash
.venv\Scripts\Activate.ps1
```

Activate it on Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Environment Variables

Create a `.env` file in the project root.

Required variables:

```env
AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_API_KEY=ag_test_key_12345
AETHERGUARD_PROXY_URL=http://localhost:8080/v1
OPENAI_MODEL=gpt-4o
AETHERGUARD_ML_SCAN=true
AETHERGUARD_TENANT_ID=demo-tenant
```

---

## Running the Application

Start AetherGuard backend services first.

Then run:

```bash
python main.py
```

Expected startup output:

```text
AetherGuard + CrewAI + Secured Corporate MCP Server
3 agents | 3 secured MCP tools | AetherGuard C1-C8
```

The app will:

1. Start the MCP server.
2. Initialize MCP client session.
3. Initialize AetherGuard SDK.
4. Register capability profiles (or reactivate if previously deregistered).
5. Start AetherGuard sessions.
6. Wrap MCP transport with AetherGuard.
7. Run CrewAI agents.
8. Evaluate each tool call.
9. Scan tool outputs.
10. Deregister agents (soft-delete).
11. Close sessions and connections.

---

## HITL Approval Flow

For the payment tool, AetherGuard may return:

```text
PENDING
```

The console will show:

```text
Waiting for human approval
```

Approval endpoint:

```text
POST /api/v1/agents/approvals/{request_id}/decide
```

Status polling endpoint:

```text
GET /api/v1/agents/approvals/{request_id}/status
```

Possible final decisions:

```text
APPROVED
DENIED
TIMED_OUT
```

If approved, the tool executes.

If denied or timed out, the tool is not executed.

---

## Output Scanning

After every successful tool execution, output is scanned using:

```python
ag.scan_output_hybrid(...)
```

Supported behavior:

| Status     | Behavior                  |
| ---------- | ------------------------- |
| CLEAN      | Output returned           |
| SUSPICIOUS | Sanitized output returned |
| BLOCKED    | Raw output withheld       |
| DISABLED   | Raw output returned       |

ML scan is controlled by:

```env
AETHERGUARD_ML_SCAN=true
```

Set it to false for local heuristic-only scanning:

```env
AETHERGUARD_ML_SCAN=false
```

---

## Important Notes

The variable `ag` starts as:

```python
ag = None
```

This is correct.

It is initialized later inside:

```python
setup_aetherguard(...)
```

using:

```python
ag = await AetherGuard.init(...)
```

So tools must not run before `setup_aetherguard()`.

---

## Common Errors

### 1. `No active session for agent`

Reason:

```text
setup_aetherguard() was not called before tool execution.
```

Fix:

Run through:

```python
main(mcp_adapter)
```

Do not directly call tools manually before initialization.

---

### 2. MCP server file not found

Error:

```text
forex_mcp_server.py not found
```

Fix:

Make sure this file exists in the same folder as `main.py`.

---

### 3. Approval request not found

Possible reason:

```text
Tenant mismatch or approval was not created correctly.
```

Check:

```env
AETHERGUARD_TENANT_ID=demo-tenant
```

Make sure the same tenant is used in backend approval APIs.

---

### 4. Proxy or API connection failed

Check:

```env
AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_PROXY_URL=http://localhost:8080/v1
```

Make sure both services are running.

---

## Production Checklist

Before production use:

* Replace test API key with secure secret manager value.
* Do not commit `.env`.
* Add `.env` to `.gitignore`.
* Use real tenant ID.
* Use real AetherGuard backend URL.
* Use real MCP server.
* Add structured logging.
* Add retry strategy around MCP calls.
* Add timeout strategy around CrewAI execution.
* Add tests for approval flow.
* Add tests for blocked tool calls.
* Add tests for output scanning.
* Add monitoring around tool verdicts.
* Add audit dashboard for AetherSign records.

---

## Example Command

```bash
python main.py
```
