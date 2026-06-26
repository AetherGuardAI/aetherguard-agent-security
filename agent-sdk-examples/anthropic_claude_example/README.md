# AetherGuard + CrewAI + Anthropic Claude Secure Agent Demo

A complete demonstration of securing CrewAI agents with AetherGuard while using Anthropic Claude as the LLM provider.

This project mirrors the `crewai_example` flow and showcases:

* Agent registration and capability enforcement
* Tool-call authorization
* Human-in-the-Loop (HITL) approvals
* Output scanning and sanitization
* Token budget controls
* Session management
* Optional Anthropic-compatible LLM routing through the AetherGuard Proxy
* Multi-agent orchestration using CrewAI

---

## Architecture

```text
CrewAI Crew
    |
    +-- Data Analyst Agent ---- run_analysis_script ---- ALLOW
    |
    +-- Payment Processor ----- process_refund --------- HITL Approval

Every tool call passes through the AetherGuard Security Layer:

* Capability enforcement
* Tool authorization
* Intent verification
* Session controls
* Token budgets
* Output scanning
* Loop detection
* Human approval workflows

Claude inference is configured through CrewAI/LiteLLM's Anthropic provider. Set
`ANTHROPIC_BASE_URL` to an Anthropic-compatible AetherGuard proxy endpoint when
you want Claude requests routed through the proxy, or set it to
`https://api.anthropic.com` for direct Anthropic API calls.
```

---

## Demonstrated Workflows

### Workflow 1 - Analysis Agent

Agent: `data-analyst-v1`

Tool:

```python
run_analysis_script
```

Behavior:

1. CrewAI invokes the tool.
2. AetherGuard evaluates the request.
3. Tool is automatically approved.
4. Script executes.
5. Output is scanned.
6. Result is returned to the agent.

Expected verdict:

```text
ALLOW
```

---

### Workflow 2 - Refund Agent

Agent: `payment-processor-v1`

Tool:

```python
process_refund
```

Behavior:

1. CrewAI invokes the refund tool.
2. AetherGuard evaluates the request.
3. Human approval request is created.
4. The app polls until a decision is available.
5. Approved requests execute the refund tool.
6. Denied or timed-out requests are blocked.

Expected verdict:

```text
PENDING
```

followed by:

```text
APPROVED
```

or:

```text
DENIED
```

---

### Workflow 3 - Agent Lifecycle

At startup, `ensure_agent_profile` handles idempotent registration:

* If the agent does not exist, register it.
* If the agent exists but is deregistered, reactivate it.
* If the agent exists and the profile is unchanged, skip it.
* If the agent exists but the profile hash differs, update it.
* If registration fails, deregister the agent as a safety measure.

At shutdown, `deregister_agents` soft-deletes all agents by setting
`active=False` while preserving profiles for audit visibility.

---

## Project Structure

```text
.
|-- main.py
|-- requirements.txt
|-- .env
`-- README.md
```

---

## Prerequisites

Running services:

```text
AetherGuard Backend
AetherGuard Proxy Engine, if routing Claude traffic through the proxy
Anthropic Claude API access
```

Default ports:

```text
Backend : 8081
Proxy   : 8080
```

---

## Installation

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Environment Variables

Create a `.env` file:

```env
AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_API_KEY=ag_test_key_12345
AETHERGUARD_PROXY_URL=http://localhost:8080/v1
AETHERGUARD_TENANT_ID=demo-tenant
AETHERGUARD_ML_SCAN=true

ANTHROPIC_API_KEY=your_anthropic_api_key
ANTHROPIC_MODEL=claude-sonnet-4-20250514
ANTHROPIC_BASE_URL=http://localhost:8080/v1
```

For direct Anthropic API calls instead of proxy routing, set:

```env
ANTHROPIC_BASE_URL=https://api.anthropic.com
```

### Variable Reference

| Variable              | Description                                      |
| --------------------- | ------------------------------------------------ |
| AETHERGUARD_API_URL   | AetherGuard backend API                          |
| AETHERGUARD_API_KEY   | AetherGuard authentication key                   |
| AETHERGUARD_PROXY_URL | Default secure LLM gateway                       |
| AETHERGUARD_TENANT_ID | Tenant identifier                                |
| AETHERGUARD_ML_SCAN   | Enable ML output scanning                        |
| ANTHROPIC_API_KEY     | Anthropic API key required for Claude inference  |
| ANTHROPIC_MODEL       | Claude model name, for example `claude-sonnet-4-20250514` |
| ANTHROPIC_BASE_URL    | Anthropic-compatible endpoint used by CrewAI     |

---

## Running the Demo

```bash
python main.py
```

Startup sequence:

1. Validate Anthropic configuration.
2. Connect to AetherGuard.
3. Register or reactivate agents.
4. Create sessions.
5. Launch the CrewAI crew using Claude.
6. Execute tasks.
7. Scan outputs.
8. Deregister agents.
9. Close sessions.

---

## Human Approval Flow

For refund requests, AetherGuard creates an approval request and this example polls:

```text
/api/v1/agents/approvals/{request_id}/status
```

Decision endpoint:

```http
POST /api/v1/agents/approvals/{request_id}/decide
```

Possible outcomes:

```text
APPROVED
DENIED
TIMED_OUT
```

---

## Output Scanning

After tool execution, the example calls:

```python
ag.scan_output_hybrid(...)
```

Scanning modes:

### Heuristic Scan

Fast local checks.

### ML Scan

Backend-powered detection for prompt injection, PII, toxicity, and data leakage.

Possible statuses:

```text
CLEAN
SUSPICIOUS
BLOCKED
```

---

## Example Output

```text
AetherGuard Evaluation: run_analysis_script
Verdict: ALLOW
Allowed: True
```

```text
Analysis Results:
- Total revenue: $2.4M
- Active customers: 1,847
- Churn rate: 3.2%
```

Refund path:

```text
AetherGuard Evaluation: process_refund
Verdict: PENDING
HITL Request: req_xxxxx
```

```text
Waiting for human approval...
```

```text
Refund Processed:
Order: ORD-7891
Amount: $149.99
```

## Demo Goals

This example is intended to demonstrate secure Claude-backed agent execution, runtime policy enforcement, human approval workflows, output validation, and compliance-oriented AI agent architectures.
