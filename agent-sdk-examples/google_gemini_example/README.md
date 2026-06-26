# AetherGuard + CrewAI + Google Gemini Secure Agent Demo

A complete demonstration of securing CrewAI agents with AetherGuard while using Google Gemini for LLM inference.

This project showcases:

* Agent registration and capability enforcement
* Tool-call authorization
* Human-in-the-Loop (HITL) approvals
* Output scanning and sanitization
* Token budget controls
* Session management
* Google Gemini model usage through CrewAI/LiteLLM
* Multi-agent orchestration using CrewAI

---

## Architecture

```text
+-------------------------------------------------------+
|                    CrewAI Crew                        |
+-------------------------------------------------------+
                         |
           +-------------+-------------+
           |                           |
           v                           v
+------------------+        +-----------------------+
| Data Analyst     |        | Payment Processor     |
| Agent            |        | Agent                 |
+------------------+        +-----------------------+
           |                           |
           v                           v
 run_analysis_script             process_refund
 (ALLOW)                         (HITL Approval)
           |                           |
           +-------------+-------------+
                         v
              AetherGuard Security Layer

       * Capability Enforcement
       * Tool Authorization
       * Intent Verification
       * Session Controls
       * Token Budgets
       * Output Scanning
       * Loop Detection
       * Human Approval Workflows
                         |
                         v
                 Google Gemini API
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

1. CrewAI invokes refund tool.
2. AetherGuard evaluates request.
3. Human approval request is created.
4. System waits for approval.
5. Approved -> execute refund.
6. Denied -> block execution.

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

### Workflow 3 - Agent Lifecycle (Register / Deregister)

At startup, `ensure_agent_profile` handles idempotent registration:

- If agent does not exist -> register it.
- If agent exists but is deregistered -> reactivate it.
- If agent exists and profile unchanged -> skip.
- If agent exists but profile hash differs -> update it.
- If registration fails -> deregister the agent as a safety measure.

At shutdown, `deregister_agents` soft-deletes all agents:

- Sets `active=False` on each agent profile.
- Profile is preserved for audit visibility.
- Agent cannot start new sessions until reactivated.

---

## Security Controls

The demo evaluates every tool invocation through AetherGuard before execution.

Configured controls include:

* Capability enforcement
* Tool allowlisting
* Session restrictions
* Token budgets
* Intent validation
* Loop detection
* Output scanning
* Human approval workflows

LLM inference is performed with Google Gemini through CrewAI/LiteLLM.

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
Google Gemini API access
```

Default ports for local AetherGuard services:

```text
Backend : 8081
Proxy   : 8080 (optional, retained for deployments that proxy Gemini traffic)
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
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

If you use `uv`, CrewAI's native Gemini provider can also be installed with:

```bash
uv add "crewai[google-genai]"
```

---

## Environment Variables

Create a `.env` file:

```env
AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_API_KEY=ag_test_key_12345

# Optional for AetherGuard deployments that proxy Gemini traffic
AETHERGUARD_PROXY_URL=http://localhost:8080/v1

AETHERGUARD_TENANT_ID=demo-tenant
AETHERGUARD_ML_SCAN=true
CREWAI_TRACING_ENABLED=false

GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini/gemini-2.0-flash
```

### Variable Reference

| Variable              | Description                                |
| --------------------- | ------------------------------------------ |
| AETHERGUARD_API_URL   | Backend API                                |
| AETHERGUARD_API_KEY   | Authentication key                         |
| AETHERGUARD_PROXY_URL | Optional secure LLM gateway URL            |
| AETHERGUARD_TENANT_ID | Tenant identifier                          |
| AETHERGUARD_ML_SCAN   | Enable ML output scanning                  |
| CREWAI_TRACING_ENABLED | Disable CrewAI trace prompts in demo runs |
| GEMINI_API_KEY        | Required Google Gemini API key             |
| GEMINI_MODEL          | Gemini model name for CrewAI/LiteLLM       |

---

## Running the Demo

```bash
python main.py
```

Startup sequence:

1. Connect to AetherGuard.
2. Register agents (or reactivate if previously deregistered).
3. Create sessions.
4. Launch CrewAI crew using Gemini.
5. Execute tasks.
6. Scan outputs.
7. Deregister agents (soft-delete).
8. Close sessions.

---

## Human Approval Flow

For refund requests, AetherGuard creates an approval request and the application polls:

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

After tool execution:

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

This example is intended to demonstrate:

* Secure agent execution
* Runtime policy enforcement
* Human approval workflows
* Google Gemini-backed CrewAI agents
* Output validation
* Compliance-oriented AI agent architectures
