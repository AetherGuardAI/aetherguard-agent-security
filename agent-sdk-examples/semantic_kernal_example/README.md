# AetherGuard + Semantic Kernel Integration

This example demonstrates how to integrate Semantic Kernel agents with AetherGuard security controls while preserving the complete AetherGuard enforcement pipeline.

## What This Example Shows

### Security Controls

* Agent registration
* Idempotent agent registration (register, reactivate, or update)
* Agent deregistration on setup failure
* Agent deregistration at shutdown (soft-delete)
* Capability profiles
* Session lifecycle management
* Tool-call authorization
* Human-in-the-loop (HITL) approvals
* Output scanning
* Policy enforcement
* Token budget controls
* Loop detection
* Data classification enforcement

### Semantic Kernel Integration

The example secures Semantic Kernel plugin functions using AetherGuard before execution.

Protected operations include:

| Agent             | Tool                  |
| ----------------- | --------------------- |
| Data Analyst      | `run_analysis_script` |
| Payment Processor | `process_refund`      |

---

## Architecture

```text
User Request
     │
     ▼
Semantic Kernel Planner
     │
     ▼
Semantic Kernel Plugin Function
     │
     ▼
AetherGuard Evaluation
     │
     ├── Allow
     ├── Block
     └── HITL Approval
     │
     ▼
Tool Execution
     │
     ▼
AetherGuard Output Scan
     │
     ▼
Response Returned
```

---

## Agents

### Data Analyst Agent

Agent ID:

```text
data-analyst-v1
```

Capabilities:

* Run analysis scripts
* Read datasets

Security Settings:

* No human approval required
* Output scanning enabled
* Loop detection enabled
* External network access disabled
* Token budget enforced

---

### Payment Processor Agent

Agent ID:

```text
payment-processor-v1
```

Capabilities:

* Process refunds

Security Settings:

* Human approval required
* Financial and PII data classifications
* Output scanning enabled
* Loop detection enabled
* External network access disabled

---

## Environment Variables

| Variable              | Default                  |
| --------------------- | ------------------------ |
| AETHERGUARD_API_URL   | http://localhost:8081    |
| AETHERGUARD_API_KEY   | ag_test_key_12345        |
| AETHERGUARD_PROXY_URL | http://localhost:8080/v1 |
| OPENAI_MODEL          | gpt-4o                   |
| AETHERGUARD_TENANT_ID | demo-tenant              |
| AETHERGUARD_ML_SCAN   | true                     |

Example:

```env
AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_API_KEY=your_api_key
AETHERGUARD_PROXY_URL=http://localhost:8080/v1
OPENAI_MODEL=gpt-4o
AETHERGUARD_TENANT_ID=demo-tenant
AETHERGUARD_ML_SCAN=true
```

---

## Installation

```bash
python -m venv .venv

source .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install -r requirements.txt
```

---

## Run

```bash
python main.py
```

---

## Execution Flow

1. Initialize AetherGuard.
2. Register capability profiles (or reactivate if previously deregistered).
3. Start agent sessions.
4. Create Semantic Kernel plugins.
5. Generate a plan.
6. Evaluate every tool call through AetherGuard.
7. Wait for approval when HITL is required.
8. Execute the tool.
9. Scan tool output.
10. Return sanitized results.
11. Deregister agents (soft-delete).
12. Close sessions.

---

## Agent Lifecycle Management

### Registration (`ensure_agent_profile`)

At startup, each agent profile is handled idempotently:

* Agent does not exist → register it
* Agent exists but is deregistered → reactivate it
* Agent exists and profile unchanged → skip
* Agent exists but profile hash differs → update it
* Registration fails → deregister the agent as a safety measure

### Deregistration (`deregister_agents`)

At shutdown, all agents are soft-deleted:

* Sets `active=False` on each agent profile
* Profile is preserved for audit visibility
* Agent cannot start new sessions until reactivated

---

## Security Notes

* Never commit production API keys.
* Store secrets in a secret manager.
* Enable TLS for AetherGuard endpoints.
* Use separate tenants for dev, staging, and production.
* Enable audit logging for HITL workflows.
* Rotate API keys regularly.

## License

Internal example for demonstrating AetherGuard integration with Semantic Kernel.
