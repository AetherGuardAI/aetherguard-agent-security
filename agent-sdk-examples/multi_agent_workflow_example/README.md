# AetherGuard + LangGraph Multi-Agent Workflow

A production-style multi-agent workflow demonstrating 7 specialized agents orchestrated through LangGraph with full AetherGuard security enforcement.

## Features

- 7 specialized agents with distinct roles and permissions
- Supervisor-based routing (deterministic business process)
- Idempotent agent registration (register, reactivate, or update)
- Agent deregistration at shutdown (soft-delete)
- Tool-call authorization per agent
- Human-in-the-Loop (HITL) approval for financial operations
- Output scanning after every tool execution
- Compliance gate before payment processing
- Token budget controls
- Loop detection
- Session lifecycle management

## Architecture

```text
User Request
     │
     ▼
Supervisor Agent (router)
     │
     ├──► Planner Agent
     │
     ├──► Data Analyst Agent
     │         ├── read_dataset
     │         └── run_analysis_script
     │
     ├──► Refund Investigator Agent
     │         └── get_order_details
     │
     ├──► Compliance Agent (approve/reject)
     │
     ├──► Payment Processor Agent (HITL)
     │         └── process_refund
     │
     └──► Report Writer Agent
```

## Agents

| Agent                | ID                       | Tools                                  | HITL |
|----------------------|--------------------------|----------------------------------------|------|
| Supervisor           | supervisor-v1            | None (routing only)                    | No   |
| Planner              | planner-v1               | None (planning only)                   | No   |
| Data Analyst         | data-analyst-v1          | read_dataset, run_analysis_script      | No   |
| Refund Investigator  | refund-investigator-v1   | get_order_details                      | No   |
| Payment Processor    | payment-processor-v1     | process_refund                         | Yes  |
| Compliance           | compliance-v1            | None (decision only)                   | No   |
| Report Writer        | report-writer-v1         | None (summarization only)              | No   |

## Workflow Sequence

1. Supervisor routes to Planner
2. Planner creates execution plan
3. Supervisor routes to Data Analyst
4. Data Analyst reads dataset and runs analysis
5. Supervisor routes to Refund Investigator
6. Investigator retrieves order details
7. Supervisor routes to Compliance
8. Compliance approves or rejects refund
9. Supervisor routes to Payment Processor (if approved)
10. Payment Processor executes refund (requires HITL approval)
11. Supervisor routes to Report Writer
12. Report Writer produces final summary

## Agent Lifecycle Management

### Registration (`ensure_agent_profile`)

At startup, each agent profile is handled idempotently:

- Agent does not exist → register it
- Agent exists but is deregistered → reactivate it
- Agent exists and profile unchanged → skip
- Agent exists but profile hash differs → update it

### Deregistration (`deregister_agents`)

At shutdown, all agents are soft-deleted:

- Sets `active=False` on each agent profile
- Profile is preserved for audit visibility
- Agent cannot start new sessions until reactivated

## Prerequisites

- Python 3.11+
- OpenAI API Key
- AetherGuard Server

## Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
```

## Environment Variables

Create a `.env` file:

```env
AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_API_KEY=your_aetherguard_api_key
AETHERGUARD_TENANT_ID=demo-tenant
AETHERGUARD_ML_SCAN=true

OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o
```

## Running

```bash
python main.py
```

## Project Structure

```text
.
├── main.py
├── requirements.txt
├── .env
└── README.md
```

## Security Controls

Every tool call goes through:

1. AetherGuard evaluation (C1-C8 controls)
2. HITL approval gate (for payment-processor-v1)
3. Output scanning (heuristic + optional ML)

## Example Output

```text
AetherGuard evaluation | agent=data-analyst-v1 | tool=run_analysis_script
Verdict: ALLOW

AetherGuard evaluation | agent=payment-processor-v1 | tool=process_refund
Verdict: PENDING
HITL request: req_xxxxx

FINAL REPORT
============
- Q3 Revenue: $2.4M (+12% YoY)
- Refund processed: $149.99 for ORD-7891
- Status: COMPLETED
```
