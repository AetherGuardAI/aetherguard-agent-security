# AetherGuard + AutoGen GroupChat Example

This project demonstrates how to integrate **AetherGuard Agent Security** with **Microsoft AutoGen** using a multi-agent architecture.

The example implements:

* Coordinator Agent
* Data Analyst Agent
* Payment Processor Agent
* UserProxy Agent
* AetherGuard Tool Authorization
* Idempotent Agent Registration (register, reactivate, or update)
* Agent Deregistration on setup failure
* Agent Deregistration at shutdown (soft-delete)
* Human-in-the-Loop (HITL) Approval
* Output Scanning
* GroupChat Orchestration

---

# Architecture

```text
User
 │
 ▼
UserProxyAgent
 │
 ▼
GroupChatManager
 │
 ▼
CoordinatorAgent
 │
 ├─────────────────────► DataAnalystAgent
 │                            │
 │                            ▼
 │                   run_analysis_script()
 │                            │
 │                            ▼
 │                     AetherGuard
 │
 │
 └─────────────────────► PaymentProcessorAgent
                              │
                              ▼
                       process_refund()
                              │
                              ▼
                         AetherGuard
                              │
                              ▼
                       HITL Approval
```

---

# Agent Responsibilities

## CoordinatorAgent

The CoordinatorAgent is responsible for:

* Understanding workflow goals
* Delegating work to specialist agents
* Collecting results
* Producing the final summary

The coordinator does **not** execute tools directly.

---

## DataAnalystAgent

The DataAnalystAgent is responsible for:

* Running analytics workflows
* Generating business insights
* Calling analysis tools

Available tool:

```python
run_analysis_script()
```

AetherGuard Policy:

* Internal data only
* No external network
* No HITL approval required

---

## PaymentProcessorAgent

The PaymentProcessorAgent is responsible for:

* Processing refunds
* Handling financial operations

Available tool:

```python
process_refund()
```

AetherGuard Policy:

* Financial data access
* PII access
* Human approval required

---

## UserProxyAgent

The UserProxyAgent acts as the execution layer.

Responsibilities:

* Starts the conversation
* Executes registered Python functions
* Returns tool results back into the AutoGen conversation

The UserProxyAgent does not make business decisions.

Example:

```python
register_function(
    process_refund,
    caller=payment_agent,
    executor=user_proxy,
)
```

Meaning:

```text
PaymentProcessorAgent requests tool
          │
          ▼
UserProxyAgent executes tool
          │
          ▼
AetherGuard validates tool execution
```

---

# Security Flow

Every tool call is evaluated before execution.

```text
Agent Requests Tool
        │
        ▼
AetherGuard Evaluation
        │
        ├── ALLOW
        │      ▼
        │  Execute Tool
        │
        ├── PENDING
        │      ▼
        │ Human Approval
        │      ▼
        │ Execute Tool
        │
        └── BLOCK
               ▼
         Reject Execution
```

After execution:

```text
Tool Output
     │
     ▼
AetherGuard Output Scan
     │
     ▼
Return Safe Output
```

---

# AutoGen Conversation Flow

Workflow execution:

```text
UserProxyAgent
      │
      ▼
GroupChatManager
      │
      ▼
CoordinatorAgent
      │
      ├──► DataAnalystAgent
      │         │
      │         ▼
      │   run_analysis_script()
      │
      └──► PaymentProcessorAgent
                │
                ▼
          process_refund()
```

Expected execution order:

1. Coordinator delegates Q3 analysis
2. DataAnalystAgent executes analysis tool
3. Coordinator receives results
4. Coordinator delegates refund task
5. PaymentProcessorAgent requests refund
6. AetherGuard creates HITL approval request
7. Human approves request
8. Refund executes
9. Coordinator summarizes results
10. Workflow completes
11. Agents are deregistered (soft-delete)

---

# Project Structure

```text
.
├── main.py
├── .env
├── README.md
└── requirements.txt
```

---

# Agent Lifecycle Management

## Registration (`ensure_agent_profile`)

At startup, each agent profile is handled idempotently:

* Agent does not exist → register it
* Agent exists but is deregistered → reactivate it
* Agent exists and profile unchanged → skip
* Agent exists but profile hash differs → update it
* Registration fails → deregister the agent as a safety measure

## Deregistration (`deregister_agents`)

At shutdown, all agents are soft-deleted:

* Sets `active=False` on each agent profile
* Profile is preserved for audit visibility
* Agent cannot start new sessions until reactivated
* Active sessions complete naturally (not terminated)

---

# Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

requirements.txt:

```txt
pyautogen>=0.2.35,<0.3
python-dotenv>=1.0.0
httpx>=0.27.0
fastapi>=0.138.0
starlette>=1.3.1
aetherguard-agent-security
```

---

# Environment Variables

Create a `.env` file:

```env
AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_API_KEY=ag_test_key_12345

AETHERGUARD_PROXY_URL=http://localhost:8080/v1

OPENAI_MODEL=gpt-4o
OPENAI_API_KEY=your_openai_api_key

AETHERGUARD_TENANT_ID=demo-tenant
AETHERGUARD_ML_SCAN=true
```

---

# Running

Start AetherGuard services.

Then run:

```bash
python main.py
```

---

# Example Output

```text
Analysis Results:
- Revenue: $2.4M
- Customers: 1,847
- Churn: 3.2%

Refund Processed:
- Order: ORD-7891
- Amount: $149.99

WORKFLOW_COMPLETE
```

---

# Why Only Two Agents Are Registered With AetherGuard?

Only these agents perform protected actions:

```text
DataAnalystAgent
PaymentProcessorAgent
```

They are the agents that execute tools.

The following are orchestration components and therefore do not require AetherGuard identities:

```text
CoordinatorAgent
GroupChatManager
UserProxyAgent
```

This follows the Principle of Least Privilege by granting permissions only to agents that perform sensitive operations.
