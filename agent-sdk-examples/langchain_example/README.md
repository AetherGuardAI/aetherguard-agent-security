# AetherGuard + LangChain + OpenAI Integration

A production-ready example demonstrating how to secure LangChain agents using AetherGuard while interacting with OpenAI models.

## Features

- Agent registration and capability enforcement
- Idempotent agent registration (register, reactivate, or update)
- Agent deregistration on profile setup failure
- Agent deregistration at shutdown (soft-delete)
- Tool-call authorization
- Human-in-the-Loop (HITL) approval workflows
- Output scanning and redaction
- Token budget controls
- Session management
- OpenAI integration through AetherGuard proxy
- Multiple secured agents with different permissions

## Architecture

```text
User
 │
 ▼
LangChain Agent
 │
 ▼
AetherGuard Security Layer
 │
 ├── Intent Validation
 ├── Tool Authorization
 ├── Policy Enforcement
 ├── HITL Approval
 └── Output Scanning
 │
 ▼
OpenAI
 │
 ▼
Authorized Tool Execution
```

## Prerequisites

- Python 3.10+
- Running AetherGuard API
- Running AetherGuard Proxy
- OpenAI API Key


Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment:

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file:

```env
AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_API_KEY=your_api_key

AETHERGUARD_PROXY_URL=http://localhost:8080/v1
AETHERGUARD_TENANT_ID=demo-tenant
AETHERGUARD_ML_SCAN=true

OPENAI_API_KEY=your_openai_key
OPENAI_MODEL=gpt-4o-mini
```

## Running

```bash
python main.py
```

Expected workflow:

1. Register agents (or reactivate if previously deregistered)
2. Start secured sessions
3. Execute data analysis task
4. Request approval for refund task
5. Scan outputs
6. Display final results
7. Deregister agents (soft-delete)
8. Close sessions

## Agents

### Data Analyst

Capabilities:

- Run analysis scripts
- Access internal data
- No external network access
- Automatic execution

Allowed tool:

- `run_analysis_script`

### Payment Processor

Capabilities:

- Process refunds
- Handle financial and PII data
- Requires human approval

Allowed tool:

- `process_refund`

## Human-in-the-Loop (HITL)

Refund operations require approval before execution.

Workflow:

```text
Tool Request
      │
      ▼
AetherGuard Evaluation
      │
      ▼
PENDING
      │
      ▼
Human Approval
      │
 ┌────┴────┐
 │         │
 ▼         ▼
Approved  Denied
 │         │
 ▼         ▼
Execute  Block
```

## Security Controls

### Tool Authorization

Only explicitly permitted tools can be executed.

### Output Scanning

Responses are scanned before being returned.

### Token Budgeting

Prevent runaway agent execution.

### Loop Detection

Detect recursive or repeated actions.

### Intent Matching

Validate actions against declared agent intent.

## Example Output

```text
🔒 AetherGuard Evaluation: run_analysis_script
Verdict: ALLOWED

📊 Executing script: q3_analysis.py

Analysis Results:
- Total revenue: $2.4M
- Active customers: 1,847
- Churn rate: 3.2%
```

## Agent Lifecycle Management

### Registration (`ensure_agent_profile`)

At startup, each agent profile is handled idempotently:

- Agent does not exist → register it
- Agent exists but is deregistered → reactivate it
- Agent exists and profile unchanged → skip
- Agent exists but profile hash differs → update it
- Registration fails → deregister the agent as a safety measure

### Deregistration (`deregister_agents`)

At shutdown, all agents are soft-deleted:

- Sets `active=False` on each agent profile
- Profile is preserved for audit visibility
- Agent cannot start new sessions until reactivated
- Active sessions complete naturally (not terminated)

## Troubleshooting

### Missing API Key

```text
KeyError: AETHERGUARD_API_KEY
```

Ensure environment variables are loaded correctly.

### Approval Not Found

```text
Approval request not found
```

Verify tenant IDs match between the application and AetherGuard.

### OpenAI Authentication Error

```text
401 Unauthorized
```

Verify your `OPENAI_API_KEY`.

## License

MIT License

## Author

Built with:

- AetherGuard
- LangChain
- OpenAI
