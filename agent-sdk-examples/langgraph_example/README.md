# AetherGuard + LangGraph + OpenAI Workflow

A secure multi-agent workflow demonstrating:

- AetherGuard policy enforcement
- Human-in-the-loop (HITL) approvals
- LangGraph orchestration
- OpenAI tool-calling
- Output scanning and governance

## Architecture

Flow:

1. Data Analyst Agent
   - Executes `run_analysis_script`
   - Generates Q3 sales analysis

2. Payment Processor Agent
   - Executes `process_refund`
   - Requires human approval through AetherGuard

3. Final Reporting Agent
   - Summarizes workflow results

## Features

### AetherGuard Security

- Tool authorization
- Intent validation
- Idempotent agent registration (register, reactivate, or update)
- Agent deregistration on setup failure
- Agent deregistration at shutdown (soft-delete)
- Human approval workflows
- Output scanning
- Loop detection
- Token budgeting
- Session controls

### LangGraph

Sequential workflow:

START
 ↓
Analysis Agent
 ↓
Tool Execution
 ↓
Refund Agent
 ↓
Tool Execution
 ↓
Final Report
 ↓
END

## Requirements

- Python 3.11+
- OpenAI API Key
- AetherGuard Server

## Installation

```bash
git clone <repository-url>
cd <project>
```

Create virtual environment:

```bash
python -m venv .venv
```

Activate:

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

## Environment Variables

Create a `.env` file:

```env
OPENAI_API_KEY=your_openai_api_key

AETHERGUARD_API_URL=http://localhost:8081
AETHERGUARD_API_KEY=your_aetherguard_api_key
AETHERGUARD_TENANT_ID=demo-tenant

OPENAI_MODEL=gpt-4o-mini

AETHERGUARD_ML_SCAN=true
```

## Running

```bash
python main.py
```

Expected workflow:

1. AetherGuard initializes
2. Agent profiles registered (or reactivated if previously deregistered)
3. Agent sessions created
4. Analysis tool executes
5. Refund request submitted
6. Human approval requested
7. Final report generated
8. Agents deregistered (soft-delete)
9. Sessions closed

## Project Structure

```text
.
├── main.py
├── README.md
├── requirements.txt
├── .env
└── .venv/
```

## Example Output

```text
Analysis Results:
- Dataset: sales_q3
- Revenue: $2.4M
- Growth: +12%

Refund Processed:
- Order: ORD-7891
- Amount: $149.99

Final Summary:
Workflow completed successfully.
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

## Security Notes

- Never commit `.env`
- Use production AetherGuard credentials
- Rotate API keys regularly
- Enable HITL approval for financial actions