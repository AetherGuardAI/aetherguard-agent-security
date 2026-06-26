"""
AetherGuard + CrewAI + Google Gemini Integration Example

Two agents, two tasks, two tools:
- Agent 1 (Analyst): runs a data analysis script → ALLOW path
- Agent 2 (Payment Processor): processes a refund → HITL (requires human approval)

All tool calls are evaluated through AetherGuard's 8 security controls before execution.
"""
import asyncio
import os
import sys
import time

from crewai import Agent, Task, Crew, LLM
from crewai.tools import BaseTool

from aetherguard_agent_security import AetherGuard, CapabilityProfile, TokenBudget, AgentNotFoundError
from aetherguard_agent_security.controls.registry import compute_capability_hash

from dotenv import load_dotenv

load_dotenv()

os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

AETHERGUARD_API_URL = os.getenv("AETHERGUARD_API_URL", "http://localhost:8081")
AETHERGUARD_API_KEY = os.getenv("AETHERGUARD_API_KEY", "ag_test_key_12345")

# AetherGuard Proxy URL, retained for AetherGuard deployments that proxy Gemini traffic
# (Nitro Enclave: injection ML, PII ML, toxicity, data residency, audit, watermarking)
AETHERGUARD_PROXY_URL = os.getenv("AETHERGUARD_PROXY_URL", "http://localhost:8080/v1")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini/gemini-2.0-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
TENANT_ID = os.getenv("AETHERGUARD_TENANT_ID", "demo-tenant")

# ML-based output scanning: when True, tool outputs that pass local heuristics
# are forwarded to backend ml-services for deep ML scan (injection ML, PII NER, toxicity).
# When False, only local heuristic scanning is used (faster, no network call).
AETHERGUARD_ML_SCAN = os.getenv("AETHERGUARD_ML_SCAN", "true").lower() in ("true", "1", "yes")

# Persistent event loop for async calls from sync code
_loop = asyncio.new_event_loop()

def run_async(coro):
    """Run an async coroutine on the persistent event loop."""
    return _loop.run_until_complete(coro)


# ─────────────────────────────────────────────────────────────────────────────
# HITL Approval Polling
# ─────────────────────────────────────────────────────────────────────────────

def _wait_for_approval(request_id: str, timeout: int = 120, poll_interval: int = 3) -> str:
    """
    Poll the HITL approval status until decided or timed out.

    Returns: "APPROVED", "DENIED", or "TIMED_OUT"
    """
    import httpx
    
    headers = {"Authorization": f"Bearer {AETHERGUARD_API_KEY}"}
    url = f"{AETHERGUARD_API_URL}/api/v1/agents/approvals/{request_id}/status"
    elapsed = 0

    while elapsed < timeout:
        time.sleep(poll_interval)
        elapsed += poll_interval
        try:
            resp = httpx.get(url, headers=headers, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "AWAITING_APPROVAL")
                if status != "AWAITING_APPROVAL":
                    return status
            elif resp.status_code == 404:
                print(f"   ⚠ Approval request not found (may be tenant mismatch)")
            else:
                print(f"   ⚠ Poll returned {resp.status_code}: {resp.text[:100]}")
        except Exception as exc:
            print(f"   ⚠ Poll error: {exc}")
        remaining = timeout - elapsed
        print(f"   ⏳ Still waiting... ({remaining}s remaining)")

    return "TIMED_OUT"


def _execute_and_scan(original_run, tool_self, session, tool_name, *args, **kwargs):
    """
    Execute the tool and scan its output via AetherGuard SDK (hybrid scan).

    Uses ag.scan_output_hybrid() which handles:
    - Local heuristic scan (fast, no network)
    - Optional ML-grade scan via backend ml-services
    """
    # Execute the actual tool
    raw_output = original_run(tool_self, *args, **kwargs)

    # Scan output through AetherGuard (heuristic + optional ML)
    scan_result = run_async(ag.scan_output_hybrid(
        session_id=session.session_id,
        tenant_id=session.tenant_id,
        tool=tool_name,
        output=str(raw_output),
        ml_scan=AETHERGUARD_ML_SCAN,
    ))

    status = scan_result.get("status", "CLEAN")
    scan_level = scan_result.get("scan_level", "heuristic")

    if scan_result.get("blocked"):
        print(f"   🛡️  OUTPUT BLOCKED ({scan_level}): {scan_result.get('violations', [])}")
        return (
            f"🛡️ OUTPUT BLOCKED by AetherGuard ({scan_level} scan): "
            f"{scan_result.get('violations', [])}\n"
            f"   The raw output has been withheld from the agent context."
        )

    if status == "SUSPICIOUS":
        print(f"   🧹 OUTPUT SANITISED ({scan_level})")
        return scan_result.get("output", raw_output)

    if status == "CLEAN":
        if scan_level == "ml":
            print(f"   ✅ OUTPUT CLEAN (ML verified)")
        return scan_result.get("output", raw_output)

    # DISABLED or fallback
    return raw_output


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Setup (run once at startup)
# ─────────────────────────────────────────────────────────────────────────────

ag = None
sessions: dict[str, object] = {}  # agent_id → session


async def ensure_agent_profile(profile: CapabilityProfile) -> None:
    """
    Idempotent agent registration: register, reactivate, skip, or update as needed.

    Uses ag.get_agent() to check existence and active status.
    - If the agent does not exist → register it.
    - If the agent exists but is deregistered → reactivate it, then update if needed.
    - If the agent exists and the profile hash matches → skip (no-op).
    - If the agent exists but the profile hash differs → update it.
    """
    if ag is None:
        raise RuntimeError("AetherGuard is not initialized")

    desired_hash = compute_capability_hash(profile)

    try:
        agent_info = await ag.get_agent(profile.agent_id, profile.tenant_id)
    except AgentNotFoundError:
        await ag.register_agent(profile)
        print(f"✅ Registered: {profile.agent_id}")
        return

    # Reactivate if the agent was previously deregistered
    if not agent_info["active"]:
        await ag.reactivate_agent(profile.agent_id, profile.tenant_id)
        print(f"✅ Reactivated: {profile.agent_id}")

    existing_hash = agent_info.get("capability_hash") or ""

    if existing_hash == desired_hash:
        print(f"ℹ️  Profile unchanged: {profile.agent_id}")
        return

    await ag.update_agent_profile(profile)
    print(f"✅ Updated profile: {profile.agent_id}")

async def setup_aetherguard():
    """Initialize AetherGuard and register both agents."""
    global ag

    # Connect to AetherGuard backend
    ag = await AetherGuard.init(
        api_url=AETHERGUARD_API_URL,
        api_key=AETHERGUARD_API_KEY,
    )

    # ── Register Agent 1: Analyst (no HITL, script execution allowed) ─────
    analyst_profile = CapabilityProfile(
        agent_id="data-analyst-v1",
        agent_name="Data Analyst",
        tenant_id=TENANT_ID,
        permitted_tools=["run_analysis_script", "read_dataset"],
        data_classifications=["internal"],
        permitted_destinations=[],
        max_tool_calls=20,
        max_session_secs=600,
        requires_human_approval=False,  # No HITL — scripts run immediately
        intent_threshold=0.00,  # Disable intent check for demo
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(
            max_total_tokens=50000,
            max_tokens_per_step=10000,
        ),
    )
    try:
        await ensure_agent_profile(analyst_profile)
    except Exception as e:
        print(f"⚠️  Profile setup error for {analyst_profile.agent_id}: {e}")
        try:
            await ag.deregister_agent(agent_id=analyst_profile.agent_id, tenant_id=TENANT_ID)
            print(f"   ✅ Agent {analyst_profile.agent_id} deregistered (soft)")
        except AgentNotFoundError:
            print(f"   ℹ️  Agent {analyst_profile.agent_id} not found — nothing to deregister")
        except Exception as dereg_exc:
            print(f"   ❌ Deregistration also failed: {dereg_exc}")

    # ── Register Agent 2: Payment Processor (HITL required) ───────────────
    payment_profile = CapabilityProfile(
        agent_id="payment-processor-v1",
        agent_name="Payment Processor",
        tenant_id=TENANT_ID,
        permitted_tools=["process_refund", "get_order_details"],
        data_classifications=["financial", "pii"],
        permitted_destinations=["payments.internal"],
        max_tool_calls=5,
        max_session_secs=300,
        requires_human_approval=True,  # HITL — every tool call needs human OK
        hitl_timeout_secs=120,  # Auto-deny after 2 minutes
        intent_threshold=0.00,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
    )
    try:
        await ensure_agent_profile(payment_profile)
    except Exception as e:
        print(f"⚠️  Profile setup error for {payment_profile.agent_id}: {e}")
        try:
            await ag.deregister_agent(agent_id=payment_profile.agent_id, tenant_id=TENANT_ID)
            print(f"   ✅ Agent {payment_profile.agent_id} deregistered (soft)")
        except AgentNotFoundError:
            print(f"   ℹ️  Agent {payment_profile.agent_id} not found — nothing to deregister")
        except Exception as dereg_exc:
            print(f"   ❌ Deregistration also failed: {dereg_exc}")

    # ── Start sessions ────────────────────────────────────────────────────
    sessions["data-analyst-v1"] = await ag.start_session(
        agent_id="data-analyst-v1",
        tenant_id=TENANT_ID,
        declared_intent="Run Q3 data analysis scripts and generate report",
    )
    print(f"✅ Analyst session: {sessions['data-analyst-v1'].session_id}")

    sessions["payment-processor-v1"] = await ag.start_session(
        agent_id="payment-processor-v1",
        tenant_id=TENANT_ID,
        declared_intent="Process customer refund for damaged order",
    )
    print(f"✅ Payment session: {sessions['payment-processor-v1'].session_id}")


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Tool Decorator
# ─────────────────────────────────────────────────────────────────────────────

def aetherguard_secured(agent_id: str):
    """
    Decorator that wraps a CrewAI tool with AetherGuard evaluation.

    Args:
        agent_id: The registered agent_id whose session to use for evaluation.

    Before executing the tool, it calls ag.evaluate_tool_call().
    - ALLOW → execute the tool normally
    - BLOCK → return violation info
    - PENDING → wait for human approval, then execute or block
    """
    def decorator(tool_class):
        original_run = tool_class._run

        def secured_run(self, *args, **kwargs):
            session = sessions.get(agent_id)
            if session is None:
                return f"🚫 ERROR: No active session for agent '{agent_id}'. Call setup_aetherguard() first."

            # Evaluate through AetherGuard (all 8 controls)
            result = run_async(ag.evaluate_tool_call(
                session_id=session.session_id,
                tenant_id=session.tenant_id,
                tool=self.name,
                params={"args": args, "kwargs": kwargs},
                reasoning=f"CrewAI tool execution: {self.name}",
               # tokens_input=_last_tokens["input"],
               # tokens_output=_last_tokens["output"]
            ))

            print(f"\n{'─'*60}")
            print(f"🔒 AetherGuard Evaluation: {self.name} (agent: {agent_id})")
            print(f"   Verdict: {result.verdict.value}")
            print(f"   Allowed: {result.allowed}")
            if result.violations:
                print(f"   Violations: {[v.value for v in result.violations]}")
            if result.hitl_request_id:
                print(f"   HITL Request: {result.hitl_request_id}")
            if result.aethersign:
                print(f"   AetherSign: {result.aethersign[:30]}...")
            print(f"{'─'*60}\n")

            if result.allowed:
                return _execute_and_scan(original_run, self, session, self.name, *args, **kwargs)
            elif result.verdict.value == "PENDING":
                # Wait for human approval — poll every 3 seconds
                print(f"   ⏳ Waiting for human approval (poll every 3s, timeout 120s)...")
                print(f"   📋 Approve via web portal or API: POST /api/v1/agents/approvals/{result.hitl_request_id}/decide")
                approval_result = _wait_for_approval(result.hitl_request_id)
                if approval_result == "APPROVED":
                    print(f"   ✅ APPROVED — executing tool")
                    return _execute_and_scan(original_run, self, session, self.name, *args, **kwargs)
                else:
                    return (
                        f"🚫 DENIED: Human operator denied this action.\n"
                        f"   Decision: {approval_result}\n"
                        f"   The tool call was not executed."
                    )
            else:
                violations = [v.value for v in result.violations]
                return (
                    f"🚫 BLOCKED by AetherGuard: {violations}\n"
                    f"   This tool call was denied by security controls."
                )

        tool_class._run = secured_run
        return tool_class

    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Tool 1: Run Analysis Script (ALLOW path — no HITL)
# ─────────────────────────────────────────────────────────────────────────────

@aetherguard_secured("data-analyst-v1")
class RunAnalysisScriptTool(BaseTool):
    name: str = "run_analysis_script"
    description: str = "Execute a Python data analysis script and return results"

    def _run(self, script_name: str = "q3_analysis.py", dataset: str = "sales_q3") -> str:
        """Simulate running an analysis script."""
        print(f"   📊 Executing script: {script_name} on dataset: {dataset}")
        time.sleep(0.5)  # Simulate processing

        # Simulated results
        return (
            f"Analysis Results ({script_name}):\n"
            f"- Total revenue: $2.4M (+12% YoY)\n"
            f"- Active customers: 1,847\n"
            f"- Top product: Enterprise Plan (62% of revenue)\n"
            f"- Churn rate: 3.2% (down from 4.1%)\n"
            f"- Dataset: {dataset} | Records processed: 48,291"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Tool 2: Process Refund (PENDING path — requires HITL approval)
# ─────────────────────────────────────────────────────────────────────────────

@aetherguard_secured("payment-processor-v1")
class ProcessRefundTool(BaseTool):
    name: str = "process_refund"
    description: str = "Process a customer refund. Requires human approval before execution."

    def _run(self, order_id: str = "ORD-7891", amount: float = 149.99, reason: str = "damaged") -> str:
        """Process the refund (only executes after HITL approval)."""
        print(f"   💰 Processing refund: {order_id} for ${amount}")
        time.sleep(0.3)

        return (
            f"Refund Processed:\n"
            f"- Order: {order_id}\n"
            f"- Amount: ${amount}\n"
            f"- Reason: {reason}\n"
            f"- Status: COMPLETED\n"
            f"- Reference: REF-{int(time.time())}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI Agents (LLM calls use Google Gemini)
# ─────────────────────────────────────────────────────────────────────────────

# LLM instance backed by the Google Gemini API via CrewAI/LiteLLM.
aetherguard_llm = LLM(
    model=GEMINI_MODEL,
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    api_key=GEMINI_API_KEY,
)

analyst_agent = Agent(
    role="Data Analyst",
    goal="Run the Q3 data analysis script and summarise key findings",
    backstory=(
        "You are a senior data analyst responsible for quarterly performance reports. "
        "You have access to the run_analysis_script tool to execute pre-approved Python scripts."
    ),
    tools=[RunAnalysisScriptTool()],
    #step_callback=track_tokens("data-analyst-v1"),
    llm=aetherguard_llm,
    verbose=True,
)

payment_agent = Agent(
    role="Payment Operations Specialist",
    goal="Process the customer refund for order ORD-7891",
    backstory=(
        "You handle customer refund requests. All payment operations require "
        "human approval before execution due to financial compliance requirements."
    ),
    tools=[ProcessRefundTool()],
    #step_callback=track_tokens("payment-processor-v1"),
    llm=aetherguard_llm,
    verbose=True,
)


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI Tasks
# ─────────────────────────────────────────────────────────────────────────────

analysis_task = Task(
    description=(
        "Run the Q3 data analysis script (q3_analysis.py) on the sales_q3 dataset. "
        "Report the key findings including revenue, customer count, and churn rate."
    ),
    expected_output="A summary of Q3 analysis results with key metrics",
    agent=analyst_agent,
)

refund_task = Task(
    description=(
        "Process a refund of $149.99 for order ORD-7891. "
        "The customer received a damaged product and has requested a full refund."
    ),
    expected_output="Confirmation that the refund was processed or is pending approval",
    agent=payment_agent,
)


# ─────────────────────────────────────────────────────────────────────────────
# Deregister Agents
# ─────────────────────────────────────────────────────────────────────────────

async def deregister_agents():
    """Deregister all agents at the end of execution (soft-delete: sets active=False)."""
    agent_ids = ["data-analyst-v1", "payment-processor-v1"]

    print("\n" + "─" * 60)
    print("  Deregistering agents")
    print("─" * 60)

    for agent_id in agent_ids:
        try:
            deregistered = await ag.deregister_agent(
                agent_id=agent_id,
                tenant_id=TENANT_ID,
            )
            print(f"  ✅ Deregistered: {deregistered.agent_id} (active={deregistered.active})")
        except AgentNotFoundError:
            print(f"  ℹ️  {agent_id} not found — skipping")
        except Exception as e:
            print(f"  ⚠️  Failed to deregister {agent_id}: {e}")

    print("─" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  AetherGuard + CrewAI + Google Gemini Integration Example")
    print("  2 agents | 2 tasks | 2 tools | HITL + script execution")
    print("=" * 70)
    print()

    try:
        # Setup AetherGuard (register agents, start sessions)
        run_async(setup_aetherguard())
        print()

        # Create and run the crew
        crew = Crew(
            agents=[analyst_agent, payment_agent],
            tasks=[analysis_task, refund_task],
            verbose=True,
        )

        print("\n" + "=" * 70)
        print("  Starting Crew Execution")
        print("=" * 70 + "\n")

        result = crew.kickoff()

        print("\n" + "=" * 70)
        print("  Crew Execution Complete")
        print("=" * 70)
        print(f"\nFinal Output:\n{result}")

        # Deregister agents after execution
        run_async(deregister_agents())

    except Exception as e:
        print(f"\n❌ Error during execution: {e}")
    finally:
        # Cleanup (ends all sessions, closes connections)
        if ag:
            run_async(ag.close())


if __name__ == "__main__":
    main()
