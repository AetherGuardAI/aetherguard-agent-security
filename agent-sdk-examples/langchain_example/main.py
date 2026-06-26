"""
AetherGuard + LangChain + OpenAI Integration Example (Cleaned)
"""
import asyncio
import os
import time

from dotenv import load_dotenv
from pydantic import BaseModel, Field

from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain.tools import BaseTool
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from aetherguard_agent_security import (
    AetherGuard,
    CapabilityProfile,
    TokenBudget,
    AgentNotFoundError,
)
from aetherguard_agent_security.controls.registry import compute_capability_hash


load_dotenv()

# ========================= CONFIG =========================
AETHERGUARD_API_URL = os.getenv("AETHERGUARD_API_URL", "http://localhost:8081")
AETHERGUARD_API_KEY = os.environ["AETHERGUARD_API_KEY"]
AETHERGUARD_PROXY_URL = os.getenv("AETHERGUARD_PROXY_URL", "http://localhost:8080/v1")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
TENANT_ID = os.getenv("AETHERGUARD_TENANT_ID", "demo-tenant")
AETHERGUARD_ML_SCAN = os.getenv("AETHERGUARD_ML_SCAN", "true").lower() in ("true", "1", "yes")

# ========================= ASYNC SETUP =========================
_loop = asyncio.new_event_loop()
asyncio.set_event_loop(_loop)


def run_async(coro):
    """Run an async coroutine on the persistent event loop."""
    return _loop.run_until_complete(coro)


# ========================= HITL HELPER =========================
def _wait_for_approval(request_id: str, timeout: int = 120, poll_interval: int = 3) -> str:
    """Poll the HITL approval status until decided or timed out."""
    import httpx

    headers = {"Authorization": f"Bearer {AETHERGUARD_API_KEY}"}
    base = AETHERGUARD_API_URL.rstrip("/") + "/"
    url = f"{base}api/v1/agents/approvals/{request_id}/status"
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
                print("   ⚠ Approval request not found, may be tenant mismatch")
            else:
                print(f"   ⚠ Poll returned {resp.status_code}: {resp.text[:100]}")
        except Exception as exc:
            print(f"   ⚠ Poll error: {exc}")

        remaining = timeout - elapsed
        print(f"   ⏳ Still waiting... ({remaining}s remaining)")

    return "TIMED_OUT"


# ========================= AETHERGUARD GLOBALS =========================
ag = None
sessions: dict[str, object] = {}
evaluations: dict[tuple[str, str], list[object]] = {}


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

    ag = await AetherGuard.init(
        api_url=AETHERGUARD_API_URL,
        api_key=AETHERGUARD_API_KEY,
    )

    analyst_profile = CapabilityProfile(
        agent_id="data-analyst-v1",
        agent_name="Data Analyst",
        tenant_id=TENANT_ID,
        permitted_tools=["run_analysis_script"],
        data_classifications=["internal"],
        max_tool_calls=20,
        max_session_secs=600,
        requires_human_approval=False,
        intent_threshold=0.0,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=50000, max_tokens_per_step=10000),
    )

    payment_profile = CapabilityProfile(
        agent_id="payment-processor-v1",
        agent_name="Payment Processor",
        tenant_id=TENANT_ID,
        permitted_tools=["process_refund"],
        data_classifications=["financial", "pii"],
        permitted_destinations=["payments.internal"],
        max_tool_calls=5,
        max_session_secs=300,
        requires_human_approval=True,
        hitl_timeout_secs=120,
        intent_threshold=0.0,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
    )

    for profile in [analyst_profile, payment_profile]:
        try:
            await ensure_agent_profile(profile)
        except Exception as exc:
            print(f"⚠️  Profile setup error for {profile.agent_id}: {exc}")
            print(f"   Deregistering agent {profile.agent_id} due to setup failure...")
            try:
                await ag.deregister_agent(
                    agent_id=profile.agent_id,
                    tenant_id=profile.tenant_id,
                )
                print(f"   ✅ Agent {profile.agent_id} deregistered (soft)")
            except AgentNotFoundError:
                print(f"   ℹ️  Agent {profile.agent_id} not found — nothing to deregister")
            except Exception as dereg_exc:
                print(f"   ❌ Deregistration also failed: {dereg_exc}")

    sessions["data-analyst-v1"] = await ag.start_session(
        agent_id="data-analyst-v1",
        declared_intent="Run Q3 data analysis scripts and generate report",
    )
    sessions["payment-processor-v1"] = await ag.start_session(
        agent_id="payment-processor-v1",
        declared_intent="Process customer refund for damaged order",
    )

    print(f"✅ Analyst session: {sessions['data-analyst-v1'].session_id}")
    print(f"✅ Payment session: {sessions['payment-processor-v1'].session_id}")


# ========================= TOOL SECURITY WRAPPER =========================
def _execute_and_scan(original_run, tool_self, session, tool_name, *args, **kwargs):
    """Execute tool and scan output."""
    raw_output = original_run(tool_self, *args, **kwargs)

    scan_result = run_async(
        ag.scan_output_hybrid(
            session_id=session.session_id,
            tenant_id=session.tenant_id,
            tool=tool_name,
            output=str(raw_output),
            ml_scan=AETHERGUARD_ML_SCAN,
        )
    )

    if scan_result.get("blocked"):
        print(f"   🛡️ OUTPUT BLOCKED: {scan_result.get('violations', [])}")
        return f"🛡️ OUTPUT BLOCKED by AetherGuard: {scan_result.get('violations', [])}"

    return scan_result.get("output", raw_output)


def aetherguard_secured(agent_id: str):
    """Decorator that wraps LangChain tool with AetherGuard evaluation."""
    def decorator(tool_class):
        original_run = tool_class._run

        def secured_run(self, *args, **kwargs):
            session = sessions.get(agent_id)
            if not session:
                return f"🚫 ERROR: No active session for agent '{agent_id}'"

            # Evaluate tool call
            result = run_async(
                ag.evaluate_tool_call(
                    session_id=session.session_id,
                    tenant_id=session.tenant_id,
                    tool=self.name,
                    params={"args": args, "kwargs": kwargs},
                    reasoning=f"LangChain tool execution: {self.name}",
                    model=OPENAI_MODEL,
                )
            )

            print(f"\n{'─' * 60}")
            print(f"🔒 AetherGuard Evaluation: {self.name} (agent: {agent_id})")
            print(f"   Verdict: {result.verdict.value} | Allowed: {result.allowed}")
            if result.violations:
                print(f"   Violations: {result.violations}")
            if result.hitl_request_id:
                print(f"   HITL Request ID: {result.hitl_request_id}")
            print(f"{'─' * 60}\n")

            if result.allowed:
                return _execute_and_scan(original_run, self, session, self.name, *args, **kwargs)

            if result.verdict.value == "PENDING":
                print("   ⏳ Waiting for human approval...")
                approval_result = _wait_for_approval(result.hitl_request_id)

                if approval_result == "APPROVED":
                    print("   ✅ APPROVED — executing tool")
                    return _execute_and_scan(original_run, self, session, self.name, *args, **kwargs)
                else:
                    return f"🚫 DENIED by human: {approval_result}"

            return f"🚫 BLOCKED by AetherGuard: {[v.value for v in result.violations] if result.violations else 'Unknown'}"

        tool_class._run = secured_run
        return tool_class

    return decorator


# ========================= TOOLS =========================
class RunAnalysisScriptInput(BaseModel):
    script_name: str = Field(default="q3_analysis.py")
    dataset: str = Field(default="sales_q3")


@aetherguard_secured("data-analyst-v1")
class   RunAnalysisScriptTool(BaseTool):
    name: str = "run_analysis_script"
    description: str = "Execute a Python data analysis script and return results"
    args_schema: type[BaseModel] = RunAnalysisScriptInput

    def _run(self, script_name: str = "q3_analysis.py", dataset: str = "sales_q3") -> str:
        print(f"   📊 Executing script: {script_name} on dataset: {dataset}")
        time.sleep(0.5)
        return (
            f"Analysis Results ({script_name}):\n"
            "- Total revenue: $2.4M (+12% YoY)\n"
            "- Active customers: 1,847\n"
            "- Top product: Enterprise Plan (62% of revenue)\n"
            "- Churn rate: 3.2%\n"
            f"- Dataset: {dataset}"
        )


class ProcessRefundInput(BaseModel):
    order_id: str = Field(..., description="Order ID")
    amount: float = Field(..., description="Refund amount")
    reason: str = Field(default="damaged")


@aetherguard_secured("payment-processor-v1")
class ProcessRefundTool(BaseTool):
    name: str = "process_refund"
    description: str = "Process a customer refund. Requires human approval before execution."
    args_schema: type[BaseModel] = ProcessRefundInput

    def _run(self, order_id: str, amount: float, reason: str = "damaged") -> str:
        print(f"   💰 Processing refund: {order_id} for ${amount}")
        time.sleep(0.3)
        return (
            "Refund Processed:\n"
            f"- Order: {order_id}\n"
            f"- Amount: ${amount}\n"
            f"- Reason: {reason}\n"
            "- Status: COMPLETED"
        )


# ========================= LLM & AGENTS =========================
aetherguard_llm = ChatOpenAI(
    model=OPENAI_MODEL,
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url="https://api.openai.com/v1",
    temperature=0,
    max_tokens=1024,
    max_retries=3,
)

analyst_tools = [RunAnalysisScriptTool()]
payment_tools = [ProcessRefundTool()]

analyst_prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a senior data analyst. Use the run_analysis_script tool to get data and summarize findings."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

payment_prompt = ChatPromptTemplate.from_messages([
    ("system", "You handle refunds. Use the process_refund tool when needed. Human approval is required for payments."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

payment_agent = create_tool_calling_agent(llm=aetherguard_llm, tools=payment_tools, prompt=payment_prompt)
analyst_agent = create_tool_calling_agent(llm=aetherguard_llm, tools=analyst_tools, prompt=analyst_prompt)

analyst_executor = AgentExecutor(
    agent=analyst_agent,
    tools=analyst_tools,
    verbose=True,
    handle_parsing_errors=True,
    max_iterations=10,
)

payment_executor = AgentExecutor(
    agent=payment_agent,
    tools=payment_tools,
    verbose=True,
    handle_parsing_errors=True,
    max_iterations=10,
)

# ========================= TASKS =========================
analysis_task = {
    "description": "Run the Q3 data analysis script q3_analysis.py on the sales_q3 dataset. "
                   "Report the key findings including revenue, customer count, and churn rate.",
    "agent": analyst_executor,
}

refund_task = {
    "description": "Process a refund of $149.99 for order ORD-7891 because the customer received a damaged product.",
    "agent": payment_executor,
}


# ========================= DEREGISTER AGENT =========================
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


# ========================= MAIN =========================
def main():
    print("=" * 80)
    print("  AetherGuard + LangChain + OpenAI Integration")
    
    print("=" * 80)

    try:
        run_async(setup_aetherguard())
        print("\n" + "=" * 80)
        print("  Starting Agent Execution")
        print("=" * 80 + "\n")

        analysis_result = analysis_task["agent"].invoke({"input": analysis_task["description"]})
        refund_result = refund_task["agent"].invoke({"input": refund_task["description"]})

        final_output = f"{analysis_result.get('output', analysis_result)}\n\n{refund_result.get('output', refund_result)}"

        print("\n" + "=" * 80)
        print("  Execution Complete")
        print("=" * 80)
        print(f"\nFinal Output:\n{final_output}")

        # ── Deregister agents after execution ──────────────────────────
        run_async(deregister_agents())

        # ── Verify deregistration via get_agent ──────────────────────────
        print("\n" + "─" * 60)
        print("  Verifying deregistration via get_agent")
        print("─" * 60)
        for agent_id in ["data-analyst-v1", "payment-processor-v1"]:
            try:
                info = run_async(ag.get_agent(agent_id, TENANT_ID))
                print(f"  {agent_id}: status={info['status']} active={info['active']}")
            except AgentNotFoundError:
                print(f"  {agent_id}: NOT FOUND")
            except Exception as e:
                print(f"  {agent_id}: error — {e}")
        print("─" * 60)

    except Exception as e:
        print(f"\n❌ Error during execution: {e}")
    finally:
        if ag:
            run_async(ag.close())


if __name__ == "__main__":
    main()
