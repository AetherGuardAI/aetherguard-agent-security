import asyncio
import functools
import inspect
import os
from typing import Any, Literal

import httpx
from dotenv import load_dotenv
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from typing_extensions import Annotated, TypedDict

from aetherguard_agent_security import (
    AetherGuard,
    AgentNotFoundError,
    CapabilityProfile,
    TokenBudget,
)
from aetherguard_agent_security.controls.registry import compute_capability_hash


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

load_dotenv()

AETHERGUARD_API_URL = os.getenv("AETHERGUARD_API_URL", "http://localhost:8081")
AETHERGUARD_API_KEY = os.getenv("AETHERGUARD_API_KEY", "ag_test_key_12345")
TENANT_ID = os.getenv("AETHERGUARD_TENANT_ID", "demo-tenant")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL") or os.getenv("AETHERGUARD_PROXY_URL")

AETHERGUARD_ML_SCAN = os.getenv("AETHERGUARD_ML_SCAN", "true").lower() in (
    "true",
    "1",
    "yes",
)


# -----------------------------------------------------------------------------
# Runtime globals
# -----------------------------------------------------------------------------

ag: AetherGuard | None = None
sessions: dict[str, object] = {}


# -----------------------------------------------------------------------------
# HITL Approval Polling
# -----------------------------------------------------------------------------

async def wait_for_approval(
    request_id: str,
    timeout: int = 120,
    poll_interval: int = 3,
) -> str:
    headers = {"Authorization": f"Bearer {AETHERGUARD_API_KEY}"}
    base = AETHERGUARD_API_URL.rstrip("/") + "/"
    url = f"{base}api/v1/agents/approvals/{request_id}/status"

    elapsed = 0

    async with httpx.AsyncClient(timeout=5.0) as client:
        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            try:
                resp = await client.get(url, headers=headers)

                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("status", "AWAITING_APPROVAL")

                    if status != "AWAITING_APPROVAL":
                        return status

            except Exception as exc:
                print(f"   ⚠ Poll error: {exc}")

            print(f"   ⏳ Still waiting... ({timeout - elapsed}s remaining)")

    return "TIMED_OUT"


# -----------------------------------------------------------------------------
# AetherGuard setup
# -----------------------------------------------------------------------------

async def ensure_agent_profile(profile: CapabilityProfile) -> None:
    """Idempotently register, reactivate, or update an agent profile."""
    if ag is None:
        raise RuntimeError("AetherGuard is not initialized")

    desired_hash = compute_capability_hash(profile)

    try:
        agent_info = await ag.get_agent(profile.agent_id, profile.tenant_id)
    except AgentNotFoundError:
        await ag.register_agent(profile)
        print(f"✅ Registered: {profile.agent_id}")
        return

    if not agent_info["active"]:
        await ag.reactivate_agent(profile.agent_id, profile.tenant_id)
        print(f"✅ Reactivated: {profile.agent_id}")

    existing_hash = agent_info.get("capability_hash") or ""

    if existing_hash == desired_hash:
        print(f"ℹ️  Profile unchanged: {profile.agent_id}")
        return

    await ag.update_agent_profile(profile)
    print(f"✅ Updated profile: {profile.agent_id}")

async def setup_aetherguard() -> None:
    global ag

    ag = await AetherGuard.init(
        api_url=AETHERGUARD_API_URL,
        api_key=AETHERGUARD_API_KEY,
    )

    analyst_profile = CapabilityProfile(
        agent_id="data-analyst-v1",
        agent_name="Data Analyst",
        tenant_id=TENANT_ID,
        permitted_tools=["run_analysis_script", "read_dataset"],
        data_classifications=["internal"],
        max_tool_calls=20,
        max_session_secs=600,
        requires_human_approval=False,
        intent_threshold=0.0,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(
            max_total_tokens=50000,
            max_tokens_per_step=10000,
        ),
    )

    payment_profile = CapabilityProfile(
        agent_id="payment-processor-v1",
        agent_name="Payment Processor",
        tenant_id=TENANT_ID,
        permitted_tools=["process_refund", "get_order_details"],
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

    print("✅ AetherGuard sessions initialized")


# -----------------------------------------------------------------------------
# AetherGuard secured decorator
# -----------------------------------------------------------------------------

def _bind_params(func, args: tuple, kwargs: dict) -> dict:
    signature = inspect.signature(func)
    bound = signature.bind_partial(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)


async def _scan_output(session, tool_name: str, raw_output: Any) -> Any:
    if ag is None:
        raise RuntimeError("AetherGuard is not initialized")

    scan_result = await ag.scan_output_hybrid(
        session_id=session.session_id,
        tenant_id=session.tenant_id,
        tool=tool_name,
        output=str(raw_output),
        ml_scan=AETHERGUARD_ML_SCAN,
    )

    if scan_result.get("blocked"):
        return f"🛡️ OUTPUT BLOCKED by AetherGuard: {scan_result.get('violations', [])}"

    return scan_result.get("output", raw_output)


def aetherguard_secured(agent_id: str):
    def decorator(func):
        if not inspect.iscoroutinefunction(func):
            raise TypeError("aetherguard_secured expects async functions")

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            if ag is None:
                raise RuntimeError("AetherGuard not initialized")

            session = sessions.get(agent_id)

            if not session:
                return f"🚫 No active session for {agent_id}"

            tool_name = func.__name__
            params = _bind_params(func, args, kwargs)

            evaluation = await ag.evaluate_tool_call(
                session_id=session.session_id,
                tenant_id=session.tenant_id,
                tool=tool_name,
                params=params,
                reasoning=func.__doc__ or tool_name,
            )

            print(f"\n{'─' * 60}")
            print(
                f"🔒 AetherGuard: {tool_name} | "
                f"{agent_id} | {evaluation.verdict.value}"
            )
            print(f"{'─' * 60}\n")

            if not evaluation.allowed:
                if evaluation.verdict.value == "PENDING":
                    print("   ⏳ Waiting for human approval...")

                    approval = await wait_for_approval(
                        evaluation.hitl_request_id
                    )

                    if approval != "APPROVED":
                        return f"🚫 DENIED by human: {approval}"

                else:
                    return f"🚫 BLOCKED by AetherGuard: {evaluation.violations}"

            raw_output = await func(*args, **kwargs)

            return await _scan_output(session, tool_name, raw_output)

        return wrapper

    return decorator


# -----------------------------------------------------------------------------
# Tools
# -----------------------------------------------------------------------------

@tool
@aetherguard_secured("data-analyst-v1")
async def run_analysis_script(
    script_name: str = "q3_analysis.py",
    dataset: str = "sales_q3",
) -> str:
    """Execute a Python data analysis script and return quarterly performance results."""
    print(f"   📊 Executing {script_name} on {dataset}")

    await asyncio.sleep(0.5)

    return (
        f"Analysis Results ({script_name}):\n"
        f"- Dataset: {dataset}\n"
        f"- Total revenue: $2.4M\n"
        f"- YoY growth: +12%\n"
        f"- Top region: North America\n"
        f"- Recommendation: Increase inventory for high-growth SKUs"
    )


@tool
@aetherguard_secured("payment-processor-v1")
async def process_refund(
    order_id: str = "ORD-7891",
    amount: float = 149.99,
    reason: str = "damaged product",
) -> str:
    """Process a customer refund. Financial actions require human approval."""
    print(f"   💰 Processing refund for {order_id}")

    await asyncio.sleep(0.3)

    return (
        f"Refund Processed:\n"
        f"- Order ID: {order_id}\n"
        f"- Amount: ${amount}\n"
        f"- Reason: {reason}\n"
        f"- Status: Completed"
    )


ALL_TOOLS = [run_analysis_script, process_refund]


# -----------------------------------------------------------------------------
# Sequential LangGraph State
# -----------------------------------------------------------------------------

class GraphState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    result: str
    stage: str


# -----------------------------------------------------------------------------
# Sequential Graph
# -----------------------------------------------------------------------------

def build_graph():
    openai_llm = ChatOpenAI(
        model=OPENAI_MODEL,
        api_key=OPENAI_API_KEY,
        base_url=OPENAI_BASE_URL,
        temperature=0,
        verbose = True
    )

    tool_node = ToolNode(ALL_TOOLS)

    async def analysis_node(state: GraphState):
        system = SystemMessage(
            content="You are a senior data analyst."
        )

        prompt = HumanMessage(
            content=(
                "Run the Q3 data analysis script q3_analysis.py "
                "on the sales_q3 dataset."
            )
        )

        response = await openai_llm.bind_tools(
            [run_analysis_script]
        ).ainvoke([system, prompt])

        return {
            "messages": [prompt, response],
            "stage": "analysis_done",
        }

    async def refund_node(state: GraphState):
        system = SystemMessage(
            content="You are a payment operations specialist."
        )

        prompt = HumanMessage(
            content=(
                "Process a refund of 149.99 USD for order ORD-7891 "
                "because the product was damaged."
            )
        )

        response = await openai_llm.bind_tools(
            [process_refund]
        ).ainvoke([system, *state["messages"], prompt])

        return {
            "messages": [prompt, response],
            "stage": "refund_done",
        }

    async def final_node(state: GraphState):
        system = SystemMessage(
            content=(
                "You are the final reporting agent. "
                "Summarize the completed workflow clearly."
            )
        )

        prompt = HumanMessage(
            content=(
                "Provide a final summary of the data analysis "
                "and refund process."
            )
        )

        response = await openai_llm.ainvoke(
            [system, *state["messages"], prompt]
        )

        return {
            "messages": [prompt, response],
            "result": response.content,
            "stage": "finished",
        }

    def route_after_tools(state: GraphState) -> Literal["refund", "final", "__end__"]:
        stage = state.get("stage", "")

        if stage == "analysis_done":
            return "refund"

        if stage == "refund_done":
            return "final"

        return "__end__"

    workflow = StateGraph(GraphState)

    workflow.add_node("analysis", analysis_node)
    workflow.add_node("tools", tool_node)
    workflow.add_node("refund", refund_node)
    workflow.add_node("final", final_node)

    workflow.add_edge(START, "analysis")
    workflow.add_edge("analysis", "tools")

    workflow.add_conditional_edges(
        "tools",
        route_after_tools,
        {
            "refund": "refund",
            "final": "final",
            "__end__": END,
        },
    )

    workflow.add_edge("refund", "tools")
    workflow.add_edge("final", END)

    return workflow.compile()


# -----------------------------------------------------------------------------
# Agent deregistration
# -----------------------------------------------------------------------------

async def deregister_agents() -> None:
    """Deregister all agents at the end of execution."""
    if ag is None:
        return

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
            print(
                f"  ✅ Deregistered: {deregistered.agent_id} "
                f"(active={deregistered.active})"
            )
        except AgentNotFoundError:
            print(f"  ℹ️  {agent_id} not found — skipping")
        except Exception as exc:
            print(f"  ⚠️  Failed to deregister {agent_id}: {exc}")

    print("─" * 60)


async def verify_deregistration() -> None:
    """Verify deregistration status through get_agent."""
    if ag is None:
        return

    print("\n" + "─" * 60)
    print("  Verifying deregistration via get_agent")
    print("─" * 60)

    for agent_id in ["data-analyst-v1", "payment-processor-v1"]:
        try:
            info = await ag.get_agent(agent_id, TENANT_ID)
            print(f"  {agent_id}: status={info['status']} active={info['active']}")
        except AgentNotFoundError:
            print(f"  {agent_id}: NOT FOUND")
        except Exception as exc:
            print(f"  {agent_id}: error — {exc}")

    print("─" * 60)

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

async def async_main():
    print("=" * 80)
    print("AetherGuard + Sequential LangGraph + OpenAI")
    print("=" * 80)

    try:
        await setup_aetherguard()

        graph = build_graph()

        print("\n🚀 Starting sequential workflow...\n")

        result = await graph.ainvoke(
            {
                "messages": [],
                "result": "",
                "stage": "",
            }
        )

        print("\n" + "=" * 80)
        print("✅ Final Output:")
        print("=" * 80)
        print(result.get("result", "No result"))

        await deregister_agents()
        await verify_deregistration()

    except Exception as exc:
        print(f"\n❌ Error during execution: {exc}")
    finally:
        await cleanup()

async def cleanup():
    global ag

    if ag:
        await ag.close()
        ag = None


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()