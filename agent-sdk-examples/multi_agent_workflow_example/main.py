"""
Comprehensive LangChain / LangGraph multi-agent workflow.

Reference behavior preserved:
- Agent-specific responsibilities
- Tool-based execution
- AetherGuard agent registration
- Per-agent AetherGuard sessions
- Pre-tool security evaluation
- HITL approval for payment actions
- Post-tool output scanning

Install:
pip install langchain langchain-openai langgraph python-dotenv httpx
"""

import os
import time
import asyncio
from typing import Any, Optional, TypedDict, Literal

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END

from aetherguard_agent_security import (
    AetherGuard,
    CapabilityProfile,
    TokenBudget,
    AgentNotFoundError,
)
from aetherguard_agent_security.controls.registry import compute_capability_hash


load_dotenv()


# =============================================================================
# Config
# =============================================================================

AETHERGUARD_API_URL = os.getenv("AETHERGUARD_API_URL", "http://localhost:8081")
AETHERGUARD_API_KEY = os.getenv("AETHERGUARD_API_KEY", "ag_test_key_12345")
TENANT_ID = os.getenv("AETHERGUARD_TENANT_ID", "demo-tenant")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

AETHERGUARD_ML_SCAN = os.getenv("AETHERGUARD_ML_SCAN", "true").lower() in {
    "true",
    "1",
    "yes",
}

_loop = asyncio.new_event_loop()
asyncio.set_event_loop(_loop)

ag: Optional[AetherGuard] = None
sessions: dict[str, Any] = {}


def run_async(coro):
    return _loop.run_until_complete(coro)


# =============================================================================
# HITL
# =============================================================================

def wait_for_approval(
    request_id: str,
    timeout: int = 120,
    poll_interval: int = 3,
) -> str:
    import httpx

    headers = {"Authorization": f"Bearer {AETHERGUARD_API_KEY}"}
    url = f"{AETHERGUARD_API_URL}/api/v1/agents/approvals/{request_id}/status"

    elapsed = 0

    while elapsed < timeout:
        time.sleep(poll_interval)
        elapsed += poll_interval

        try:
            response = httpx.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                status = response.json().get("status", "AWAITING_APPROVAL")
                if status != "AWAITING_APPROVAL":
                    return status
        except Exception as exc:
            print(f"HITL polling error: {exc}")

    return "TIMED_OUT"


# =============================================================================
# AetherGuard Setup
# =============================================================================

async def ensure_agent_profile(profile: CapabilityProfile) -> None:
    if ag is None:
        raise RuntimeError("AetherGuard is not initialized")

    desired_hash = compute_capability_hash(profile)

    try:
        existing = await ag.get_agent(profile.agent_id, profile.tenant_id)
    except AgentNotFoundError:
        await ag.register_agent(profile)
        print(f"Registered agent: {profile.agent_id}")
        return

    if not existing["active"]:
        await ag.reactivate_agent(profile.agent_id, profile.tenant_id)

    existing_hash = existing.get("capability_hash") or ""

    if existing_hash != desired_hash:
        await ag.update_agent_profile(profile)
        print(f"Updated profile: {profile.agent_id}")


async def setup_aetherguard() -> None:
    global ag

    ag = await AetherGuard.init(
        api_url=AETHERGUARD_API_URL,
        api_key=AETHERGUARD_API_KEY,
    )

    profiles = [
        CapabilityProfile(
            agent_id="supervisor-v1",
            agent_name="Supervisor Agent",
            tenant_id=TENANT_ID,
            permitted_tools=[],
            data_classifications=["internal"],
            permitted_destinations=[],
            max_tool_calls=0,
            max_session_secs=600,
            requires_human_approval=False,
            intent_threshold=0.0,
            allow_external_network=False,
            output_scanning_enabled=True,
            loop_detection_enabled=True,
        ),
        CapabilityProfile(
            agent_id="planner-v1",
            agent_name="Planning Agent",
            tenant_id=TENANT_ID,
            permitted_tools=[],
            data_classifications=["internal"],
            permitted_destinations=[],
            max_tool_calls=0,
            max_session_secs=600,
            requires_human_approval=False,
            intent_threshold=0.0,
            allow_external_network=False,
            output_scanning_enabled=True,
            loop_detection_enabled=True,
        ),
        CapabilityProfile(
            agent_id="data-analyst-v1",
            agent_name="Data Analyst Agent",
            tenant_id=TENANT_ID,
            permitted_tools=["read_dataset", "run_analysis_script"],
            data_classifications=["internal"],
            permitted_destinations=[],
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
        ),
        CapabilityProfile(
            agent_id="refund-investigator-v1",
            agent_name="Refund Investigator Agent",
            tenant_id=TENANT_ID,
            permitted_tools=["get_order_details"],
            data_classifications=["internal", "pii"],
            permitted_destinations=[],
            max_tool_calls=10,
            max_session_secs=600,
            requires_human_approval=False,
            intent_threshold=0.0,
            allow_external_network=False,
            output_scanning_enabled=True,
            loop_detection_enabled=True,
        ),
        CapabilityProfile(
            agent_id="payment-processor-v1",
            agent_name="Payment Processor Agent",
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
        ),
        CapabilityProfile(
            agent_id="compliance-v1",
            agent_name="Compliance Agent",
            tenant_id=TENANT_ID,
            permitted_tools=[],
            data_classifications=["internal", "financial", "pii"],
            permitted_destinations=[],
            max_tool_calls=0,
            max_session_secs=600,
            requires_human_approval=False,
            hitl_timeout_secs=120,
            intent_threshold=0.0,
            allow_external_network=False,
            output_scanning_enabled=True,
            loop_detection_enabled=True,
        ),
        CapabilityProfile(
            agent_id="report-writer-v1",
            agent_name="Report Writer Agent",
            tenant_id=TENANT_ID,
            permitted_tools=[],
            data_classifications=["internal"],
            permitted_destinations=[],
            max_tool_calls=0,
            max_session_secs=600,
            requires_human_approval=False,
            intent_threshold=0.0,
            allow_external_network=False,
            output_scanning_enabled=True,
            loop_detection_enabled=True,
        ),
    ]

    for profile in profiles:
        await ensure_agent_profile(profile)

    for profile in profiles:
        sessions[profile.agent_id] = await ag.start_session(
            agent_id=profile.agent_id,
            tenant_id=TENANT_ID,
            declared_intent=f"Execute role-specific workflow for {profile.agent_name}",
        )


async def deregister_agents() -> None:
    if ag is None:
        return

    for agent_id in list(sessions.keys()):
        try:
            await ag.deregister_agent(agent_id=agent_id, tenant_id=TENANT_ID)
        except AgentNotFoundError:
            pass


# =============================================================================
# Secured Tool Execution
# =============================================================================

def secured_tool_call(
    agent_id: str,
    tool_name: str,
    params: dict[str, Any],
    executor,
) -> str:
    if ag is None:
        return "AetherGuard is not initialized."

    session = sessions.get(agent_id)
    if session is None:
        return f"No active AetherGuard session for {agent_id}."

    evaluation = run_async(
        ag.evaluate_tool_call(
            session_id=session.session_id,
            tenant_id=session.tenant_id,
            tool=tool_name,
            params=params,
            reasoning=f"LangGraph tool execution: {tool_name}",
        )
    )

    print("=" * 70)
    print(f"AetherGuard evaluation | agent={agent_id} | tool={tool_name}")
    print(f"Verdict: {evaluation.verdict.value}")
    print(f"Allowed: {evaluation.allowed}")
    if evaluation.violations:
        print(f"Violations: {[v.value for v in evaluation.violations]}")
    if evaluation.hitl_request_id:
        print(f"HITL request: {evaluation.hitl_request_id}")
    print("=" * 70)

    if evaluation.allowed:
        raw_output = executor()

    elif evaluation.verdict.value == "PENDING":
        approval_status = wait_for_approval(evaluation.hitl_request_id)

        if approval_status != "APPROVED":
            return (
                "Payment action was not executed.\n"
                f"HITL decision: {approval_status}"
            )

        raw_output = executor()

    else:
        return (
            "Tool call blocked by AetherGuard.\n"
            f"Violations: {[v.value for v in evaluation.violations]}"
        )

    scan = run_async(
        ag.scan_output_hybrid(
            session_id=session.session_id,
            tenant_id=session.tenant_id,
            tool=tool_name,
            output=str(raw_output),
            ml_scan=AETHERGUARD_ML_SCAN,
        )
    )

    if scan.get("blocked"):
        return (
            "Output blocked by AetherGuard.\n"
            f"Violations: {scan.get('violations', [])}"
        )

    return scan.get("output", raw_output)


# =============================================================================
# Tools
# =============================================================================

@tool
def read_dataset(dataset: str = "sales_q3") -> str:
    """Read metadata for an internal dataset."""

    def execute():
        return (
            f"Dataset loaded: {dataset}\n"
            "Rows: 48,291\n"
            "Columns: order_id, customer_id, plan, revenue, churned, region"
        )

    return secured_tool_call(
        agent_id="data-analyst-v1",
        tool_name="read_dataset",
        params={"dataset": dataset},
        executor=execute,
    )


@tool
def run_analysis_script(
    script_name: str = "q3_analysis.py",
    dataset: str = "sales_q3",
) -> str:
    """Run an approved analysis script."""

    def execute():
        time.sleep(0.5)
        return (
            f"Analysis Results ({script_name})\n"
            "- Total revenue: $2.4M (+12% YoY)\n"
            "- Active customers: 1,847\n"
            "- Top product: Enterprise Plan, 62% of revenue\n"
            "- Churn rate: 3.2%, down from 4.1%\n"
            f"- Dataset: {dataset}"
        )

    return secured_tool_call(
        agent_id="data-analyst-v1",
        tool_name="run_analysis_script",
        params={
            "script_name": script_name,
            "dataset": dataset,
        },
        executor=execute,
    )


@tool
def get_order_details(order_id: str = "ORD-7891") -> str:
    """Retrieve order details before deciding whether a refund is valid."""

    def execute():
        return (
            f"Order Details\n"
            f"- Order ID: {order_id}\n"
            "- Customer status: verified\n"
            "- Product condition report: damaged on arrival\n"
            "- Payment status: captured\n"
            "- Refund eligibility: eligible\n"
            "- Recommended refund: $149.99"
        )

    return secured_tool_call(
        agent_id="refund-investigator-v1",
        tool_name="get_order_details",
        params={"order_id": order_id},
        executor=execute,
    )


@tool
def process_refund(
    order_id: str = "ORD-7891",
    amount: float = 149.99,
    reason: str = "damaged product",
) -> str:
    """Process a refund. This requires human approval."""

    def execute():
        time.sleep(0.3)
        return (
            "Refund Processed\n"
            f"- Order ID: {order_id}\n"
            f"- Amount: ${amount}\n"
            f"- Reason: {reason}\n"
            "- Status: COMPLETED\n"
            f"- Reference: REF-{int(time.time())}"
        )

    return secured_tool_call(
        agent_id="payment-processor-v1",
        tool_name="process_refund",
        params={
            "order_id": order_id,
            "amount": amount,
            "reason": reason,
        },
        executor=execute,
    )


# =============================================================================
# LLM
# =============================================================================

llm = ChatOpenAI(
    model=OPENAI_MODEL,
    api_key=OPENAI_API_KEY,
    temperature=0,
)


analyst_llm = llm.bind_tools([read_dataset, run_analysis_script])
investigator_llm = llm.bind_tools([get_order_details])
payment_llm = llm.bind_tools([process_refund])


# =============================================================================
# State
# =============================================================================

class WorkflowState(TypedDict):
    user_request: str
    plan: Optional[str]
    analysis_result: Optional[str]
    order_result: Optional[str]
    compliance_result: Optional[str]
    refund_result: Optional[str]
    final_report: Optional[str]
    next_step: Optional[str]
    errors: list[str]


# =============================================================================
# Agent Nodes
# =============================================================================

def supervisor_agent(state: WorkflowState) -> WorkflowState:
    """
    Routes the workflow.

    This is intentionally deterministic because the requested reference workflow
    has a fixed business process:
    plan -> analyze -> investigate -> compliance -> payment -> report
    """

    if not state.get("plan"):
        next_step = "planner"

    elif not state.get("analysis_result"):
        next_step = "data_analyst"

    elif not state.get("order_result"):
        next_step = "refund_investigator"

    elif not state.get("compliance_result"):
        next_step = "compliance"

    elif "APPROVED_FOR_REFUND" in state.get("compliance_result", "") and not state.get("refund_result"):
        next_step = "payment_processor"

    elif not state.get("final_report"):
        next_step = "report_writer"

    else:
        next_step = "end"

    return {
        **state,
        "next_step": next_step,
    }


def planner_agent(state: WorkflowState) -> WorkflowState:
    response = llm.invoke(
        [
            SystemMessage(
                content=(
                    "You are the Planning Agent. Break the user request into "
                    "safe operational steps. Do not execute tools."
                )
            ),
            HumanMessage(content=state["user_request"]),
        ]
    )

    return {
        **state,
        "plan": response.content,
    }


def data_analyst_agent(state: WorkflowState) -> WorkflowState:
    response = analyst_llm.invoke(
        [
            SystemMessage(
                content=(
                    "You are the Data Analyst Agent. "
                    "Read the dataset, then run the approved Q3 analysis script. "
                    "Use tools when needed."
                )
            ),
            HumanMessage(content=state["user_request"]),
        ]
    )

    outputs = []

    for call in response.tool_calls:
        if call["name"] == "read_dataset":
            outputs.append(read_dataset.invoke(call["args"]))
        elif call["name"] == "run_analysis_script":
            outputs.append(run_analysis_script.invoke(call["args"]))

    if not outputs:
        outputs.append(response.content)

    return {
        **state,
        "analysis_result": "\n\n".join(outputs),
    }


def refund_investigator_agent(state: WorkflowState) -> WorkflowState:
    response = investigator_llm.invoke(
        [
            SystemMessage(
                content=(
                    "You are the Refund Investigator Agent. "
                    "Verify the order and determine refund eligibility. "
                    "Use get_order_details."
                )
            ),
            HumanMessage(content=state["user_request"]),
        ]
    )

    outputs = []

    for call in response.tool_calls:
        if call["name"] == "get_order_details":
            outputs.append(get_order_details.invoke(call["args"]))

    if not outputs:
        outputs.append(response.content)

    return {
        **state,
        "order_result": "\n\n".join(outputs),
    }


def compliance_agent(state: WorkflowState) -> WorkflowState:
    response = llm.invoke(
        [
            SystemMessage(
                content=(
                    "You are the Compliance Agent. "
                    "Review the analysis and order investigation. "
                    "Decide whether the refund should proceed. "
                    "Return exactly one of these decision markers:\n"
                    "APPROVED_FOR_REFUND\n"
                    "REJECTED_FOR_REFUND\n\n"
                    "Then provide a short explanation."
                )
            ),
            HumanMessage(
                content=(
                    f"User request:\n{state['user_request']}\n\n"
                    f"Analysis result:\n{state.get('analysis_result')}\n\n"
                    f"Order investigation:\n{state.get('order_result')}"
                )
            ),
        ]
    )

    return {
        **state,
        "compliance_result": response.content,
    }


def payment_processor_agent(state: WorkflowState) -> WorkflowState:
    response = payment_llm.invoke(
        [
            SystemMessage(
                content=(
                    "You are the Payment Processor Agent. "
                    "Only process the refund if compliance approved it. "
                    "Use process_refund with order_id ORD-7891, amount 149.99, "
                    "reason damaged product."
                )
            ),
            HumanMessage(
                content=(
                    f"Compliance decision:\n{state.get('compliance_result')}\n\n"
                    f"Original request:\n{state['user_request']}"
                )
            ),
        ]
    )

    outputs = []

    for call in response.tool_calls:
        if call["name"] == "process_refund":
            outputs.append(process_refund.invoke(call["args"]))

    if not outputs:
        outputs.append(response.content)

    return {
        **state,
        "refund_result": "\n\n".join(outputs),
    }


def report_writer_agent(state: WorkflowState) -> WorkflowState:
    response = llm.invoke(
        [
            SystemMessage(
                content=(
                    "You are the Report Writer Agent. "
                    "Produce a concise final operational report."
                )
            ),
            HumanMessage(
                content=(
                    f"Plan:\n{state.get('plan')}\n\n"
                    f"Analysis:\n{state.get('analysis_result')}\n\n"
                    f"Order investigation:\n{state.get('order_result')}\n\n"
                    f"Compliance:\n{state.get('compliance_result')}\n\n"
                    f"Refund:\n{state.get('refund_result')}"
                )
            ),
        ]
    )

    return {
        **state,
        "final_report": response.content,
    }


# =============================================================================
# Routing
# =============================================================================

def route_from_supervisor(state: WorkflowState) -> str:
    next_step = state["next_step"]

    if next_step == "planner":
        return "planner"

    if next_step == "data_analyst":
        return "data_analyst"

    if next_step == "refund_investigator":
        return "refund_investigator"

    if next_step == "compliance":
        return "compliance"

    if next_step == "payment_processor":
        return "payment_processor"

    if next_step == "report_writer":
        return "report_writer"

    return END


def build_workflow():
    graph = StateGraph(WorkflowState)

    graph.add_node("supervisor", supervisor_agent)
    graph.add_node("planner", planner_agent)
    graph.add_node("data_analyst", data_analyst_agent)
    graph.add_node("refund_investigator", refund_investigator_agent)
    graph.add_node("compliance", compliance_agent)
    graph.add_node("payment_processor", payment_processor_agent)
    graph.add_node("report_writer", report_writer_agent)

    graph.set_entry_point("supervisor")

    graph.add_conditional_edges("supervisor", route_from_supervisor)

    graph.add_edge("planner", "supervisor")
    graph.add_edge("data_analyst", "supervisor")
    graph.add_edge("refund_investigator", "supervisor")
    graph.add_edge("compliance", "supervisor")
    graph.add_edge("payment_processor", "supervisor")
    graph.add_edge("report_writer", "supervisor")

    return graph.compile()


# =============================================================================
# Main
# =============================================================================

def main():
    try:
        run_async(setup_aetherguard())

        workflow = build_workflow()

        result = workflow.invoke(
            {
                "user_request": (
                    "Run Q3 data analysis on sales_q3 and process a refund "
                    "of $149.99 for order ORD-7891 because the product arrived damaged."
                ),
                "plan": None,
                "analysis_result": None,
                "order_result": None,
                "compliance_result": None,
                "refund_result": None,
                "final_report": None,
                "next_step": None,
                "errors": [],
            }
        )

        print("\n" + "=" * 80)
        print("FINAL REPORT")
        print("=" * 80)
        print(result["final_report"])

    except Exception as exc:
        print(f"\n❌ Workflow error: {exc}")

    finally:
        if ag is not None:
            try:
                run_async(deregister_agents())
            except Exception as exc:
                print(f"⚠️  Deregistration error: {exc}")
            try:
                run_async(ag.close())
            except Exception as exc:
                print(f"⚠️  Cleanup error: {exc}")


if __name__ == "__main__":
    main()