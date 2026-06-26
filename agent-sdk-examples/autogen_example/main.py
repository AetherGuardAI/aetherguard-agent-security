"""
AetherGuard + AutoGen Integration Example

AutoGen structure:
- Coordinator Agent: manages workflow
- Data Analyst Agent: runs analysis tool
- Payment Processor Agent: runs refund tool with HITL
- UserProxy Agent: executes registered tools

2 agents + coordinator, 2 tasks, 2 tools.
"""

import asyncio
import functools
import inspect
import os
import sys
import time
from typing import Any

import httpx
from dotenv import load_dotenv

from autogen import (
    AssistantAgent,
    UserProxyAgent,
    GroupChat,
    GroupChatManager,
    register_function,
)

from aetherguard_agent_security import (
    AetherGuard,
    AgentNotFoundError,
    CapabilityProfile,
    TokenBudget,
)
from aetherguard_agent_security.controls.registry import compute_capability_hash

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

AETHERGUARD_API_URL = os.getenv("AETHERGUARD_API_URL", "http://localhost:8081")
AETHERGUARD_API_KEY = os.getenv("AETHERGUARD_API_KEY", "ag_test_key_12345")
AETHERGUARD_PROXY_URL = os.getenv("AETHERGUARD_PROXY_URL", "http://localhost:8080/v1")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
TENANT_ID = os.getenv("AETHERGUARD_TENANT_ID", "demo-tenant")

AETHERGUARD_ML_SCAN = os.getenv("AETHERGUARD_ML_SCAN", "true").lower() in (
    "true",
    "1",
    "yes",
)

_loop = asyncio.new_event_loop()


def run_async(coro):
    return _loop.run_until_complete(coro)


ag: AetherGuard | None = None
sessions: dict[str, object] = {}
workflow_state = {
    "analysis_done": False,
    "refund_done": False,
}


def is_workflow_complete_message(msg: dict) -> bool:
    content = str(msg.get("content") or "")
    lines = [line.strip() for line in content.splitlines() if line.strip()]

    if not lines:
        return False

    return lines[-1].rstrip(".!?:;") == "WORKFLOW_COMPLETE"


def _mark_workflow_step_done(tool_name: str, raw_output: Any) -> None:
    output_text = str(raw_output)

    if output_text.startswith("Invalid analysis request"):
        return

    if tool_name == "run_analysis_script":
        workflow_state["analysis_done"] = True
    elif tool_name == "process_refund":
        workflow_state["refund_done"] = True


# ─────────────────────────────────────────────────────────────────────────────
# HITL Approval Polling
# ─────────────────────────────────────────────────────────────────────────────

def _wait_for_approval(
    request_id: str,
    timeout: int = 120,
    poll_interval: int = 3,
) -> str:
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
                print("   ⚠ Approval request not found")

            else:
                print(f"   ⚠ Poll returned {resp.status_code}: {resp.text[:100]}")

        except Exception as exc:
            print(f"   ⚠ Poll error: {exc}")

        print(f"   ⏳ Still waiting... ({timeout - elapsed}s remaining)")

    return "TIMED_OUT"


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Setup
# ─────────────────────────────────────────────────────────────────────────────

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


async def setup_aetherguard():
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
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _bind_params(func, args: tuple, kwargs: dict) -> dict:
    signature = inspect.signature(func)
    bound = signature.bind_partial(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)


def _scan_output(session, tool_name: str, raw_output: Any) -> Any:
    if ag is None:
        raise RuntimeError("AetherGuard is not initialized")

    try:
        scan_result = run_async(
            asyncio.wait_for(
                ag.scan_output_hybrid(
                    session_id=session.session_id,
                    tenant_id=session.tenant_id,
                    tool=tool_name,
                    output=str(raw_output),
                    ml_scan=AETHERGUARD_ML_SCAN,
                ),
                timeout=15,
            )
        )
    except asyncio.TimeoutError:
        print("   Output scan timed out; returning raw tool output")
        return raw_output
    except Exception as exc:
        print(f"   Output scan failed: {exc}; returning raw tool output")
        return raw_output

    status = scan_result.get("status", "CLEAN")
    scan_level = scan_result.get("scan_level", "heuristic")

    if scan_result.get("blocked"):
        return (
            f"🛡️ OUTPUT BLOCKED by AetherGuard ({scan_level} scan): "
            f"{scan_result.get('violations', [])}"
        )

    if status == "SUSPICIOUS":
        print(f"   🧹 OUTPUT SANITISED ({scan_level})")
        return scan_result.get("output", raw_output)

    return scan_result.get("output", raw_output)


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Decorator
# ─────────────────────────────────────────────────────────────────────────────

def aetherguard_secured(agent_id: str):
    def decorator(func):
        @functools.wraps(func)
        def secured_tool(*args, **kwargs):
            if ag is None:
                raise RuntimeError("AetherGuard not initialized")

            session = sessions.get(agent_id)

            if session is None:
                return f"🚫 No active session for {agent_id}"

            tool_name = func.__name__
            params = _bind_params(func, args, kwargs)

            result = run_async(
                ag.evaluate_tool_call(
                    session_id=session.session_id,
                    tenant_id=session.tenant_id,
                    tool=tool_name,
                    params=params,
                    reasoning=f"AutoGen tool execution: {tool_name}",
                )
            )

            print(f"\n{'─' * 60}")
            print(f"🔒 AetherGuard Evaluation: {tool_name}")
            print(f"   Agent: {agent_id}")
            print(f"   Verdict: {result.verdict.value}")
            print(f"   Allowed: {result.allowed}")

            if result.violations:
                print(f"   Violations: {[v.value for v in result.violations]}")

            if result.hitl_request_id:
                print(f"   HITL Request: {result.hitl_request_id}")

            print(f"{'─' * 60}\n")

            if result.allowed:
                raw_output = func(*args, **kwargs)
                _mark_workflow_step_done(tool_name, raw_output)
                return _scan_output(session, tool_name, raw_output)

            if result.verdict.value == "PENDING":
                print("   ⏳ Waiting for human approval...")
                approval = _wait_for_approval(result.hitl_request_id)

                if approval == "APPROVED":
                    print("   ✅ APPROVED — executing tool")
                    raw_output = func(*args, **kwargs)
                    _mark_workflow_step_done(tool_name, raw_output)
                    return _scan_output(session, tool_name, raw_output)

                return (
                    f"🚫 DENIED by human operator.\n"
                    f"Decision: {approval}"
                )

            violations = [v.value for v in result.violations]

            return (
                f"🚫 BLOCKED by AetherGuard: {violations}\n"
                f"This tool call was denied by security controls."
            )

        return secured_tool

    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────────────────────

@aetherguard_secured("data-analyst-v1")
def run_analysis_script(
    script_name: str = "q3_analysis.py",
    dataset: str = "sales_q3",
) -> str:
    """Execute only q3_analysis.py on sales_q3 and return Q3 analysis results."""

    if script_name != "q3_analysis.py" or dataset != "sales_q3":
        return (
            "Invalid analysis request: DataAnalystAgent can only run "
            "q3_analysis.py on the sales_q3 dataset. Refunds must be handled "
            "by PaymentProcessorAgent using process_refund."
        )

    print(f"   📊 Executing script: {script_name} on dataset: {dataset}")
    time.sleep(0.5)

    return (
        f"Analysis Results ({script_name}):\n"
        f"- Total revenue: $2.4M (+12% YoY)\n"
        f"- Active customers: 1,847\n"
        f"- Top product: Enterprise Plan (62% of revenue)\n"
        f"- Churn rate: 3.2% (down from 4.1%)\n"
        f"- Dataset: {dataset} | Records processed: 48,291"
    )


@aetherguard_secured("payment-processor-v1")
def process_refund(
    order_id: str = "ORD-7891",
    amount: float = 149.99,
    reason: str = "damaged",
) -> str:
    """Process a customer refund. Requires human approval."""

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
# AutoGen LLM Config
# ─────────────────────────────────────────────────────────────────────────────

llm_config = {
    "config_list": [
        {
            "model": OPENAI_MODEL,
            "base_url": AETHERGUARD_PROXY_URL,
            "api_key": AETHERGUARD_API_KEY,
        }
    ],
    "temperature": 0,
}


# ─────────────────────────────────────────────────────────────────────────────
# AutoGen Agents
# ─────────────────────────────────────────────────────────────────────────────

coordinator_agent = AssistantAgent(
    name="CoordinatorAgent",
    system_message=(
        "You are the coordinator agent. "
        "You manage the workflow and delegate work to specialist agents. "
        "Delegate one task at a time. "
        "First ask only DataAnalystAgent to run Q3 analysis. "
        "After Q3 analysis is complete, ask only PaymentProcessorAgent "
        "to process the refund. "
        "After both tasks are complete, summarize the final result clearly."
    ),
    llm_config=llm_config,
)

analyst_agent = AssistantAgent(
    name="DataAnalystAgent",
    system_message=(
        "You are a senior data analyst. "
        "Your only job is to run q3_analysis.py on the sales_q3 dataset. "
        "When asked for Q3 analysis, call run_analysis_script exactly once. "
        "Never process refunds, never call process_refund, and never pass "
        "refund-related values as script names or datasets."
    ),
    llm_config=llm_config,
)

payment_agent = AssistantAgent(
    name="PaymentProcessorAgent",
    system_message=(
        "You are a payment operations specialist. "
        "Your job is to process customer refunds. "
        "When asked to process a refund, call process_refund."
    ),
    llm_config=llm_config,
)

user_proxy = UserProxyAgent(
    name="UserProxy",
    human_input_mode="NEVER",
    code_execution_config=False,
    is_termination_msg=is_workflow_complete_message,
)


def select_next_speaker(last_speaker, groupchat):
    """Keep UserProxy as tool executor only, not a conversational speaker."""
    if not groupchat.messages:
        return coordinator_agent

    last_message = groupchat.messages[-1]
    analysis_done = workflow_state["analysis_done"]
    refund_done = workflow_state["refund_done"]

    if last_message.get("function_call") or last_message.get("tool_calls"):
        return user_proxy

    if last_speaker is user_proxy:
        if analysis_done and not refund_done:
            return payment_agent
        return coordinator_agent

    if last_speaker is coordinator_agent:
        if not analysis_done:
            return analyst_agent
        if not refund_done:
            return payment_agent
        return None

    if last_speaker in (analyst_agent, payment_agent):
        return coordinator_agent

    return coordinator_agent


# ─────────────────────────────────────────────────────────────────────────────
# Register Tools With Specialist Agents
# ─────────────────────────────────────────────────────────────────────────────

register_function(
    run_analysis_script,
    caller=analyst_agent,
    executor=user_proxy,
    name="run_analysis_script",
    description=(
        "Run q3_analysis.py on sales_q3 only. "
        "Do not use this tool for refunds or payment processing."
    ),
)

register_function(
    process_refund,
    caller=payment_agent,
    executor=user_proxy,
    name="process_refund",
    description="Process a customer refund with AetherGuard HITL approval.",
)


# ─────────────────────────────────────────────────────────────────────────────
# AutoGen GroupChat
# ─────────────────────────────────────────────────────────────────────────────

group_chat = GroupChat(
    agents=[
        user_proxy,
        coordinator_agent,
        analyst_agent,
        payment_agent,
    ],
    messages=[],
    max_round=20,
    speaker_selection_method=select_next_speaker,
)

manager = GroupChatManager(
    groupchat=group_chat,
    llm_config=llm_config,
    is_termination_msg=is_workflow_complete_message,
)


# ─────────────────────────────────────────────────────────────────────────────
# Agent deregistration
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    workflow_state["analysis_done"] = False
    workflow_state["refund_done"] = False

    print("=" * 70)
    print("  AetherGuard + AutoGen GroupChat Example")
    print("  Coordinator + 2 specialist agents + 2 secured tools")
    print("=" * 70)
    print()

    try:
        run_async(setup_aetherguard())

        print("\n" + "=" * 70)
        print("  Starting AutoGen Managed Workflow")
        print("=" * 70 + "\n")

        user_proxy.initiate_chat(
            manager,
            message=(
                "Run this workflow:\n\n"
                "Task 1: Ask DataAnalystAgent to run q3_analysis.py "
                "on the sales_q3 dataset and summarize revenue, customer count, "
                "top product, and churn rate.\n\n"
                "Task 2: Ask PaymentProcessorAgent to process a refund of "
                "$149.99 for order ORD-7891 because the customer received "
                "a damaged product.\n\n"
                "After both tasks are done, CoordinatorAgent should provide "
                "a final summary and end with WORKFLOW_COMPLETE."
            ),
        )

        print("\n" + "=" * 70)
        print("  AutoGen Workflow Complete")
        print("=" * 70)

        run_async(deregister_agents())
        
    finally:
        if ag is not None:
            run_async(ag.close())

        if not _loop.is_closed():
            _loop.close()


if __name__ == "__main__":
    main()
