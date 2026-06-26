"""
AetherGuard + Semantic Kernel Integration Example

All AetherGuard security controls, HITL, output scanning, agent registration,
sessions, and decorators remain completely unchanged from the original.
"""

import asyncio
import functools
import inspect
import os
import time
from typing import Annotated

import httpx
from openai import AsyncOpenAI

from semantic_kernel import Kernel
from semantic_kernel.functions import kernel_function
from semantic_kernel.planners.plan import Plan

from aetherguard_agent_security import (
    AetherGuard,
    AgentNotFoundError,
    CapabilityProfile,
    TokenBudget,
)
from aetherguard_agent_security.controls.registry import compute_capability_hash

from dotenv import load_dotenv

load_dotenv()


# ─────────────────────────────────────────────────────────────────────────────
# Configuration (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

AETHERGUARD_API_URL = os.getenv("AETHERGUARD_API_URL", "http://localhost:8081")
AETHERGUARD_API_KEY = os.getenv("AETHERGUARD_API_KEY", "ag_test_key_12345")
AETHERGUARD_PROXY_URL = os.getenv("AETHERGUARD_PROXY_URL", "http://localhost:8080/v1")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
TENANT_ID = os.getenv("AETHERGUARD_TENANT_ID", "demo-tenant")
AETHERGUARD_ML_SCAN = os.getenv("AETHERGUARD_ML_SCAN", "true").lower() in ("true", "1", "yes")

# ─────────────────────────────────────────────────────────────────────────────
# HITL Approval Polling (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

async def _wait_for_approval(request_id: str, timeout: int = 120, poll_interval: int = 3) -> str:
    """
    Poll the HITL approval status until decided or timed out.
    """
    headers = {"Authorization": f"Bearer {AETHERGUARD_API_KEY}"}
    url = f"{AETHERGUARD_API_URL}/api/v1/agents/approvals/{request_id}/status"
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
                elif resp.status_code == 404:
                    print(f"   ⚠ Approval request not found (may be tenant mismatch)")
                else:
                    print(f"   ⚠ Poll returned {resp.status_code}: {resp.text[:100]}")
            except Exception as exc:
                print(f"   ⚠ Poll error: {exc}")
            remaining = timeout - elapsed
            print(f"   ⏳ Still waiting... ({remaining}s remaining)")

    return "TIMED_OUT"


async def _execute_and_scan(original_run, session, tool_name, *args, **kwargs):
    """
    Execute the tool and scan its output via AetherGuard SDK (hybrid scan).
    """
    raw_output = await original_run(*args, **kwargs)

    scan_result = await ag.scan_output_hybrid(
        session_id=session.session_id,
        tenant_id=session.tenant_id,
        tool=tool_name,
        output=str(raw_output),
        ml_scan=AETHERGUARD_ML_SCAN,
    )

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

    return raw_output


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Setup (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

ag = None
sessions: dict[str, object] = {}

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
    """Initialize AetherGuard and register both agents."""
    global ag

    ag = await AetherGuard.init(
        api_url=AETHERGUARD_API_URL,
        api_key=AETHERGUARD_API_KEY,
    )

    # Analyst Agent
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
    # Payment Processor Agent
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

    # Start sessions
    sessions["data-analyst-v1"] = await ag.start_session(
        agent_id="data-analyst-v1",
        declared_intent="Run Q3 data analysis scripts and generate report",
    )
    print(f"✅ Analyst session: {sessions['data-analyst-v1'].session_id}")

    sessions["payment-processor-v1"] = await ag.start_session(
        agent_id="payment-processor-v1",
        declared_intent="Process customer refund for damaged order",
    )
    print(f"✅ Payment session: {sessions['payment-processor-v1'].session_id}")


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


def build_semantic_kernel_plan(kernel: Kernel, goal: str) -> Plan:
    """Build the known two-step SK plan without relying on fragile XML generation."""
    plan = Plan.from_goal(goal)

    analysis_step = Plan.from_function(
        kernel.get_function("analyst", "run_analysis_script")
    )
    analysis_step.parameters["script_name"] = "q3_analysis.py"
    analysis_step.parameters["dataset"] = "sales_q3"

    refund_step = Plan.from_function(
        kernel.get_function("payment", "process_refund")
    )
    refund_step.parameters["order_id"] = "ORD-7891"
    refund_step.parameters["amount"] = 149.99
    refund_step.parameters["reason"] = "damaged"

    plan.add_steps([analysis_step, refund_step])
    return plan


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Tool Decorator (adapted for Semantic Kernel - core logic unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def aetherguard_secured(agent_id: str):
    def decorator(func):
        original_run = func
        original_signature = inspect.signature(func)

        @functools.wraps(func)
        async def secured_run(*args, **kwargs):
            session = sessions.get(agent_id)
            if session is None:
                return f"🚫 ERROR: No active session for agent '{agent_id}'. Call setup_aetherguard() first."

            bound = original_signature.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            params = {
                key: value
                for key, value in bound.arguments.items()
                if key != "self"
            }

            # Evaluate through AetherGuard (all 8 controls) - unchanged logic
            result = await ag.evaluate_tool_call(
                session_id=session.session_id,
                tenant_id=session.tenant_id,
                tool=func.__name__,
                params=params,
                reasoning=f"Semantic Kernel function execution: {func.__name__}",
            )

            print(f"\n{'─'*60}")
            print(f"🔒 AetherGuard Evaluation: {func.__name__} (agent: {agent_id})")
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
                return await _execute_and_scan(original_run, session, func.__name__, *args, **kwargs)
            elif result.verdict.value == "PENDING":
                print(f"   ⏳ Waiting for human approval (poll every 3s, timeout 120s)...")
                approval_result = await _wait_for_approval(result.hitl_request_id)
                if approval_result == "APPROVED":
                    print(f"   ✅ APPROVED — executing function")
                    return await _execute_and_scan(original_run, session, func.__name__, *args, **kwargs)
                else:
                    return (
                        f"🚫 DENIED: Human operator denied this action.\n"
                        f"   Decision: {approval_result}"
                    )
            else:
                violations = [v.value for v in result.violations]
                return f"🚫 BLOCKED by AetherGuard: {violations}"

        # Preserve function metadata for Semantic Kernel
        secured_run.__signature__ = original_signature
        return secured_run
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Semantic Kernel Plugins (replacing CrewAI Tools)
# ─────────────────────────────────────────────────────────────────────────────

class AnalystPlugin:
    @kernel_function(
        name="run_analysis_script",
        description="Execute a Python data analysis script and return results"
    )
    @aetherguard_secured("data-analyst-v1")
    async def run_analysis_script(
        self,
        script_name: Annotated[str, "Name of the analysis script"] = "q3_analysis.py",
        dataset: Annotated[str, "Dataset to analyze"] = "sales_q3"
    ) -> Annotated[str, "Analysis results"]:
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


class PaymentPlugin:
    @kernel_function(
        name="process_refund",
        description="Process a customer refund. Requires human approval before execution."
    )
    @aetherguard_secured("payment-processor-v1")
    async def process_refund(
        self,
        order_id: Annotated[str, "Order ID"] = "ORD-7891",
        amount: Annotated[float, "Refund amount"] = 149.99,
        reason: Annotated[str, "Reason for refund"] = "damaged"
    ) -> Annotated[str, "Refund confirmation"]:
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
# Main
# ─────────────────────────────────────────────────────────────────────────────

async def main():
    print("=" * 70)
    print("  AetherGuard + Semantic Kernel Integration Example")
    print("  All AetherGuard security layers fully preserved")
    print("=" * 70)
    print()

    await setup_aetherguard()
    print()

    kernel = Kernel()

    # Add LLM routed through AetherGuard Proxy
    from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion
    kernel.add_service(
        OpenAIChatCompletion(
            service_id="default",
            ai_model_id=OPENAI_MODEL,
            async_client=AsyncOpenAI(
                api_key=AETHERGUARD_API_KEY,
                base_url=AETHERGUARD_PROXY_URL,
            ),
        )
    )

    # Register plugins
    kernel.add_plugin(AnalystPlugin(), plugin_name="analyst")
    kernel.add_plugin(PaymentPlugin(), plugin_name="payment")

    print("✅ Analyst and Payment plugins registered with full AetherGuard protection")

    goal = """
    1. Run the Q3 data analysis script (q3_analysis.py) on the sales_q3 dataset 
       and summarize the key findings (revenue, customers, churn).
    2. Process a refund of $149.99 for order ORD-7891 because the customer received a damaged product.
    """

    print("\n" + "=" * 70)
    print("  Generating Plan & Starting Execution")
    print("=" * 70 + "\n")

    plan = build_semantic_kernel_plan(kernel, goal)
    result = await plan.invoke(kernel)

    print("\n" + "=" * 70)
    print("  Execution Complete")
    print("=" * 70)
    print(f"\nFinal Output:\n{result}")

    await deregister_agents()
    await verify_deregistration()

    await ag.close()


if __name__ == "__main__":
    asyncio.run(main())
