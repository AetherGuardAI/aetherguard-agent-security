from __future__ import annotations

import asyncio
import concurrent.futures
import os
import threading
import time
from typing import Any, Callable, Awaitable

import httpx
from dotenv import load_dotenv

from crewai import Agent, Crew, LLM, Task
from crewai.tools import BaseTool

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aetherguard_agent_security import AetherGuard, CapabilityProfile, TokenBudget, AgentNotFoundError
from aetherguard_agent_security.controls.registry import compute_capability_hash
from aetherguard_agent_security.extended.mcp_transport import AetherGuardMCPTransport
from aetherguard_agent_security.remote import CacheConfig


# ─────────────────────────────────────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

AETHERGUARD_API_URL = os.getenv("AETHERGUARD_API_URL", "")
AETHERGUARD_API_KEY = os.getenv("AETHERGUARD_API_KEY", "")
AETHERGUARD_PROXY_URL = os.getenv("AETHERGUARD_PROXY_URL", "http://localhost:8080/v1")
AETHERGUARD_ML_SCAN = os.getenv("AETHERGUARD_ML_SCAN", "true").lower() in ("true", "1", "yes")
TENANT_ID = os.getenv("AETHERGUARD_TENANT_ID", "demo-tenant")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")


# ─────────────────────────────────────────────────────────────────────────────
# Globals owned by async runtime
# ─────────────────────────────────────────────────────────────────────────────

ag: AetherGuard | None = None
sessions: dict[str, object] = {}
secure_transports: dict[str, AetherGuardMCPTransport] = {}


# ─────────────────────────────────────────────────────────────────────────────
# MCP adapter
# ─────────────────────────────────────────────────────────────────────────────

class MCPClientSessionAdapter:
    def __init__(self, session: ClientSession):
        self.session = session

    async def send_tool_call(self, tool_name: str, params: dict[str, Any]) -> Any:
        return await self.session.call_tool(tool_name, params)

    async def close(self):
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Long-term async runtime bridge
# This owns stdio_client + ClientSession in ONE async task.
# Do not manually call __aenter__ / __aexit__ elsewhere.
# ─────────────────────────────────────────────────────────────────────────────

class AsyncRuntime:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._thread_main, daemon=True)

        self.queue: asyncio.Queue | None = None
        self.ready: concurrent.futures.Future = concurrent.futures.Future()
        self.stopped: concurrent.futures.Future = concurrent.futures.Future()

    def _thread_main(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._runtime_main())
        except Exception as exc:
            if not self.ready.done():
                self.ready.set_exception(exc)
            if not self.stopped.done():
                self.stopped.set_exception(exc)
        finally:
            self.loop.close()

    async def _runtime_main(self):
        global ag

        self.queue = asyncio.Queue()

        server_params = StdioServerParameters(
            command="python",
            args=["forex_mcp_server.py"],
        )

        try:
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as mcp_session:
                    await mcp_session.initialize()

                    mcp_adapter = MCPClientSessionAdapter(mcp_session)
                    await setup_aetherguard(mcp_adapter)

                    if not self.ready.done():
                        self.ready.set_result(True)

                    while True:
                        item = await self.queue.get()

                        if item is None:
                            break

                        func, future = item

                        try:
                            result = await func()
                            future.set_result(result)
                        except Exception as exc:
                            future.set_exception(exc)

        finally:
            try:
                await close_aetherguard()
            finally:
                if not self.stopped.done():
                    self.stopped.set_result(True)

    def start(self):
        self.thread.start()
        self.ready.result()

    def run(self, func: Callable[[], Awaitable[Any]]) -> Any:
        if self.queue is None:
            raise RuntimeError("AsyncRuntime is not started")

        future: concurrent.futures.Future = concurrent.futures.Future()

        def enqueue():
            self.queue.put_nowait((func, future))

        self.loop.call_soon_threadsafe(enqueue)
        return future.result()

    def stop(self):
        if self.queue is None:
            return

        def enqueue_stop():
            self.queue.put_nowait(None)

        self.loop.call_soon_threadsafe(enqueue_stop)
        self.stopped.result(timeout=30)
        self.thread.join(timeout=5)


runtime = AsyncRuntime()


# ─────────────────────────────────────────────────────────────────────────────
# HITL Approval Polling
# ─────────────────────────────────────────────────────────────────────────────

def _wait_for_approval(request_id: str, timeout: int = 120, poll_interval: int = 3) -> str:
    headers = {"Authorization": f"Bearer {AETHERGUARD_API_KEY}"}
    base_url = AETHERGUARD_API_URL.rstrip("/")
    url = f"{base_url}/api/v1/agents/approvals/{request_id}/status"

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

        remaining = timeout - elapsed
        print(f"   ⏳ Still waiting... ({remaining}s remaining)")

    return "TIMED_OUT"


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard setup
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_agent_profile(profile: CapabilityProfile) -> None:
    """
    Idempotent agent registration: register, reactivate, skip, or update as needed.

    Uses ag.get_agent() to check existence and active status.
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


async def setup_aetherguard(mcp_inner_transport):
    global ag

    if mcp_inner_transport is None:
        raise RuntimeError("Real MCP inner transport is required.")

    ag = await AetherGuard.init(
        api_url=AETHERGUARD_API_URL,
        api_key=AETHERGUARD_API_KEY,
        cache_config=CacheConfig(
            profile_ttl=120.0,
            session_ttl=3.0,
            policy_hash_ttl=30.0,
            public_key_ttl=300.0,
        ),
        timeout=5.0,
        max_retries=3,
        http2=True,
    )

    analyst_profile = CapabilityProfile(
        agent_id="data-analyst-v1",
        agent_name="Data Analyst",
        tenant_id=TENANT_ID,
        permitted_tools=["run_analysis_script"],
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
        permitted_tools=["process_refund"],
        data_classifications=["financial", "pii"],
        permitted_destinations=[],
        max_tool_calls=5,
        max_session_secs=300,
        requires_human_approval=True,
        hitl_timeout_secs=120,
        intent_threshold=0.0,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
    )

    financial_profile = CapabilityProfile(
        agent_id="financial-agent-v1",
        agent_name="Financial Agent",
        tenant_id=TENANT_ID,
        permitted_tools=["fetch_forex_rates"],
        data_classifications=["public"],
        permitted_destinations=["api.frankfurter.dev"],
        max_tool_calls=10,
        max_session_secs=300,
        requires_human_approval=False,
        intent_threshold=0.0,
        allow_external_network=True,
        output_scanning_enabled=False,
        loop_detection_enabled=True,
        token_budget=TokenBudget(
            max_total_tokens=20000,
            max_tokens_per_step=5000,
        ),
    )

    for profile in (analyst_profile, payment_profile, financial_profile):
        try:
            await ensure_agent_profile(profile)
        except Exception as e:
            print(f"⚠️  Profile setup error for {profile.agent_id}: {e}")
            try:
                await ag.deregister_agent(agent_id=profile.agent_id, tenant_id=TENANT_ID)
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

    sessions["payment-processor-v1"] = await ag.start_session(
        agent_id="payment-processor-v1",
        tenant_id=TENANT_ID,
        declared_intent="Process customer refund for damaged order",
    )

    sessions["financial-agent-v1"] = await ag.start_session(
        agent_id="financial-agent-v1",
        tenant_id=TENANT_ID,
        declared_intent="Fetch free public forex exchange rates through MCP",
    )

    secure_transports["data-analyst-v1"] = AetherGuardMCPTransport(
        inner_transport=mcp_inner_transport,
        engine=ag,
        session_id=sessions["data-analyst-v1"].session_id,
        tenant_id=TENANT_ID,
    )

    secure_transports["payment-processor-v1"] = AetherGuardMCPTransport(
        inner_transport=mcp_inner_transport,
        engine=ag,
        session_id=sessions["payment-processor-v1"].session_id,
        tenant_id=TENANT_ID,
    )

    secure_transports["financial-agent-v1"] = AetherGuardMCPTransport(
        inner_transport=mcp_inner_transport,
        engine=ag,
        session_id=sessions["financial-agent-v1"].session_id,
        tenant_id=TENANT_ID,
    )


async def deregister_agents():
    """Deregister all agents at the end of execution (soft-delete: sets active=False)."""
    agent_ids = ["data-analyst-v1", "payment-processor-v1", "financial-agent-v1"]

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


async def close_aetherguard():
    global ag

    # Deregister agents before closing
    if ag is not None:
        await deregister_agents()

    for transport in secure_transports.values():
        disconnect = getattr(transport, "disconnect", None)

        if disconnect:
            maybe_coro = disconnect()

            if asyncio.iscoroutine(maybe_coro):
                await maybe_coro

    secure_transports.clear()
    sessions.clear()

    if ag is not None:
        await ag.close()
        ag = None


async def call_mcp_tool(agent_id: str, tool_name: str, params: dict) -> str:
    transport = secure_transports.get(agent_id)

    if transport is None:
        raise RuntimeError(f"No secure MCP transport for agent_id={agent_id}")

    result = await transport.send_tool_call(tool_name, params)
    return str(result)


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Tool Decorator
# ─────────────────────────────────────────────────────────────────────────────

def _execute_and_scan(original_run, tool_self, session, tool_name, *args, **kwargs):
    raw_output = original_run(tool_self, *args, **kwargs)

    if ag is None:
        return raw_output

    scan_result = runtime.run(
        lambda: ag.scan_output_hybrid(
            session_id=session.session_id,
            tenant_id=session.tenant_id,
            tool=tool_name,
            output=str(raw_output),
            ml_scan=AETHERGUARD_ML_SCAN,
        )
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
            print("   ✅ OUTPUT CLEAN (ML verified)")
        return scan_result.get("output", raw_output)

    return raw_output


def aetherguard_secured(agent_id: str):
    def decorator(tool_class):
        original_run = tool_class._run

        def secured_run(self, *args, **kwargs):
            if ag is None:
                return "🚫 ERROR: AetherGuard is not initialized."

            session = sessions.get(agent_id)

            if session is None:
                return f"🚫 ERROR: No active session for agent '{agent_id}'."

            result = runtime.run(
                lambda: ag.evaluate_tool_call(
                    session_id=session.session_id,
                    tenant_id=session.tenant_id,
                    tool=self.name,
                    params={"args": args, "kwargs": kwargs},
                    reasoning=f"CrewAI tool execution: {self.name}",
                )
            )

            print(f"\n{'─' * 60}")
            print(f"🔒 AetherGuard Evaluation: {self.name} (agent: {agent_id})")
            print(f"   Verdict: {result.verdict.value}")
            print(f"   Allowed: {result.allowed}")

            if result.violations:
                print(f"   Violations: {[v.value for v in result.violations]}")

            if result.hitl_request_id:
                print(f"   HITL Request: {result.hitl_request_id}")

            if result.aethersign:
                print(f"   AetherSign: {result.aethersign[:30]}...")

            print(f"{'─' * 60}\n")

            if result.allowed:
                return _execute_and_scan(original_run, self, session, self.name, *args, **kwargs)

            if result.verdict.value == "PENDING":
                print("   ⏳ Waiting for human approval...")
                print(
                    f"   📋 Approve via web portal or API: "
                    f"POST /api/v1/agents/approvals/{result.hitl_request_id}/decide"
                )

                approval_result = _wait_for_approval(result.hitl_request_id)

                if approval_result == "APPROVED":
                    print("   ✅ APPROVED — executing tool")
                    return _execute_and_scan(original_run, self, session, self.name, *args, **kwargs)

                return (
                    f"🚫 DENIED: Human operator denied this action.\n"
                    f"   Decision: {approval_result}\n"
                    f"   The tool call was not executed."
                )

            violations = [v.value for v in result.violations]

            return (
                f"🚫 BLOCKED by AetherGuard: {violations}\n"
                f"   This tool call was denied by security controls."
            )

        tool_class._run = secured_run
        return tool_class

    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────────────────────

@aetherguard_secured("data-analyst-v1")
class RunAnalysisScriptTool(BaseTool):
    name: str = "run_analysis_script"
    description: str = "Execute a Python data analysis script through secured MCP."

    def _run(self, script_name: str = "q3_analysis.py", dataset: str = "sales_q3") -> str:
        return runtime.run(
            lambda: call_mcp_tool(
                agent_id="data-analyst-v1",
                tool_name=self.name,
                params={
                    "script_name": script_name,
                    "dataset": dataset,
                },
            )
        )


@aetherguard_secured("payment-processor-v1")
class ProcessRefundTool(BaseTool):
    name: str = "process_refund"
    description: str = "Process a customer refund through secured MCP. Requires HITL approval."

    def _run(
        self,
        order_id: str = "ORD-7891",
        amount: float = 149.99,
        reason: str = "damaged",
    ) -> str:
        return runtime.run(
            lambda: call_mcp_tool(
                agent_id="payment-processor-v1",
                tool_name=self.name,
                params={
                    "order_id": order_id,
                    "amount": amount,
                    "reason": reason,
                },
            )
        )


@aetherguard_secured("financial-agent-v1")
class FetchForexRatesTool(BaseTool):
    name: str = "fetch_forex_rates"
    description: str = "Fetch free public forex rates through secured real MCP server."

    def _run(self, base_currency: str = "USD", target_currency: str = "PKR") -> str:
        return runtime.run(
            lambda: call_mcp_tool(
                agent_id="financial-agent-v1",
                tool_name=self.name,
                params={
                    "base_currency": base_currency,
                    "target_currency": target_currency,
                },
            )
        )


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI objects
# ─────────────────────────────────────────────────────────────────────────────


aetherguard_llm = LLM(
    model=OPENAI_MODEL,
    base_url="https://api.openai.com/v1",
    api_key="",
)

analyst_agent = Agent(
    role="Data Analyst",
    goal="Run the Q3 data analysis script and summarize key findings",
    backstory="You use MCP tools through AetherGuard secure transport.",
    tools=[RunAnalysisScriptTool()],
    llm=aetherguard_llm,
    verbose=True,
)

payment_agent = Agent(
    role="Payment Operations Specialist",
    goal="Process customer refund requests",
    backstory="You handle refunds through MCP tools protected by AetherGuard HITL.",
    tools=[ProcessRefundTool()],
    llm=aetherguard_llm,
    verbose=True,
)

financial_agent = Agent(
    role="Financial Analyst",
    goal="Fetch latest public forex exchange rates",
    backstory="You fetch forex rates only through a real MCP server protected by AetherGuard.",
    tools=[FetchForexRatesTool()],
    llm=aetherguard_llm,
    verbose=True,
)

analysis_task = Task(
    description=(
        "Run the Q3 data analysis script q3_analysis.py on the sales_q3 dataset. "
        "Report revenue, customer count, top product, and churn rate."
    ),
    expected_output="A summary of Q3 analysis results with key metrics",
    agent=analyst_agent,
)

refund_task = Task(
    description=(
        "Process a refund of $149.99 for order ORD-7891. "
        "The customer received a damaged product and requested a full refund."
    ),
    expected_output="Confirmation that the refund was processed, blocked, or pending approval",
    agent=payment_agent,
)

forex_task = Task(
    description=(
        "Fetch the latest free public forex rate from USD to PKR through the real MCP server. "
        "Return source, date, base currency, target currency, exchange rate, cost, "
        "and whether an API key is required."
    ),
    expected_output="Latest USD to PKR forex exchange rate with source and date",
    agent=financial_agent,
)


def build_crew() -> Crew:
    return Crew(
        agents=[
            analyst_agent,
            payment_agent,
            financial_agent,
        ],
        tasks=[
            analysis_task,
            refund_task,
            forex_task,
        ],
        verbose=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def print_all_outputs(result):
    print("\n" + "=" * 70)
    print("FINAL CREW OUTPUT")
    print("=" * 70)
    print(result)

    if hasattr(result, "tasks_output") and result.tasks_output:
        print("\n" + "=" * 70)
        print("ALL TASK OUTPUTS")
        print("=" * 70)

        for index, task_output in enumerate(result.tasks_output, start=1):
            print(f"\n--- TASK {index} ---")

            agent = getattr(task_output, "agent", None)
            description = getattr(task_output, "description", None)
            raw = getattr(task_output, "raw", None)

            if agent:
                print(f"Agent: {agent}")

            if description:
                print(f"Task: {description}")

            print("\nOutput:")
            print(raw if raw is not None else task_output)


def main():
    print("=" * 70)
    print("AetherGuard + CrewAI + Secured Corporate MCP Server")
    print("3 agents | 3 secured MCP tools | AetherGuard C1-C8")
    print("=" * 70)

    runtime.start()

    try:
        crew = build_crew()

        print("\n" + "=" * 70)
        print("Starting Crew Execution")
        print("=" * 70 + "\n")

        result = crew.kickoff()

        print("\n" + "=" * 70)
        print("Crew Execution Complete")
        print("=" * 70)
        print_all_outputs(result)

        return result

    finally:
        runtime.stop()


if __name__ == "__main__":
    main()