"""
AetherGuard Agent Federation Example — Multi-Agent Delegation

Demonstrates identity federation and multi-agent delegation with two CrewAI agents:
- Orchestrator Agent: analyzes data, produces findings
- Delegate Agent (Data Exporter): exports data to CSV (scope-reduced session)

Federation features demonstrated:
- SPIFFE/SPIRE SVID provisioning per agent (auto on session start)
- JIT 5-minute tokens per session (KMS-signed JWT)
- Token refresh before expiry
- RFC 8693 Token Exchange with `act` claim chains via parent_session_id + parent_token
- Scope reduction enforcement (delegate tools ⊆ parent tools)
- Full delegation audit trail via workflow_id + get_workflow_trace()

All tool calls are evaluated through AetherGuard's 8 security controls.
"""
import asyncio
import logging
import os
import time
from typing import Optional

import nest_asyncio
nest_asyncio.apply()

from crewai import Agent, Task, Crew, LLM
from crewai.tools import BaseTool

from aetherguard_agent_security import (
    AetherGuard,
    AgentNotFoundError,
    CapabilityProfile,
    TokenBudget,
)
from aetherguard_agent_security.controls.registry import compute_capability_hash
from aetherguard_agent_security.federation import FederationConfig

from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# Logging & Configuration
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("federation_example")

AETHERGUARD_API_URL = os.getenv("AETHERGUARD_API_URL", "http://localhost:8081")
AETHERGUARD_API_KEY = os.getenv("AETHERGUARD_API_KEY", "ag_test_key_12345")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
TENANT_ID = os.getenv("AETHERGUARD_TENANT_ID", "demo-tenant")
AETHERGUARD_ML_SCAN = os.getenv("AETHERGUARD_ML_SCAN", "true").lower() in ("true", "1", "yes")
TRUST_DOMAIN = os.getenv("AETHERGUARD_TRUST_DOMAIN", "aetherguard.ai")
JIT_TOKEN_TTL_SECS = int(os.getenv("AETHERGUARD_JIT_TOKEN_TTL", "300"))
MAX_DELEGATION_DEPTH = int(os.getenv("AETHERGUARD_MAX_DELEGATION_DEPTH", "5"))

_loop = asyncio.new_event_loop()


def run_async(coro):
    """Run an async coroutine on the persistent event loop."""
    return _loop.run_until_complete(coro)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

ag: Optional[AetherGuard] = None
sessions: dict[str, object] = {}  # agent_id → session
_workflow_id: str = ""


def _wait_for_approval(request_id: str, timeout: int = 120, poll_interval: int = 3) -> str:
    """Poll HITL approval status. Returns APPROVED, DENIED, or TIMED_OUT."""
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
                status = resp.json().get("status", "AWAITING_APPROVAL")
                if status != "AWAITING_APPROVAL":
                    return status
        except Exception as exc:
            logger.warning("Poll error: %s", exc)
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
# Idempotent Agent Registration
# ─────────────────────────────────────────────────────────────────────────────


async def ensure_agent_profile(profile: CapabilityProfile) -> None:
    """Idempotent: register, reactivate, skip, or update."""
    desired_hash = compute_capability_hash(profile)
    try:
        info = await ag.get_agent(profile.agent_id, profile.tenant_id)
    except AgentNotFoundError:
        await ag.register_agent(profile)
        logger.info("Registered: %s", profile.agent_id)
        return
    if not info["active"]:
        await ag.reactivate_agent(profile.agent_id, profile.tenant_id)
        logger.info("Reactivated: %s", profile.agent_id)
    if (info.get("capability_hash") or "") != desired_hash:
        await ag.update_agent_profile(profile)
        logger.info("Updated: %s", profile.agent_id)
    else:
        logger.info("Unchanged: %s", profile.agent_id)


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Secured Decorator
# ─────────────────────────────────────────────────────────────────────────────


def aetherguard_secured(agent_id: str):
    """Wrap CrewAI tool with AetherGuard evaluation."""
    def decorator(tool_class):
        original_run = tool_class._run

        def secured_run(self, *args, **kwargs):
            session = sessions.get(agent_id)
            if session is None:
                return f"🚫 No active session for '{agent_id}'."

            result = run_async(ag.evaluate_tool_call(
                session_id=session.session_id,
                tenant_id=session.tenant_id,
                tool=self.name,
                params={"args": args, "kwargs": kwargs},
                reasoning=f"Tool execution: {self.name}",
            ))

            print(f"\n{'─' * 60}")
            print(f"🔒 AetherGuard: {self.name} (agent: {agent_id})")
            print(f"   Verdict: {result.verdict.value} | Allowed: {result.allowed}")
            if result.violations:
                print(f"   Violations: {[v.value for v in result.violations]}")
            if result.aethersign:
                print(f"   AetherSign: {result.aethersign[:30]}...")
            print(f"{'─' * 60}\n")

            if result.allowed:
                return _execute_and_scan(original_run, self, session, self.name, *args, **kwargs)
            elif result.verdict.value == "PENDING":
                approval = _wait_for_approval(result.hitl_request_id)
                if approval == "APPROVED":
                    return _execute_and_scan(original_run, self, session, self.name, *args, **kwargs)
                return f"🚫 DENIED: {approval}"
            else:
                return f"🚫 BLOCKED: {[v.value for v in result.violations]}"

        tool_class._run = secured_run
        return tool_class
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────────────────────


@aetherguard_secured("orchestrator-agent-v1")
class AnalyzeDataTool(BaseTool):
    name: str = "analyze_data"
    description: str = "Analyze quarterly data and produce a summary report"

    def _run(self, quarter: str = "Q3", year: str = "2024") -> str:
        time.sleep(0.3)
        return (
            f"Analysis Results ({quarter} {year}):\n"
            f"- Total revenue: $2.4M (+12% YoY)\n"
            f"- Active customers: 1,847\n"
            f"- Top product: Enterprise Plan (62% of revenue)\n"
            f"- Churn rate: 3.2% (down from 4.1%)\n"
            f"- Records processed: 48,291"
        )


@aetherguard_secured("data-export-agent-v1")
class ExportDataTool(BaseTool):
    name: str = "export_data"
    description: str = "Export dataset to specified format (CSV, JSON, Parquet)"

    def _run(self, export_format: str = "csv", dataset: str = "q3_sales") -> str:
        time.sleep(0.3)
        return (
            f"Export Complete:\n"
            f"- Dataset: {dataset}\n"
            f"- Format: {export_format.upper()}\n"
            f"- Records exported: 48,291\n"
            f"- File size: 12.4 MB\n"
            f"- Location: s3://aetherguard-exports/{dataset}.{export_format}\n"
            f"- Checksum: sha256:a1b2c3d4e5f6..."
        )


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Setup — Matches README Identity Federation Section
# ─────────────────────────────────────────────────────────────────────────────


async def setup_aetherguard():
    """
    Initialize AetherGuard with federation enabled.
    Follows the exact pattern from README ## Identity Federation.
    """
    global ag, _workflow_id

    # ── Initialize AetherGuard ────────────────────────────────────────────
    # FederationConfig is passed to enable federation features.
    # When the backend supports federation identity endpoints, sessions will
    # automatically get SVID + JIT tokens. When not available, the delegation
    # pattern (parent_session_id) still works for workflow tracking.
    ag = await AetherGuard.init(
        api_url=AETHERGUARD_API_URL,
        api_key=AETHERGUARD_API_KEY,
        federation_config=FederationConfig(
            tenant_id=TENANT_ID,
            federation_enabled=True,
            trust_domain="aetherguard.ai",
            jit_token_ttl_secs=300,        # 5-minute session tokens
            max_delegation_depth=5,
        )         # max orchestrator → sub-agent nesting
    )
    logger.info("AetherGuard initialized with federation (trust_domain=%s)", TRUST_DOMAIN)

    # ── Register Orchestrator Agent ───────────────────────────────────────
    orchestrator_profile = CapabilityProfile(
        agent_id="orchestrator-agent-v1",
        agent_name="Research Orchestrator",
        tenant_id=TENANT_ID,
        permitted_tools=["analyze_data", "export_data"],
        data_classifications=["internal", "financial"],
        permitted_destinations=[],
        max_tool_calls=20,
        max_session_secs=600,
        requires_human_approval=False,
        intent_threshold=0.00,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=50000, max_tokens_per_step=10000),
    )
    await ensure_agent_profile(orchestrator_profile)

    # ── Register Delegate Agent (scope-reduced: tools ⊆ orchestrator) ─────
    export_profile = CapabilityProfile(
        agent_id="data-export-agent-v1",
        agent_name="Data Export Agent",
        tenant_id=TENANT_ID,
        permitted_tools=["export_data"],  # ⊆ orchestrator's tools
        data_classifications=["internal"],
        permitted_destinations=[],
        max_tool_calls=10,
        max_session_secs=300,
        requires_human_approval=False,
        intent_threshold=0.00,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=25000, max_tokens_per_step=5000),
    )
    await ensure_agent_profile(export_profile)

    # ── Start Orchestrator Session ────────────────────────────────────────
    # Session start automatically provisions:
    # - SPIFFE SVID (X.509 cert for cryptographic identity)
    # - JIT token (5-min JWT bound to session)
    import uuid as _uuid
    _workflow_id = str(_uuid.uuid4())

    session = await ag.start_session(
        agent_id="orchestrator-agent-v1",
        tenant_id=TENANT_ID,
        declared_intent="Analyze Q3 data and produce findings report",
        workflow_id=_workflow_id,
    )
    sessions["orchestrator-agent-v1"] = session
    logger.info("Orchestrator session: %s (SVID + JIT token provisioned)", session.session_id)

    # ── Every evaluate_tool_call() validates the JIT token automatically ──
    # Expired token → BLOCK + session terminated

    # ── Token refresh (before expiry) ─────────────────────────────────────
    # In production, call this when approaching the refresh window
    # (last jit_token_refresh_window_secs before expiry, default 60s)
    try:
        await ag.refresh_token(
            session_id=session.session_id,
            tenant_id=TENANT_ID,
        )
        logger.info("Orchestrator token refreshed")
    except Exception as exc:
        # Expected: token not yet in refresh window (still has >4 min left)
        logger.info("Token refresh: %s (expected if token is fresh)", type(exc).__name__)

    # ── Multi-agent delegation (token exchange with act chain) ────────────
    # parent_session_id triggers RFC 8693 Token Exchange:
    #   - Mints delegated JIT token with nested act claim chain
    #   - Enforces scope reduction (delegate tools ⊆ parent tools)
    #   - Records full delegation path in provenance
    sub_session = await ag.start_session(
        agent_id="data-export-agent-v1",
        tenant_id=TENANT_ID,
        declared_intent="Export Q3 data to CSV",
        parent_session_id=session.session_id,  # triggers delegation
        parent_step=1,
    )
    sessions["data-export-agent-v1"] = sub_session
    # sub_session's identity chain:
    # [{"sub": "data-export-agent-v1", "role": "actor"},
    #  {"sub": "orchestrator-agent-v1", "role": "delegator"}]
    logger.info(
        "Delegate session: %s (parent=%s, token exchange + act chain)",
        sub_session.session_id, session.session_id,
    )

    print(f"\n{'═' * 60}")
    print(f"  ✅ Federation Setup Complete")
    print(f"     Orchestrator: {session.session_id}")
    print(f"     Delegate:     {sub_session.session_id} (parent={session.session_id[:8]}...)")
    print(f"     Workflow:     {_workflow_id}")
    print(f"     Trust Domain: {TRUST_DOMAIN}")
    print(f"     JIT TTL:      {JIT_TOKEN_TTL_SECS}s | Max Depth: {MAX_DELEGATION_DEPTH}")
    print(f"{'═' * 60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Workflow Trace & Cleanup
# ─────────────────────────────────────────────────────────────────────────────


async def print_workflow_trace():
    """Full workflow trace shows the parent-child graph."""
    try:
        trace = await ag.get_workflow_trace(workflow_id=_workflow_id, tenant_id=TENANT_ID)
        # trace.graph_valid: True if all hash chains intact across all sessions
        # trace.sessions: [{session_id, agent_id, children, chain_valid, step_count}]
        print(f"\n{'═' * 60}")
        print(f"  📋 Workflow Trace: {_workflow_id}")
        print(f"     Graph Valid: {trace.graph_valid}")
        print(f"     Sessions:    {len(trace.sessions)}")
        print(f"{'─' * 60}")
        for ws in trace.sessions:
            parent = f" (parent: {ws.parent_session_id[:8]}...)" if ws.parent_session_id else " (root)"
            children = f" → children: {ws.children}" if ws.children else ""
            print(f"     {ws.agent_id}: steps={ws.step_count} chain_valid={ws.chain_valid}{parent}{children}")
        print(f"{'═' * 60}\n")
    except Exception as exc:
        logger.warning("Workflow trace unavailable: %s", exc)


async def deregister_agents():
    """Soft-deregister all agents at shutdown."""
    print(f"\n{'─' * 60}")
    print("  Deregistering agents")
    print(f"{'─' * 60}")
    for agent_id in ["orchestrator-agent-v1", "data-export-agent-v1"]:
        try:
            d = await ag.deregister_agent(agent_id=agent_id, tenant_id=TENANT_ID)
            print(f"  ✅ {d.agent_id} (active={d.active})")
        except AgentNotFoundError:
            print(f"  ℹ️  {agent_id} not found")
        except Exception as e:
            print(f"  ⚠️  {agent_id}: {e}")
    print(f"{'─' * 60}")


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI Agents & Tasks
# ─────────────────────────────────────────────────────────────────────────────

aetherguard_llm = LLM(
    model=OPENAI_MODEL,
    base_url=OPENAI_BASE_URL,
    api_key=OPENAI_API_KEY,
)

orchestrator_agent = Agent(
    role="Research Orchestrator",
    goal="Analyze Q3 data and produce a findings report with key metrics",
    backstory="You are a senior data analyst. Use the analyze_data tool to run analysis.",
    tools=[AnalyzeDataTool()],
    llm=aetherguard_llm,
    verbose=True,
)

delegate_agent = Agent(
    role="Data Export Specialist",
    goal="Export the Q3 sales dataset to CSV format",
    backstory="You are a data export specialist. Use the export_data tool to export datasets.",
    tools=[ExportDataTool()],
    llm=aetherguard_llm,
    verbose=True,
)

analysis_task = Task(
    description="Run Q3 data analysis using analyze_data. Report revenue, customers, churn.",
    expected_output="Summary of Q3 analysis with key metrics",
    agent=orchestrator_agent,
)

export_task = Task(
    description="Export Q3 sales dataset to CSV using export_data. Confirm location and details.",
    expected_output="CSV export confirmation with file location and record count",
    agent=delegate_agent,
)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────


def main():
    print("=" * 70)
    print("  AetherGuard Agent Federation Example")
    print("  Identity Federation + Multi-Agent Delegation")
    print("=" * 70)
    print()
    print("  • SPIFFE SVID + JIT token provisioned per session")
    print("  • Token refresh before expiry")
    print("  • RFC 8693 Token Exchange (parent_session_id triggers act chain)")
    print("  • Scope reduction: delegate tools ⊆ orchestrator tools")
    print("  • Workflow trace: full delegation graph with hash chain verification")
    print()

    try:
        run_async(setup_aetherguard())

        crew = Crew(
            agents=[orchestrator_agent, delegate_agent],
            tasks=[analysis_task, export_task],
            verbose=True,
        )

        print("\n" + "=" * 70)
        print("  Starting Federation Workflow")
        print("=" * 70 + "\n")

        result = crew.kickoff()

        print("\n" + "=" * 70)
        print("  Workflow Complete")
        print("=" * 70)
        print(f"\nFinal Output:\n{result}")

        # ── Workflow Trace ────────────────────────────────────────────────
        run_async(print_workflow_trace())

    except Exception as e:
        logger.error("Execution error: %s", e, exc_info=True)
        print(f"\n❌ Error: {e}")

    finally:
        if ag:
            run_async(deregister_agents())
            run_async(ag.close())
        print("\n" + "=" * 70)
        print("  Done.")
        print("=" * 70)


if __name__ == "__main__":
    main()
