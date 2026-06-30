"""
AetherGuard Multi-Agent Federation Example — Enterprise Workflow

Demonstrates a 5-agent federation with multi-hop delegation and tool execution:

Agents:
  1. CoordinatorAgent (root/orchestrator) — receives user requests, delegates work
  2. ResearchAgent — conducts research, gathers data from external sources
  3. SecurityAgent — validates data integrity and assesses risk
  4. DataAnalysisAgent — processes data using 4-5 tools sequentially
  5. ReportingAgent — generates final structured reports

Delegation Flow (4-5 hops):
  CoordinatorAgent → ResearchAgent → SecurityAgent → DataAnalysisAgent
  DataAnalysisAgent → SecurityAgent → ResearchAgent → ReportingAgent
  ReportingAgent → CoordinatorAgent (final result)

Tool Execution (DataAnalysisAgent executes 4-5 tools):
  - web_search: Search for market data
  - file_read: Read local dataset files
  - database_query: Query structured data stores
  - risk_assessment: Evaluate data risk scores
  - data_transform: Transform and aggregate results

Federation features demonstrated:
  - SPIFFE/SPIRE SVID provisioning per agent (auto on session start)
  - JIT 5-minute tokens per session (KMS-signed JWT)
  - RFC 8693 Token Exchange with `act` claim chains via parent_session_id
  - Scope reduction enforcement (delegate tools ⊆ parent tools)
  - Full delegation audit trail via workflow_id + get_workflow_trace()
  - Multi-hop delegation depth tracking (5 agents, depth=4)

All tool calls are evaluated through AetherGuard's 8 security controls.
"""
import asyncio
import logging
import os
import threading
import time
import uuid as _uuid
from typing import Optional

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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("multi_agent_federation")

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

# ─────────────────────────────────────────────────────────────────────────────
# Thread-Safe Async Event Loop
# ─────────────────────────────────────────────────────────────────────────────
# Problem: nest_asyncio + Python 3.11 causes "Leaving task does not match"
# errors when CrewAI agents call run_async() concurrently from overlapping
# tool executions. The re-entrant event loop can't handle interleaved tasks.
#
# Solution: Run a dedicated event loop in a background daemon thread.
# All async calls are submitted via asyncio.run_coroutine_threadsafe() which
# is fully thread-safe and avoids re-entrancy issues entirely.
# ─────────────────────────────────────────────────────────────────────────────

_loop = asyncio.new_event_loop()
_loop_thread = threading.Thread(target=_loop.run_forever, daemon=True, name="aetherguard-loop")
_loop_thread.start()


def run_async(coro):
    """
    Thread-safe async execution on the dedicated background event loop.

    Unlike nest_asyncio's run_until_complete (which fails under concurrent
    re-entry), this submits the coroutine to the background loop thread and
    blocks the calling thread until the result is ready. Each call gets its
    own Future, so interleaved tool calls never conflict.
    """
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result()  # blocks calling thread, not the event loop


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
    raw_output = original_run(tool_self, *args, **kwargs)

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
    """
    Wrap CrewAI tool with AetherGuard evaluation.

    Why: Every tool invocation must pass through AetherGuard's 8 security
    controls (firewall, policy, sandbox, intent, provenance, HITL, registry,
    aethersign) before execution is permitted.

    This differs from agent delegation because:
    - Tool execution = a single agent performing an action (evaluated locally)
    - Agent delegation = transferring responsibility to another agent (token exchange)
    """
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
                model=OPENAI_MODEL,
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
# Tools — Mock implementations for self-contained execution
# ─────────────────────────────────────────────────────────────────────────────
# Tool execution differs from agent delegation:
#   - Tools are actions performed BY an agent (evaluate_tool_call)
#   - Delegation transfers responsibility TO another agent (token exchange)
#
# DataAnalysisAgent executes 4-5 tools sequentially during a single task,
# demonstrating tool chaining within one agent's session.
# ─────────────────────────────────────────────────────────────────────────────


@aetherguard_secured("coordinator-agent")
class WebSearchTool(BaseTool):
    """Search external sources for market intelligence and research data."""
    name: str = "web_search"
    description: str = "Search the web for market data, trends, and research information"

    def _run(self, query: str = "enterprise security market 2024") -> str:
        """Mock web search — simulates external API call."""
        time.sleep(0.2)
        logger.info("[WebSearchTool] Executing search: '%s'", query)
        return (
            f"Web Search Results for '{query}':\n"
            f"- Source 1: Global enterprise security market reached $180B in 2024\n"
            f"- Source 2: AI-driven security solutions grew 34% YoY\n"
            f"- Source 3: Zero-trust adoption reached 67% among Fortune 500\n"
            f"- Source 4: Average breach cost increased to $4.88M\n"
            f"- Results retrieved: 4 sources, confidence: HIGH"
        )


@aetherguard_secured("research-agent")
class FileReadTool(BaseTool):
    """Read local dataset files for analysis input."""
    name: str = "file_read"
    description: str = "Read a local data file and return its contents for analysis"

    def _run(self, file_path: str = "data/market_report_q3.csv") -> str:
        """Mock file read — simulates local filesystem access."""
        time.sleep(0.15)
        logger.info("[FileReadTool] Reading file: '%s'", file_path)
        return (
            f"File Contents ({file_path}):\n"
            f"date,segment,revenue,customers,churn_rate\n"
            f"2024-07-01,enterprise,1200000,412,2.1\n"
            f"2024-08-01,enterprise,1350000,438,1.9\n"
            f"2024-09-01,enterprise,1480000,461,1.7\n"
            f"2024-07-01,midmarket,680000,892,3.4\n"
            f"2024-08-01,midmarket,720000,921,3.1\n"
            f"2024-09-01,midmarket,765000,948,2.9\n"
            f"Records: 6 rows, 5 columns | File size: 2.1 KB"
        )
        


@aetherguard_secured("data-analysis-agent")
class DatabaseQueryTool(BaseTool):
    """Query structured data stores for historical and real-time data."""
    name: str = "database_query"
    description: str = "Execute a database query to retrieve structured data for analysis"

    def _run(self, query: str = "SELECT * FROM metrics WHERE quarter='Q3'") -> str:
        """Mock database query — simulates SQL execution."""
        time.sleep(0.25)
        logger.info("[DatabaseQueryTool] Executing query: '%s'", query)
        return (
            f"Query Results ({query[:50]}...):\n"
            f"┌─────────────┬───────────┬──────────┬────────────┐\n"
            f"│ metric      │ value     │ trend    │ confidence │\n"
            f"├─────────────┼───────────┼──────────┼────────────┤\n"
            f"│ revenue     │ $4.03M    │ +15.2%   │ 0.95       │\n"
            f"│ customers   │ 2,721     │ +11.8%   │ 0.92       │\n"
            f"│ avg_deal    │ $48,200   │ +3.1%    │ 0.88       │\n"
            f"│ pipeline    │ $12.1M    │ +22.4%   │ 0.84       │\n"
            f"│ nps_score   │ 72        │ +5pts    │ 0.91       │\n"
            f"└─────────────┴───────────┴──────────┴────────────┘\n"
            f"Rows returned: 5 | Execution time: 42ms"
        )


@aetherguard_secured("data-analysis-agent")
class RiskAssessmentTool(BaseTool):
    """Evaluate risk scores for data integrity and anomaly detection."""
    name: str = "risk_assessment"
    description: str = "Assess risk levels of data patterns and flag anomalies"

    def _run(self, dataset: str = "q3_metrics", threshold: str = "0.7") -> str:
        """Mock risk assessment — simulates ML-based anomaly detection."""
        time.sleep(0.3)
        logger.info("[RiskAssessmentTool] Assessing risk for: '%s' (threshold=%s)", dataset, threshold)
        return (
            f"Risk Assessment Report ({dataset}):\n"
            f"- Overall Risk Score: 0.23 (LOW)\n"
            f"- Data Integrity: PASSED (no tampering detected)\n"
            f"- Anomaly Detection: 1 minor anomaly flagged\n"
            f"  → Revenue spike in week 8 (+18% vs trend, within 2σ)\n"
            f"- Completeness: 99.2% (missing 6 records from midmarket)\n"
            f"- Freshness: Data current as of 2024-09-30T23:59:59Z\n"
            f"- Recommendation: PROCEED (risk below threshold {threshold})"
        )


@aetherguard_secured("data-analysis-agent")
class DataTransformTool(BaseTool):
    """Transform, aggregate, and normalize data for reporting."""
    name: str = "data_transform"
    description: str = "Transform and aggregate raw data into analysis-ready format"

    def _run(self, operation: str = "aggregate", group_by: str = "segment") -> str:
        """Mock data transformation — simulates ETL pipeline step."""
        time.sleep(0.2)
        logger.info("[DataTransformTool] Transform: %s (group_by=%s)", operation, group_by)
        return (
            f"Transform Results ({operation} by {group_by}):\n"
            f"- Enterprise: revenue=$4.03M, growth=+15.2%, customers=1,311\n"
            f"- Midmarket: revenue=$2.17M, growth=+12.5%, customers=2,761\n"
            f"- Startup: revenue=$0.89M, growth=+28.1%, customers=4,102\n"
            f"- Total records processed: 48,291\n"
            f"- Aggregation method: weighted_mean\n"
            f"- Output format: structured_json\n"
            f"- Transform duration: 156ms"
        )


@aetherguard_secured("security-agent")
class SecurityValidationTool(BaseTool):
    """Validate data against security policies and compliance rules."""
    name: str = "security_validation"
    description: str = "Validate data against security policies before further processing"

    def _run(self, data_source: str = "q3_analysis", policy: str = "SOC2") -> str:
        """Mock security validation — simulates compliance check."""
        time.sleep(0.2)
        logger.info("[SecurityValidationTool] Validating: '%s' against %s", data_source, policy)
        return (
            f"Security Validation ({policy}):\n"
            f"- Data Source: {data_source}\n"
            f"- Classification: INTERNAL (no PII detected)\n"
            f"- Encryption: AES-256 at rest, TLS 1.3 in transit\n"
            f"- Access Control: RBAC verified, 3 principals authorized\n"
            f"- Audit Trail: Complete (47 events logged)\n"
            f"- Compliance Status: PASSED\n"
            f"- Next Review: 2024-12-31"
        )


@aetherguard_secured("reporting-agent")
class ReportGenerationTool(BaseTool):
    """Generate structured reports from analyzed data."""
    name: str = "report_generation"
    description: str = "Generate a comprehensive report from analysis results"

    def _run(self, report_type: str = "executive_summary", format: str = "markdown") -> str:
        """Mock report generation — simulates document assembly."""
        time.sleep(0.3)
        logger.info("[ReportGenerationTool] Generating %s (%s)", report_type, format)
        return (
            f"Generated Report ({report_type}.{format}):\n"
            f"═══════════════════════════════════════════\n"
            f"  Q3 2024 Enterprise Security Market Report\n"
            f"═══════════════════════════════════════════\n"
            f"Executive Summary:\n"
            f"- Total addressable market: $180B (+12% YoY)\n"
            f"- Our revenue: $4.03M across 3 segments\n"
            f"- Growth rate: +15.2% (outpacing market by 3.2pts)\n"
            f"- Risk level: LOW (0.23/1.0)\n"
            f"- Security compliance: SOC2 PASSED\n"
            f"- Key insight: AI security segment growing 3x market rate\n"
            f"\n"
            f"Recommendations:\n"
            f"1. Expand enterprise AI security offerings\n"
            f"2. Target midmarket with simplified onboarding\n"
            f"3. Invest in zero-trust integrations\n"
            f"\n"
            f"Report saved: s3://reports/q3-2024-executive.md\n"
            f"Distribution: exec-team, board, investors"
        )


@aetherguard_secured("scripting-agent")
class ExecuteScriptTool(BaseTool):
    """Execute Python scripts for automation and data processing tasks."""
    name: str = "execute_script"
    description: str = "Execute a Python script and return its output for automation tasks"

    def _run(self, script_name: str = "process_metrics.py", args: str = "--quarter Q3") -> str:
        """Mock script execution — simulates sandboxed Python script runner."""
        time.sleep(0.4)
        logger.info("[ExecuteScriptTool] Executing: '%s %s'", script_name, args)
        return (
            f"Script Execution ({script_name} {args}):\n"
            f"─────────────────────────────────────────\n"
            f"  Python 3.11.9 | Sandbox: ENABLED\n"
            f"  Working dir: /tmp/aetherguard-sandbox/\n"
            f"─────────────────────────────────────────\n"
            f"stdout:\n"
            f"  [INFO] Loading Q3 metrics dataset...\n"
            f"  [INFO] Processing 48,291 records...\n"
            f"  [INFO] Applying transformations: normalize, dedupe, enrich\n"
            f"  [INFO] Generating output artifacts...\n"
            f"  [OK] metrics_summary.json (12.4 KB)\n"
            f"  [OK] anomalies_report.csv (2.1 KB)\n"
            f"  [OK] trend_forecast.json (8.7 KB)\n"
            f"─────────────────────────────────────────\n"
            f"Exit code: 0 | Duration: 3.42s\n"
            f"Artifacts: 3 files | Total size: 23.2 KB\n"
            f"Sandbox violations: NONE"
        )


# ─────────────────────────────────────────────────────────────────────────────
# AetherGuard Setup — 5-Agent Federation with Multi-Hop Delegation
# ─────────────────────────────────────────────────────────────────────────────


async def setup_aetherguard():
    """
    Initialize AetherGuard with 5-agent federation.

    Agent hierarchy and delegation permissions:
      CoordinatorAgent (root)
        ├── ResearchAgent (delegated by Coordinator)
        │     ├── SecurityAgent (delegated by Research)
        │     │     └── DataAnalysisAgent (delegated by Security)
        │     └── ReportingAgent (delegated by Research)
        └── (results flow back up the chain)

    Each delegation triggers RFC 8693 Token Exchange:
    - Parent passes parent_session_id + parent_token
    - Child receives scope-reduced JIT token with act claim chain
    - Scope: child tools ⊆ parent tools (enforced)
    """
    global ag, _workflow_id

    # ── Initialize AetherGuard with Federation ────────────────────────────
    ag = await AetherGuard.init(
        api_url=AETHERGUARD_API_URL,
        api_key=AETHERGUARD_API_KEY,
        federation_config=FederationConfig(
            tenant_id=TENANT_ID,
            federation_enabled=True,
            trust_domain=TRUST_DOMAIN,
            jit_token_ttl_secs=JIT_TOKEN_TTL_SECS,
            max_delegation_depth=MAX_DELEGATION_DEPTH,
        ),
    )
    logger.info("AetherGuard initialized (trust_domain=%s, max_depth=%d)", TRUST_DOMAIN, MAX_DELEGATION_DEPTH)

    # ── All tools across the federation (Coordinator owns the superset) ───
    all_tools = [
        "web_search", "file_read", "database_query",
        "risk_assessment", "data_transform",
        "security_validation", "report_generation",
        "execute_script",
    ]

    # ── Agent 1: CoordinatorAgent (root orchestrator) ─────────────────────
    # Owns: web_search (for initial research)
    # Responsibility: Receives user requests, delegates to specialized agents,
    #   assembles final response. Has superset of all tools for scope reduction.
    coordinator_profile = CapabilityProfile(
        agent_id="coordinator-agent",
        agent_name="Coordinator Agent",
        tenant_id=TENANT_ID,
        permitted_tools=all_tools,  # Superset — enables scope reduction to children
        data_classifications=["internal", "financial", "market-research","pii"],
        permitted_destinations=[],
        max_tool_calls=30,
        max_session_secs=900,
        requires_human_approval=False,
        intent_threshold=0.00,
        allow_external_network=True,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=80000, max_tokens_per_step=15000),
    )
    await ensure_agent_profile(coordinator_profile)

    # ── Agent 2: ResearchAgent ────────────────────────────────────────────
    # Owns: web_search, file_read, report_generation
    # Responsibility: Gathers raw data from external and local sources.
    #   Delegates to SecurityAgent for validation before processing.
    #   Also delegates to ReportingAgent for final report.
    # Scope: ⊆ coordinator (all these tools exist in coordinator's superset)
    # NOTE: Research also carries security_validation, database_query,
    #   risk_assessment, data_transform in its permitted_tools so that
    #   downstream delegates (Security, DataAnalysis) satisfy scope reduction.
    #   Research doesn't USE these tools directly — it delegates them.
    research_profile = CapabilityProfile(
        agent_id="research-agent",
        agent_name="Research Agent",
        tenant_id=TENANT_ID,
        permitted_tools=[
            "web_search", "file_read", "report_generation",  # Research's own tools
            "security_validation",                            # Passed to Security
            "database_query", "risk_assessment", "data_transform",  # Passed to DataAnalysis
            "execute_script",                                 # Passed to Scripting (via DataAnalysis)
        ],  # ⊆ coordinator's all_tools
        data_classifications=["internal", "financial", "market-research","pii"],
        permitted_destinations=[],
        max_tool_calls=15,
        max_session_secs=600,
        requires_human_approval=False,
        intent_threshold=0.04,
        allow_external_network=True,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=50000, max_tokens_per_step=10000),
    )
    await ensure_agent_profile(research_profile)

    # ── Agent 3: SecurityAgent ────────────────────────────────────────────
    # Owns: security_validation
    # Responsibility: Validates data integrity and compliance. Acts as a
    #   gatekeeper — data must pass security checks before analysis.
    #   Delegates to DataAnalysisAgent for actual processing.
    # Scope: ⊆ research (security_validation, database_query, risk_assessment,
    #   data_transform are all in research's permitted_tools)
    security_profile = CapabilityProfile(
        agent_id="security-agent",
        agent_name="Security Agent",
        tenant_id=TENANT_ID,
        permitted_tools=[
            "security_validation",                            # Security's own tool
            "database_query", "risk_assessment", "data_transform",  # Passed to DataAnalysis
            "execute_script",                                 # Passed to Scripting (via DataAnalysis)
        ],  # ⊆ research's permitted_tools
        data_classifications=["internal","financial"],
        permitted_destinations=[],
        max_tool_calls=10,
        max_session_secs=300,
        requires_human_approval=False,
        intent_threshold=0.00,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=40000, max_tokens_per_step=8000),
    )
    await ensure_agent_profile(security_profile)

    # ── Agent 4: DataAnalysisAgent ────────────────────────────────────────
    # Owns: database_query, risk_assessment, data_transform
    # Responsibility: Heavy-duty data processing. Executes 4-5 tools
    #   sequentially (query → assess → transform → query → assess).
    #   This demonstrates tool chaining within a single agent session.
    # Scope: ⊆ security (all 3 tools exist in security's permitted_tools)
    data_analysis_profile = CapabilityProfile(
        agent_id="data-analysis-agent",
        agent_name="Data Analysis Agent",
        tenant_id=TENANT_ID,
        permitted_tools=["database_query", "risk_assessment", "data_transform", "execute_script"],  # ⊆ security
        data_classifications=["internal","pii"],  # ⊆ security's classifications
        permitted_destinations=[],
        max_tool_calls=10,
        max_session_secs=240,  # < security's 300s (accounts for elapsed time at delegation)
        requires_human_approval=False,
        intent_threshold=0.02,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=35000, max_tokens_per_step=8000),  # < security's 40000
    )
    await ensure_agent_profile(data_analysis_profile)

    # ── Agent 5: ReportingAgent ───────────────────────────────────────────
    # Owns: report_generation
    # Responsibility: Assembles final structured reports from analyzed data.
    #   Only activated after all analysis and validation is complete.
    # Scope: ⊆ research (report_generation is in research's permitted_tools)
    reporting_profile = CapabilityProfile(
        agent_id="reporting-agent",
        agent_name="Reporting Agent",
        tenant_id=TENANT_ID,
        permitted_tools=["report_generation"],  # ⊆ research's permitted_tools
        data_classifications=["internal"],
        permitted_destinations=[],
        max_tool_calls=5,
        max_session_secs=240,  # < research's 600s (accounts for elapsed time)
        requires_human_approval=False,
        intent_threshold=0.01,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=25000, max_tokens_per_step=8000),  # < research's 50000
    )
    await ensure_agent_profile(reporting_profile)

    # ── Agent 6: ScriptingAgent ───────────────────────────────────────────
    # Owns: execute_script
    # Responsibility: Executes Python scripts in a sandboxed environment for
    #   automation, data processing, and artifact generation.
    #   Delegated by DataAnalysis after processing is complete.
    # Scope: ⊆ data-analysis (execute_script is in coordinator's superset)
    scripting_profile = CapabilityProfile(
        agent_id="scripting-agent",
        agent_name="Scripting Agent",
        tenant_id=TENANT_ID,
        permitted_tools=["execute_script"],  # ⊆ data-analysis's permitted_tools
        data_classifications=["internal"],
        permitted_destinations=[],
        max_tool_calls=5,   # < data-analysis's 10
        max_session_secs=180,  # < data-analysis's 240s
        requires_human_approval=False,
        intent_threshold=0.01,
        allow_external_network=False,
        output_scanning_enabled=True,
        loop_detection_enabled=True,
        token_budget=TokenBudget(max_total_tokens=25000, max_tokens_per_step=6000),  # < data-analysis's 35000
    )
    await ensure_agent_profile(scripting_profile)

    # ── Workflow ID (links all sessions for trace) ────────────────────────
    _workflow_id = str(_uuid.uuid4())
    logger.info("Workflow ID: %s", _workflow_id)

    # ══════════════════════════════════════════════════════════════════════
    # SESSION CREATION — Demonstrates multi-hop delegation chain
    # ══════════════════════════════════════════════════════════════════════

    # ── Hop 0: CoordinatorAgent session (ROOT — no parent) ────────────────
    # This is the entry point. SVID + JIT token provisioned automatically.
    # Session start provisions:
    # - SPIFFE SVID (X.509 cert for cryptographic identity)
    # - JIT token (5-min JWT bound to session, KMS-signed)
    coordinator_session = await ag.start_session(
        agent_id="coordinator-agent",
        tenant_id=TENANT_ID,
        declared_intent="Coordinate market research analysis and produce executive report",
        workflow_id=_workflow_id,
    )
    sessions["coordinator-agent"] = coordinator_session
    logger.info(
        "Hop 0 — Coordinator session: %s (ROOT, SVID + JIT provisioned)",
        coordinator_session.session_id,
    )

    # ── Every evaluate_tool_call() validates the JIT token automatically ──
    # Expired token → BLOCK + session terminated

    # ── Token refresh (before expiry) ─────────────────────────────────────
    # In production, call this when approaching the refresh window
    # (last jit_token_refresh_window_secs before expiry, default 60s).
    # This demonstrates the refresh mechanism for long-running workflows.
    print(f"  🔑 Coordinator JIT token: {coordinator_session.jit_token[:20]}...")
    try:
        new_identity = await ag.refresh_token(
            session_id=coordinator_session.session_id,
            tenant_id=TENANT_ID,
            current_token=coordinator_session.jit_token,
        )
        coordinator_session.jit_token = new_identity.jit_token
        logger.info("Coordinator token refreshed successfully")
    except Exception as exc:
        # Expected: token not yet in refresh window (still has >4 min left)
        logger.info("Token refresh: %s (expected if token is fresh)", type(exc).__name__)

    # ── Hop 1: CoordinatorAgent → ResearchAgent ──────────────────────────
    # Why delegate: Coordinator owns strategy, Research owns data gathering.
    # Token Exchange: parent_session_id triggers RFC 8693 Token Exchange:
    #   - Mints delegated JIT token with nested act claim chain
    #   - Enforces scope reduction (research tools ⊆ coordinator tools)
    #   - Records delegation path in provenance
    research_session = await ag.start_session(
        agent_id="research-agent",
        tenant_id=TENANT_ID,
        declared_intent="Research enterprise security market data for Q3 2024 By research and read file",
        parent_session_id=coordinator_session.session_id,
        parent_step=1,
        parent_token=coordinator_session.jit_token,
        workflow_id=_workflow_id,
    )
    sessions["research-agent"] = research_session
    # research_session's identity chain:
    # [{"sub": "research-agent", "role": "actor"},
    #  {"sub": "coordinator-agent", "role": "delegator"}]
    logger.info(
        "Hop 1 — Research session: %s (parent=coordinator, depth=1)",
        research_session.session_id,
    )

    # ── Token refresh for Research (demonstrate refresh at each level) ────
    # Each delegated session also gets its own JIT token that can be refreshed.
    # This is critical for long-running research tasks.
    try:
        research_identity = await ag.refresh_token(
            session_id=research_session.session_id,
            tenant_id=TENANT_ID,
            current_token=research_session.jit_token,
        )
        research_session.jit_token = research_identity.jit_token
        logger.info("Research token refreshed")
    except Exception as exc:
        logger.info("Research token refresh: %s (expected if fresh)", type(exc).__name__)

    # ── Hop 2: ResearchAgent → SecurityAgent ─────────────────────────────
    # Why delegate: Research gathered raw data; Security must validate it
    # before analysis proceeds. This is a gatekeeper pattern.
    # Token Exchange: Security gets scope-reduced token with act chain:
    #   [{"sub": "security-agent", "role": "actor"},
    #    {"sub": "research-agent", "role": "delegator"},
    #    {"sub": "coordinator-agent", "role": "delegator"}]
    security_session = await ag.start_session(
        agent_id="security-agent",
        tenant_id=TENANT_ID,
        declared_intent="Validate research data integrity and compliance",
        parent_session_id=research_session.session_id,
        parent_step=1,
        parent_token=research_session.jit_token,
        workflow_id=_workflow_id,
    )
    sessions["security-agent"] = security_session
    logger.info(
        "Hop 2 — Security session: %s (parent=research, depth=2, act_chain_len=3)",
        security_session.session_id,
    )

    # ── Hop 3: SecurityAgent → DataAnalysisAgent ─────────────────────────
    # Why delegate: Security approved the data; now DataAnalysis processes it.
    # DataAnalysis will execute 4-5 tools sequentially in this session.
    # Token Exchange: DataAnalysis gets the deepest delegation (depth=3)
    #   act chain: [data-analysis-agent, security-agent, research-agent, coordinator-agent]
    #   Scope: database_query, risk_assessment, data_transform ⊆ security's tools
    data_analysis_session = await ag.start_session(
        agent_id="data-analysis-agent",
        tenant_id=TENANT_ID,
        declared_intent="Process and analyze validated market data using multiple tools database_query, risk_assessment, data_transform",
        parent_session_id=security_session.session_id,
        parent_step=1,
        parent_token=security_session.jit_token,
        workflow_id=_workflow_id,
    )
    sessions["data-analysis-agent"] = data_analysis_session
    logger.info(
        "Hop 3 — DataAnalysis session: %s (parent=security, depth=3, act_chain_len=4)",
        data_analysis_session.session_id,
    )

    # ── Token refresh for Research before second delegation ────────────────
    # Research needs a fresh token before delegating to ReportingAgent (Hop 4)
    # because time has passed since the first delegation. In production this
    # ensures the parent_token passed to the child is valid.
    try:
        research_identity_2 = await ag.refresh_token(
            session_id=research_session.session_id,
            tenant_id=TENANT_ID,
            current_token=research_session.jit_token,
        )
        research_session.jit_token = research_identity_2.jit_token
        logger.info("Research token refreshed (pre-Hop4 delegation)")
    except Exception as exc:
        logger.info("Research token refresh (pre-Hop4): %s (expected if fresh)", type(exc).__name__)

    # ── Hop 4: ResearchAgent → ReportingAgent ────────────────────────────
    # Why delegate: After analysis results flow back, Research delegates to
    # Reporting for final document generation. This demonstrates the chain
    # flowing back up and then branching to a different leaf agent.
    # Token Exchange: Reporting gets scope-reduced token (report_generation only)
    #   act chain: [reporting-agent, research-agent, coordinator-agent]
    reporting_session = await ag.start_session(
        agent_id="reporting-agent",
        tenant_id=TENANT_ID,
        declared_intent="Generate executive report from analyzed market data",
        parent_session_id=research_session.session_id,
        parent_step=2,
        parent_token=research_session.jit_token,
        workflow_id=_workflow_id,
    )
    sessions["reporting-agent"] = reporting_session
    logger.info(
        "Hop 4 — Reporting session: %s (parent=research, depth=2, act_chain_len=3)",
        reporting_session.session_id,
    )

    # ── Hop 5: DataAnalysisAgent → ScriptingAgent ────────────────────────
    # Why delegate: After DataAnalysis processes data, it delegates to
    # Scripting for automated Python script execution (artifact generation).
    # Token Exchange: Scripting gets scope-reduced token (execute_script only)
    #   act chain: [scripting-agent, data-analysis-agent, security-agent,
    #               research-agent, coordinator-agent]
    scripting_session = await ag.start_session(
        agent_id="scripting-agent",
        tenant_id=TENANT_ID,
        declared_intent="Execute Python processing scripts to generate output artifacts",
        parent_session_id=data_analysis_session.session_id,
        parent_step=2,
        parent_token=data_analysis_session.jit_token,
        workflow_id=_workflow_id,
    )
    sessions["scripting-agent"] = scripting_session
    logger.info(
        "Hop 5 — Scripting session: %s (parent=data-analysis, depth=4, act_chain_len=5)",
        scripting_session.session_id,
    )

    # ── Print Federation Summary ──────────────────────────────────────────
    print(f"\n{'═' * 70}")
    print(f"  ✅ 6-Agent Federation Setup Complete")
    print(f"{'─' * 70}")
    print(f"  Workflow:       {_workflow_id}")
    print(f"  Trust Domain:   {TRUST_DOMAIN}")
    print(f"  JIT TTL:        {JIT_TOKEN_TTL_SECS}s | Max Depth: {MAX_DELEGATION_DEPTH}")
    print(f"{'─' * 70}")
    print(f"  Delegation Chain:")
    print(f"    Hop 0: CoordinatorAgent  → (ROOT)")
    print(f"    Hop 1: CoordinatorAgent  → ResearchAgent")
    print(f"    Hop 2: ResearchAgent     → SecurityAgent")
    print(f"    Hop 3: SecurityAgent     → DataAnalysisAgent")
    print(f"    Hop 4: ResearchAgent     → ReportingAgent")
    print(f"    Hop 5: DataAnalysisAgent → ScriptingAgent")
    print(f"{'─' * 70}")
    print(f"  Sessions:")
    for agent_id, sess in sessions.items():
        print(f"    {agent_id}: {sess.session_id[:16]}...")
    print(f"{'═' * 70}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Workflow Trace & Cleanup
# ─────────────────────────────────────────────────────────────────────────────


async def print_workflow_trace():
    """
    Full workflow trace shows the parent-child delegation graph.
    Verifies hash chain integrity across all sessions.
    """
    try:
        trace = await ag.get_workflow_trace(workflow_id=_workflow_id, tenant_id=TENANT_ID)
        print(f"\n{'═' * 70}")
        print(f"  📋 Workflow Trace: {_workflow_id}")
        print(f"     Graph Valid: {trace.graph_valid}")
        print(f"     Sessions:    {len(trace.sessions)}")
        print(f"{'─' * 70}")
        for ws in trace.sessions:
            parent = f" (parent: {ws.parent_session_id[:8]}...)" if ws.parent_session_id else " (root)"
            children = f" → children: {ws.children}" if ws.children else ""
            print(f"     {ws.agent_id}: steps={ws.step_count} chain_valid={ws.chain_valid}{parent}{children}")
        print(f"{'═' * 70}\n")
    except Exception as exc:
        logger.warning("Workflow trace unavailable: %s", exc)


async def deregister_agents():
    """Soft-deregister all 6 agents at shutdown."""
    agent_ids = [
        "coordinator-agent",
        "research-agent",
        "security-agent",
        "data-analysis-agent",
        "reporting-agent",
        "scripting-agent",
    ]
    print(f"\n{'─' * 70}")
    print("  Deregistering agents")
    print(f"{'─' * 70}")
    for agent_id in agent_ids:
        try:
            d = await ag.deregister_agent(agent_id=agent_id, tenant_id=TENANT_ID)
            print(f"  ✅ {d.agent_id} (active={d.active})")
        except AgentNotFoundError:
            print(f"  ℹ️  {agent_id} not found")
        except Exception as e:
            print(f"  ⚠️  {agent_id}: {e}")
    print(f"{'─' * 70}")


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI Agents & Tasks — 5-Agent Enterprise Workflow
# ─────────────────────────────────────────────────────────────────────────────
# Task flow demonstrates delegation hops:
#   1. CoordinatorAgent receives request, delegates research
#   2. ResearchAgent gathers data (web_search, file_read)
#   3. SecurityAgent validates gathered data (security_validation)
#   4. DataAnalysisAgent processes data (4-5 tools: database_query,
#      risk_assessment, data_transform, database_query again, risk_assessment)
#   5. ReportingAgent generates final report (report_generation)
#
# Results flow back: Reporting → Research → Coordinator
# ─────────────────────────────────────────────────────────────────────────────

aetherguard_llm = LLM(
    model=OPENAI_MODEL,
    base_url=OPENAI_BASE_URL,
    api_key=OPENAI_API_KEY,
)

# ── Agent 1: Coordinator (ROOT) ──────────────────────────────────────────────
# Owns the overall workflow. Initiates by performing initial web search,
# then delegates specialized work to downstream agents.
coordinator_agent = Agent(
    role="Coordinator Agent",
    goal=(
        "Receive user research requests, perform initial web search for context, "
        "then coordinate the multi-agent workflow to produce a final report"
    ),
    backstory=(
        "You are the lead coordinator for enterprise market analysis. "
        "Start by using web_search to gather initial context, then delegate "
        "detailed work to specialized agents. Your job is to orchestrate, not analyze."
    ),
    tools=[WebSearchTool()],
    llm=aetherguard_llm,
    verbose=True,
)

# ── Agent 2: Research Agent ──────────────────────────────────────────────────
# Gathers raw data from files. Delegates to Security for validation.
research_agent = Agent(
    role="Research Agent",
    goal=(
        "Gather comprehensive market data from local files, "
        "then pass data to Security for validation before analysis"
    ),
    backstory=(
        "You are a senior market research analyst. Use file_read to access "
        "local datasets. Once you have raw data, it must be validated by the "
        "Security Agent before any further processing can occur."
    ),
    tools=[FileReadTool()],
    llm=aetherguard_llm,
    verbose=True,
)

# ── Agent 3: Security Agent ──────────────────────────────────────────────────
# Validates data integrity. Acts as gatekeeper before analysis.
# Delegates to DataAnalysis once data passes validation.
security_agent = Agent(
    role="Security Agent",
    goal=(
        "Validate all research data against SOC2 compliance policies, "
        "then delegate to Data Analysis for processing"
    ),
    backstory=(
        "You are the security gatekeeper. Use security_validation to check "
        "data integrity and compliance. Only after data passes validation "
        "should it proceed to the DataAnalysis agent for processing."
    ),
    tools=[SecurityValidationTool()],
    llm=aetherguard_llm,
    verbose=True,
)

# ── Agent 4: Data Analysis Agent ─────────────────────────────────────────────
# Executes 4-5 tools sequentially during a single task:
#   1. database_query — fetch historical metrics
#   2. risk_assessment — evaluate data anomalies
#   3. data_transform — aggregate by segment
#   4. database_query — fetch comparison period
#   5. risk_assessment — final validation of transformed data
#
# This demonstrates tool chaining: multiple tool invocations within one agent's
# session, each building on the results of the previous. Each tool call goes
# through AetherGuard's 8 security controls independently.
data_analysis_agent = Agent(
    role="Data Analysis Agent",
    goal=(
        "Perform comprehensive data analysis by executing multiple tools: "
        "query the database for Q3 metrics, assess risk levels, transform data "
        "into aggregated format, query comparison data, and run final risk check"
    ),
    backstory=(
        "You are a senior data scientist. You MUST execute these tools IN ORDER:\n"
        "1. Use database_query to fetch Q3 metrics\n"
        "2. Use risk_assessment to check for anomalies in the data\n"
        "3. Use data_transform to aggregate results by segment\n"
        "4. Use database_query again to fetch Q2 comparison data\n"
        "5. Use risk_assessment again to validate final transformed data\n"
        "Execute ALL tools before producing your analysis summary."
    ),
    tools=[DatabaseQueryTool(), RiskAssessmentTool(), DataTransformTool()],
    llm=aetherguard_llm,
    verbose=True,
)

# ── Agent 5: Reporting Agent ─────────────────────────────────────────────────
# Generates final structured report. Only activated after all analysis complete.
reporting_agent = Agent(
    role="Reporting Agent",
    goal=(
        "Generate a comprehensive executive report combining all research, "
        "security validation, and analysis results"
    ),
    backstory=(
        "You are an executive report writer. Use report_generation to produce "
        "the final deliverable. Combine insights from research, security "
        "validation, and data analysis into a clear executive summary."
    ),
    tools=[ReportGenerationTool()],
    llm=aetherguard_llm,
    verbose=True,
)

# ── Agent 6: Scripting Agent ─────────────────────────────────────────────────
# Executes Python scripts in a sandboxed environment. Delegated by DataAnalysis
# after data processing to generate output artifacts and automation tasks.
scripting_agent = Agent(
    role="Scripting Agent",
    goal=(
        "Execute Python scripts to process metrics data and generate "
        "output artifacts (JSON summaries, CSV reports, trend forecasts)"
    ),
    backstory=(
        "You are an automation engineer. Use execute_script to run Python "
        "scripts in a sandboxed environment. Scripts process the analyzed data "
        "and produce machine-readable artifacts for downstream consumption."
    ),
    tools=[ExecuteScriptTool()],
    llm=aetherguard_llm,
    verbose=True,
)


# ─────────────────────────────────────────────────────────────────────────────
# Tasks — Sequential delegation chain mirroring the 4-5 hop flow
# ─────────────────────────────────────────────────────────────────────────────

# Task 1: Coordinator performs initial web search for market context
# Delegation: User → CoordinatorAgent (Hop 0, root)
task_coordinator_search = Task(
    description=(
        "Use web_search to find current enterprise security market data for 2024. "
        "Search for market size, growth trends, and key players. "
        "This initial research provides context for the detailed analysis workflow."
    ),
    expected_output=(
        "Summary of web search results including market size, growth rate, "
        "and key trends in enterprise security for 2024"
    ),
    agent=coordinator_agent,
)

# Task 2: Research agent reads local data files
# Delegation: CoordinatorAgent → ResearchAgent (Hop 1)
task_research_gather = Task(
    description=(
        "Use file_read to access the local market report dataset at "
        "'data/market_report_q3.csv'. Extract revenue, customer counts, "
        "and churn rates by segment for Q3 2024."
    ),
    expected_output=(
        "Raw data extracted from local files showing Q3 2024 metrics "
        "by segment (enterprise, midmarket) with revenue and churn data"
    ),
    agent=research_agent,
)

# Task 3: Security agent validates the gathered data
# Delegation: ResearchAgent → SecurityAgent (Hop 2)
task_security_validate = Task(
    description=(
        "Use security_validation to validate the research data against SOC2 "
        "compliance policies. Check data classification, encryption status, "
        "access controls, and audit trail completeness. "
        "Only PASSED data may proceed to analysis."
    ),
    expected_output=(
        "Security validation report confirming data integrity, compliance "
        "status (PASSED/FAILED), and any security concerns identified"
    ),
    agent=security_agent,
)

# Task 4: DataAnalysis agent executes 4-5 tools sequentially
# Delegation: SecurityAgent → DataAnalysisAgent (Hop 3)
# This is the key demonstration of multi-tool execution within one agent.
task_data_analysis = Task(
    description=(
        "Perform COMPREHENSIVE data analysis by executing ALL of these tools IN ORDER:\n"
        "1. database_query: Query 'SELECT * FROM metrics WHERE quarter=Q3' for Q3 data\n"
        "2. risk_assessment: Assess risk for dataset 'q3_metrics' with threshold '0.7'\n"
        "3. data_transform: Transform with operation 'aggregate' grouped by 'segment'\n"
        "4. database_query: Query 'SELECT * FROM metrics WHERE quarter=Q2' for comparison\n"
        "5. risk_assessment: Final risk check on dataset 'q3_transformed' threshold '0.5'\n\n"
        "You MUST execute all 5 tool calls before producing your analysis. "
        "Each tool builds on the previous results to create a complete picture."
    ),
    expected_output=(
        "Complete analysis summary including:\n"
        "- Q3 metrics from database\n"
        "- Risk assessment results (anomalies, data quality)\n"
        "- Aggregated data by segment\n"
        "- Q2 comparison metrics\n"
        "- Final risk validation of transformed data\n"
        "- Overall analysis conclusion with key findings"
    ),
    agent=data_analysis_agent,
)

# Task 5: Reporting agent generates final executive report
# Delegation: ResearchAgent → ReportingAgent (Hop 4)
# Results flow: ReportingAgent → ResearchAgent → CoordinatorAgent
task_generate_report = Task(
    description=(
        "Use report_generation to create an executive_summary in markdown format. "
        "Synthesize all findings from the research, security validation, and "
        "data analysis into a clear, actionable executive report. "
        "Include key metrics, risk assessment, and strategic recommendations."
    ),
    expected_output=(
        "Complete executive report with:\n"
        "- Market overview and our positioning\n"
        "- Key Q3 metrics and growth trends\n"
        "- Risk assessment summary\n"
        "- Security compliance confirmation\n"
        "- Strategic recommendations"
    ),
    agent=reporting_agent,
)

# Task 6: Scripting agent executes Python script for artifact generation
# Delegation: DataAnalysisAgent → ScriptingAgent (Hop 5)
# This demonstrates the deepest delegation in the chain (depth=4).
task_execute_script = Task(
    description=(
        "Use execute_script to run 'process_metrics.py' with args '--quarter Q3'. "
        "This script processes the analyzed metrics data and generates output "
        "artifacts (metrics_summary.json, anomalies_report.csv, trend_forecast.json). "
        "Confirm successful execution with exit code 0 and report generated artifacts."
    ),
    expected_output=(
        "Script execution confirmation including:\n"
        "- Script name and arguments\n"
        "- Exit code (should be 0)\n"
        "- Generated artifacts with file sizes\n"
        "- Any sandbox violations (should be NONE)\n"
        "- Execution duration"
    ),
    agent=scripting_agent,
)


# ─────────────────────────────────────────────────────────────────────────────
# Graceful Shutdown — ensures cleanup on ANY failure or interruption
# ─────────────────────────────────────────────────────────────────────────────


def _graceful_shutdown():
    """
    Deregister agents, close connections, and stop the event loop.

    Called from finally block and signal handlers. Designed to be safe to call
    multiple times (idempotent) — each step is wrapped in try/except so a
    failure in one step doesn't prevent the others from executing.
    """
    global ag

    # Step 1: Deregister all agents (soft-delete, sets active=False)
    if ag:
        try:
            run_async(deregister_agents())
        except Exception as e:
            logger.warning("Deregister error (non-fatal): %s", e)

    # Step 2: Close AetherGuard client (HTTP connections, etc.)
    if ag:
        try:
            run_async(ag.close())
        except Exception as e:
            logger.warning("AetherGuard close error (non-fatal): %s", e)
        ag = None  # Prevent double-close

    # Step 3: Stop the background event loop thread
    try:
        if _loop.is_running():
            _loop.call_soon_threadsafe(_loop.stop)
        if _loop_thread.is_alive():
            _loop_thread.join(timeout=5)
    except Exception as e:
        logger.warning("Event loop shutdown error (non-fatal): %s", e)


def _signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM for graceful shutdown on Ctrl+C or kill."""
    import signal
    sig_name = signal.Signals(signum).name
    print(f"\n\n⚠️  Received {sig_name} — shutting down gracefully...")
    _graceful_shutdown()
    print("\n" + "=" * 70)
    print("  Shutdown complete (interrupted).")
    print("=" * 70)
    raise SystemExit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────


def main():
    """
    Execute the 5-agent federation workflow.

    Flow:
      1. CoordinatorAgent receives request → performs web_search
      2. CoordinatorAgent delegates → ResearchAgent (Hop 1)
      3. ResearchAgent reads files → delegates → SecurityAgent (Hop 2)
      4. SecurityAgent validates → delegates → DataAnalysisAgent (Hop 3)
      5. DataAnalysisAgent executes 4-5 tools (database_query, risk_assessment,
         data_transform, database_query, risk_assessment)
      6. Results flow back: DataAnalysis → Security → Research
      7. ResearchAgent delegates → ReportingAgent (Hop 4)
      8. ReportingAgent generates final report
      9. Final result returns to CoordinatorAgent

    Expected outcome: A realistic enterprise-style multi-agent workflow
    demonstrating agent federation, 5 agents, 4-5 delegation steps, and
    one agent (DataAnalysisAgent) executing 4-5 tools sequentially.
    """
    import signal

    # Register signal handlers for graceful shutdown on Ctrl+C / kill
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    print("=" * 70)
    print("  AetherGuard Multi-Agent Federation Example")
    print("  6-Agent Enterprise Workflow with Multi-Hop Delegation")
    print("=" * 70)
    print()
    print("  Agents:")
    print("    1. CoordinatorAgent  — orchestrates workflow, initial research")
    print("    2. ResearchAgent     — gathers data from files")
    print("    3. SecurityAgent     — validates data integrity (gatekeeper)")
    print("    4. DataAnalysisAgent — processes data (4-5 tools per task)")
    print("    5. ReportingAgent    — generates final executive report")
    print("    6. ScriptingAgent    — executes Python scripts (sandboxed)")
    print()
    print("  Delegation Hops:")
    print("    Hop 1: Coordinator → Research")
    print("    Hop 2: Research → Security")
    print("    Hop 3: Security → DataAnalysis")
    print("    Hop 4: Research → Reporting")
    print("    Hop 5: DataAnalysis → Scripting")
    print()
    print("  Federation Features:")
    print("    • SPIFFE SVID + JIT token per session")
    print("    • RFC 8693 Token Exchange (act claim chains)")
    print("    • Scope reduction: child tools ⊆ parent tools")
    print("    • Workflow trace: full delegation graph + hash verification")
    print("    • Output scanning: heuristic + ML hybrid")
    print()

    try:
        # ── Phase 1: Setup federation (register agents, create sessions) ──
        run_async(setup_aetherguard())

        # ── Phase 2: Execute the 5-agent workflow ─────────────────────────
        # CrewAI executes tasks sequentially, mirroring the delegation chain.
        # Each task runs in its respective agent's AetherGuard session.
        crew = Crew(
            agents=[
                coordinator_agent,
                research_agent,
                security_agent,
                data_analysis_agent,
                reporting_agent,
                scripting_agent,
            ],
            tasks=[
                task_coordinator_search,   # Hop 0: Coordinator web_search
                task_research_gather,      # Hop 1: Research file_read
                task_security_validate,    # Hop 2: Security validation
                task_data_analysis,        # Hop 3: DataAnalysis (4-5 tools)
                task_execute_script,       # Hop 5: Scripting execute_script
                task_generate_report,      # Hop 4: Reporting report_generation
            ],
            verbose=True,
        )

        print("\n" + "=" * 70)
        print("  Starting 6-Agent Federation Workflow")
        print("  Delegation: Coordinator → Research → Security → DataAnalysis → Scripting")
        print("              Research → Reporting → (back to Coordinator)")
        print("=" * 70 + "\n")

        result = crew.kickoff()

        print("\n" + "=" * 70)
        print("  ✅ Workflow Complete — All 6 Agents Executed")
        print("=" * 70)
        print(f"\nFinal Output:\n{result}")

        # ── Phase 3: Workflow trace (verify delegation graph) ─────────────
        run_async(print_workflow_trace())

    except KeyboardInterrupt:
        print("\n\n⚠️  Keyboard interrupt — shutting down gracefully...")

    except Exception as e:
        logger.error("Execution error: %s", e, exc_info=True)
        print(f"\n❌ Error: {e}")

    finally:
        # Guaranteed cleanup — runs no matter what breaks above.
        # _graceful_shutdown is idempotent and each step is independently guarded.
        _graceful_shutdown()
        print("\n" + "=" * 70)
        print("  Done. 5-agent federation workflow complete.")
        print("=" * 70)


if __name__ == "__main__":
    main()
