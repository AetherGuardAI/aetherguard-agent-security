<p align="right"><strong>AetherGuard, Inc.</strong></p>

<h1 align="center"><img width="120" height="120" alt="ag_security_logo - github" src="https://github.com/user-attachments/assets/0d5b299d-c9e9-4024-9356-25216f9740ca" /><br/>
 AetherGuard Agent Security — REST API</h1>

<p align="center">
  <em>Zero-trust runtime security for autonomous AI agents — no SDK required.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Protocol-HTTPS%20REST-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Auth-API%20Key-green?style=flat-square" />
  <img src="https://img.shields.io/badge/Format-JSON-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/Signing-ECDSA--P256-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/Policy-OPA%2FRego-blueviolet?style=flat-square" />
  <img src="https://img.shields.io/badge/Audit-ImmuDB-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/Storage-AWS%20S3-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/KMS-AWS%20KMS-orange?style=flat-square" />
</p>

---

## 🏛️ AetherGuard Agent Security Controls

AetherGuard secures AI agents through **eight integrated security controls** that automatically evaluate every agent action before execution. Together, these controls provide policy enforcement, identity verification, execution governance, and cryptographic assurance for autonomous AI systems.

| Control | Business Description | Primary OWASP Agentic AI Alignment |
|---|---|---|
| 🔥 **C1. Tool Invocation Firewall** | Ensures AI agents can only access approved tools, prevents unauthorized external connections, enforces data classification policies, and blocks sensitive information from being sent to untrusted destinations. | Agent Authorization, Tool Security, Data Protection |
| 📜 **C2. Policy Enforcement Engine** | Evaluates every agent action against organizational security and compliance policies. If policies cannot be verified, execution is automatically denied (fail-closed). | Policy Enforcement, Governance, Secure Defaults |
| 📦 **C3. Secure Execution Controls** | Prevents runaway agents through execution limits, session timeouts, resource quotas, recursion detection, and abuse prevention mechanisms. | Resource Management, Agent Containment, Availability |
| 🔗 **C4. Immutable Provenance** | Creates tamper-evident audit records for every AI decision and action, enabling complete traceability for compliance, forensics, and governance. | Audit Logging, Accountability, Non-Repudiation |
| 🎯 **C5. Intent-to-Action Validation** | Verifies that an agent's requested action matches the user's original intent, helping prevent prompt injection, unintended actions, and malicious task manipulation. | Prompt Injection Defense, Agent Integrity, Intent Validation |
| 🔐 **C6. Capability Verification** | Confirms that each AI agent possesses only approved capabilities using cryptographic verification, preventing unauthorized tools or modified agent profiles from executing. | Identity & Trust Management, Supply Chain Security |
| 👤 **C7. Human Approval Workflow** | Automatically requires human authorization for high-risk or sensitive operations, with configurable approval routing and automatic denial when approvals expire. | Human Oversight, High-Risk Operations, Governance |
| ✍️ **C8. AetherSign Cryptographic Assurance** | Digitally signs every AI action using enterprise-grade cryptography, providing verifiable integrity and preventing tampering throughout the execution lifecycle. | Integrity Protection, Non-Repudiation, Trust Verification |

### 💼 Business Benefits

- ✅ Prevents unauthorized AI agent actions **before** execution
- ✅ Enforces enterprise security and governance policies automatically
- ✅ Protects sensitive data from unintended disclosure
- ✅ Ensures every AI decision is fully auditable and cryptographically verifiable
- ✅ Supports human oversight for high-risk business operations
- ✅ Helps organizations implement secure, trustworthy, and compliant AI agents

### 🌐 Alignment with OWASP Agentic AI

AetherGuard's security architecture aligns with the key principles of the **OWASP Agentic AI** framework by providing:

| # | Principle | Controls |
|:---:|---|---|
| 1 | Agent Authorization & Identity Verification | C1, C6 |
| 2 | Secure Tool Invocation | C1, C3 |
| 3 | Policy-as-Code Enforcement | C2 |
| 4 | Prompt Injection & Intent Validation | C5 |
| 5 | Execution Sandboxing & Resource Controls | C3 |
| 6 | Human-in-the-Loop Governance | C7 |
| 7 | Tamper-Evident Audit Trails | C4 |
| 8 | Cryptographic Integrity & Provenance | C4, C8 |

> Together, these controls enable organizations to deploy autonomous AI agents with **enterprise-grade security, governance, and operational trust**.

---

> 🚀 **Get started:** Sign up at [genesis.aetherguard.ai](https://genesis.aetherguard.ai), create a tenant, and grab your API key.

> 📦 **Prefer Python?** Contact AetherGuard AI for SDK `agent-runtime-operating-environment-sdk` for caching, batching, and the full federation layer.

---

## 📐 Architecture

```
┌─────────────────┐        HTTPS / JSON         ┌──────────────────────────────────┐
│   Your Agent    │ ─────────────────────────▶   │     AetherGuard Backend          │
│  (any language) │   Authorization: Bearer ...  │                                  │
└─────────────────┘                              │  ┌────────────────────────────┐  │
                                                 │  │  🔥 C1  Tool Firewall      │  │
                                                 │  │  📜 C2  OPA Policy Engine  │  │
                                                 │  │  📦 C3  Execution Sandbox  │  │
                                                 │  │  🔗 C4  Hash-Chain Audit   │  │
                                                 │  │  🎯 C5  Intent Validator   │  │
                                                 │  │  🔐 C6  Capability Verify  │  │
                                                 │  │  👤 C7  Human-in-the-Loop  │  │
                                                 │  │  ✍️  C8  AetherSign (ECDSA) │  │
                                                 │  └────────────────────────────┘  │
                                                 │  + FR-1→FR-11 Advanced Suite     │
                                                 └──────────────────────────────────┘
```

All 8 security controls + the full advanced suite fire automatically on every tool evaluation.

---

## ✅ What's available without the SDK

| Capability | Status | Notes |
|---|:---:|---|
| 📝 Register agent + publish capabilities | ✅ | Full profile |
| 🔄 Update capabilities | ✅ | Auto-increments version, re-signs |
| ▶️ Start session | ✅ | Returns `session_id` |
| 🛡️ Evaluate tool calls (enforcement + telemetry) | ✅ | All 8 controls + advanced suite |
| 🔍 Scan tool output | ✅ | Injection, PII, secrets |
| 👤 Human-in-the-loop (HITL) | ✅ | Full approval routing |
| 📋 Session trace + provenance | ✅ | Hash-chain audit |
| 🤝 Multi-agent delegation (sub-agents) | ✅ | Via `parent_session_id` |
| 🚨 Quarantine / incidents | ✅ | Operational controls |
| 📄 Agent SBOM | ❌ | CycloneDX 1.6, KMS-signed (web portal only) |
| 🆔 **Federation (SPIFFE + JIT tokens)** | ❌ | SDK only |

> 💡 Federation (SPIFFE/SVID + ephemeral JIT tokens) is an additional identity layer provided by the SDK.
> Without it, all security controls (C1–C8) still apply in full — federation is not a prerequisite.

---

## 🔑 Authentication

**Base URL:**
```
https://agentexample.aetherguard.ai/api/v1/agents
```

**Header:**
```
Authorization: Bearer ag_live_xxxxxxxxxxxx
```

- `HTTP 200` for all verdict outcomes (ALLOW / BLOCK / PENDING / TIMEOUT)
- `HTTP 4xx` for validation errors, auth failures, and not-found

---

## 🔄 Lifecycle overview

```
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │  ① POST /register          Register agent + capabilities        │
 │        │                                                         │
 │        ▼                                                         │
 │  ② POST /session/start     Start bounded session                │
 │        │                                                         │
 │        ▼                                                         │
 │  ③ POST /session/{id}/tool  ◀─── loop for each tool call        │
 │        │                                                         │
 │        ├── ✅ ALLOW  → execute tool → scan output                │
 │        ├── 🚫 BLOCK  → handle violations                        │
 │        ├── ⏳ PENDING → await HITL decision                      │
 │        └── ⏰ TIMEOUT → session expired                          │
 │        │                                                         │
 │        ▼                                                         │
 │  ④ POST /session/{id}/end  Close session                        │
 │                                                                  │
 └──────────────────────────────────────────────────────────────────┘
```

---

## 📝 1. Register Agent

Validates tool names (no wildcards), computes SHA-256 capability hash, signs with KMS ECDSA-P256,
persists the profile, and generates the signed SBOM.

```http
POST /register
```

### Request

```json
{
  "agent_id": "payment-processor-v1",
  "agent_name": "Payment Processor",
  "version": "1.0.0",
  "capability": {
    "permitted_tools": ["get_invoice", "process_refund", "send_receipt"],
    "data_classifications": ["financial", "pii"],
    "permitted_destinations": ["payments.internal", "@company.com"],
    "max_tool_calls": 10,
    "max_session_secs": 600,
    "requires_human_approval": false,
    "hitl_timeout_secs": 900,
    "hitl_approval_group": null,
    "hitl_approval_user": null,
    "intent_threshold": 0.72,
    "allow_external_network": false,
    "output_scanning_enabled": true,
    "loop_detection_enabled": true,
    "token_budget": {
      "max_total_tokens": 50000,
      "max_tokens_per_step": 5000,
      "max_reasoning_tokens": 25000
    },
    "owner": "platform-ai-team",
    "department": "Engineering",
    "framework": "langchain"
  }
}
```

<details>
<summary>📋 Field reference</summary>

| Field | Required | Description |
|---|:---:|---|
| `agent_id` | ✅ | Unique identifier within the tenant |
| `agent_name` | ✅ | Human-readable display name |
| `permitted_tools` | ✅ | Exact tool names — no wildcards, no regex |
| `data_classifications` | | Permitted PII/PHI categories (`pii`, `phi`, `financial`, `confidential`, `internal`) |
| `permitted_destinations` | | Allowed domain suffixes (e.g. `@company.com`) |
| `max_tool_calls` | | Hard cap per session (default: 20) |
| `max_session_secs` | | Session timeout in seconds (default: 300) |
| `requires_human_approval` | | Gate every tool call through C7 HITL |
| `hitl_approval_group` | | Only group members can approve |
| `hitl_approval_user` | | Only this user can approve |
| `intent_threshold` | | C5 cosine similarity minimum (default: 0.72, set 0 to disable) |
| `allow_external_network` | | Allow external HTTP destinations (default: false) |
| `token_budget` | | Optional per-session token budget |
| `owner` | | Inventory metadata — owning person/team |
| `department` | | Inventory metadata — business unit |
| `framework` | | Agent framework (`langchain`, `crewai`, `autogen`, `mcp`, etc.) |

</details>

### Response

```json
{
  "agent_id": "payment-processor-v1",
  "status": "ACTIVE",
  "capability_hash": "sha256:a3f5c7d2e9b1084f63cc452bd8e71a90...",
  "capability_sig": "base64:MEUCIQD...",
  "registration_id": "payment-processor-v1"
}
```

> 🔐 `capability_hash` = SHA-256 of canonical profile JSON  
> ✍️ `capability_sig` = KMS ECDSA-P256 signature over that hash  
> Both verified before every session start (C6)

---

## 🔄 2. Update Capabilities

Rejects if agent has active sessions. Auto-increments `version`, recomputes hash, re-signs.

```http
PUT /profile
```

Same request shape as register. Response includes new `version` number.

---

## ⏹️ 3. Deregister / Reactivate

```http
POST /deregister       →  { "agent_id": "..." }
POST /reactivate       →  { "agent_id": "..." }
```

Soft-deregister preserves the profile for audit; blocks new sessions.

---

## ▶️ 4. Start Session

Verifies capability integrity (C6), blocks quarantined/deregistered agents.

```http
POST /session/start
```

```json
{
  "agent_id": "payment-processor-v1",
  "declared_intent": "Process refund for order ORD-123",
  "workflow_id": "550e8400-...",
  "parent_session_id": null,
  "parent_step": null
}
```

| Field | Required | Description |
|---|:---:|---|
| `agent_id` | ✅ | Registered, active agent |
| `declared_intent` | ✅ | Locked at creation; C5 validates every tool call against this |
| `workflow_id` | | UUID to group multi-agent sessions |
| `parent_session_id` | | Orchestrator's session → triggers FR-11 containment |
| `parent_step` | | Which step in parent spawned this sub-agent |

### Response

```json
{
  "session_id": "7f3a9c12-4b8e-4d21-bc7f-1a2b3c4d5e6f",
  "tenant_id": "your-tenant-uuid",
  "status": "ACTIVE",
  "started_at": 1751000400,
  "user_intent": "Process refund for order ORD-123"
}
```

> 💾 Store `session_id` — every subsequent call requires it.

---

## 🛡️ 5. Evaluate Tool Call

The core enforcement endpoint. All 8 controls + FR-1→FR-11 advanced suite fire automatically.

```http
POST /session/{session_id}/tool
```

```json
{
  "tool": "process_refund",
  "params": { "order_id": "ORD-123", "amount": 49.99 },
  "reasoning": "Customer requested refund for damaged item",
  "tokens_input": 1240,
  "tokens_output": 380,
  "model": "claude-sonnet-4-6",
  "transport_type": "REST"
}
```

<details>
<summary>📋 Full field reference</summary>

| Field | Required | Description |
|---|:---:|---|
| `tool` | ✅ | Tool name to evaluate |
| `params` | ✅ | Tool parameters (C1 checks for PII) |
| `reasoning` | | Agent reasoning (C5 intent validation) |
| `tokens_input` | | Input tokens for C3 budget tracking |
| `tokens_output` | | Output tokens for C3 budget tracking |
| `model` | | LLM model name (provenance + inventory) |
| `transport_type` | | `REST` (default) or `MCP` |
| `user_id` | | Who initiated the request |
| `model_version_hash` | | SHA-256 of model artifact |
| `region` | | AWS region of inference |
| `input_fingerprint` | | SHA-256 of prompt |
| `output_fingerprint` | | SHA-256 of response |
| `policy_check_detail` | | `{"pii_detected": false, "injection_score": 0.04, "secrets_detected": false}` |

</details>

### Response

```json
{
  "allowed": true,
  "verdict": "ALLOW",
  "violations": [],
  "session_id": "7f3a9c12-...",
  "step_id": "step-uuid",
  "intent_score": 0.87,
  "sanitized_params": null,
  "hitl_request_id": null,
  "evaluated_at": 1751000450
}
```

### Verdicts

| Verdict | `allowed` | Action |
|---|:---:|---|
| ✅ `ALLOW` | `true` | Execute the tool (use `sanitized_params` if present) |
| 🚫 `BLOCK` | `false` | Do not execute. Inspect `violations`. |
| ⏳ `PENDING` | `false` | Awaiting human approval. Poll HITL status. |
| ⏰ `TIMEOUT` | `false` | Session expired. Start a new one. |

### ⚠️ Handle `sanitized_params`

When `AGENT_PARAM_EGRESS_REDACTION=true` (server-side), the engine scrubs secrets/PII from params:

```python
outbound = result["sanitized_params"] or original_params
execute_tool("process_refund", outbound)  # use scrubbed version
```

<details>
<summary>📋 All violation codes</summary>

| Code | Control | Trigger |
|---|---|---|
| `C1_PERMISSION_DENIED` | 🔥 Firewall | Tool not in `permitted_tools` |
| `C1_DATA_SENSITIVITY_VIOLATION` | 🔥 Firewall | PII detected, classification not permitted |
| `C1_DESTINATION_UNTRUSTED` | 🔥 Firewall | Destination not in permitted list |
| `C1_EXTERNAL_NETWORK_DENIED` | 🔥 Firewall | External URL blocked |
| `C2_POLICY_DENIED` | 📜 Policy | OPA policy denied |
| `C3_TOOL_CALL_LIMIT_EXCEEDED` | 📦 Sandbox | Tool call cap hit |
| `C3_TOKEN_BUDGET_EXCEEDED` | 📦 Sandbox | Token limit hit |
| `C3_LOOP_DETECTED` | 📦 Sandbox | Same tool+params 3+ times |
| `C3_STUCK_AGENT_DETECTED` | 📦 Sandbox | Repeated BLOCKs on same tool |
| `C3_CALL_DEPTH_EXCEEDED` | 📦 Sandbox | Nested sub-invocation depth exceeded |
| `C3_CYCLIC_CONTEXT` | 📦 Sandbox | Repeated context hash or verdict cycle |
| `C3_MEMORY_POISONING` | 📦 Sandbox | Context replay / unauthorized state mutation |
| `C3_EXFILTRATION_ATTEMPT` | 📦 Sandbox | Exfil tool, external URL, smuggled payload |
| `C3_PRIVILEGE_ESCALATION` | 📦 Sandbox | Sub-agent exceeds parent capability |
| `C3_KILL_CHAIN_DETECTED` | 📦 Sandbox | ≥3 kill-chain stages correlated |
| `C3_QUARANTINED` | 📦 Sandbox | Agent or parent quarantined |
| `C5_INTENT_MISMATCH` | 🎯 Intent | Cosine similarity below threshold |
| `C5_ACTION_CATEGORY_VIOLATION` | 🎯 Intent | Tool category inconsistent with intent |
| `C7_HUMAN_DENIED` | 👤 HITL | Approver denied |
| `C7_APPROVAL_TIMEOUT` | 👤 HITL | No decision within timeout |
| `C8_SIGNING_FAILURE` | ✍️ AetherSign | KMS signing failed (fail-closed) |

</details>

---

## 🔍 6. Scan Tool Output

After executing a tool, scan output for injection/PII/secrets before passing to LLM context.

```http
POST /session/{session_id}/scan-output
```

```json
{ "tool": "process_refund", "output": "Refund of $49.99 for john.doe@example.com" }
```

```json
{
  "status": "SUSPICIOUS",
  "sanitised_output": "Refund of $49.99 for [PII_REDACTED]",
  "findings": [],
  "pii_findings": [{ "category": "email", "severity": "MEDIUM", "position": 38 }]
}
```

| Status | Meaning |
|---|---|
| `CLEAN` | ✅ No issues |
| `SUSPICIOUS` | ⚠️ PII or low-severity injection found, output sanitized |
| `MALICIOUS` | 🚨 High-confidence injection, output sanitized |
| `DISABLED` | ⏭️ Scanning disabled in profile |

> Always use `sanitised_output`, not raw output.

---

## 👤 7. Human-in-the-Loop (HITL)

When `verdict == "PENDING"`:

```http
GET  /approvals/{hitl_request_id}/status    →  check decision status
POST /approvals/{hitl_request_id}/decide    →  submit approval/denial
```

```json
{ "approver_id": "alice@company.com", "approved": true, "notes": "Verified" }
```

Only authorized approvers can decide (HTTP 403 otherwise).

---

## ⏹️ 8. End Session

```http
POST /session/{session_id}/end
```

Marks session `COMPLETED`, flushes provenance chain to immudb.

---

## 🤝 9. Multi-Agent Delegation

Pass `parent_session_id` at session start. FR-11 enforces: child ⊆ parent capability.

```json
{
  "agent_id": "data-export-agent",
  "declared_intent": "Export Q3 data",
  "workflow_id": "same-uuid-as-parent",
  "parent_session_id": "orchestrator-session-id",
  "parent_step": 3
}
```

HTTP 403 `PRIVILEGE_ESCALATION_DENIED` if child exceeds parent's remaining budget/tools.

```http
GET /workflow/{workflow_id}/trace    →  full parent→child graph + chain integrity
```

> 🔐 Token exchange (RFC 8693 `act` chains) and SPIFFE delegation require the Python SDK.
> REST delegation enforces all privilege containment without federated identity.

---

## 📋 10. Session Trace & Provenance

```http
GET /session/{session_id}/trace
```

Returns: all steps, verdicts, intent scores, violations, AetherSign signatures,
hash-chain links, `risk_score` (0–100), `risk_level`, `risk_factors`, `chain_valid`.

```http
GET /session/{session_id}/provenance    →  immudb-verified record
```

---

## 🗂️ 11. Agent Inventory

```http
GET /inventory              →  full agent grid (all registered agents)
GET /inventory/{agent_id}   →  complete profile + last session + risk
```

---

## 🚨 12. Operational Controls

```http
POST /{agent_id}/quarantine       →  { "mode": "SOFT|HARD|FULL_LOCKDOWN" }
POST /{agent_id}/release          →  lift quarantine
GET  /quarantined                 →  list quarantined agents
GET  /incidents                   →  kill-chain incidents
GET  /public-key                  →  KMS ECDSA-P256 public key (no auth)
```

---

## 💻 Complete Example (curl)

```bash
API_KEY="ag_live_xxxxxxxxxxxx"
BASE="https://agent-gateway.aetherguard.ai/api/v1/agents"
AUTH="Authorization: Bearer $API_KEY"

# ① Register
curl -s -X POST "$BASE/register" -H "$AUTH" -H "Content-Type: application/json" -d '{
  "agent_id": "support-agent-v1",
  "agent_name": "Customer Support Agent",
  "capability": {
    "permitted_tools": ["create_ticket", "lookup_faq", "send_email"],
    "data_classifications": ["pii"],
    "max_tool_calls": 15,
    "max_session_secs": 300,
    "intent_threshold": 0.72,
    "framework": "langchain"
  }
}'

# ② Start session
SESSION=$(curl -s -X POST "$BASE/session/start" -H "$AUTH" \
  -H "Content-Type: application/json" -d '{
  "agent_id": "support-agent-v1",
  "declared_intent": "Help customer with billing query for ACC-456"
}' | jq -r '.session_id')

# ③ Evaluate tool call
RESULT=$(curl -s -X POST "$BASE/session/$SESSION/tool" -H "$AUTH" \
  -H "Content-Type: application/json" -d '{
  "tool": "lookup_faq",
  "params": { "query": "how to cancel subscription" },
  "reasoning": "Customer asked about cancellation",
  "tokens_input": 420,
  "tokens_output": 180,
  "model": "gpt-4o"
}')

VERDICT=$(echo $RESULT | jq -r '.verdict')

if [ "$VERDICT" = "ALLOW" ]; then
  # Execute tool → scan output
  curl -s -X POST "$BASE/session/$SESSION/scan-output" -H "$AUTH" \
    -H "Content-Type: application/json" \
    -d '{"tool":"lookup_faq","output":"Cancel at Settings > Subscription."}'
fi

# ④ End session
curl -s -X POST "$BASE/session/$SESSION/end" -H "$AUTH"
```

---

## 🆚 SDK vs REST

| Feature | SDK | REST API |
|---|:---:|:---:|
| All 8 security controls (C1–C8) | ✅ | ✅ |
| Advanced controls (FR-1→FR-11) | ✅ | ✅ |
| 🤝 Multi-agent delegation | ✅ | ✅ |
| 👤 HITL approval routing | ✅ | ✅ |
| Local caching (reduced latency) | ✅ | ❌ |
| Request batching | ✅ | ❌ |
| Automatic retry + backoff | ✅ | ❌ |
| SPIFFE/SVID identity | ✅ | ❌ |
| JIT token lifecycle | ✅ | ❌ |
| RFC 8693 token exchange (`act` chains) | ✅ | ❌ |

---

<p align="center">© 2026 AetherGuard, Inc.</p>
