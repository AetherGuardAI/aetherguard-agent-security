<img width="120" height="120" alt="ag_security_logo - github" src="https://github.com/user-attachments/assets/0d5b299d-c9e9-4024-9356-25216f9740ca" /><br/>
# AetherGuard Agent Security — Examples

> 🤖 Zero-trust runtime security for autonomous AI agents. Evaluate every tool call, scan every output, approve high-risk actions — before they execute.

---

## 🚀 Getting Started

1. **Sign up** at [https://portal.aetherguard.ai](https://portal.aetherguard.ai)
2. Create your tenant and generate an **API key**
3. You'll receive:
   - `AETHERGUARD_API_URL` — your backend API endpoint
   - `AETHERGUARD_PROXY_URL` — your proxy-engine endpoint (for LLM call scanning)
   - `AETHERGUARD_API_KEY` — your tenant API key (starts with `ag_`)
4. Install the SDK: `pip install aetherguard-agent-security-runtime-operating-environment` - contact AetherGuard team for SDK

---

## 🧠 Supported Agent Frameworks

AetherGuard secures agents built with any framework:

| Framework | Integration |
|-----------|-------------|
| 🚢 **CrewAI** | Tool decorator wraps `_run` method |
| 🤝 **AutoGen** | Override `a_execute_function` on agents |
| 🔗 **LangGraph** | Custom tool node in the graph |
| 🧩 **Semantic Kernel** | Function invocation filter |
| 🟢 **OpenAI Function/Tool Calling** | Intercept before dispatch |
| 🟣 **Anthropic Claude** | Wrap `tool_use` block execution |
| 🔵 **Google Gemini** | Wrap function call dispatch |
| 🔌 **MCP (Model Context Protocol)** | `AetherGuardMCPTransport` wraps any MCP transport |

All integrations follow the same pattern: intercept tool calls, evaluate via AetherGuard, execute only if allowed, scan the output.

---

## 🔐 8 Security Controls (evaluate_tool_call)

Every `evaluate_tool_call()` triggers all 8 controls automatically:

| # | Control | What It Does |
|---|---------|-------------|
| 🧱 C1 | **Tool Invocation Firewall** | Checks permitted tools, data sensitivity, destination trust, external network |
| 📜 C2 | **Policy Engine (OPA)** | Evaluates tenant-configured Rego policies + platform safety floor |
| 📦 C3 | **Execution Sandboxing** | Enforces tool call limits, session timeout, token budget, loop detection |
| 🔗 C4 | **Provenance** | Writes hash-chained step record to append-only audit ledger (always runs) |
| 🎯 C5 | **Intent-to-Action Validation** | TF-IDF / sentence-transformer cosine similarity + action category check |
| 🔑 C6 | **Capability Integrity** | Verifies SHA-256 hash + ECDSA-P256 signature of agent profile (tamper detection) |
| 👤 C7 | **Human-in-the-Loop Gate** | Requires human approval before execution (configurable per agent or per tenant policy) |
| ✍️ C8 | **AetherSign** | ECDSA-P256 digital signature on every step record (always runs, fail-closed) |

Additionally, **tenant-level policies** (Layer 2) apply to all agents under a tenant — tool denylists, rate limits, operating hours, data classification gates, and high-value action approval. These are configured in the web portal's Policies screen.

---

## 🔍 Output Scanner

After a tool executes (ALLOW verdict), the output is scanned before reaching the agent's context window:

**Two-pass hybrid scanning:**

1. ⚡ **Heuristic scan (local, instant)** — regex-based detection of injection patterns (role overrides, instruction smuggling, unicode tricks, base64 payloads) and PII (SSN, credit card, email, phone)

2. 🧠 **ML scan (optional, via backend)** — when `AETHERGUARD_ML_SCAN=true`, the output is forwarded to AetherGuard's ML services for deep analysis:
   - 💉 Injection detection model (score-based)
   - 🪪 PII NER (named entity recognition)
   - ☣️ Toxicity classifier

If heuristics detect **MALICIOUS** content, the output is blocked immediately without the ML call. If **CLEAN** or **SUSPICIOUS**, the ML scan provides a second opinion.

---

## 🌐 Proxy Integration (LLM Call Scanning)

Route all LLM inference calls through the AetherGuard proxy-engine for full ML-grade content safety:

- Set `AETHERGUARD_PROXY_URL` as the LLM base URL
- The proxy runs inside an 🔒 **AWS Nitro Enclave** (TEE)
- 8-stage ML pipeline: ingress → injection ML → PII NER → toxicity → policy → data residency → LLM routing → provenance signing
- All prompts and responses are processed inside the enclave — data never leaves the TEE in plaintext

This means your agents get content safety on both sides:
- 🛠️ **Tool calls** — secured by the agent security SDK
- 🧠 **LLM calls** — secured by the proxy-engine in Nitro Enclave

---

## 🧪 Pre-Execution Safety Tools

Optional security checks that run before tool execution:

🏗️ **E2B Sandbox** — For code execution tools (run_script, exec_python, shell_command):
- Static analysis of script content (dangerous patterns, exfiltration attempts)
- Optional: execute in E2B ephemeral sandbox (isolated VM, no network, destroyed after check)
- Requires `E2B_API_KEY` for sandbox execution; static analysis works without it

🔗 **URL Scan** — For tools that process URLs (http_request, web_fetch, api_call):
- Local heuristic: blocklist, suspicious TLDs, IP-based URLs
- Optional: urlscan.io threat intelligence lookup (phishing, malware, C2 domains)
- Requires `URLSCAN_API_KEY` for remote scan; local heuristic works without it

---

## 🪪 Agent Identity and Federation

**SPIFFE/SPIRE-based identity** for production-grade agent authentication:

- 🆔 Each agent session receives a **SPIFFE SVID** (X.509 certificate) as cryptographic identity
- ⏱️ **JIT tokens** (5-minute JWT, KMS-signed) bound to each session — credential theft window is 5 minutes max
- 🚫 Expired or revoked tokens automatically BLOCK the session (fail-closed)

**🔄 Multi-agent workflows with delegation:**

- Parent agents can delegate to sub-agents via **token exchange**
- The delegated token carries an **`act` claim chain** recording who delegated to whom
- Sub-agent's permitted tools are always a subset of the parent's (scope reduction)
- Full delegation audit trail in every step record
- Maximum delegation depth configurable (default: 5 levels)

**📊 Workflow tracing:**

- Group multiple sessions into a named workflow (`workflow_id`)
- Full parent-child graph with hash chain verification across all sessions
- Verify no sessions were inserted, deleted, or tampered with

---

## ⚙️ Environment Variables

The following environment variables are used in the CrewAI example (and apply to any integration):

### 🔑 Required

| Variable | Description |
|----------|-------------|
| `AETHERGUARD_API_URL` | Backend API endpoint (e.g., `https://example.aetherguard.ai`) |
| `AETHERGUARD_API_KEY` | Your tenant API key (starts with `ag_`) |
| `OPENAI_API_KEY` | OpenAI API key (or your LLM provider's key) |

### 🌐 Proxy Integration

| Variable | Description |
|----------|-------------|
| `AETHERGUARD_PROXY_URL` | Proxy-engine endpoint for LLM scanning (e.g., `https://gateway.aetherguard.io/v1`) |
| `OPENAI_MODEL` | LLM model to use (default: `gpt-4o`) |

### 🔍 Output Scanning

| Variable | Description |
|----------|-------------|
| `AETHERGUARD_ML_SCAN` | `true` or `false` — enable ML-grade output scanning via backend (default: `true`) |

### 🧪 Pre-Execution Safety (Optional)

| Variable | Description |
|----------|-------------|
| `E2B_API_KEY` | E2B sandbox API key for script verification (free tier: 100 sandboxes/day at [e2b.dev](https://e2b.dev)) |
| `URLSCAN_API_KEY` | urlscan.io API key for URL threat intelligence (free tier: 100 scans/day at [urlscan.io](https://urlscan.io)) |

### 🪪 Federation (Optional)

| Variable | Description |
|----------|-------------|
| `AETHERGUARD_FEDERATION_ENABLED` | `true` to enable SPIFFE/SPIRE identity provisioning |
| `AETHERGUARD_TRUST_DOMAIN` | SPIFFE trust domain (e.g., `aetherguard.io`) |
| `AETHERGUARD_JIT_TOKEN_TTL` | JIT token lifetime in seconds (default: `300`) |

---

## 📁 Examples

| Directory | Framework | What It Demonstrates |
|-----------|-----------|---------------------|
| `crewai_example/` | 🚢 CrewAI | Two agents, HITL approval, output scanning, proxy integration |

---

## 📊 Rate Limits and Quotas

Agent API calls count toward your tenant's plan quota (same pool as proxy and RAG):

| Tier | Requests/Month | Requests/Minute | Concurrent Sessions |
|------|---------------|-----------------|---------------------|
| 🆓 Free | 1000 | 10 | 3 |
| ⭐ Starter | 25,000 | 100 | 10 |
| 💼 Professional | 150,000 | 100 | 50 |
| 🏢 Enterprise | custom/unlimited | 10,000 | 500 |

---

## 🆘 Support

- 🌐 Portal: [https://portal.aetherguard.ai](https://portal.aetherguard.ai)
- 📖 Documentation: [info@aetherguard.ai](info@aetherguard.ai)

---

 AetherGuard, Inc
