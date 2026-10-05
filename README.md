# MCP-Guard

**Zero-Trust Security Gateway for AI Agent Tool Execution**

> LLM is a proposer. Policy is a decider.
>
> Tool Description / Tool Result / Memory are untrusted data.
>
> We do not just detect Prompt Injection. We block the full attack chain:
> Prompt → Tool → Data → Sink.

Interactive AI customer-service app with a five-gate security gateway between an AI agent and MCP tool servers.

---

## Why

An AI agent that can call tools is a new attack surface:

- A poisoned tool description can hijack the agent.
- A poisoned knowledge-base document can inject instructions.
- A tool result can contain instructions that the agent obeys.
- A combination of **individually legitimate** tools can leak PII.
- A compromised MCP server can impersonate a trusted one.

Most defenses stop at "detect prompt injection". MCP-Guard enforces **policy** at every boundary.

---

## Architecture

---

## Five Security Gates

| Gate | Purpose | Covers |
|---|---|---|
| **G1** Canonicalization | Unicode NFKC, zero-width, full-width, Base64, URL, Markdown/HTML | A5 |
| **G2** Semantic Risk | 3-class malicious anchors + 20 benign anchors + margin | A2, A6 |
| **G3** Tool Trust | Tool registry, 4-hash check, version, approved | A1, P5, P7 |
| **G4** Policy + Data Flow | RBAC + delegation + data labels + semantic risk | A3, A4, A6, P7, P8 |
| **G5** Approval + Exec + Result | Approval token, sandbox, result validation | A3, A4, P8 |

---

## Attack Catalog

| # | Attack | Without Guard | With MCP-Guard | Blocked at |
|---|---|---|---|---|
| A1 | Tool Poisoning | exfiltrated | BLOCKED | G3 DESCRIPTION_HASH_MISMATCH |
| A2 | Indirect Prompt Injection | refund bypassed | BLOCKED | G4 POLICY_DENY |
| A3 | Tool Result Injection | email sent | BLOCKED | G5 RESULT_INSTRUCTION_DETECTED |
| A4 | PII Exfiltration | pii leaked | BLOCKED | G4 PII_TO_EXTERNAL |
| A5 | Obfuscation Bypass | bypassed | BLOCKED | G1 NORMALIZED_MATCH |
| A6 | Memory Poisoning | role bypassed | BLOCKED | G4 MEMORY_TYPE_REJECTED |
| P7 | Fake Server Registration | registered | BLOCKED | G3 FINGERPRINT_MISMATCH |
| P8 | Resource Boundary Violation | file read | BLOCKED | G5 SANDBOX_PATH_VIOLATION |

### The flagship demo (A4)

The most compelling scenario is **not** a jailbreak.

It is a combination of **individually legitimate** tool calls:

The agent was not jailbroken. Every tool is registered and approved. Every permission check passes. **Only the data-flow policy stops it.**

---
## Metrics

| Metric | Target | Measured |
|---|---|---|
| Attack Recall | > 95% | 8 / 8 catalog attacks blocked |
| False Positive Rate | < 5% | 0 / 4 benign prompts blocked |
| Critical Policy Bypass | 0 | 0 |
| PII Exfiltration Success | 0 | 0 |
| Cross-Tenant Leakage | 0 | 0 |
| P95 Guard Latency | < 50 ms | 6 ms (after G2 cache warm) |
| Hash Chain Integrity | 100% | 100% |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker Desktop (for Redis + PostgreSQL)
- Ollama with `qwen2.5:7b` and `nomic-embed-text`

### Setup

```bash
git clone https://github.com/WZ1887/ai-security-lab.git
cd ai-security-lab

python -m venv .venv
.venv\Scripts\activate.bat

cd backend
pip install -r requirements.txt

docker run -d --name mcp-redis -p 6379:6379 redis:7-alpine
docker run -d --name mcp-postgres -e POSTGRES_USER=mcp -e POSTGRES_PASSWORD=mcp_dev_password -e POSTGRES_DB=mcp_guard -p 5432:5432 postgres:16-alpine

alembic upgrade head

ollama pull qwen2.5:7b
ollama pull nomic-embed-text

uvicorn app.main:app --reload --reload-dir app --port 8000
Open
Chat: http://127.0.0.1:8000/chat.html

Admin: http://127.0.0.1:8000/admin.html

Red Team: http://127.0.0.1:8000/redteam.html

Repository Layout
text
ai-security-lab/
├── docs/            # security-controls.md, attack-catalog.md
├── frontend/        # chat.html, admin.html, redteam.html
├── backend/
│   ├── app/
│   │   ├── api/         # FastAPI routes
│   │   ├── agent/       # Ollama planner
│   │   ├── mcp_guard/   # G1-G5 + gateway + audit
│   │   ├── mcp_servers/ # Order / KB / Email / Finance
│   │   └── models/      # SQLAlchemy
│   └── alembic/
└── attacks/         # (P0 roadmap)
Design Principles
LLM is a proposer, Policy is a decider. The model never grants itself permission.

Data ≠ Instruction. Tool descriptions, tool results, and memory are all untrusted input.

Data-flow policy over per-call checks. Legal-per-step attacks require legal-per-flow defense.

Every gate produces an audit record. Hash chain ensures tamper evidence.

Fail closed. Any security-critical component failure denies high-risk operations.

Roadmap
☑ G1-G5 gates
☑ Gateway orchestration
☑ Audit logging with hash chain
☑ MCP servers (Order / KB / Email / Finance)
☑ Agent planner (Ollama)
☑ Chat API + audit API
☑ Frontend (chat / admin / redteam)
☑ Persistent embedding cache
□ Real MCP Python SDK
□ Full regression harness
□ Docker Compose one-command deploy
License
MIT

