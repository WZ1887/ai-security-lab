# MCP-Guard

[![ci](https://github.com/WZ1887/ai-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/WZ1887/ai-security-lab/actions/workflows/ci.yml)

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
- An attacker can simply claim a role in the request body.

Most defenses stop at "detect prompt injection". MCP-Guard enforces **policy** at every boundary.

---

## Architecture

```
frontend (chat / admin / redteam)
   │  Authorization: Bearer <jwt>
   ▼
FastAPI  /api/chat  ──►  Agent planner (Ollama)  ──►  tool call intent
   │                                                       │
   ▼                                                       ▼
G1 Canonicalize ─► G2 Semantic risk ─► G3 Tool trust ─► G4 Policy + Data flow ─► G5 Approval + Sandbox + Result guard
   │                                                          │
   └────────────────────► audit_events (hash chain) ◄──────────┘
                       GET /api/audit/verify 校验链完整性
```

四个关键约定：

1. **身份只来自签名令牌**。`/api/chat` 不读请求体里的 `user_id / tenant_id / roles / agent_id`；
   角色、租户、资源归属全部由 `Principal`（见 `app/security/principal.py`）推导。
2. **工具元数据只有一个来源**：各 MCP Server 的 `ToolSpec`。`tool_registry` 由
   `app/mcp_guard/registry/sync.py` 在启动时派生（幂等），三处副本漂移导致 G3 全线拒绝的历史问题已消除。
3. **Gate 只产出信号，G4 统一裁决**。任一层失败即终止，并写一条带哈希链的审计事件。
4. **降级要显式**。数据库不可用 → 注册表为空 → G3 拒绝所有调用；嵌入模型不可用 → G2 标记 `degraded`
   → 中高风险工具抬高到人工审批。两条路径都不会静默放行。

---

## Five Security Gates

| Gate | Purpose | Covers |
|---|---|---|
| **G1** Canonicalization | NFKC、零宽/格式化字符（Cf）、全角、URL、内嵌 Base64、Markdown/HTML，按字节判膨胀 | A5 |
| **G2** Semantic Risk | 3 类恶意锚点 + 20 条良性锚点 + margin，失败降级为 `degraded` | A2, A6 |
| **G3** Tool Trust | 注册表 + Server 指纹 + 版本 + 4 个哈希 + schema 校验（拒未知字段、数字字符串规范化） | A1, P5, P7 |
| **G4** Policy + Data Flow | RBAC + 委派范围 + 数据标签 × sink + 语义风险合并（含降级升级） | A3, A4, A6, P7, P8 |
| **G5** Approval + Exec + Result | 审批令牌（绑定会话/工具/发起人 + jti 防重放）、沙箱路径白名单、结果先过 G1 再检出注入 | A3, A4, P8 |

---

## Attack Catalog

| # | Attack | Without Guard | With MCP-Guard | Blocked at |
|---|---|---|---|---|
| A1 | Tool Poisoning | exfiltrated | BLOCKED | G3 `DESCRIPTION_HASH_MISMATCH` |
| A2 | Indirect Prompt Injection | 指令随毒文档回流 | BLOCKED | G5 `RESULT_GUARD_FAIL:RESULT_INSTRUCTION_DETECTED`（语义分由 G2 另行评分） |
| A3 | Tool Result Injection | email sent | BLOCKED | G5 `RESULT_GUARD_FAIL:RESULT_INSTRUCTION_DETECTED` |
| A4 | PII Exfiltration | pii leaked | BLOCKED | G4 `PII_TO_EXTERNAL` |
| A5 | Obfuscation Bypass | bypassed | BLOCKED | G1 归一化（`zero_width_removed` / `url_decoded` / `base64_decoded`）+ G5 |
| A6 | Memory Poisoning | role bypassed | BLOCKED | G4 `MEMORY_CANNOT_STORE_POLICY`（写入侧）+ 读取侧隔离 |
| P7 | Fake Server Registration | registered | BLOCKED | G3 `SERVER_FINGERPRINT_MISMATCH` |
| P8 | Resource Boundary Violation | file read | BLOCKED | G5 `SANDBOX_PATH_VIOLATION` |

详细攻击路径、证据字段与回归样本见 [docs/attack-catalog.md](docs/attack-catalog.md)。
每条攻击都有对应的可执行测试，见 [backend/tests/test_attack_catalog.py](backend/tests/test_attack_catalog.py)。

### The flagship demo (A4)

The most compelling scenario is **not** a jailbreak.

It is a combination of **individually legitimate** tool calls: the agent reads its own order
(`get_order`, allowed), then tries to email the content out (`send_email`, allowed by RBAC).

The agent was not jailbroken. Every tool is registered and approved. Every permission check passes.
**Only the data-flow policy stops it** — `data_labels_in` 里带着上一轮返回的 `PII`，sink 是 `EXTERNAL`。

---

## Metrics

数字分两类：**回归测试**（证明实现符合设计）与**评测**（证明设计对攻击有效、对正常流量无害）。
评测用 `backend/eval/` 下的带标签样本集跑，报告见 [docs/eval-report.md](docs/eval-report.md)。

```bash
cd backend
pytest -q                                    # 69 个用例（含评测自检）
python -m eval.run_eval                      # 离线评测：不需要 Postgres / Redis / Ollama
python -m eval.run_eval --semantic required  # 带模型跑，观察 G2 语义层分数
```

| Metric | Target | Measured（离线，167 样本：106 攻击 / 56 良性 / 5 跳过） |
|---|---|---|
| Attack Recall | > 95% | **106/106 = 100%**（确定性规则层；语义层需 `--semantic required` 另测） |
| False Positive Rate | < 5% | **0/56 = 0%**（含 10 条与攻击共享词汇的硬负样本） |
| Precision | > 95% | **1.000** |
| PII Exfiltration Success | 0 | 0（A4 全部拦在 G4 数据流） |
| Cross-Tenant / Cross-User Read | 0 | 0（工具层归属校验，计为 `tool_denied`） |
| Hash Chain Integrity | 100% | `GET /api/audit/verify`；篡改 / 删行都能定位到断裂点 |
| Guard 延迟（离线） | p95 < 50 ms | **p50 8 ms / p95 14 ms**（本机 Python 3.13；逐 Gate 数字见报告） |
| G2 语义层阈值 | 待标定 | 未标定：先用 `--semantic required` 跑出分数分布，再谈阈值 |

运行回归测试（不需要 Postgres / Redis / Ollama）：

```bash
cd backend
pytest -q
```

---

## Authentication & Identity

身份的第一来源是登录，不是请求体：

```
POST /api/auth/login {email, password, totp_code?}
      │  bcrypt 校验 → 失败累加计数 → 连续 5 次锁 15 分钟
      │  开启 MFA 的账号必须带 TOTP
      ▼
access_token (JWT, 默认 15 分钟)  +  refresh_token (随机串, 默认 7 天, 库内只存 sha256)
      │                                   │
      │                                   └─ POST /api/auth/refresh 轮换；POST /api/auth/logout 注销
      ▼
Principal{ user_id, tenant_id, roles[], agent_id, on_behalf_of }
      │
      └─ resource_user_id = on_behalf_of or user_id  → 资源归属按这个判定
```

- **角色来自数据库**（`users.roles`），不是客户端自报；`/api/chat` 的请求体里没有身份字段。
- **代理语义**：客服账号的 `on_behalf_of` 指向被代理的客户，因此"查订单"查的是客户的订单，
  而审计里记录的仍是操作者。当前该属性由管理员通过 `/api/auth/users/{id}/scope` 绑定并作废旧令牌，
  "按会话申领客户 + ACL 校验"还没做，见 [implementation-status.md](docs/implementation-status.md)。
- **dev-token 默认关闭**（`ALLOW_DEV_TOKEN`，且只在 `app_env=dev` 生效），只作为本机调试后门。
- **弱配置检查**：`JWT_SECRET` / `APPROVAL_TOKEN_SECRET` 少于 32 字节时，dev 环境告警、
  其他环境直接拒绝启动。

### 自注册

```
POST /api/auth/register {email, password}
      │  租户与角色由服务端固定：tenant_public + customer（ROLE_TOOLS 里零权限）
      │  口令策略：≥8 位且同时含字母与数字；同一 IP 15 分钟最多 5 次
      ▼
status=pending ──> POST /api/auth/verify-email {token} ──> status=active，直接签发令牌
```

- 注册响应**不区分"邮箱已存在"与"注册成功"**，避免拿注册接口枚举账号；
- 邮箱验证令牌是不透明随机串，库内只存 sha256，默认 24 小时过期。
  dev 环境会在响应里回显令牌（本机没有邮件服务），真实部署应改为发信；
- 自注册账号落在**公共租户**（`DEFAULT_SIGNUP_TENANT`）且**零权限**。要让它变成可用身份，
  需要某个租户的管理员把它纳入自己的租户：`POST /api/auth/users/{id}/adopt`
  （只允许针对公共租户里的账号，避免跨租户提权），可同时指定角色与代客范围，并作废旧令牌；
- **特权角色只能由管理员授予**：`POST /api/auth/users`（建号，可同时指定角色与代客范围）、
  `/users/{id}/roles`、`/users/{id}/status`、`/users/{id}/scope`；角色变更会作废该用户刷新令牌
  （已签发的访问令牌最长 15 分钟后失效）；
- 改密：`POST /api/auth/password`，校验旧口令，成功后撤销该账号全部刷新令牌。

### 演示账号（仅 dev 环境自动创建，口令统一 `Demo1234!`）

| 邮箱 | 角色 | 租户 | 代客 | 用途 |
|---|---|---|---|---|
| `cs01@example.com` | cs_agent | tenant_001 | user_001 | 客服，能查该客户订单 |
| `cs02@example.com` | cs_agent | tenant_002 | user_002 | 另一租户客服，读不到 user_001 的订单 |
| `finance01@example.com` | finance_agent | tenant_001 | — | 可发起转账（须人工审批） |
| `manager01@example.com` | admin / finance_manager / auditor | tenant_001 | — | 审批、看审计、校验哈希链 |

---

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL（或用任意 SQLAlchemy 支持的 URL；跑测试用内存 SQLite 即可）
- Ollama，至少一个 chat 模型 + 一个 embedding 模型

Redis 不是必需依赖：审批令牌的 jti 防重放是进程内缓存（多实例部署时才需要换成 Redis）。

### Setup

```bash
git clone https://github.com/WZ1887/ai-security-lab.git
cd ai-security-lab

python -m venv .venv
.venv\Scripts\activate.bat

cd backend
pip install -r requirements.txt

# 数据库（示例用 Docker，也可以直接用本机 PostgreSQL）
docker run -d --name mcp-postgres -e POSTGRES_USER=mcp -e POSTGRES_PASSWORD=mcp_dev_password -e POSTGRES_DB=mcp_guard -p 5432:5432 postgres:16-alpine

alembic upgrade head

ollama pull qwen2.5:7b
ollama pull nomic-embed-text

# 在 backend/ 下启动即可：配置与静态资源都锚定到仓库根目录，不依赖 CWD
uvicorn app.main:app --reload --reload-dir app --port 8000
```

打开：

- Chat：<http://127.0.0.1:8000/chat.html>
- Admin（审计看板）：<http://127.0.0.1:8000/admin.html>
- Red Team：<http://127.0.0.1:8000/redteam.html>

启动时可以留意日志里的 `[registry] 已同步 N 个工具`；`GET /health/deps` 会回报数据库与
Ollama 的可用性，以及不可用时各自会触发的 fail-closed 行为。

### API

```bash
# 0. 自注册（可选）：只能拿到 customer 角色，需要用管理员账号再授权
curl -X POST http://127.0.0.1:8000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"Passw0rd!"}'

# dev 环境响应里带 verification_token，直接验证即可完成注册并登录
curl -X POST http://127.0.0.1:8000/api/auth/verify-email \
  -H 'Content-Type: application/json' -d '{"token":"<上一步返回的令牌>"}'

# 1. 登录拿令牌（演示口令见上表）
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"cs01@example.com","password":"Demo1234!"}' | python -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

# 2. 发消息（身份只来自令牌）
curl -X POST http://127.0.0.1:8000/api/chat \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"session_id":"sess_1","user_input":"帮我查一下订单 #10023"}'

# 3. 高风险操作会返回 approval_id，由具备审批角色的人批准
MANAGER_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"manager01@example.com","password":"Demo1234!"}' | python -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

curl -X POST http://127.0.0.1:8000/api/approvals/$APPROVAL_ID/approve \
  -H "Authorization: Bearer $MANAGER_TOKEN"

# 4. 带 approval_token 重发同一请求即可执行
curl -X POST http://127.0.0.1:8000/api/chat \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"session_id":"sess_1","user_input":"把 1000 元转到账户 B","approval_token":"..."}'

# 5. 校验审计哈希链（需要 admin / auditor / security_analyst 角色）
curl http://127.0.0.1:8000/api/audit/verify -H "Authorization: Bearer $MANAGER_TOKEN"

# 6. 会话维护
curl -X POST http://127.0.0.1:8000/api/auth/refresh -H 'Content-Type: application/json' -d '{"refresh_token":"..."}'
curl -X POST http://127.0.0.1:8000/api/auth/logout  -H 'Content-Type: application/json' -d '{"refresh_token":"..."}'
curl http://127.0.0.1:8000/api/auth/me -H "Authorization: Bearer $TOKEN"
```

---

## Repository Layout

```
ai-security-lab/
├── README.md · LICENSE · .gitattributes · .gitignore
├── .github/workflows/ci.yml     # pytest + 离线评测门禁
├── docs/                        # attack-catalog / security-controls / implementation-status / eval-report
├── frontend/                    # chat.html, admin.html, redteam.html
├── backend/
│   ├── requirements.txt         # 应用依赖
│   ├── alembic/                 # 数据库迁移
│   ├── eval/                    # 带标签评测集 + 指标脚本（见 eval/README.md）
│   ├── tests/                   # 攻击目录回归 + Gate 单测 + 评测自检
│   └── app/
│       ├── api/                 # chat / audit / approvals / auth / memory
│       ├── agent/               # Ollama planner（记忆事实按“不可信数据”注入）
│       ├── config.py            # 配置（叶子模块，避免循环导入）
│       ├── security/            # Principal + JWT + bcrypt + TOTP + 会话
│       ├── mcp_guard/           # G1-G5 + gateway + registry + policy + audit + approval + sandbox
│       ├── memory/              # 记忆守卫（只存事实）+ 存储
│       ├── mcp_servers/         # Order / KB / Email / Finance / Memory
│       └── models/              # SQLAlchemy
└── labs/                        # 早期专项实验脚本（独立于应用，见 labs/README.md）
    ├── 01_prompt_injection/ … 07_full_system_simulation/
    └── requirements.txt         # 只服务于 labs 的依赖
```

## Design Principles

- **LLM is a proposer, Policy is a decider.** The model never grants itself permission.
- **Data ≠ Instruction.** Tool descriptions, tool results, and memory are all untrusted input.
- **Data-flow policy over per-call checks.** Legal-per-step attacks require legal-per-flow defense.
- **Every gate produces an audit record.** Hash chain ensures tamper evidence.
- **Fail closed.** Any security-critical component failure denies high-risk operations.

## Roadmap

- [x] G1-G5 gates
- [x] Gateway orchestration
- [x] Audit logging with hash chain + `GET /api/audit/verify`
- [x] MCP servers (Order / KB / Email / Finance / Memory)
- [x] Agent planner (Ollama)
- [x] JWT identity + approvals API
- [x] Regression harness（攻击目录 → pytest）
- [x] 真正的登录：bcrypt 口令 + TOTP + 可轮换刷新令牌（dev-token 默认关闭）
- [x] 自注册（最低权限 + 邮箱验证）+ 管理员授角色 / 停用 / 绑定客户范围
- [ ] 代理授权：按会话申领客户（当前由管理员绑定固定客户范围）
- [x] 记忆子系统（A6）：只存事实 + 读取侧隔离 + `GET/DELETE /api/memory`
- [ ] `policy_rules` 表接线（策略可配置化）
- [ ] Redis / DB 版 jti 防重放（多实例部署）
- [ ] Real MCP Python SDK
- [ ] Docker Compose one-command deploy

## License

MIT
