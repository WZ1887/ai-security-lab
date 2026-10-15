# 实现状态

> 这份文件只回答一个问题：docs 里写的东西，代码到底做了没有。
>
> 状态三档：**已实现**（有测试或接口可复现）、**部分实现**（写清缺什么）、**未实现**。
> 判据是代码与回归测试，不是文档里的措辞。

## 身份与授权

| 能力 | 状态 | 证据 / 缺口 |
|---|---|---|
| 身份只来自签名令牌（JWT/HS256） | 已实现 | `app/security/principal.py`；`tests/test_identity_and_ownership.py` |
| 请求体里的身份字段被忽略 | 已实现 | `ChatRequest` 不含身份字段；`test_a6_identity_cannot_be_self_asserted` |
| 登录（bcrypt 口令 + 失败计数锁定） | 已实现 | `app/security/users.py`、`POST /api/auth/login`；`tests/test_auth_login.py` |
| MFA（TOTP，RFC 6238） | 已实现 | `app/security/totp.py` + `/mfa/enroll`、`/mfa/activate`；用官方测试向量回归 |
| 会话与刷新令牌（轮换 / 注销） | 已实现 | `app/security/sessions.py`；库内只存 sha256，旧令牌立刻失效 |
| 刷新令牌族复用检测 | 未实现 | 只做轮换、不记录历史摘要，无法判定“旧令牌曾被他人使用” |
| 自注册（最低权限 + 邮箱验证） | 已实现 | `app/security/registration.py`；`tests/test_registration.py` |
| 邮箱验证投递（真实发信） | 未实现 | dev 环境在响应里回显令牌，真实部署需接邮件服务 |
| 注册限流 | 部分实现 | 进程内固定窗口（按 IP）；多实例部署需换成共享计数 |
| 管理员建号 / 授角色 / 停用 | 已实现 | `/api/auth/users`、`/users/{id}/roles`、`/users/{id}/status`（仅管理员、限本租户） |
| 自注册账号纳入租户（invite / claim） | 已实现 | `POST /api/auth/users/{id}/adopt`；只允许针对公共租户账号，防跨租户提权 |
| 改密 | 已实现 | `POST /api/auth/password` + 撤销该账号全部刷新令牌 |
| 找回口令 / 登录告警 | 未实现 | — |
| dev-token 后门 | 默认关闭 | `ALLOW_DEV_TOKEN`（且仅 dev 生效）；测试断言默认返回 403 |
| 代理授权（按会话申领客户） | 部分实现 | 管理员可绑定账号的固定客户范围（`/users/{id}/scope`）并作废旧令牌；按会话申领 + ACL 未做 |
| 审批角色白名单 | 已实现 | `APPROVER_ROLES = {admin, finance_manager}` |
| 双人复核 / 独立通道验证码 | 未实现 | `approvals` 表已留 `second_approver_id` / `verification_code_*` 字段，未接线 |
| 租户隔离 | 已实现 | 审计按租户过滤；审批跨租户按 404 处理；订单同时校验 user 与 tenant |
| 用户 / 租户表接线 | 已实现 | 登录、会话、角色都走 `users` / `tenants` / `sessions`；dev 环境自动种 4 个演示账号 |
| 弱配置检查 | 已实现 | `JWT_SECRET` / `APPROVAL_TOKEN_SECRET` < 32 字节：dev 告警，其他环境拒绝启动 |

## Gate

| 能力 | 状态 | 证据 / 缺口 |
|---|---|---|
| G1 归一化（NFKC / Cf / 全角 / URL / 内嵌 Base64 / HTML / Markdown） | 已实现 | `tests/test_attack_catalog.py::test_a5_*` |
| G1 展开比例拒绝 | 已实现 | 按字节计算，NFKC 兼容分解可触发 `high_expansion_ratio` |
| G1 超时熔断（`timeout_ms`） | 未实现 | 只有 `max_bytes` 与解码深度限制，没有按时间中断 |
| G2 语义风险（锚点 + margin） | 已实现（需 Ollama） | `app/mcp_guard/semantic/` |
| G2 嵌入不可用时的降级 | 已实现 | `degraded=True` → `POL-202` 对中高风险工具强制审批 |
| G2 锚点配置化 | 部分实现 | 锚点硬编码在 `anchors.py`，尚未入库 |
| G3 注册表 + Server 指纹 + 版本 + 4 个哈希 | 已实现 | `tests/test_tool_trust.py` |
| G3 参数校验 | 部分实现 | 自研简化 schema（拒未知字段 / 类型校验 / 数字字符串规范化），不是标准 JSON Schema，也没有“必填”概念 |
| G4 RBAC + 委派范围 + 数据流 | 已实现 | `app/mcp_guard/policy/engine.py`、`dataflow/engine.py` |
| G4 ABAC（时间 / 金额等属性条件） | 未实现 | 文档提到过，代码里没有 |
| G4 跨租户标签规则（`TENANT_PRIVATE`） | 未实现 | 标签已定义、规则未写；当前跨租户靠工具层归属校验 |
| G4 策略入库（`policy_rules` 表） | 未实现 | 策略硬编码在 `policy/rules.py`，表建了没用 |
| G5 审批令牌（签名 / 有效期 / 绑定会话+工具+发起人） | 已实现 | `app/mcp_guard/approval/tokens.py`；`tests/test_approval_tokens.py` |
| G5 jti 防重放 | 部分实现 | 进程内缓存 + TTL；多实例部署需要 Redis 或 DB 唯一约束 |
| G5 沙箱路径白名单 | 已实现 | 真实路径归一 + 目录前缀判定 + symlink 逃逸检查 |
| G5 子进程隔离 / 资源限制 / 网络白名单 | 未实现 | 仍是同进程调用，只有参数长度与路径校验 |
| G5 `execution_token`（docs 提到） | 未实现 | 代码里没有这一层 |
| 审计哈希链 + 链校验接口 | 已实现 | 写入加锁（进程内）；`GET /api/audit/verify` |
| 审计链的多进程安全 | 未实现 | 进程内锁；多 worker 需要数据库层串行化（行锁 / 序号列） |
| Result Guard（结果先过 G1 再检出注入） | 已实现 | `tests/test_attack_catalog.py::test_a3_*` |
| 前端审批 UI | 未实现 | 审批单号目前只出现在回复文本与红队页输出里 |

## 其它

| 能力 | 状态 | 证据 / 缺口 |
|---|---|---|
| 工具元数据单源化 + 启动同步注册表 | 已实现 | `app/mcp_guard/registry/sync.py`；启动日志 `[registry] 已同步 N 个工具` |
| 真实 MCP Python SDK | 未实现 | 用 Python 类模拟（`app/mcp_servers/base.py`） |
| 记忆子系统（A6） | 已实现 | `app/memory/`、`save_memory` 工具、`GET/DELETE /api/memory` |
| 记忆只存事实（写入侧） | 已实现 | G4 规则 MEM-001 + 工具内兜底；`tests/test_memory_poisoning.py` |
| 记忆读取侧隔离 | 已实现 | 注入模型上下文前重新分类，策略类内容置 `quarantined` |
| 记忆按 (tenant, user) 隔离 | 已实现 | 客服只能读写被代理客户（`resource_user_id`）的记忆 |
| 记忆向量检索 / 相似度召回 | 未实现 | 当前按写入时间倒序取最近 N 条（`MEMORY_RECALL_LIMIT`） |
| 记忆加密存储 / 用户数据导出 | 未实现 | 目前是明文列 + 接口查看/删除 |
| `labs/01_…07_` 专项实验脚本 | 独立运行 | 与 `backend/` 无代码交叉，依赖见 `labs/requirements.txt` |
| 依赖探活 | 已实现 | `GET /health/deps`（数据库 / Ollama + 各自触发哪种 fail-closed） |
| 带标签评测集 + 指标脚本 + CI 门禁 | 已实现 | `backend/eval/`（167 样本）、`python -m eval.run_eval`、`.github/workflows/ci.yml` |
| G2 语义层阈值标定 | 未实现 | 需要模型环境；`--semantic required` 先跑出分数分布 |

## 怎么自己验证

```bash
cd backend
pytest -q                                 # 69 个用例，不需要 Postgres / Redis / Ollama
python -m eval.run_eval                   # 离线评测：Recall / FPR / 延迟报告
python -m app.mcp_guard.registry.sync     # 手动同步工具注册表
```

运行时接口：

- `GET /health/deps` — 数据库与模型可用性
- `GET /api/audit/verify` — 审计哈希链完整性（需 admin / auditor / security_analyst 角色）
