# MCP-Guard Security Controls

> 五类安全 Gate 的输入、输出、失败策略、对应攻击、对应指标。
>
> 设计原则：
> 1. 每个 Gate 只做一件事，输出结构化结果
> 2. Gate 不直接做最终授权，只产出信号/校验结果
> 3. 最终决策由 Policy Engine 统一做
> 4. 任何 Gate 失败 → fail-closed（高风险拒绝，低风险降级）
> 5. 所有 Gate 输出可审计、可回放

---

## G1：Canonicalization Gate

### 目的
把不可信输入转换为统一表示，为后续 Gate 提供干净数据。不做判定。

### 输入

    CanonicalizeInput:
        raw_text: str
        source: user | tool_description | tool_result | memory | document
        max_bytes: 65536
        max_decode_depth: 3
        max_expansion_ratio: 10.0
        timeout_ms: 50

### 处理逻辑

    1. 资源预检：len(raw_text) <= max_bytes，否则 TRUNCATE + WARN
    2. Unicode NFKC 归一化
    3. 移除零宽字符：U+200B~U+200D, U+2060, U+FEFF
    4. 全角转半角
    5. URL 编码解码（最多 max_decode_depth 层）
    6. Base64 检测与解码（最多 max_decode_depth 层）
    7. Markdown 结构剥离（保留纯文本）
    8. HTML 标签剥离
    9. 展开比例检查：len(out)/len(in) > max_expansion_ratio → 拒绝
    10. 输出规范化文本 + 变换记录

### 输出

    CanonicalizeOutput:
        normalized_text: str
        transformations: list[str]
        risk_signals: list[str]
        truncated: bool
        elapsed_ms: int

### 失败策略

| 故障 | 策略 |
|---|---|
| 超时 | 高风险工具拒绝，低风险放行 + 审计 |
| 展开比例超限 | 直接拒绝 |
| 输入超长 | 截断 + WARN + 高风险拒绝 |

### 覆盖攻击
A5 混淆绕过

### 指标
- g1_latency_p95 < 5ms
- g1_expansion_reject_total

---

## G2：Semantic Risk Gate

### 目的
产出风险信号，不做最终判定。

### 输入

    SemanticInput:
        normalized_text: str
        source: str
        context_window: list[str]
        anchors: list[Anchor]

### 处理逻辑

    1. 分片重组：把 context_window 合并（按时间序）
    2. 对 normalized_text 与合并文本分别做嵌入
    3. 与 3 类锚点比较余弦相似度
       - data_exfiltration
       - instruction_override
       - tool_misuse
    4. 取最高分 + 命中类别
    5. 输出 risk_score ∈ [0, 1] + signals

### 输出

    SemanticOutput:
        risk_score: float
        signals: list[str]
        action: ALLOW | REVIEW | REQUIRE_APPROVAL
        anchor_scores: dict[str, float]
        elapsed_ms: int

### 风险 → 动作映射

    risk < 0.6           → ALLOW
    0.6 <= risk < 0.85   → REVIEW（记录，不阻断）
    risk >= 0.85         → REQUIRE_APPROVAL（抬高审批门槛）

### 失败策略

| 故障 | 策略 |
|---|---|
| 嵌入服务超时 | 返回 risk_score=0.0, action=REVIEW，不阻断 |
| 锚点缺失 | 拒绝启动，配置错误 |
| 分片过长 | 截断到 max_tokens |

### 覆盖攻击
A2 间接注入、A6 语义规避

### 指标
- g2_latency_p95 < 30ms
- g2_review_total / g2_require_approval_total

---

## G3：Tool Trust / Schema Gate

### 目的
校验工具身份、版本、Schema、描述，拦截工具投毒与重定义。

### 输入

    ToolCallInput:
        server_id: str
        tool_name: str
        tool_version: str
        input_schema_hash: str
        description_hash: str
        capability_hash: str
        arguments: dict
        session_token: str

### 处理逻辑

    1. 查 Tool Registry：server_id + tool_name 是否存在
    2. 校验 approved == True
    3. 校验 tool_version 匹配
    4. 校验 input_schema_hash 匹配
    5. 校验 description_hash 匹配
    6. 校验 capability_hash 匹配
    7. Pydantic 强校验 arguments（拒绝多余字段）
    8. 输出校验结果

### 输出

    ToolTrustOutput:
        valid: bool
        reason: str
        validated_args: dict
        tool_risk_level: low | medium | high
        output_labels: list[str]
        elapsed_ms: int

### 失败策略

| 故障 | 策略 |
|---|---|
| Registry 不可用 | 拒绝所有工具调用 |
| 哈希不匹配 | BLOCK + 告警 |
| Schema 校验失败 | BLOCK |

### 覆盖攻击
A1 工具投毒、P5 工具重定义、P7 Server 冒充

### 指标
- g3_latency_p95 < 10ms
- g3_metadata_changed_total

---

## G4：IAM + Policy + Data Flow Gate

### 目的
最终授权决策。这是整个系统的安全核心。

### 输入

    PolicyInput:
        subject: Subject
        agent: AgentIdentity
        session: SessionInfo
        tool: ToolTrustOutput
        semantic: SemanticOutput
        data_labels_in: list[str]
        requested_action: str
        resource: dict

### 处理逻辑

    1. RBAC：subject.roles 是否允许 tool
    2. ABAC：属性条件（时间、金额、数据标签）是否满足
    3. 委派范围：tool 是否在 agent 的 delegation_scope 内
    4. 数据流策略：
       - 输入标签 × 工具 output_labels → 检查是否违反 sink 规则
       - PII → EXTERNAL → DENY
    5. 风险信号合并：
       - semantic.risk >= 0.85 且 tool.risk_level == high → REQUIRE_APPROVAL
    6. jti/nonce 防重放检查（Redis）
    7. 输出决策

### 输出

    PolicyOutput:
        decision: ALLOW | DENY | REQUIRE_APPROVAL
        reason: str
        policy_id: str
        data_labels_out: list[str]
        approval_required: bool
        elapsed_ms: int

### 数据流标签

    PUBLIC
    INTERNAL
    PII
    FINANCIAL
    SECRET
    TENANT_PRIVATE

### Sink 规则

    PII            → EXTERNAL   DENY
    FINANCIAL      → EXTERNAL   DENY
    SECRET         → ANY        DENY
    TENANT_PRIVATE → 跨租户     DENY
    INTERNAL       → EXTERNAL   REQUIRE_APPROVAL

### 失败策略

| 故障 | 策略 |
|---|---|
| Redis 不可用 | 拒绝所有高风险工具 |
| Policy Engine 异常 | 拒绝所有工具调用 |
| 数据标签未知 | 按 SECRET 处理，拒绝 |

### 覆盖攻击
A3 工具返回注入、A4 PII 外泄、A6 记忆投毒、P7/P8

### 指标
- g4_latency_p95 < 10ms
- g4_policy_deny_total{reason}
- g4_dataflow_block_total{from_label, to_sink}

---

## G5：Approval + Execution + Result Validation Gate

### 目的
高风险操作人工审批 + 沙箱执行 + 结果再校验。

### 输入

    ExecutionInput:
        policy: PolicyOutput
        tool_call: ToolCallInput
        approval_token: str | None

### 处理逻辑

    1. 若 policy.decision == REQUIRE_APPROVAL：
       - 校验 approval_token 有效（签名、jti、exp）
       - 校验审批人 ≠ 发起人
       - 校验审批内容与工具调用一致
    2. 生成 execution_token（短生命周期、audience-bound）
    3. 沙箱执行：
       - 子进程隔离
       - 禁敏感文件路径
       - 网络白名单
       - 超时熔断
    4. 工具返回结果 → 进入 Result Guard：
       - G1 清洗
       - Schema 校验
       - G2 检测是否含指令
       - 打数据标签
    5. 输出最终结果

### 输出

    ExecutionOutput:
        success: bool
        result: dict
        result_labels: list[str]
        result_risk: float
        execution_token_jti: str
        elapsed_ms: int

### 人工确认展示

    {
      "action": "TRANSFER_FUNDS",
      "amount": 1250,
      "from_account": "A***1234",
      "to_account": "B***5678",
      "reason": "Refund #R10231",
      "requested_by": "cs_agent_01",
      "session_id": "sess_abc"
    }

只展示结构化字段，不展示模型生成的自由文本。

### 失败策略

| 故障 | 策略 |
|---|---|
| Approval 服务不可用 | 高风险拒绝 |
| 沙箱启动失败 | 拒绝执行 |
| 结果 Schema 校验失败 | 拒绝返回，记审计 |
| 执行超时 | 熔断，返回超时错误 |

### 覆盖攻击
A3 工具结果注入、A4 数据外泄、P8 资源越权

### 指标
- g5_approval_total{result}
- g5_sandbox_violation_total
- g5_result_guard_block_total

---

## Gate 汇总表

| Gate | 输入 | 输出 | 失败策略 | 覆盖攻击 | 延迟目标 |
|---|---|---|---|---|---|
| G1 Canonicalization | 原始文本 | 规范化文本 | 高风险拒绝 | A5 | <5ms |
| G2 Semantic Risk | 规范化文本 | 风险信号 | 不阻断 | A2/A6 | <30ms |
| G3 Tool Trust | 工具调用 | 校验结果 | 拒绝所有 | A1/P5/P7 | <10ms |
| G4 Policy/DataFlow | 全部上下文 | 决策 | fail-closed | A3/A4/A6/P7/P8 | <10ms |
| G5 Approval/Exec | 决策+调用 | 执行结果 | 高风险拒绝 | A3/A4/P8 | 视工具 |

---

## 审计事件统一 Schema

    {
      "event_id": "uuid",
      "timestamp": "2026-10-02T21:30:00Z",
      "tenant_id": "tenant_001",
      "session_id": "sess_abc",
      "subject": "user_123",
      "agent": "cs_agent_01",
      "server_id": "order-server",
      "tool_name": "get_order",
      "gate_results": {
        "g1": {"transformations": [], "elapsed_ms": 2},
        "g2": {"risk_score": 0.12, "signals": [], "elapsed_ms": 25},
        "g3": {"valid": true, "reason": "OK", "elapsed_ms": 3},
        "g4": {"decision": "ALLOW", "reason": "OK", "elapsed_ms": 5},
        "g5": {"success": true, "result_labels": ["PII"], "elapsed_ms": 40}
      },
      "policy_action": "ALLOW",
      "policy_reason": "OK",
      "input_hash": "sha256:...",
      "tool_schema_hash": "sha256:...",
      "result_hash": "sha256:...",
      "latency_ms": 75
    }

---

## 指标定义

| 指标 | 定义 | 目标 |
|---|---|---|
| ASR | 攻击最终完成危险目标的比例 | <1% |
| Recall | 检测出的攻击 / 全部攻击 | >95% |
| FPR | 正常请求被错误拦截比例 | <5% |
| Precision | 判恶意中真正恶意比例 | >95% |
| P95 Guard Latency | Guard 额外延迟 | <50ms |
| Policy Bypass | 未授权完成工具操作比例 | 0 |
| PII Exfiltration Success | PII 到达外部 Sink 比例 | 0 |
| Cross-Tenant Leakage | 跨租户读取成功次数 | 0 |