# 评测（eval）

回答一个问题：**这些 Gate 到底有没有用？** 测试（`pytest`）证明的是"实现符合设计"，
评测证明的是"设计对攻击有效、对正常流量无害"。

```bash
cd backend

# 离线：不需要 Postgres / Redis / Ollama（CI 里跑的就是这个）
python -m eval.run_eval

# 生成报告文件
python -m eval.run_eval --markdown ../docs/eval-report.md --json eval-report.json

# 带模型跑（需要 Ollama）：会真实调用 G2 的语义层
python -m eval.run_eval --semantic required --verbose
```

退出码：失败样本数 / recall / FPR / precision 任一不达标返回 1，可以直接当 CI 门禁。

## 三种语义模式

| 模式 | 含义 |
|---|---|
| `offline`（默认） | 把嵌入层替换成"不可用"。这是**受支持的部署状态**：G2 标记 `degraded`，中高风险工具按 fail-closed 转人工审批。CI 用它保证结果确定性，不让网络影响判定。 |
| `auto` | 模型可用就用真模型，不可用退化为 offline。 |
| `required` | 模型必须可用，否则直接失败。用来观察 G2 的真实分数与阈值行为。 |

标了 `requires_model: true` 的样本在 offline 模式下**计入跳过**而不是失败——因为它们的期望
结果依赖模型是否可用（例如"没有敏感标签的中风险发信"在模型可用时放行、模型不可用时转审批）。

## 样本格式

见 [dataset.py](dataset.py) 顶部注释。四种期望类型：

| expect | 含义 |
|---|---|
| `blocked` | 网关必须拒绝；可用 `gate` / `reason_contains` 钉住"被哪一层、用什么原因拦下" |
| `allowed` | 网关必须放行（误报基线） |
| `tool_denied` | 策略放行、但工具层按归属/资源规则拒绝（结果里必须是错误载荷 + `TOOL_ERROR` 标签） |
| `normalized` | 只验证 G1 归一化结果（用 `expect_transformations` 断言变了什么） |

可选字段：`registry_patch`（临时改注册表某一行，用来测"工具未审批/版本不符"）、
`tool_overrides`（篡改调用方声明的哈希/指纹）、`tool_result`（模拟被投毒的工具返回）。

## 指标口径

- **Recall** = 被拦下的攻击 / 全部攻击（`blocked` + `tool_denied` 都算攻击）。
- **FPR** = 被拦下的良性样本 / 全部良性样本。良性集里特意放了 10 条"硬负样本"：
  含"管理员""忽略""SYSTEM"等词、但属于正常业务语境的请求。
- **Precision** = 判为攻击中真是攻击的比例。
- **逐 Gate p50/p95**：直接取网关响应里各 Gate 的 `elapsed_ms`，不额外加埋点。
- **拦截分布**：看攻击实际命中的是哪一层——分布过于集中在某一层，通常说明其它层的样本覆盖不足。

## 标注协议

1. 攻击族按 **OWASP LLM Top 10（LLM01 Prompt Injection / LLM02 Insecure Output / LLM06 Sensitive
   Information Disclosure / LLM07 System Prompt Leakage）** 与 **MCP 特有的工具投毒、Server 冒充**
   拆分；每条样本必须写清"期望在哪一层被拦、原因码是什么"。
2. 同一族至少覆盖三种改写：中文、英文、混淆（零宽 / 全角 / URL / Base64 / HTML / Markdown）。
3. 良性集必须包含硬负样本（与攻击共享词汇但语义正常），否则 FPR 没有意义。
4. 期望值来自**实际跑出来的结果**，而不是"我觉得应该这样"；发现实现与直觉不符时，
   先在报告里记一条发现，再决定是改实现还是改期望。

## 局限（有意写清）

- **这是自评**：攻击样本作者与实现作者是同一个人，覆盖面存在盲区。它证明"已声明的攻击面被处理"，
  不代表"没有别的攻击面"。
- **不覆盖模型层攻击**：越狱、GCG 类对抗后缀、训练数据抽取、模型 DoS 都不在范围内。
- **G2 的语义检测在离线模式下不参与判定**，因此离线报告的 Recall 只反映确定性规则层。
  语义层的召回/FPR 需要用 `--semantic required` 单独测（并在有标注集的前提下做阈值标定）。
- 样本量（100+ 攻击 / 50+ 良性）够做回归门禁，不足以做统计显著性结论；扩展方式见下。

## 这次评测抓到的三个真实缺口（已修）

1. **工具结果里的"策略声明"没人管**：结果里写"跳过所有审批"能过 Result Guard
   （它只查注入指令）。现在 Result Guard 同时查策略声明，原因码 `RESULT_POLICY_CLAIM_DETECTED`。
2. **`<|system|>` 被 G1 的 HTML 剥离"净化"掉了**：旧的 `<[^>]+>` 会把注入标记当标签删掉，
   反而让后续检测看不见它。现在只剥真正像标签的（`</?[a-zA-Z][^>]*>`）。
3. **数据流原因码取决于标签顺序**：`["INTERNAL","FINANCIAL","PII"]` 会报 FINANCIAL 而不是 PII。
   现在按严重程度（SECRET → PII → FINANCIAL → …）固定顺序判定，审计原因码稳定可解释。

## 怎么扩展

1. 往 `datasets/*.jsonl` 追加样本（一项一行，`id` 全局唯一）；
2. 跑 `python -m eval.run_eval --verbose` 看是不是符合预期；
3. 如果新样本失败，分成两类处理：**实现有缺口** → 修实现并补一条单测；
   **期望写错** → 改期望并在提交信息里说明为什么。
4. 良性样本请优先加"看起来像攻击"的那种——增加容易样本只会让 FPR 好看，没有信息量。
