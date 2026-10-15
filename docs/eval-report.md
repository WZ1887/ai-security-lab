# MCP-Guard 评测报告

| 项 | 值 |
|---|---|
| 生成时间 | 2026-10-15 08:42:56Z |
| 语义模式 | offline（实际 offline） |
| 样本目录 | eval\datasets |
| Python | 3.13.9 |
| 平台 | Windows-11-10.0.26200-SP0 |
| 样本数 | 167（计入 162，跳过 5） |

## 总体指标

| Metric | Value |
|---|---|
| Recall（攻击） | 106/106 = 1.000 |
| Precision | 1.000 |
| FPR（良性被拦） | 0/56 = 0.000 |
| 端点总延迟 p50 / p95 | 8.0 ms / 16.0 ms |

## 逐 Gate 延迟（响应内计时）

> 数字取自网关响应里各 Gate 的 `elapsed_ms`，整数毫秒；0 表示低于 1 ms。

| Gate | p50 (ms) | p95 (ms) |
|---|---|---|
| g1 | 0.0 | 0.0 |
| g2 | 0.0 | 0.0 |
| g3 | 0.0 | 2.0 |
| g4 | 0.0 | 0.0 |
| g5 | 0.0 | 6.0 |

## 各族的拦截/放行是否符合作者预期

| Family | Total | Pass | Fail |
|---|---|---|---|
| A1_tool_poisoning | 12 | 12 | 0 |
| A2_indirect_injection | 12 | 12 | 0 |
| A3_result_injection | 10 | 10 | 0 |
| A4_pii_exfiltration | 14 | 14 | 0 |
| A5_obfuscation | 19 | 19 | 0 |
| A6_memory_poisoning | 15 | 15 | 0 |
| P7_fake_server | 6 | 6 | 0 |
| RBAC | 11 | 11 | 0 |
| arg_smuggling | 8 | 8 | 0 |
| benign_customer | 24 | 24 | 0 |
| benign_hard_negative | 10 | 10 | 0 |
| benign_memory | 7 | 7 | 0 |
| ownership | 8 | 8 | 0 |
| registry_integrity | 5 | 5 | 0 |
| schema_coercion | 1 | 1 | 0 |

## 拦截发生在哪一层

| Gate | 命中数 |
|---|---|
| - | 7 |
| G3 | 31 |
| G4 | 34 |
| G5 | 34 |
