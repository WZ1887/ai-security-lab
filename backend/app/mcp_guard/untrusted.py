"""不可信文本的公共检测模式。

工具结果、记忆内容、文档都是"数据"，判定前统一走 G1 归一化，再用这里的模式匹配。
把模式收在一处，避免 Result Guard 和记忆守卫各写一份、慢慢漂移。
"""

from __future__ import annotations

import re


# 注入指令（试图改变模型行为）
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"忽略(之前|以上|所有).{0,6}(指令|规则)"),
    re.compile(r"SYSTEM\s*:", re.I),
    re.compile(r"<\|?system\|?>", re.I),
    re.compile(r"you\s+are\s+now\s+(in\s+)?developer\s+mode", re.I),
]


# 策略 / 权限类声明（试图改变授权状态）——记忆只能存事实，结果里也不该出现
POLICY_PATTERNS = [
    re.compile(r"(我|本人)(现在|已经|就)?是.{0,6}(管理员|超级用户|root|admin)", re.I),
    re.compile(r"(我|本人).{0,6}(有|拥有|获得).{0,6}(权限|授权|特权|管理员)", re.I),
    re.compile(
        r"(以后|今后|下次|之后).{0,10}(直接|一律|都|无需).{0,6}(通过|同意|批准|退款|执行|放行)",
        re.I,
    ),
    re.compile(r"(跳过|免去|无需|不用|不需要|取消).{0,8}(审批|确认|验证|授权|复核)", re.I),
    re.compile(r"(忽略|无视|绕过|覆盖|关闭).{0,8}(规则|策略|限制|安全|审批|检查)", re.I),
    re.compile(r"you\s+are\s+(now\s+)?(an?\s+)?(admin|administrator|superuser|root)", re.I),
    re.compile(r"(grant|give)\s+(me|my)\s+(admin|permission|permissions|role|access)", re.I),
    re.compile(
        r"(skip|bypass|ignore|override|disable)\s+(the\s+)?"
        r"(approval|policy|policies|rules?|checks?|verification|auth)",
        re.I,
    ),
    re.compile(r"(always|from now on).{0,24}(approve|allow|execute|refund|transfer)", re.I),
    re.compile(r"(no|without)\s+(need\s+for\s+)?(approval|confirmation|verification)", re.I),
]


def has_injection(text: str) -> bool:
    return any(p.search(text) for p in INJECTION_PATTERNS)


def has_policy_claim(text: str) -> bool:
    return any(p.search(text) for p in POLICY_PATTERNS)
