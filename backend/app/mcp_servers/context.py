"""工具执行的调用者上下文。

身份只来自认证令牌（见 app/security/principal.py），绝不来自请求体——
否则 RBAC 与资源归属校验都能被客户端伪造。

放在 mcp_servers 下的原因是它是叶子模块，Server / 沙箱 / G5 都能依赖它，
不会引入反向依赖。
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CallContext:
    user_id: str = ""
    tenant_id: str = ""
    agent_id: str = ""
    session_id: str = ""
    roles: tuple[str, ...] = field(default_factory=tuple)

    @property
    def identified(self) -> bool:
        """身份是否完整：缺失身份的工具调用一律按越权处理。"""
        return bool(self.user_id and self.tenant_id)
