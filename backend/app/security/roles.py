"""角色白名单与 FastAPI 依赖。

集中一处，避免每个路由各写一份（之前 approvals / audit 各有一份）。
"""

from fastapi import Depends, HTTPException

from app.security.principal import Principal, get_principal


# 审批高风险操作
APPROVER_ROLES = {"admin", "finance_manager"}
# 读审计与校验哈希链
AUDIT_ROLES = {"admin", "auditor", "security_analyst"}
# 用户与角色管理
ADMIN_ROLES = {"admin"}


def requires_role(allowed: set[str], detail: str):
    """生成一个只允许白名单角色的依赖。"""

    def _dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has_any_role(allowed):
            raise HTTPException(status_code=403, detail=detail)
        return principal

    return _dependency


require_approver_role = requires_role(APPROVER_ROLES, "APPROVER_ROLE_REQUIRED")
require_audit_role = requires_role(AUDIT_ROLES, "AUDIT_ROLE_REQUIRED")
require_admin_role = requires_role(ADMIN_ROLES, "ADMIN_ROLE_REQUIRED")
