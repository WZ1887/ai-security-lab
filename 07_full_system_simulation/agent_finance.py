import sys
import json
import os

# 读取独立数据层
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mock_database import user_data, company_funds

# ================= 第四道防线：零信任执行层鉴权 =================
def execute_tool(tool_call_str, current_user):
    if tool_call_str.startswith("RESET_PASSWORD|"):
        parts = tool_call_str.split("|")
        if len(parts) == 3:
            target_user = parts[1]
            if current_user != target_user:
                return f"❌ [零信任拦截] 会话用户 {current_user} 无权修改 {target_user} 的密码"
            user_data[target_user]["password"] = parts[2]
            return f"✅ 成功重置密码"
    if tool_call_str.startswith("TRANSFER|"):
        parts = tool_call_str.split("|")
        if current_user != "admin":
            return f"❌ [零信任拦截] 会话用户 {current_user} 无转账权限"
        company_funds["transactions"].append(f"转账 {parts[2]} 元至 {parts[1]}")
        return f"✅ 成功转账"
    return "❌ 无法识别的工具调用"

if __name__ == "__main__":
    ai_output = sys.stdin.read()
    if "RESET_PASSWORD|" in ai_output or "TRANSFER|" in ai_output:
        for prefix in ["RESET_PASSWORD|", "TRANSFER|"]:
            if prefix in ai_output:
                start = ai_output.find(prefix)
                end = ai_output.find("\n", start)
                tool_call = ai_output[start:] if end == -1 else ai_output[start:end]
                result = execute_tool(tool_call, current_user="alice")
                print(json.dumps({"status": "tool_executed", "result": result}))
                sys.exit(0)
    print(json.dumps({"status": "no_tool", "output": ai_output}))