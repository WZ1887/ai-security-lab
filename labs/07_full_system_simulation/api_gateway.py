import sys
import re
import json


# ================= 第一道防线：输入过滤 =================
def sanitize_input(text):
    patterns = [r"忽略.*规则", r"忽略.*指令", r"RESET_PASSWORD\|", r"TRANSFER\|"]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return None, f"检测到恶意注入特征：{p}"
    return text, None


# ================= 第二道防线：PII 脱敏 =================
def mask_pii(text):
    mapping = {}
    # 手机号
    for i, match in enumerate(re.findall(r'1[3-9]\d{9}', text)):
        ph = f"<PHONE_{i}>"
        mapping[ph] = match
        text = text.replace(match, ph)
    # 邮箱
    for i, match in enumerate(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)):
        ph = f"<EMAIL_{i}>"
        mapping[ph] = match
        text = text.replace(match, ph)
    return text, mapping


# ================= 网关入口 =================
def process_request(user_input):
    print(f"👤 [网关] 收到用户请求：{user_input}", file=sys.stderr)

    # 1. 输入过滤
    cleaned, reason = sanitize_input(user_input)
    if cleaned is None:
        print(f"🛡️ [网关] 拦截！{reason}", file=sys.stderr)
        return {"status": "blocked", "message": "请求包含恶意内容，已拦截。"}

    # 2. PII 脱敏
    masked_text, mapping = mask_pii(cleaned)
    if mapping:
        print(f"🛡️ [网关] 检测到隐私信息，已脱敏。发送给AI的内容：{masked_text}", file=sys.stderr)

    # 3. 转发给客服 Agent（微服务间通信，实际是标准输出转JSON）
    # 这里为了保持微服务解耦，通过标准输出返回处理后的请求
    return {"status": "allowed", "cleaned_input": masked_text, "privacy_mapping": mapping}


if __name__ == "__main__":
    # 模拟接收外部 HTTP Body
    user_input = sys.stdin.read().strip()
    result = process_request(user_input)
    print(json.dumps(result))  # 输出 JSON 给调用方