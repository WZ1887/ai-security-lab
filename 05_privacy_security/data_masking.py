import ollama
import re

print("正在连接本地模型...")

# ================= 防御策略：数据脱敏（Data Masking） =================
# 定义敏感信息正则
PII_PATTERNS = {
    "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    "PHONE": r'1[3-9]\d{9}',  # 中国大陆手机号
    "ID_CARD": r'\d{17}[\dXx]'  # 18位身份证号
}


def mask_sensitive_data(text):
    """在发送给AI前，替换敏感信息为占位符"""
    mapping = {}  # 记录原始值，用于后续还原
    masked_text = text

    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, masked_text)
        for i, match in enumerate(matches):
            placeholder = f"<{pii_type}_{i}>"
            mapping[placeholder] = match
            masked_text = masked_text.replace(match, placeholder)

    return masked_text, mapping


def unmask_data(text, mapping):
    """在AI返回结果后，将占位符替换回真实数据"""
    for placeholder, real_value in mapping.items():
        text = text.replace(placeholder, real_value)
    return text


# =========================================================================

# 模拟用户提问（包含敏感隐私）
user_question = "你好，我的手机号是 13812345678，邮箱是 test@example.com，请帮我记录一下，顺便查一下我名下有没有逾期记录。"

print(f"\n👤 用户原始输入（未脱敏）：\n{user_question}")

# 1. 脱敏处理
masked_question, privacy_mapping = mask_sensitive_data(user_question)
print(f"\n🛡️ [隐私脱敏层] 处理后发送给 AI 的 Prompt：\n{masked_question}")

# 2. 发送脱敏后的 Prompt 给 AI
try:
    response = ollama.chat(model='deepseek-r1:1.5b', messages=[{'role': 'user', 'content': masked_question}])
    ai_response = response['message']['content']
    print(f"\n🤖 [AI 原始响应]：\n{ai_response}")

    # 3. 还原数据，展示给用户
    final_response = unmask_data(ai_response, privacy_mapping)
    print(f"\n✅ [返回给用户的最终结果（已还原）]：\n{final_response}")

except Exception as e:
    print(f"\n--- 连接失败 ---\n错误信息：{e}")