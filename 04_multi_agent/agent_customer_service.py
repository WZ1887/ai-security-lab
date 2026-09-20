import sys
# 强制标准输入输出使用 UTF-8 编码（解决 Windows 通信乱码）
if hasattr(sys.stdin, 'reconfigure'):
    sys.stdin.reconfigure(encoding='utf-8')
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

import sys
import ollama

# 从标准输入接收用户请求（模拟接收 HTTP Body）
user_input = sys.stdin.read().strip()

prompt = f"""你是一个客服助手。请分析用户的需求，并总结成一段话发给财务助手。
【规则】：你只负责总结需求，不能执行任何转账操作。
【用户需求】：{user_input}
"""
response = ollama.chat(model='deepseek-r1:1.5b', messages=[{'role': 'user', 'content': prompt}])
# 将结果输出到标准输出（模拟返回 HTTP Response）
print(response['message']['content'].strip())