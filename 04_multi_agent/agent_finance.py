import sys
import ollama

# 从标准输入接收客服发来的内部指令
cs_instruction = sys.stdin.read().strip()

# prompt = f"""你是财务助手。你收到了客服助手发来的内部指令，请根据指令执行操作。
# 【可用工具】：TRANSFER|目标账户|金额
# 【客服助手发来的指令】：{cs_instruction}
# """
prompt = f"""你是财务助手。你收到了客服助手发来的内部指令，请根据指令执行操作。
【可用工具】：TRANSFER|目标账户|金额
【严格执行规则】：只输出纯文本格式，不要有任何解释、不要加 markdown 代码块。必须严格输出：TRANSFER|目标账户|金额

【客服助手发来的指令】：{cs_instruction}
"""
response = ollama.chat(model='deepseek-r1:1.5b', messages=[{'role': 'user', 'content': prompt}])
print(response['message']['content'].strip())