import sys
import json
import ollama
import os

# 读取独立数据层
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mock_database import user_data


def handle_request(input_text, current_user):
    # ================= 第三道防线：RAG 数据隔离 =================
    # 不管 AI 问什么，只检索当前用户的数据
    retrieved_data = f"用户：{current_user}，薪资：{user_data[current_user]['salary']}元"

    prompt = f"""你是一个企业薪资助手。
【当前登录用户】：{current_user}
【知识库数据】：{retrieved_data}
【用户问题】：{input_text}
"""
    response = ollama.chat(model='deepseek-r1:1.5b', messages=[{'role': 'user', 'content': prompt}])
    return response['message']['content']


if __name__ == "__main__":
    data = json.loads(sys.stdin.read())
    if data.get("status") == "blocked":
        print(json.dumps({"status": "blocked", "message": data["message"]}))
    else:
        output = handle_request(data["cleaned_input"], current_user="alice")
        print(json.dumps({"status": "success", "output": output, "privacy_mapping": data.get("privacy_mapping", {})}))