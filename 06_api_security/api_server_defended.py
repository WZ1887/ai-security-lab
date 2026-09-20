from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, field_validator
import ollama
import uvicorn
import time

app = FastAPI(title="AI 客服系统 (防御版)")

# ================= 防御策略 1：原生 IP 限流器（防 CC 攻击） =================
# 记录每个 IP 的请求时间戳
rate_limit_records = {}
RATE_LIMIT_INTERVAL = 60  # 60 秒
RATE_LIMIT_MAX_REQUESTS = 5  # 最多 5 次请求


def check_rate_limit(client_ip: str):
    now = time.time()
    if client_ip not in rate_limit_records:
        rate_limit_records[client_ip] = []
    # 清理过期的请求记录
    rate_limit_records[client_ip] = [t for t in rate_limit_records[client_ip] if now - t < RATE_LIMIT_INTERVAL]
    if len(rate_limit_records[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后再试（限流 5 次/分钟）")
    rate_limit_records[client_ip].append(now)


# =========================================================================

class ChatRequest(BaseModel):
    prompt: str

    # ================= 防御策略 2：输入长度限制（防 Token 炸弹） =================
    @field_validator('prompt')
    @classmethod
    def limit_length(cls, v: str) -> str:
        if len(v) > 1000:
            raise ValueError('输入过长，请精简后重试 (单次最大1000字符)')
        return v


@app.post("/api/chat")
async def chat(request: Request, chat_request: ChatRequest):
    # 1. 执行限流检查
    client_ip = request.client.host
    check_rate_limit(client_ip)

    # 2. 执行正常业务逻辑
    try:
        response = ollama.chat(
            model='deepseek-r1:1.5b',
            messages=[{'role': 'user', 'content': chat_request.prompt}]
        )
        return {"response": response['message']['content']}
    except Exception as e:
        # 拦截底层报错，防止信息泄露
        return {"error": "AI 服务暂时不可用，请稍后再试。"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)