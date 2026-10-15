from fastapi import FastAPI
from pydantic import BaseModel
import ollama
import uvicorn

app = FastAPI(title="AI 客服系统 (脆弱版)")

class ChatRequest(BaseModel):
    prompt: str

@app.post("/api/chat")
async def chat(request: ChatRequest):
    # 直接将用户的 prompt 发给 AI，无长度校验，无频率限制
    response = ollama.chat(
        model='deepseek-r1:1.5b',
        messages=[{'role': 'user', 'content': request.prompt}]
    )
    return {"response": response['message']['content']}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)