import httpx

r = httpx.post(
    "http://localhost:11434/api/generate",
    json={"model": "qwen2.5:7b", "prompt": "你好", "stream": False},
    timeout=60,
)
print(r.json()["response"])

r = httpx.post(
    "http://localhost:11434/api/embeddings",
    json={"model": "nomic-embed-text", "prompt": "test"},
    timeout=30,
)
print("embedding 维度:", len(r.json()["embedding"]))