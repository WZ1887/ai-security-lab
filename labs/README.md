# labs — 早期专项实验脚本

这里的 7 个目录是项目早期逐个验证攻击手法时写的**独立脚本**，与应用（`backend/` + `frontend/`）
没有代码交叉：它们各自直接调用本地 Ollama，用 print 输出结果，不经过 MCP-Guard 网关、不写数据库。

| 目录 | 主题 | 额外依赖 |
|---|---|---|
| `01_prompt_injection/` | 直接 / 间接提示注入 | ollama |
| `02_agent_security/` | Agent 越权（角色自报、工具滥用） | ollama |
| `03_rag_security/` | RAG 知识库投毒（含 Chroma 向量库构建） | langchain + chromadb + ollama |
| `04_multi_agent/` | 多 Agent 信任链攻击 | ollama |
| `05_privacy_security/` | 数据脱敏 | ollama |
| `06_api_security/` | 有漏洞 / 已加固的 API 服务对比（含限流与参数校验） | fastapi + uvicorn + requests + ollama |
| `07_full_system_simulation/` | 微服务化综合演练（网关 + 客服 + 财务） | ollama |

## 怎么跑

这些脚本用的是**相对路径**（`./knowledge_base`、`./chroma_db`、按文件名调用子进程），
所以必须在各自目录下执行，并且需要本机 Ollama 在跑。

```bash
cd labs
pip install -r requirements.txt

cd 06_api_security          && python api_server_vuln.py      # 需要本机 Ollama
cd 07_full_system_simulation && python red_team_runner.py      # 需要本机 Ollama
```

`03_rag_security` 需要先建库再提问：

```bash
cd labs/03_rag_security
python build_db.py          # 读取 ./knowledge_base 下的 txt，写入 ./chroma_db
python ask_ai.py
```

## 与主项目的关系

主项目是这批实验的"防御侧答案"：每个 Gate 的动机都能在这里找到对应脚本，但实现是重新写的
（工具注册表、策略引擎、审计哈希链、人工审批、带标签评测与回归测试）。
两者的依赖集合几乎不重叠，所以各自保留一份 requirements——`labs/requirements.txt` 只服务于本目录。
