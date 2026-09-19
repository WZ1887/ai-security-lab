# AI Security Lab - RAG 与 Agent 安全攻防实战

本项目是一个面向 AI 安全（Security for AI）方向的实战演练库。基于本地大模型（Ollama + DeepSeek），针对 OWASP LLM Top 10 中的核心风险（LLM01 提示注入、LLM06 过度代理、LLM02 数据泄露），构建了完整的攻击复现与防御验证。

## 🛠️ 技术栈
- 本地大模型：Ollama (DeepSeek-R1:1.5b)
- 向量数据库：ChromaDB
- 嵌入模型：nomic-embed-text
- 开发语言：Python 3.13

## 🚨 已复现的安全风险与防御方案

### 1. RAG 投毒攻击与数据清洗防御 (OWASP LLM01/02)
- **攻击场景**：在本地知识库中上传包含恶意指令的文档，大模型在 RAG 检索时被投毒文档劫持。
- **防御方案（硬防御）**：在 `build_db.py` 入库阶段引入数据清洗机制，通过恶意特征词过滤，在数据进入向量数据库前将其物理丢弃。
- **核心文件**：`build_db.py` / `ask_ai.py`

### 2. Agent 工具滥用与越权攻击防御 (OWASP LLM06)
- **攻击场景**：攻击者通过提示注入伪装管理员，诱导模型输出越权工具调用指令。
- **防御方案（零信任）**：在工具执行层（Python 后端）引入强制鉴权机制，无视 AI 输出逻辑，只校验当前真实会话身份（Session）。
- **核心文件**：`agent_security.py`

## 🚀 快速开始
1. 安装依赖：`pip install -r requirements.txt`
2. 拉取模型：`ollama pull deepseek-r1:1.5b` 和 `ollama pull nomic-embed-text`
3. 构建数据库：`python build_db.py`
4. 开始安全问答：`python ask_ai.py`