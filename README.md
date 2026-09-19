# AI Security Lab - RAG 与 Agent 安全攻防实战

本项目是一个面向 AI 安全（Security for AI）方向的实战演练库。基于本地大模型（Ollama + DeepSeek），针对 OWASP LLM Top 10 中的核心风险（LLM01 提示注入、LLM06 过度代理、LLM02 数据泄露），构建了完整的攻击复现与防御验证。

## 🛠️ 技术栈
- 本地大模型：Ollama (DeepSeek-R1:1.5b)
- 向量数据库：ChromaDB
- 嵌入模型：nomic-embed-text
- 开发语言：Python 3.13

## 🚨 已复现的安全风险与防御方案

### 实验一：提示词注入与越狱（OWASP LLM01）
- **直接注入**：尝试用“忽略之前的指令”绕过模型安全对齐，模型防御成功。
- **角色扮演绕过**：使用科幻小说角色扮演 Prompt，导致 1.5B 模型陷入逻辑死循环（退化性循环，造成拒绝服务 DoS）。
- **间接注入（数据污染）**：将恶意指令隐藏在简历文档中，模型未能区分“数据”与“指令”，被成功劫持。
- **防御验证**：尝试正则清洗与提示词加固。实验证明基于关键词的“软防御”极易被同义词或自然语言改写绕过。
- **核心文件**：`01_prompt_injection/`

### 实验二：Agent 工具滥用与越权攻击（OWASP LLM06）
- **攻击场景**：攻击者伪装管理员，诱导模型输出 `RESET_PASSWORD|admin|hacked` 的越权工具调用指令。
- **防御方案（零信任）**：在 Python 后端工具执行层引入强制鉴权。无论 AI 输出什么，后端只校验真实会话身份（Session），彻底阻断越权操作。
- **核心文件**：`02_agent_security/`

### 实验三：RAG 投毒攻击与数据清洗（OWASP LLM02/01）
- **攻击场景**：在本地知识库上传包含“系统指令”的毒文档，诱导模型输出错误信息（如补贴涨至 5000 元）。
- **防御方案（硬防御）**：在 `build_db.py` 入库阶段引入数据清洗机制，通过恶意特征词过滤，在数据进入向量数据库前将其物理丢弃，从根本上消除隐患。
- **核心文件**：`03_rag_security/`

## 🚀 快速开始
1. 安装依赖：`pip install -r requirements.txt`
2. 拉取模型：`ollama pull deepseek-r1:1.5b` 和 `ollama pull nomic-embed-text`
3. 进入对应的实验文件夹运行对应脚本（如 `python 02_agent_security/agent_privilege_escalation.py`）