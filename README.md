# AI Security Lab - RAG 与 Agent 安全攻防实战

本项目是一个面向 AI 安全（Security for AI）方向的实战演练库。基于本地大模型（Ollama + DeepSeek），针对 OWASP LLM Top 10 中的核心风险，构建了完整的攻击复现与防御验证。

## 🛠️ 技术栈
- 本地大模型：Ollama (DeepSeek-R1:1.5b)
- 向量数据库：ChromaDB
- 嵌入模型：nomic-embed-text
- 开发语言：Python 3.13

## 🚨 已复现的安全风险与防御方案

### 实验一：提示词注入与越狱（OWASP LLM01）
- **攻击场景**：直接注入（伪装权威）、角色扮演绕过（导致模型退化性循环/DoS）。
- **核心文件**：`01_prompt_injection/`

### 实验二：Agent 工具滥用与越权防御（OWASP LLM06）
- **攻击场景**：攻击者伪装管理员，诱导模型输出 `RESET_PASSWORD|admin|hacked` 的越权工具调用指令。
- **防御方案（零信任）**：在 Python 后端工具执行层引入强制鉴权，无视 AI 输出逻辑，只校验当前真实会话身份。
- **核心文件**：`02_agent_security/`

### 实验三：RAG 投毒攻击与数据清洗（OWASP LLM02/01）
- **攻击场景**：在本地知识库上传包含“系统指令”的毒文档，大模型在 RAG 检索时被投毒文档劫持。
- **防御方案（硬防御）**：在 `build_db.py` 入库阶段引入数据清洗机制，通过恶意特征词过滤，在数据进入向量数据库前将其物理丢弃。
- **核心文件**：`03_rag_security/`

### 实验四：多 Agent 信任链攻击与零信任防御（OWASP LLM06）
- **攻击场景**：基于微服务架构模拟“客服 Agent”与“财务 Agent”的通信。攻击者通过提示注入洗脑客服 Agent，使其向财务 Agent 传递越权转账指令。
- **防御方案（执行层鉴权）**：前端大脑被欺骗，但在最终执行工具（`execute_transfer`）时，后端代码强制校验会话身份，成功阻断越权转账。
- **核心文件**：`04_multi_agent/`

## 🚀 快速开始

1. **安装依赖**：
   ```bash
   pip install -r requirements.txt