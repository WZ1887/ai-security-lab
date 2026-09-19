import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings  # 导入的是这个类，不是 embeddings 变量
from langchain_chroma import Chroma

print("开始构建知识库...")

# 1. 定义本地文件夹路径和数据库存储路径
DOC_PATH = "./knowledge_base"
DB_PATH = "./chroma_db"

# 2. 从本地文件夹加载所有文本文件
# 如果文件夹里是空白的，请确保先按第一步创建文件
loader = DirectoryLoader(DOC_PATH, glob="*.txt", loader_cls=TextLoader, loader_kwargs={'encoding': 'utf-8'})
documents = loader.load()

if len(documents) == 0:
    print("⚠️ 警告：knowledge_base 文件夹里没有找到任何 .txt 文件，请检查！")
else:
    print(f"成功加载了 {len(documents)} 个本地文档。")

    # 3. 文本切分（真实 RAG 必须做的一步，防止文本太长）
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=200, chunk_overlap=50)
    chunks = text_splitter.split_documents(documents)
    print(f"切分成了 {len(chunks)} 个文本片段。")

    # ================= 防御策略：入库前数据清洗 =================
    clean_chunks = []
    for chunk in chunks:
        # 排除包含“忽略之前”、“系统指令”等恶意指令的片段
        malicious_phrases = ["忽略之前", "系统指令", "新标准已生效", "无需其他解释"]
        if any(phrase in chunk.page_content for phrase in malicious_phrases):
            print(f"🚨 [投毒拦截] 发现恶意片段，已丢弃！内容开头：{chunk.page_content[:30]}...")
        else:
            clean_chunks.append(chunk)

    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    # 用清洗后的干净数据存库
    vector_store = Chroma.from_documents(
        documents=clean_chunks,
        embedding=embeddings,
        persist_directory=DB_PATH
    )
    # ==========================================================
    # 4. 向量化并持久化存入本地向量数据库 (Chroma)
    print("正在向量化并写入本地数据库...")
    embeddings = OllamaEmbeddings(model="nomic-embed-text")

    # persist_directory 参数决定了数据库是否保存在本地磁盘
    vector_store = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=DB_PATH
    )

    print(f"✅ 知识库构建完成！已保存到本地文件夹：{DB_PATH}")