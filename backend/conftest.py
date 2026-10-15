"""pytest 配置：把 backend/ 放进 sys.path，并给测试一个可用的默认连接串。

运行方式：cd backend && pytest
"""

import os
import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

# 测试不需要真实数据库：默认指向内存 SQLite，
# 免得在没装 psycopg2 的机器上 import app.models.db 就失败。
os.environ.setdefault("DATABASE_URL", "sqlite://")
