#!/usr/bin/env python3
"""GIL 争用负载（方法1）：N 线程纯 Python 计数——线程在 GIL 上排队（futex 睡眠）
用法: python3 gil_bomb.py [线程数=8] [持续秒=20]
单线程版（N=1）作为对照组：无争用 → 不应出现锁竞争告警
"""
import sys
import time
import threading

N = int(sys.argv[1]) if len(sys.argv) > 1 else 8
DUR = int(sys.argv[2]) if len(sys.argv) > 2 else 20

end = time.time() + DUR


def burn():
    n = 0
    while time.time() < end:
        n += 1
    return n


threads = [threading.Thread(target=burn) for _ in range(N)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print("gil_bomb done threads=%d dur=%d" % (N, DUR))
