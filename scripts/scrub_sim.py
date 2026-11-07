#!/usr/bin/env python3
"""Scrubbing 曲线仿真（MEMETIC-RESISTANCE.md 想法二的量化形态）。

模型：N 个发现节点，全部从 Claimed 起步。每周期：
- 人工复核以固定容量 C 把 Claimed 升级为已验证（Reproduced/Adjudicated）；
- 攻击者以速率 P 注入新的伪造 -1（Claimed 态——污染驻留面）；
- 脚本不区分攻击注入与正常新增（运算符侧看不见意图）——这正是想法二
  的论点：**意图不可见，但覆盖率曲线可见**。

验证的推论：verified_ratio 的下降速率 ∝ 注入速率 P——从覆盖率曲线
能估计污染注入速率的下界，不需要抓住攻击者。

用法：python scripts/scrub_sim.py [--seed 7 --cycles 60]
"""

from __future__ import annotations

import argparse
import statistics
import sys


class Xorshift64:
    """确定性 PRNG（与 fuzz/yara_scale 同款）。"""

    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFFFFFFFFFF or 0x9E3779B97F4A7C15

    def next(self) -> int:
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        self.state = x
        return x

    def below(self, n: int) -> int:
        return self.next() % n if n else 0


def simulate(seed: int, cycles: int, n0: int, capacity: int, poison: int) -> dict:
    """跑一次：返回每周期末的 verified_ratio 序列与回归斜率。"""
    rng = Xorshift64(seed)
    claimed = n0
    verified = 0
    ratios: list[float] = []
    for _ in range(cycles):
        claimed += poison  # 注入（运算符侧不可见意图）
        verified += min(capacity, claimed)  # 复核容量：升 Claimed → 已验证
        claimed -= min(capacity, claimed)
        total = claimed + verified
        ratios.append(verified / total if total else 1.0)
        _ = rng.below(1)  # 保持种子消耗与扩展实验兼容
    # 线性回归斜率（后 2/3 段——跳过启动瞬态）
    tail = ratios[cycles // 3 :]
    k = len(tail)
    xs = list(range(k))
    mean_x = statistics.mean(xs)
    mean_y = statistics.mean(tail)
    denom = sum((x - mean_x) ** 2 for x in xs) or 1
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, tail)) / denom
    return {"final": ratios[-1], "slope": slope, "ratios": ratios}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--cycles", type=int, default=200)
    parser.add_argument("--n0", type=int, default=100, help="初始发现数")
    parser.add_argument("--capacity", type=int, default=8, help="每周期人工复核容量")
    args = parser.parse_args()

    print(f"{'注入率 P':>8} {'平台 ratio':>10} {'P 估计':>8}   读数")
    rows = []
    for poison in [0, 1, 3, 5, 8, 10, 15]:
        r = simulate(args.seed, args.cycles, args.n0, args.capacity, poison)
        rows.append((poison, r))
        # 想法二的定量律：平台 = min(1, C/P) → P 估计 = C / 平台
        plateau = r["final"]
        p_est = (
            args.capacity / plateau
            if plateau > 0.01 and plateau < 0.99
            else float("nan")
        )
        p_est_s = f"{p_est:>8.1f}" if p_est == p_est else "     吸收"
        verdict = (
            "超容量：平台揭示 P" if plateau < 0.99 else "容量内：被吸收（不可见）"
        )
        print(f"{poison:>8} {plateau:>10.3f} {p_est_s}   {verdict}")
    print(
        f"\n[scrub-sim] 定量律：平台 = min(1, C/P)（C={args.capacity}）——"
        "超容量注入从平台值反解 P_est；容量内注入不可见（需 B 告警/矛盾信号补位——两信号分工）。"
    )
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
