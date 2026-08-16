#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三方案深度对比: baseline / optimized(cap=60) / optimized(cap=40)

两部分证据:
  A. 纯经验回放(假设不变): 指标对比 + cap 细扫。
  B. 压力情景(robustness): 假设某道失败题"其实重试能解出"(翻转其 attempt-2 为解出),
     检验各 cap 是否错杀上行空间——cap 越激进,省空转越多,但可能切断"忙时偏高但本可解出"的题。
"""
import copy
import json
import sys

sys.path.insert(0, 'bench')
from simulate import Policy, run_sim, BASELINE, OPTIMIZED, GLOBAL_DEADLINE_MIN


def load():
    with open('bench/dataset-run9874.json', encoding='utf-8') as f:
        return json.load(f)


def flip(dataset, code, solve_min, points=None):
    """把某题翻转为'第 2 次 attempt 解出'(模拟上行情景)。"""
    ds = copy.deepcopy(dataset)
    ch = next(c for c in ds['challenges'] if c['code'] == code)
    pts = points if points is not None else round(ch['nominal_score'] * 0.9)
    ch['attempts'].append({'start_min': -1, 'fail_offsets': [], 'points': pts,
                           'solve_min': solve_min, 'duration_min': solve_min + 2, 'solved': True})
    return ds


def brief(r, max_score):
    m = r.metrics(max_score)
    return m['M1_总点数'], m['M2_得分提前度'], m['M3_空转分钟'], m['M4_最长真空min']


def main():
    ds = load()
    max_score = sum(c['nominal_score'] for c in ds['challenges'])

    print('===== A. 纯经验回放: cap 细扫 (其余参数 = optimized 默认) =====')
    print(f"{'cap':>5} {'M1总分':>8} {'M2提前度':>9} {'M3空转min':>10} {'M4真空min':>10}")
    rows = {}
    for cap in (None, 35, 40, 45, 50, 60, 75, 90, 120):
        name = 'baseline' if cap is None else f'cap={cap}'
        pol = BASELINE if cap is None else Policy(**{**OPTIMIZED.__dict__, 'retry_busy_cap': float(cap), 'name': name})
        r = run_sim(ds, pol)
        rows[name] = r
        print(f"{name:>8} {r.final_score:>8} {r.metrics(max_score)['M2_得分提前度']:>9} "
              f"{r.metrics(max_score)['M3_空转分钟']:>10} {r.metrics(max_score)['M4_最长真空min']:>10}")

    print('\n===== B. 压力情景: 单题翻转"重试可解出",各方案能否捕获 =====')
    # 每行: (翻转题, 重试解出耗时, 该题 pass-1 已占用) —— 占用决定各 cap 给的 retry 预算
    scenarios = [
        ('bctf-35 ColdByte',   18, 25),   # cap40 预算 22min < 25 → 错杀; cap60 预算 35 → 捕获
        ('bctf-35 ColdByte',   18, 20),   # cap40 预算 22 ≥ 20 → 也能捕获(边界内)
        ('bctf-28 NEXUS-7',     8, 20),   # 低占用, 两 cap 都捕获
        ('bctf-23 HELM',       35, 15),   # cap40 预算 5 < 15 → 错杀; cap60 预算 25 → 捕获
        ('bctf-27 墨记轻博客',  41, 30),   # cap40 直接跳过; cap60 预算 19 < 30 → 也错杀
        ('bctf-25 FOUNDRY',    51, 25),   # cap40 跳过; cap60 预算 9 < 25 → 也错杀
    ]
    caps = (None, 40, 60)
    print(f"{'情景(题/busymin/重试需)':<34}" + ''.join(f"{('baseline' if c is None else f'cap={c}'):>12}" for c in caps))
    for label_code, busy, need in scenarios:
        code = label_code.split()[0]
        ds_f = flip(ds, code, need)
        cells = []
        for cap in caps:
            pol = BASELINE if cap is None else Policy(**{**OPTIMIZED.__dict__, 'retry_busy_cap': float(cap)})
            r = run_sim(ds_f, pol)
            caught = r.final_score > 12860
            cells.append(f"{'✔ +' + str(r.final_score - 12860) if caught else '✘ 错杀':>12}")
        print(f"{label_code + f' busy={busy} 需{need}min':<34}" + ''.join(cells))

    print('\n===== B2. 组合情景: 3 题同时可重试解出(上行兑现能力总账) =====')
    combos = [
        ('低占用组: NEXUS-7(20)+ColdByte(20)+AURORA(20)', [('bctf-28', 20), ('bctf-35', 20), ('bctf-34', 20)]),
        ('中占用组: HELM(15)+检查环境(20)+NexusPoint(20)', [('bctf-23', 15), ('bctf-18', 20), ('bctf-24', 20)]),
    ]
    for label, flips in combos:
        ds_f = ds
        for code, need in flips:
            ds_f = flip(ds_f, code, need)
        cells = []
        for cap in caps:
            pol = BASELINE if cap is None else Policy(**{**OPTIMIZED.__dict__, 'retry_busy_cap': float(cap)})
            r = run_sim(ds_f, pol)
            m = r.metrics(max_score)
            cells.append(f"{r.final_score} 空转{m['M3_空转分钟']:.0f}")
        print(f"{label:<44} baseline: {cells[0]:>16}  cap=40: {cells[1]:>16}  cap=60: {cells[2]:>16}")


if __name__ == '__main__':
    main()
