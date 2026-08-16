#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从跑分事件流 CSV 提取逐题 attempt 级数据集(调度回放模拟器的 ground truth)。

用法: python3 bench/extract_dataset.py <events.csv> <out.json>
事件流字段: 时间,事件类型,关联题目,题目编码,附加信息
"""
import csv, re, json, sys
from datetime import datetime
from collections import defaultdict

# 未解题的名目分值/flag 数在事件流中不可见 —— 按同档题估计,仅用于 what-if 敏感性分析,
# 不影响 baseline/optimized 的主指标(它们由经验 attempt 结果驱动)。
ESTIMATES = {  # code: (nominal_score_est, flag_count_est)
    'bctf-26': (500, 2), 'bctf-32': (500, 1), 'bctf-02': (600, 3), 'bctf-22': (700, 2),
    'bctf-27': (500, 2), 'bctf-23': (600, 1), 'bctf-34': (600, 1), 'bctf-18': (600, 1),
    'bctf-35': (500, 1), 'bctf-01': (600, 1), 'bctf-24': (600, 1), 'bctf-28': (600, 1),
    'bctf-25': (700, 2), 'bctf-08': (600, 1),
}
HINT_COST_RATIO = 0.1  # 平台规则: 兑换提示后该题得分打 9 折


def main(csv_path: str, out_path: str) -> None:
    rows = []
    with open(csv_path, encoding='utf-8') as f:
        r = csv.reader(f)
        next(r)
        for row in r:
            rows.append((datetime.strptime(row[0], '%Y/%m/%d %H:%M:%S'), row[1], row[2], row[3], row[4]))

    t0, tend = rows[0][0], rows[-1][0]
    horizon = (tend - t0).total_seconds() / 60
    ch, order = {}, []
    for t, etype, name, code, info in rows:
        if not code:
            continue
        if code not in ch:
            ch[code] = {'code': code, 'name': name, 'attempts': [], 'hints': []}
            order.append(code)
        d = ch[code]
        rel = (t - t0).total_seconds() / 60
        if etype == '启动靶场':
            d['attempts'].append({'start_min': rel, 'end_min': None, 'fail_offsets': [], 'points': 0, 'solve_min': None})
        elif etype == '关闭靶场':
            if d['attempts'] and d['attempts'][-1]['end_min'] is None:
                d['attempts'][-1]['end_min'] = rel
        elif etype == '答题失败':
            a = d['attempts'][-1] if d['attempts'] else None
            if a and a['end_min'] is None:
                a['fail_offsets'].append(round(rel - a['start_min'], 2))
        elif etype == '得分成功':
            pts = int(re.search(r'\+(\d+)', info).group(1))
            a = d['attempts'][-1]
            a['points'] += pts
            if a['solve_min'] is None:
                a['solve_min'] = round(rel - a['start_min'], 2)
        elif etype == '查看提示':
            d['hints'].append({'at_min': round(rel, 2), 'attempt_idx': len(d['attempts']) - 1})

    out = []
    for code in order:
        d = ch[code]
        for a in d['attempts']:
            if a['end_min'] is None:
                a['end_min'] = horizon
            a['duration_min'] = round(a['end_min'] - a['start_min'], 2)
            a['solved'] = a['points'] > 0
            del a['end_min']
        d['empirical_order'] = len(out)          # pass-1 经验队列顺序(首次开靶时间序)
        d['total_points'] = sum(a['points'] for a in d['attempts'])
        d['hint_used'] = len(d['hints']) > 0
        solved_attempt = next((a for a in d['attempts'] if a['solved']), None)
        if solved_attempt:
            nominal = d['total_points'] / (1 - HINT_COST_RATIO) if d['hint_used'] else d['total_points']
            d['nominal_score'] = round(nominal)
            d['score_estimated'] = False
        else:
            est = ESTIMATES.get(code, (600, 1))
            d['nominal_score'] = est[0]
            d['score_estimated'] = True
        d['flag_count'] = 3 if code == 'bctf-09' else 1  # 事件流可见的多 flag 题
        out.append(d)

    meta = {
        'run_id': 'run-9874', 'start': str(t0), 'horizon_min': round(horizon, 2),
        'workers': 3, 'task_minutes': 360, 'hint_cost_ratio': HINT_COST_RATIO,
        'total_points_actual': sum(d['total_points'] for d in out),
        'solved_actual': sum(1 for d in out if d['total_points'] > 0),
        # pass-2 经验重试顺序(实际观测): 用于 baseline 复现校验
        'pass2_empirical_order': ['bctf-32', 'bctf-11', 'bctf-26', 'bctf-36', 'bctf-02',
                                  'bctf-22', 'bctf-27', 'bctf-23', 'bctf-34'],
    }
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({'meta': meta, 'challenges': out}, f, ensure_ascii=False, indent=1)
    print(f"written {out_path}: {len(out)} challenges, horizon {horizon:.0f}min, "
          f"actual {meta['total_points_actual']}pts/{meta['solved_actual']} solved")


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
