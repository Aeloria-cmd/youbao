#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""调度策略回放模拟器 —— 用真实 run 的 attempt 级经验数据评估调度算法。

核心思想(为什么可信):
  一道题的一次 attempt 的结果(解出耗时/烧满预算失败/连续提交失败)由题目难度和模型能力决定,
  调度策略改变不了单次 attempt 的"天赋",但能决定: 给哪次 attempt 多少预算、什么时候给、
  失败后要不要/怎么重试、卡死要不要重启。因此把经验 attempt 结果当作"环境响应函数",
  在其上重放不同调度策略,可以隔离出调度本身的收益。

诚实边界(读报告前必读):
  - 经验数据里 12 道题从未解出 → 重放中它们在任何策略下都不得分(保守下界)。
    调度优化带来的"最终总分"提升只能来自: 卡死恢复提前(CloudDB 模式)和末段提示转化(what-if)。
  - 调度对"效率类指标"(空转率/得分提前度/最长真空)的影响是真实可测的,这是本工具的主战场。
  - p_convert > 0 的场景是能力 what-if(更强模型/更有效提示),不是调度的直接功劳,报告会标注。

指标定义见 bench/README.md。
"""
import heapq
import json
import random
import sys
from dataclasses import dataclass, field

RESTART_OVERHEAD_MIN = 1.0   # close+start 重启容器的观测开销(平台实测秒级,留足余量)
GLOBAL_DEADLINE_MIN = 360.0  # TASK_MINUTES


@dataclass
class Policy:
    name: str
    # pass>=2 队列排序: 'empirical'(按实测重试顺序) | 'busy_asc'(累计占用最少者优先)
    retry_order: str = 'empirical'
    # 提交熔断: 单 attempt 连续 N 次提交失败 → 判定环境异常,立即重启容器换新 attempt
    circuit_breaker_fails: int | None = None
    # 熔断重启后仍累计 N 次失败 → 提前放弃本 attempt(保预算)
    breaker_abandon_fails: int | None = None
    # 跨 attempt 累计占用上限(分钟);达到后本场不再自动重试
    retry_busy_cap: float | None = None
    # 单题最大 attempt 数
    max_attempts: int | None = None
    # 重试 attempt 的预算 = min(名义上限, 累计上限-已占用) —— 防止失败题每次都拿全新预算
    retry_shrink_budget: bool = False
    # 末段窗口(剩余 N 分钟进入末段策略)
    endgame_min: float | None = None
    # what-if: 末段提示辅助 attempt 对未解题的转化率(0 = 纯经验重放)
    endgame_hint_convert_p: float = 0.0
    seed: int = 42


@dataclass
class SimResult:
    policy: str
    final_score: int = 0
    solved: int = 0
    coverage: int = 0
    score_events: list = field(default_factory=list)   # (t_min, pts, code)
    wasted_min: float = 0.0                            # 零分 attempt 消耗的 worker 分钟
    total_worker_min: float = 0.0
    restarts: int = 0
    endgame_conversions: int = 0

    @property
    def horizon(self):
        return GLOBAL_DEADLINE_MIN

    def metrics(self, max_score: int) -> dict:
        auc = sum(p * (self.horizon - t) for t, p, _ in self.score_events)
        # 最长得分真空(含收尾段)
        gaps, prev = [], 0.0
        for t, _, _ in self.score_events:
            gaps.append(t - prev)
            prev = t
        gaps.append(self.horizon - prev)
        return {
            'M1_总点数': self.final_score,
            'M7_解出题数': self.solved,
            'M6_覆盖率': f"{self.coverage}",
            'M2_得分提前度': round(auc / (max_score * self.horizon), 4) if max_score else 0,
            'M3_空转率': round(self.wasted_min / self.total_worker_min, 4) if self.total_worker_min else 0,
            'M3_空转分钟': round(self.wasted_min, 1),
            'M4_最长真空min': round(max(gaps), 1),
            '重启次数': self.restarts,
            '末段转化': self.endgame_conversions,
        }


def empirical_attempt(ch, k):
    """返回第 k 次(0-based) attempt 的经验记录;超出观测范围时合成保守结果。"""
    atts = ch['attempts']
    if k < len(atts):
        return atts[k], False
    solved_att = next((a for a in atts if a['solved']), None)
    if solved_att:
        # 经验证据: 该题重启后可复现解出(CloudDB/ezSpring 模式)
        return {'duration_min': solved_att['duration_min'], 'solved': True,
                'solve_min': solved_att['solve_min'], 'points': solved_att['points'],
                'fail_offsets': []}, True
    # 从未解出: 保守假设重复首次失败形态
    first = atts[0]
    return {'duration_min': first['duration_min'], 'solved': False,
            'solve_min': None, 'points': 0, 'fail_offsets': first['fail_offsets'][:]}, True


def nominal_cap(ch):
    # 与 runner.ts capMinutesFor 对齐(单 flag 35min;多 flag 20min×n,上限总时长一半)
    return 35.0 if ch['flag_count'] <= 1 else min(20.0 * ch['flag_count'], GLOBAL_DEADLINE_MIN * 0.5)


def run_sim(dataset, policy: Policy) -> SimResult:
    rng = random.Random(policy.seed)
    chs = {c['code']: dict(c) for c in dataset['challenges']}
    res = SimResult(policy=policy.name)
    state = {code: {'busy': 0.0, 'attempts': 0, 'solved': False, 'hint': c['hint_used']}
             for code, c in chs.items()}
    pass2_emp = dataset['meta'].get('pass2_empirical_order', [])

    def build_queue(pass_num, now):
        unfinished = [c for c in chs.values() if not state[c['code']]['solved']]
        if pass_num == 1:
            unfinished.sort(key=lambda c: c['empirical_order'])
            return unfinished
        # 过滤: 累计占用上限 / attempt 上限
        eligible = []
        for c in unfinished:
            s = state[c['code']]
            if policy.max_attempts and s['attempts'] >= policy.max_attempts:
                continue
            if policy.retry_busy_cap and s['busy'] >= policy.retry_busy_cap:
                continue
            eligible.append(c)
        if policy.retry_order == 'busy_asc':
            eligible.sort(key=lambda c: (state[c['code']]['busy'], c['empirical_order']))
        else:  # empirical: 实测 pass-2 重试顺序优先,其余按 pass-1 顺序
            rank = {code: i for i, code in enumerate(pass2_emp)}
            eligible.sort(key=lambda c: (rank.get(c['code'], 1000 + c['empirical_order'])))
        return eligible

    def attempt_outcome(c, k, budget, t_start):
        """解析一次 attempt: 返回 (结束时刻, 得分事件列表[(t,pts)], 消耗分钟, 触发重启数)。"""
        emp, synthesized = empirical_attempt(c, k)
        events, restarts = [], 0
        # 提交熔断: 连续失败达阈值 → 立即重启,以新鲜 attempt 继续(同一 worker)
        if (policy.circuit_breaker_fails and not emp['solved']
                and len(emp['fail_offsets']) >= policy.circuit_breaker_fails):
            t_break = emp['fail_offsets'][policy.circuit_breaker_fails - 1]
            if t_break < budget:
                restarts += 1
                consumed = t_break + RESTART_OVERHEAD_MIN
                # 重启后的新 attempt(经验上的下一次)继续用剩余预算
                nxt, _ = empirical_attempt(c, k + 1)
                remain = budget - consumed
                if nxt['solved'] and nxt['solve_min'] <= remain:
                    events.append((t_start + consumed + nxt['solve_min'], nxt['points']))
                    consumed += nxt['duration_min']
                else:
                    consumed += min(nxt['duration_min'], remain)
                return t_start + consumed, events, consumed, restarts
        if emp['solved'] and emp['solve_min'] <= budget:
            # 保真: 得分时刻用经验 solve_min,但 worker 占用按经验全程计(解出后还有收尾/观察开销)
            events.append((t_start + emp['solve_min'], emp['points']))
            return t_start + emp['duration_min'], events, emp['duration_min'], restarts
        # 末段提示 what-if: 仅对从未解出且进入末段窗口的 attempt 生效
        if (policy.endgame_hint_convert_p > 0 and not emp['solved']
                and t_start >= GLOBAL_DEADLINE_MIN - (policy.endgame_min or 0)
                and rng.random() < policy.endgame_hint_convert_p):
            pts = round(c['nominal_score'] * (1 - dataset['meta']['hint_cost_ratio']))
            solve_at = min(15.0, budget)
            events.append((t_start + solve_at, pts))
            res.endgame_conversions += 1
            return t_start + solve_at, events, solve_at, restarts
        consumed = min(emp['duration_min'], budget)
        return t_start + consumed, events, consumed, restarts

    # ---- 事件驱动 worker 池 ----
    now = 0.0
    pass_num = 0
    while now < GLOBAL_DEADLINE_MIN:
        pass_num += 1
        if pass_num > 1 and GLOBAL_DEADLINE_MIN - now <= 10:
            break  # 对齐 runner: 剩余 <10min 不开新 pass
        queue = build_queue(pass_num, now)
        if not queue:
            break
        # 3 个 worker 共享队列;pass 内所有 worker 收工才开下一 pass(对齐 Promise.all)
        free = [(now, w) for w in range(dataset['meta']['workers'])]
        heapq.heapify(free)
        while queue and free:
            t_free, w = heapq.heappop(free)
            if t_free >= GLOBAL_DEADLINE_MIN:
                break
            c = queue.pop(0)
            code = c['code']
            s = state[code]
            budget = nominal_cap(c)
            if s['attempts'] > 0 and policy.retry_shrink_budget and policy.retry_busy_cap:
                budget = max(5.0, min(budget, policy.retry_busy_cap - s['busy']))
            budget = min(budget, GLOBAL_DEADLINE_MIN - t_free)
            if budget <= 0:
                continue
            t_end, events, consumed, restarts = attempt_outcome(c, s['attempts'], budget, t_free)
            s['attempts'] += 1
            s['busy'] += consumed
            res.restarts += restarts
            res.total_worker_min += consumed
            if events:
                for t_ev, pts in events:
                    res.score_events.append((t_ev, pts, code))
                s['solved'] = True
                res.final_score += sum(p for _, p in events)
            else:
                res.wasted_min += consumed
            heapq.heappush(free, (min(t_end, GLOBAL_DEADLINE_MIN), w))
        if free:
            now = max(now, max(t for t, _ in free))
        if pass_num > 20:
            break

    res.score_events.sort()
    res.solved = sum(1 for s in state.values() if s['solved'])
    res.coverage = sum(1 for s in state.values() if s['attempts'] > 0)
    return res


BASELINE = Policy(name='baseline(现行)')
OPTIMIZED = Policy(
    name='optimized(v2)',
    retry_order='busy_asc',
    circuit_breaker_fails=3,
    breaker_abandon_fails=6,
    retry_busy_cap=60.0,
    max_attempts=3,
    retry_shrink_budget=True,
    endgame_min=75.0,
    endgame_hint_convert_p=0.0,
)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'bench/dataset-run9874.json'
    with open(path, encoding='utf-8') as f:
        dataset = json.load(f)
    meta = dataset['meta']
    max_score = sum(c['nominal_score'] for c in dataset['challenges'])

    print(f"=== 数据集 {meta['run_id']} ===")
    print(f"实际战绩: {meta['total_points_actual']} 点 / 解出 {meta['solved_actual']} 题 / "
          f"horizon {meta['horizon_min']:.0f}min / 名目总分(含估计) {max_score}\n")

    rows = []
    base = run_sim(dataset, BASELINE)
    rows.append(('baseline(现行)', base.metrics(max_score)))
    print("--- baseline 复现校验(与实际战绩对比) ---")
    print(f"  sim: {base.final_score} 点 / 解出 {base.solved} / 覆盖 {base.coverage}  |  "
          f"实际: {meta['total_points_actual']} 点 / 解出 {meta['solved_actual']} / 40")
    if base.score_events:
        print(f"  最后得分时刻: sim {base.score_events[-1][0]:.0f}min  (实际 ~314min)\n")

    opt = run_sim(dataset, OPTIMIZED)
    rows.append(('optimized(v2)', opt.metrics(max_score)))

    # 敏感性扫描: 末段提示转化率(能力 what-if,5 个随机种子取均值)
    def sweep(name, **over):
        ms = []
        for seed in range(5):
            r = run_sim(dataset, Policy(**{**OPTIMIZED.__dict__, 'name': name, 'seed': seed, **over}))
            ms.append(r.metrics(max_score))
        avg = {}
        for k in ms[0]:
            vals = [m[k] for m in ms]
            if k == 'M6_覆盖率':
                avg[k] = f"{sum(float(v) for v in vals) / len(vals):.0f}"
            else:
                avg[k] = round(sum(float(v) for v in vals) / len(vals), 4 if isinstance(vals[0], float) and vals[0] < 10 else 1)
        rows.append((name, avg))

    for p in (0.1, 0.2, 0.3):
        sweep(f'optimized+p={p}(what-if)', endgame_hint_convert_p=p)

    # 敏感性扫描: 累计占用上限
    for cap in (40.0, 90.0):
        sweep(f'optimized cap={cap:.0f}', retry_busy_cap=cap)

    keys = list(rows[0][1].keys())
    print('=== 策略对比 ===')
    print(f"{'策略':<26}" + ''.join(f'{k:>14}' for k in keys))
    for name, m in rows:
        print(f"{name:<26}" + ''.join(f'{str(v):>14}' for v in m.values()))

    print('\n=== optimized 得分时间线 ===')
    cum = 0
    for t, p, code in opt.score_events:
        cum += p
        print(f"  {t:6.1f}min  +{p:<4} 累计 {cum:<6} {code}")


if __name__ == '__main__':
    main()
