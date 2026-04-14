# judge/__init__.py
"""
judge/ 文件夹 — 共识决策层（Layer 1，最终仲裁）
═════════════════════════════════════════════════════════════════════════════

【职责概述】
Judge 负责把多个专家的 AuditResult 聚合成一个可执行的 ConsensusVerdict。
它是 1+N+1 架构中“落地动作”的最后一环。

【当前文件组成】

judge/__init__.py ← 当前模块说明文件

judge/consensus.py
  - 包含两个入口：
    1) run_consensus_pipeline(packet): 并发执行所有 Agent 并直接给结论。
    2) build_verdict(results, packet_id): 对已得到的结果做纯聚合。

【当前核心参数】

- BLOCK_THRESHOLD = 0.70
- QUARANTINE_THRESHOLD = 0.45
- AGENT_WEIGHTS:
  pattern_agent_v1 = 1.0
  context_agent_v1 = 1.2

【当前算法流程】

1. 并发执行所有已注册 Agent，得到 results。
2. 按 threat_category 进行“加权平均置信度”统计。
3. 选出主导威胁（优先考虑非 BENIGN）。
4. 按阈值映射 status：BLOCK / QUARANTINE / ALLOW。
5. 记录 contributing_agents 与 dissenting_agents。
6. 生成 judge_reasoning，构造并返回 ConsensusVerdict。

【为什么拆成两个入口】

- run_consensus_pipeline 适合网关直接调用（一步完成）。
- build_verdict 适合前端分步演示（先展示各 Agent，再做最终裁决）。

【扩展说明】

若新增 Agent：
1. 在 agents 下实现新 Agent。
2. 在 _AGENTS 注册。
3. 按需要在 AGENT_WEIGHTS 配置权重。
4. 聚合逻辑无需改动。
"""
