# judge/__init__.py
"""
judge/ 文件夹 — 共识决策层（Layer 1，最终仲裁）
═════════════════════════════════════════════════════════════════════════════

【职责概述】
Judge 层是 1+N+1 架构的最内层（第三层），负责：
  1. 将一个 Packet 并发分配给所有已注册的智能体
  2. 等待所有智能体返回各自的 AuditResult
  3. 对 AuditResult 进行加权汇总
  4. 选择置信度最高的威胁类别作为"主导判定"
  5. 根据主导判定和阈值选择最终动作（ALLOW/BLOCK/QUARANTINE）
  6. 记录同意/反对意见的智能体（便于后续调试）
  7. 返回最终的 ConsensusVerdict

简单来说：Judge 是"智力汇总员"，负责把 N 个单独的判定融合成 1 个最终决策。

【文件组成】

judge/__init__.py ← 当前模块说明文件

judge/consensus.py
  - 核心文件，包含共识算法的全部逻辑
  - 主要函数：run_consensus_pipeline(packet) → ConsensusVerdict
  
  - 主要配置参数：
    ✓ BLOCK_THRESHOLD = 0.70
      含义：聚合置信度 ≥ 0.70 时，动作是 BLOCK（硬拒绝）
      作用：高置信度威胁直接拦截
    
    ✓ QUARANTINE_THRESHOLD = 0.45
      含义：聚合置信度 ≥ 0.45 且 < 0.70 时，动作是 QUARANTINE（隔离待审）
      作用：中等置信度的可疑请求先隔离，由人工判决
    
    ✓ AGENT_WEIGHTS
      作用：设置各智能体的权重（影响其对最终决策的影响力）
      例如：{"pattern_agent_v1": 1.0, "context_agent_v1": 1.2}
      含义：Context Agent 的意见稍微权重更高（1.2 倍）
    
    ✓ _AGENTS 列表
      作用：已注册的智能体列表（新增 Agent 就在这里注册）
      内容：[PatternAgent(), ContextAgent()]

【共识算法详细流程】

第 1 步：并发分发（Concurrent Dispatch）
──────────────────────────────────────
  for each agent in _AGENTS:
    启动异步任务：agent.analyse(packet)
  await 所有任务完成
  汇总结果到 results[] 列表

  好处：
    • N 个智能体同时工作 → 总耗时 = max(各自耗时)
    • 不是顺序执行，不是 sum(耗时)
    • Pattern Agent（1ms）和 Context Agent（500ms）同时跑
    • 总时间只是 500ms 多一点，而非 501ms

第 2 步：威胁分类加权汇总（Weighted Aggregation）
──────────────────────────────────────────────────
  目的：计算每个威胁类别的"综合置信度"
  
  算法：
    for each result in results:
      weight = AGENT_WEIGHTS.get(result.agent_id, DEFAULT_WEIGHT)
      category_scores[result.threat_category] += result.confidence * weight
      category_weight_totals[result.threat_category] += weight

    for each category:
      category_avg[category] = category_scores[category] / category_weight_totals[category]

  例子：
    如果 Pattern Agent 说 SQLi (置信度 0.93, 权重 1.0)
       Context Agent 说 Benign (置信度 0.1, 权重 1.2)
    那么：
      SQLi 得分 = 0.93 * 1.0 = 0.93
      Benign 得分 = 0.1 * 1.2 = 0.12
      SQLi 平均置信度 = 0.93 / 1.0 = 0.93
      Benign 平均置信度 = 0.12 / 1.2 = 0.10
  
  作用：不是简单平均，而是加权平均，尊重了各 Agent 的可靠性

第 3 步：选主导威胁（Select Dominant Threat）
──────────────────────────────────────────────
  目的：从所有威胁类别中选择置信度最高的一个
  
  算法：
    排除 BENIGN 类别（它是"非威胁"标签）
    if 还有威胁类别:
      dominant_threat = 置信度最高的威胁类别
      aggregate_confidence = 该类别的平均置信度
    else:
      dominant_threat = BENIGN
      aggregate_confidence = 1 - (Benign 平均置信度)

  理由：
    • BENIGN 置信度 0.95 = 威胁置信度 0.05
    • 反过来理解：系统 95% 确定没有威胁 → 5% 不确定
    • 用补集来表示威胁程度

第 4 步：阈值决策（Threshold-based Decision）
──────────────────────────────────────────────
  目的：根据聚合置信度选择最终动作
  
  算法：
    if dominant_threat == BENIGN:
      status = ALLOW          （肯定没有威胁）
    elif aggregate_confidence >= BLOCK_THRESHOLD:
      status = BLOCK          （极有把握是威胁）
    elif aggregate_confidence >= QUARANTINE_THRESHOLD:
      status = QUARANTINE     （不确定，先隔离）
    else:
      status = ALLOW          （信心不足，放行）

  阈值的含义：
    • 0.70 — 警告线：超过这条线，把赌注压在"这是坏东西"上
    • 0.45 — 犹豫线：不确定到什么程度才值得人工审查
    • 低于 0.45 — 放行：特征太模糊，假阳性风险太高

第 5 步：分歧记录（Dissent Tracking）
───────────────────────────────────────
  目的：记录哪些 Agent 赞成，哪些反对
  
  算法：
    contributing_agents = [r.agent_id for r in results 
                           if r.threat_category == dominant_threat]
    dissenting_agents = [r.agent_id for r in results 
                         if r.threat_category != dominant_threat]

  用途：
    • 如果两个智能体意见一致 → 高度自信
    • 如果有分歧 → 标记为需人工审查
    • 调试时能看到谁反对谁赞成

第 6 步：生成判决书（Generate Reasoning）
──────────────────────────────────────────
  目的：为本判决提供人类可读的解释
  
  例子：
    "Consensus over 2 agent(s): [pattern_agent_v1→sql_injection(0.93); 
     context_agent_v1→benign(0.10)]. Dominant threat 'sql_injection' 
     reached aggregate confidence 0.93 (block≥0.70, quarantine≥0.45). 
     Verdict: block. Dissenters: [context_agent_v1]."

第 7 步：返回 ConsensusVerdict（Return Final Verdict）
────────────────────────────────────────────────────────
  返回完整的判决对象，包含：
    ✓ packet_id — 本次审计涉及的 Packet ID
    ✓ status — 最终动作（ALLOW/BLOCK/QUARANTINE）
    ✓ dominant_threat — 主导威胁类别
    ✓ aggregate_confidence — 聚合置信度 [0.0, 1.0]
    ✓ contributing_agents — 支持这个判决的 Agent ID 列表
    ✓ dissenting_agents — 反对的 Agent ID 列表
    ✓ judge_reasoning — 判决理由（无损原始分析过程）
    ✓ decided_at — 决策时间戳（UTC）
    ✓ raw_audits — 原始 AuditResult 对象列表（完全透明）

【为什么要加权？】

并非所有智能体都等权重：
  • Pattern Agent（权重 1.0）：高精度但覆盖面受限
  • Context Agent（权重 1.2）：泛化能力强但有幻觉风险

1.2 倍权重 = "相信语义分析稍微多一点"。
当然这个数字可以根据实战调整，例如：
  • 如果语义 Agent 幻觉太多，降权到 0.9
  • 如果规则 Agent 覆盖面太窄，提权到 1.5

【为什么并发而不是顺序？】

顺序执行（坏）：
  Pattern Agent (1ms) → Context Agent (500ms) = 501ms

并发执行（好）：
  Pattern: ──── 1ms
  Context: ──────────────────────────────── 500ms
  合并：   ──────────────────────────────── 500ms

节省时间，用户体验更好。

【阈值如何调整？】

假设你发现太多漏放（假负性率高 = 漏过真威胁）：
  → 降低 BLOCK_THRESHOLD 从 0.70 到 0.60
  → 更多威胁会被拦截
  → 但假阳性也会增加（误杀无辜请求）

假设你发现太多误杀（假正性率高 = 拦截无辜请求）：
  → 提高 BLOCK_THRESHOLD 从 0.70 到 0.80
  → 要求证据更确凿才拦截
  → 但有些真威胁会漏掉

实战中需在精度(Precision)和召回(Recall)之间权衡。

【新增智能体的方法】

假设你写了一个 RateLimitAgent（检测滥用请求）：

  1. 在 agents/ 下创建新文件夹
     agents/rate_limit_agent/agent.py

  2. 继承 BaseAgent 并实现 _analyse()
     class RateLimitAgent(BaseAgent):
         agent_id = "rate_limit_agent_v1"
         async def _analyse(self, packet: Packet) -> AuditResult:
             # 实现具体逻辑
             ...

  3. 在 consensus.py 注册
     _AGENTS = [
         PatternAgent(),
         ContextAgent(),
         RateLimitAgent(),  ← 新增
     ]

  4. 配置权重（可选）
     AGENT_WEIGHTS = {
         "pattern_agent_v1": 1.0,
         "context_agent_v1": 1.2,
         "rate_limit_agent_v1": 0.8,  ← 新增
     }

  5. Judge 会自动纳入其判定，无需改算法代码

这就是"N"的威力——直接扩展，不破坏架构。
"""
