# agents/__init__.py
"""
agents/ 文件夹 — 专家智能体层（Layer N）
═════════════════════════════════════════════════════════════════════════════

【职责概述】
该目录承载 SentinelAgent 的多专家分析能力。所有专家接收同一个 Packet，
分别输出 AuditResult，随后由 Judge 层做统一共识裁决。

【当前实现（与代码一致）】

1. base_agent.py（抽象基类）
   - 提供 analyse() 公共入口：日志、统一调用、结果校验。
   - 子类必须实现 _analyse(packet)。
   - 内置证据锚定校验：非 BENIGN 结果若 evidence 不在原文中，
     会将该结果 confidence 降为 0.0，避免不可信证据进入后续决策。

2. pattern_agent/（规则专家）
   - 使用预编译正则规则做快速匹配。
   - 重点覆盖：SQL 注入、XSS、提示词注入的词法特征。
   - 特点：本地执行、稳定可复现、低延迟。

3. context_agent/（语义专家）
   - 通过 DeepSeek（OpenAI 兼容接口）进行语义分析。
   - 当前实现是“始终调用真实 API”，不依赖 SENTINEL_DEMO_MODE。
   - API 异常或解析异常时会走 safe-pass 降级路径，保障流程可继续。

【单次分析链路】

Packet
  -> PatternAgent.analyse(packet)
  -> ContextAgent.analyse(packet)
  -> 结果经 BaseAgent 证据锚定校验
  -> 返回 Judge 层聚合

【为什么保留多专家】

- 规则专家负责“快且稳”的已知攻击识别。
- 语义专家负责“广覆盖”的意图级攻击识别。
- 双专家并行后由 Judge 做加权融合，可减少单模型盲区。

【扩展方式】

新增专家时，按以下步骤接入：
1. 新建 agents/xxx_agent/agent.py。
2. 继承 BaseAgent 并实现 _analyse()。
3. 在 judge/consensus.py 的 _AGENTS 注册实例。
4. 在 AGENT_WEIGHTS 配置对应权重。
"""
